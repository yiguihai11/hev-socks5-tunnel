/*
 ============================================================================
 Name        : hev-filter.c
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2025 hev
 Description : High-Performance Filter Implementation
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <arpa/inet.h>
#include <time.h>
#include <lwip/ip_addr.h>

#include <lwip/tcp.h>
#include "hev-rbtree.h"

#include "hev-logger.h"
#include "hev-memory-allocator.h"
#include "hev-filter.h"
#include <hev-task.h>
#include <hev-task-mutex.h>

/* ============================================================================
   Radix Tree for IP Address Lookups (O(1) best case)
   ============================================================================ */

typedef struct _RadixNode {
    struct _RadixNode *left;   /* 0 bit */
    struct _RadixNode *right;  /* 1 bit */
    uint8_t is_leaf;           /* Leaf node flag */
    uint8_t blocked;           /* Blocked flag for ACL */
} RadixNode;

static RadixNode *acl_ipv4_tree = NULL;
static RadixNode *acl_ipv6_tree = NULL;

static RadixNode *
radix_node_create (void)
{
    RadixNode *node = hev_malloc0 (sizeof (RadixNode));
    return node;
}

static void
radix_tree_free (RadixNode *node)
{
    RadixNode *left;
    RadixNode *right;
    
    if (!node)
        return;
    
    // ✅ 先保存子节点指针,避免访问已释放的内存
    left = node->left;
    right = node->right;
    
    // ✅ 先释放当前节点
    hev_free (node);
    
    // ✅ 再递归释放子节点
    radix_tree_free (left);
    radix_tree_free (right);
}

/* ============================================================================
   Hash Table for Hostname Lookups (O(1) average)
   Using simple chaining for collision resolution
   ============================================================================ */


#define HOSTNAME_HASH_SIZE 65536

typedef struct _HostnameEntry {
    char hostname[MAX_HOST_LENGTH + 1];
    struct _HostnameEntry *next;
} HostnameEntry;

static HostnameEntry *hostname_table[HOSTNAME_HASH_SIZE];

/* ============================================================================
   CIDR Ranges for Routing (Binary Search - O(log n))
   ============================================================================ */

typedef struct _CIDRRange4 {
    uint32_t start;
    uint32_t end;
} CIDRRange4;

typedef struct _CIDRRange6 {
    uint8_t start[16];
    uint8_t end[16];
} CIDRRange6;

static CIDRRange4 *chnroutes_ipv4 = NULL;
static uint32_t chnroutes_ipv4_count = 0;
static CIDRRange6 *chnroutes_ipv6 = NULL;
static uint32_t chnroutes_ipv6_count = 0;

/* Statistics */

static HevFilterStats stats;

/* ============================================================================
   Blacklist Hash Table (O(1) average case lookup)
   ============================================================================ */

#define BLACKLIST_HASH_SIZE 65536

static HevBlacklistedIP *blacklist_table[BLACKLIST_HASH_SIZE];
static size_t blacklist_count = 0;
static HevTaskMutex blacklist_mutex;

/* High-performance hash function optimized for 65536 buckets */
static unsigned int
blacklist_hash_func (const ip_addr_t *addr)
{
    unsigned int hash = 0;

    if (IP_IS_V4 (addr)) {
        /* Optimized for IPv4 - use full 32-bit address */
        uint32_t ip = ip4_addr_get_u32 (ip_2_ip4 (addr));
        /* Mix bits for better distribution in larger table */
        hash = (ip ^ (ip >> 16)) * 0x85ebca6b;
        hash ^= (hash >> 13);
        hash = hash * 0xc2b2ae35;
    } else if (IP_IS_V6 (addr)) {
        /* Optimized for IPv6 - use all 128 bits efficiently */
        const u32_t *ip = ip_2_ip6 (addr)->addr;
        for (int i = 0; i < 4; i++) {
            hash ^= ip[i] * 0x9e3779b9;
            hash = (hash << 13) | (hash >> 19);
        }
    }

    return hash & (BLACKLIST_HASH_SIZE - 1); /* Faster than modulo for power of 2 */
}

static void
radix_tree_insert_ipv4 (uint32_t ip, uint8_t prefix)
{
    RadixNode **current = &acl_ipv4_tree;
    
    if (!*current)
        *current = radix_node_create ();
    
    for (int i = 0; i < prefix; i++) {
        uint8_t bit = (ip >> (31 - i)) & 1;
        RadixNode **next = bit ? &(*current)->right : &(*current)->left;
        
        if (!*next)
            *next = radix_node_create ();
        
        current = next;
    }
    
    (*current)->is_leaf = 1;
    (*current)->blocked = 1;
}

static void
radix_tree_insert_ipv6 (const uint8_t *ip, uint8_t prefix)
{
    RadixNode **current = &acl_ipv6_tree;
    
    if (!*current)
        *current = radix_node_create ();
    
    for (int i = 0; i < prefix; i++) {
        uint8_t byte = i / 8;
        uint8_t bit_in_byte = 7 - (i % 8);
        uint8_t bit = (ip[byte] >> bit_in_byte) & 1;
        
        RadixNode **next = bit ? &(*current)->right : &(*current)->left;
        
        if (!*next)
            *next = radix_node_create ();
        
        current = next;
    }
    
    (*current)->is_leaf = 1;
    (*current)->blocked = 1;
}

static int
radix_tree_lookup_ipv4 (uint32_t ip)
{
    RadixNode *current = acl_ipv4_tree;
    int blocked = 0;
    
    for (int i = 0; i < 32 && current; i++) {
        if (current->blocked) { // Check if any parent prefix is blocked
            blocked = 1;
        }
        
        uint8_t bit = (ip >> (31 - i)) & 1;
        current = bit ? current->right : current->left;
    }
    
    if (current && current->blocked) { // Check the final node
        blocked = 1;
    }
    
    return blocked;
}

static int
radix_tree_lookup_ipv6 (const uint8_t *ip)
{
    RadixNode *current = acl_ipv6_tree;
    int blocked = 0;
    
    for (int i = 0; i < 128 && current; i++) {
        if (current->blocked) { // Check if any parent prefix is blocked
            blocked = 1;
        }
        
        uint8_t byte = i / 8;
        uint8_t bit_in_byte = 7 - (i % 8);
        uint8_t bit = (ip[byte] >> bit_in_byte) & 1;
        
        current = bit ? current->right : current->left;
    }
    
    if (current && current->blocked) { // Check the final node
        blocked = 1;
    }
    
    return blocked;
}

/* ============================================================================
   Hash Table Operations
   ============================================================================ */

/* Helper Functions - must be declared before use */
static void safe_str_copy (char *dest, const char *src, size_t max_len);
static void debug_free_and_clear (void *ptr, size_t size, const char *name);
static time_t get_current_time_ms (void);
static time_t get_current_time_seconds (void);

/* Safe string copy with null termination */
static void
safe_str_copy (char *dest, const char *src, size_t max_len)
{
    strncpy (dest, src, max_len - 1);
    dest[max_len - 1] = '\0';
}

/* Enhanced memory cleanup with debugging */
static void
debug_free_and_clear (void *ptr, size_t size, const char *name)
{
    if (ptr) {
        memset (ptr, 0, size);  /* Clear sensitive data */
        LOG_D ("filter: Freed %s (%p)", name, ptr);
        hev_free (ptr);
    }
}

/* High-precision time functions */
static time_t
get_current_time_ms (void)
{
    struct timeval tv;
    gettimeofday (&tv, NULL);
    return (time_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static time_t
get_current_time_seconds (void)
{
    struct timeval tv;
    gettimeofday (&tv, NULL);
    return tv.tv_sec;
}

/* High-performance hostname hash function optimized for 65536 buckets */
static uint32_t
hostname_hash (const char *hostname)
{
    uint32_t hash = 5381;
    int c;

    /* DJB2 hash algorithm with better mixing for large tables */
    while ((c = tolower ((unsigned char)*hostname++))) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
        /* Additional mixing for better distribution in larger table */
        hash ^= (hash >> 11);
    }

    /* Final mixing round */
    hash ^= (hash >> 16);
    hash *= 0x85ebca6b;
    hash ^= (hash >> 13);
    hash *= 0xc2b2ae35;

    return hash & (HOSTNAME_HASH_SIZE - 1); /* Faster than modulo for power of 2 */
}

static void
hostname_table_insert (const char *hostname)
{
    uint32_t hash = hostname_hash (hostname);
    HostnameEntry *entry = hev_malloc (sizeof (HostnameEntry));

    if (!entry)
        return;

    safe_str_copy (entry->hostname, hostname, MAX_HOST_LENGTH + 1);
    entry->next = hostname_table[hash];
    hostname_table[hash] = entry;
}

static int
hostname_table_lookup (const char *hostname)
{
    uint32_t hash = hostname_hash (hostname);
    HostnameEntry *entry = hostname_table[hash];
    
    while (entry) {
        if (strcasecmp (entry->hostname, hostname) == 0)
            return 1;
        entry = entry->next;
    }
    
    return 0;
}

static void
hostname_table_free (void)
{
    int freed_count = 0;

    for (int i = 0; i < HOSTNAME_HASH_SIZE; i++) {
        HostnameEntry *entry = hostname_table[i];
        while (entry) {
            HostnameEntry *next = entry->next;
            debug_free_and_clear (entry, sizeof (HostnameEntry), "hostname entry");
            freed_count++;
            entry = next;
        }
        hostname_table[i] = NULL;
    }

    if (freed_count > 0) {
        LOG_D ("filter: Freed %d hostname entries", freed_count);
    }
}

/* ============================================================================
   CIDR Range Operations (Binary Search)
   ============================================================================ */

static int
compare_cidr4 (const void *a, const void *b)
{
    const CIDRRange4 *ra = a;
    const CIDRRange4 *rb = b;
    if (ra->start < rb->start)
        return -1;
    if (ra->start > rb->start)
        return 1;
    return 0;
}

static int
compare_cidr6 (const void *a, const void *b)
{
    const CIDRRange6 *ra = a;
    const CIDRRange6 *rb = b;
    return memcmp (ra->start, rb->start, 16);
}

static int
cidr_lookup_ipv4 (uint32_t ip)
{
    int left = 0;
    int right = chnroutes_ipv4_count - 1;
    
    while (left <= right) {
        int mid = left + (right - left) / 2;
        
        if (ip >= chnroutes_ipv4[mid].start && ip <= chnroutes_ipv4[mid].end)
            return 1;
        
        if (ip < chnroutes_ipv4[mid].start)
            right = mid - 1;
        else
            left = mid + 1;
    }
    
    return 0;
}

static int
cidr_lookup_ipv6 (const uint8_t *ip)
{
    int left = 0;
    int right = chnroutes_ipv6_count - 1;
    
    while (left <= right) {
        int mid = left + (right - left) / 2;
        
        if (memcmp (ip, chnroutes_ipv6[mid].start, 16) >= 0 &&
            memcmp (ip, chnroutes_ipv6[mid].end, 16) <= 0)
            return 1;
        
        if (memcmp (ip, chnroutes_ipv6[mid].start, 16) < 0)
            right = mid - 1;
        else
            left = mid + 1;
    }
    
    return 0;
}

/* ============================================================================
   TLS Parser (from original hev-tls-parser.c)
   ============================================================================ */

static uint16_t
read_uint16 (const unsigned char *buf)
{
    return (buf[0] << 8) | buf[1];
}

static uint32_t
read_uint24 (const unsigned char *buf)
{
    return (buf[0] << 16) | (buf[1] << 8) | buf[2];
}

static int
parse_sni_extension (const unsigned char *data, size_t len, char *sni_out, size_t sni_max)
{
    size_t pos = 0;
    
    if (len < 2)
        return -1;
    
    uint16_t list_len = read_uint16 (data + pos);
    pos += 2;
    
    if (list_len + 2 > len)
        return -1;
    
    while (pos < len) {
        if (pos + 3 > len)
            break;
        
        uint8_t name_type = data[pos++];
        uint16_t name_len = read_uint16 (data + pos);
        pos += 2;
        
        if (pos + name_len > len)
            break;
        
        if (name_type == 0) {
            size_t copy_len = (name_len < sni_max) ? name_len : sni_max;
            memcpy (sni_out, data + pos, copy_len);
            sni_out[copy_len] = '\0';
            return 0;
        }
        
        pos += name_len;
    }
    
    return -1;
}

static int
parse_alpn_extension (const unsigned char *data, size_t len, char *alpn_out, size_t alpn_max)
{
    size_t pos = 0;
    
    if (len < 2)
        return -1;
    
    uint16_t alpn_len = read_uint16 (data + pos);
    pos += 2;
    
    if (alpn_len + 2 > len)
        return -1;
    
    if (pos < len) {
        uint8_t proto_len = data[pos++];
        if (pos + proto_len <= len) {
            size_t copy_len = (proto_len < alpn_max - 1) ? proto_len : alpn_max - 1;
            memcpy (alpn_out, data + pos, copy_len);
            alpn_out[copy_len] = '\0';
            return 0;
        }
    }
    
    return -1;
}

int
hev_filter_parse_tls (void *log_data, const unsigned char *data, size_t len,
                      HevTLSClientHello *hello)
{
    size_t pos = 0;
    
    memset (hello, 0, sizeof (HevTLSClientHello));
    
    if (len < 5)
        return -1;
    
    uint8_t content_type = data[pos++];
    if (content_type != TLS_CONTENT_TYPE_HANDSHAKE) {
        LOG_D ("%p filter: Not TLS handshake (0x%02x)", log_data, content_type);
        return -1;
    }
    
    uint16_t tls_version = read_uint16 (data + pos);
    pos += 2;
    hello->tls_version = tls_version;
    
    uint16_t record_len = read_uint16 (data + pos);
    pos += 2;
    
    if (pos + record_len > len) {
        LOG_D ("%p filter: Incomplete TLS record", log_data);
        return -1;
    }
    
    if (pos >= len)
        return -1;
    uint8_t handshake_type = data[pos++];
    if (handshake_type != TLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
        LOG_D ("%p filter: Not ClientHello (0x%02x)", log_data, handshake_type);
        return -1;
    }
    
    if (pos + 3 > len)
        return -1;
    uint32_t handshake_len = read_uint24 (data + pos);
    pos += 3;
    
    LOG_D ("%p filter: ClientHello (version=0x%04x, len=%u)", log_data, tls_version, handshake_len);
    
    /* Skip Client Version + Random */
    if (pos + 34 > len)
        return -1;
    pos += 34;
    
    /* Session ID */
    if (pos >= len)
        return -1;
    uint8_t session_id_len = data[pos++];
    if (pos + session_id_len > len)
        return -1;
    pos += session_id_len;
    
    /* Cipher Suites */
    if (pos + 2 > len)
        return -1;
    uint16_t cipher_suites_len = read_uint16 (data + pos);
    pos += 2;
    if (pos + cipher_suites_len > len)
        return -1;
    pos += cipher_suites_len;
    
    /* Compression Methods */
    if (pos >= len)
        return -1;
    uint8_t compression_len = data[pos++];
    if (pos + compression_len > len)
        return -1;
    pos += compression_len;
    
    /* Extensions */
    if (pos + 2 > len) {
        LOG_D ("%p filter: No extensions", log_data);
        hello->detected = 1;
        return 0;
    }
    
    uint16_t extensions_len = read_uint16 (data + pos);
    pos += 2;
    
    if (pos + extensions_len > len)
        return -1;
    
    LOG_D ("%p filter: Parsing extensions (len=%u)", log_data, extensions_len);
    
    size_t extensions_end = pos + extensions_len;
    while (pos + 4 <= extensions_end) {
        uint16_t ext_type = read_uint16 (data + pos);
        pos += 2;
        
        uint16_t ext_len = read_uint16 (data + pos);
        pos += 2;
        
        if (pos + ext_len > extensions_end)
            break;
        
        switch (ext_type) {
        case TLS_EXT_SERVER_NAME:
            LOG_D ("%p filter: Found SNI extension", log_data);
            parse_sni_extension (data + pos, ext_len, hello->sni, MAX_SNI_LENGTH);
            break;
        
        case TLS_EXT_ALPN:
            LOG_D ("%p filter: Found ALPN extension", log_data);
            parse_alpn_extension (data + pos, ext_len, hello->alpn, sizeof (hello->alpn));
            break;
        }
        
        pos += ext_len;
    }
    
    hello->detected = 1;
    
    if (hello->sni[0]) {
        LOG_I ("%p filter: Detected SNI: %s", log_data, hello->sni);
        stats.tls_parsed++;
    }
    
    return 0;
}

/* ============================================================================
   HTTP Host Parser
   ============================================================================ */

static char *
strcasestr_custom (const char *haystack, const char *needle)
{
    if (!*needle)
        return (char *)haystack;
    for (; *haystack; ++haystack) {
        if (strncasecmp (haystack, needle, strlen (needle)) == 0)
            return (char *)haystack;
    }
    return NULL;
}

int
hev_filter_parse_http_host (void *log_data, const unsigned char *data, size_t len,
                            char *hostname, size_t hostname_len)
{
    if (len == 0 || len >= 8192)
        return -1;
    
    char *buffer = hev_malloc (len + 1);
    if (!buffer)
        return -1;
    
    memcpy (buffer, data, len);
    buffer[len] = '\0';
    
    char *host_start = strcasestr_custom (buffer, "\r\nHost: ");
    if (host_start) {
        host_start += 8;
        char *host_end = strstr (host_start, "\r\n");
        if (host_end) {
            size_t copy_len = host_end - host_start;
            if (copy_len > 0 && copy_len < hostname_len) {
                memcpy (hostname, host_start, copy_len);
                hostname[copy_len] = '\0';
                hev_free (buffer);
                LOG_I ("%p filter: Detected HTTP Host: %s", log_data, hostname);
                stats.http_parsed++;
                return 0;
            }
        }
    }
    
    char *url_start = strcasestr_custom (buffer, "GET http://");
    if (url_start) {
        url_start += 11;
        char *url_end = strchr (url_start, '/');
        if (!url_end)
            url_end = strchr (url_start, ' ');
        
        if (url_end) {
            size_t copy_len = url_end - url_start;
            if (copy_len > 0 && copy_len < hostname_len) {
                memcpy (hostname, url_start, copy_len);
                hostname[copy_len] = '\0';
                hev_free (buffer);
                LOG_I ("%p filter: Detected HTTP URL Host: %s", log_data, hostname);
                stats.http_parsed++;
                return 0;
            }
        }
    }
    
    hev_free (buffer);
    return -1;
}

/* ============================================================================
   Hash Table Operations
   ============================================================================ */

/* File opening with error handling */
static FILE *
safe_fopen (const char *path, const char *mode)
{
    FILE *fp = fopen (path, mode);
    if (!fp) {
        LOG_E ("filter: Failed to open file '%s': %s", path, strerror (errno));
    }
    return fp;
}

/* ============================================================================
   Public API
   ============================================================================ */

int
hev_filter_init (void)
{
    /* Use single memset for all zero-initialization */
    memset (&stats, 0, sizeof (HevFilterStats));
    memset (hostname_table, 0, sizeof (hostname_table));
    memset (blacklist_table, 0, sizeof (blacklist_table));
    blacklist_count = 0;

    hev_task_mutex_init (&blacklist_mutex);

    LOG_I ("filter: Initialized");
    return 0;
}

void
hev_filter_fini (void)
{
    LOG_D ("filter: Cleaning up resources");  // 这行日志会验证函数是否被调用
    
    // ✅ 释放顺序：和分配顺序完全相反（最后分配的先释放）
    // 1. 释放 chnroutes（最后分配：load_chnroutes）
    if (chnroutes_ipv6) {
        LOG_D ("filter: Freeing chnroutes IPv6 (%u entries)", chnroutes_ipv6_count);
        hev_free (chnroutes_ipv6);
        chnroutes_ipv6 = NULL;
        chnroutes_ipv6_count = 0;
    }
    
    if (chnroutes_ipv4) {
        LOG_D ("filter: Freeing chnroutes IPv4 (%u entries)", chnroutes_ipv4_count);
        hev_free (chnroutes_ipv4);
        chnroutes_ipv4 = NULL;
        chnroutes_ipv4_count = 0;
    }
    
    // 2. 释放 acl 树（中间分配：load_acl）
    if (acl_ipv6_tree) {
        LOG_D ("filter: Freeing ACL IPv6 tree");
        RadixNode *tree = acl_ipv6_tree;
        acl_ipv6_tree = NULL;  // 先置空，防重复释放
        radix_tree_free (tree);
    }
    
    if (acl_ipv4_tree) {
        LOG_D ("filter: Freeing ACL IPv4 tree");
        RadixNode *tree = acl_ipv4_tree;
        acl_ipv4_tree = NULL;  // 先置空，防重复释放
        radix_tree_free (tree);
    }
    
    // 3. 释放 hostname_table（最先分配：hev_filter_init）
    LOG_D ("filter: Freeing hostname table");
    hostname_table_free ();

    // 4. 清理黑名单
    LOG_D ("filter: Freeing blacklist");
    hev_filter_blacklist_clear ();

    // 5. 清零统计信息
    memset(&stats, 0, sizeof(stats));

    LOG_I ("filter: Finalized successfully");  // 验证函数执行完成
}

int
hev_filter_load_acl (const char *file_path)
{
    FILE *fp;
    char line[1024];
    int ipv4_count = 0, ipv6_count = 0, hostname_count = 0;
    
    if (!file_path || strlen (file_path) == 0) {
        LOG_D ("filter: ACL file path not set");
        return 0;
    }
    
    fp = safe_fopen (file_path, "r");
    if (!fp) {
        return -1;
    }
    
    LOG_I ("filter: Loading ACL from %s", file_path);
    
    while (fgets (line, sizeof (line), fp)) {
        char *trim = line;
        while (isspace ((unsigned char)*trim))
            trim++;
        
        char *end = trim + strlen (trim) - 1;
        while (end >= trim && isspace ((unsigned char)*end))
            *end-- = '\0';
        
        char *comment = strchr (trim, '#');
        if (comment)
            *comment = '\0';
        
        if (strlen (trim) == 0)
            continue;
        
        ip_addr_t ip_test;
        if (ipaddr_aton (trim, &ip_test)) {
            if (IP_IS_V4 (&ip_test)) {
                uint32_t ip = ntohl (ip_2_ip4 (&ip_test)->addr);
                radix_tree_insert_ipv4 (ip, 32);
                ipv4_count++;
            } else if (IP_IS_V6 (&ip_test)) {
                radix_tree_insert_ipv6 ((const uint8_t *)ip_2_ip6 (&ip_test)->addr, 128);
                ipv6_count++;
            }
        } else {
            hostname_table_insert (trim);
            hostname_count++;
        }
    }
    
    fclose (fp);
    LOG_I ("filter: Loaded %d ACL entries (IPv4:%d, IPv6:%d, Hostname:%d)",
           ipv4_count + ipv6_count + hostname_count, ipv4_count, ipv6_count, hostname_count);
    return 0;
}

int
hev_filter_load_chnroutes (const char *file_path)
{
    FILE *fp;
    char line[128];
    
    if (!file_path) {
        LOG_D ("filter: chnroutes file not configured");
        return 0;
    }
    
    fp = fopen (file_path, "r");
    if (!fp) {
        LOG_E ("filter: Failed to open chnroutes file %s", file_path);
        return -1;
    }
    
    LOG_I ("filter: Loading chnroutes from %s", file_path);
    
    while (fgets (line, sizeof (line), fp)) {
        char ip_str[128];
        int prefix_len;
        
        if (sscanf (line, "%[^/]/%d", ip_str, &prefix_len) != 2)
            continue;
        
        if (strchr (ip_str, ':')) {
            /* IPv6 */
            chnroutes_ipv6_count++;
            chnroutes_ipv6 = realloc (chnroutes_ipv6, sizeof (CIDRRange6) * chnroutes_ipv6_count);
            
            struct in6_addr addr;
            inet_pton (AF_INET6, ip_str, &addr);
            
            CIDRRange6 *range = &chnroutes_ipv6[chnroutes_ipv6_count - 1];
            memcpy (range->start, &addr, 16);
            memcpy (range->end, &addr, 16);
            
            int bits_to_mask = 128 - prefix_len;
            int i = 15;
            while (bits_to_mask > 0 && i >= 0) {
                int bits_in_byte = (bits_to_mask > 8) ? 8 : bits_to_mask;
                uint8_t mask = (0xFF >> bits_in_byte);
                range->start[i] &= mask;
                range->end[i] |= ~mask;
                bits_to_mask -= bits_in_byte;
                i--;
            }
        } else {
            /* IPv4 */
            chnroutes_ipv4_count++;
            chnroutes_ipv4 = realloc (chnroutes_ipv4, sizeof (CIDRRange4) * chnroutes_ipv4_count);
            
            struct in_addr addr;
            inet_aton (ip_str, &addr);
            uint32_t addr_host = ntohl (addr.s_addr);
            uint32_t mask_host = (prefix_len == 0) ? 0 : (0xFFFFFFFF << (32 - prefix_len));
            uint32_t start_host = addr_host & mask_host;
            uint32_t end_host = start_host | (~mask_host);
            
            chnroutes_ipv4[chnroutes_ipv4_count - 1].start = start_host;
            chnroutes_ipv4[chnroutes_ipv4_count - 1].end = end_host;
        }
    }
    
    fclose (fp);
    
    if (chnroutes_ipv4)
        qsort (chnroutes_ipv4, chnroutes_ipv4_count, sizeof (CIDRRange4), compare_cidr4);
    if (chnroutes_ipv6)
        qsort (chnroutes_ipv6, chnroutes_ipv6_count, sizeof (CIDRRange6), compare_cidr6);
    
    LOG_I ("filter: Loaded chnroutes (IPv4:%u, IPv6:%u)", chnroutes_ipv4_count, chnroutes_ipv6_count);
    return 0;
}

int
hev_filter_is_blocked_ip (const ip_addr_t *ip)
{
    if (IP_IS_V4 (ip)) {
        uint32_t addr = ntohl (ip_2_ip4 (ip)->addr);
        if (radix_tree_lookup_ipv4 (addr)) {
            stats.ip_blocked++;
            return 1;
        }
    } else if (IP_IS_V6 (ip)) {
        if (radix_tree_lookup_ipv6 ((const uint8_t *)ip_2_ip6 (ip)->addr)) {
            stats.ip_blocked++;
            return 1;
        }
    }
    return 0;
}

int
hev_filter_is_blocked_hostname (const char *hostname)
{
    if (!hostname || strlen (hostname) == 0)
        return 0;
    
    if (hostname_table_lookup (hostname)) {
        stats.hostname_blocked++;
        return 1;
    }
    return 0;
}

int
hev_filter_is_domestic (const ip_addr_t *ip)
{
    if (IP_IS_V4 (ip)) {
        if (!chnroutes_ipv4)
            return 0;
        
        uint32_t addr = ntohl (ip_2_ip4 (ip)->addr);
        if (cidr_lookup_ipv4 (addr)) {
            stats.domestic_hits++;
            return 1;
        }
        stats.foreign_hits++;
    } else if (IP_IS_V6 (ip)) {
        if (!chnroutes_ipv6)
            return 0;
        
        if (cidr_lookup_ipv6 ((const uint8_t *)ip_2_ip6 (ip)->addr)) {
            stats.domestic_hits++;
            return 1;
        }
        stats.foreign_hits++;
    }
    return 0;
}

int
hev_filter_sniff_pcb_hostname (struct tcp_pcb *pcb, struct pbuf *queue,
                               char *hostname, size_t hostname_len)
{
    unsigned char buffer[2048];
    size_t total_len = 0;
    struct pbuf *p;
    
    if (!queue || !hostname || hostname_len == 0)
        return -1;
    
    /* Copy data from pbuf queue */
    for (p = queue; p && total_len < sizeof (buffer) - 1; p = p->next) {
        size_t copy_len = p->len;
        if (total_len + copy_len >= sizeof (buffer))
            copy_len = sizeof (buffer) - 1 - total_len;
        
        memcpy (buffer + total_len, p->payload, copy_len);
        total_len += copy_len;
    }
    
    if (total_len == 0)
        return -1;
    
    /* Try TLS for port 443 */
    if (pcb->local_port == 443) {
        HevTLSClientHello hello;
        if (hev_filter_parse_tls (pcb, buffer, total_len, &hello) == 0 && hello.sni[0]) {
            strncpy (hostname, hello.sni, hostname_len - 1);
            hostname[hostname_len - 1] = '\0';
            return 0;
        }
    }
    /* Try HTTP for ports 80/8080 */
    else if (pcb->local_port == 80 || pcb->local_port == 8080) {
        if (hev_filter_parse_http_host (pcb, buffer, total_len, hostname, hostname_len) == 0) {
            return 0;
        }
    }
    
    return -1;
}

void
hev_filter_get_stats (HevFilterStats *out_stats)
{
    if (out_stats)
        memcpy (out_stats, &stats, sizeof (HevFilterStats));
}

void
hev_filter_reset_stats (void)
{
    memset (&stats, 0, sizeof (stats));
}

/* ============================================================================
   Blacklist Implementation
   ============================================================================ */

#include "hev-config.h"

void
hev_filter_blacklist_add (const ip_addr_t *addr)
{
    HevBlacklistedIP *bip;
    unsigned int hash;
    int expiry_minutes;
    char ip_str[INET6_ADDRSTRLEN];

    if (!addr) {
        LOG_E ("filter: blacklist_add called with NULL address");
        return;
    }

    expiry_minutes = hev_config_get_smart_proxy_blocked_ip_expiry_minutes ();
    if (expiry_minutes <= 0)
        return;

    bip = hev_malloc (sizeof (HevBlacklistedIP));
    if (!bip) {
        LOG_E ("filter: Failed to allocate blacklist entry");
        return;
    }

    ip_addr_copy (bip->addr, *addr);
    bip->added_time = get_current_time_seconds ();
    bip->expiry = bip->added_time + expiry_minutes * 60;

    /* Log with millisecond precision for debugging */
    time_t current_ms = get_current_time_ms ();
    LOG_D ("filter: Adding blacklist entry at %ld ms", current_ms % 1000);

    hash = blacklist_hash_func (addr);
    ipaddr_ntoa_r (addr, ip_str, sizeof (ip_str));

    hev_task_mutex_lock (&blacklist_mutex);
    bip->next = blacklist_table[hash];
    blacklist_table[hash] = bip;
    blacklist_count++;
    hev_task_mutex_unlock (&blacklist_mutex);

    LOG_I ("filter: Added %s to blacklist (expires in %d minutes)", ip_str, expiry_minutes);
}

int
hev_filter_blacklist_check (const ip_addr_t *addr)
{
    HevBlacklistedIP **current, *prev, *to_delete = NULL;
    unsigned int hash;
    time_t now;
    int found = 0;
    int expired_count = 0;
    char ip_str[INET6_ADDRSTRLEN];

    if (!addr) {
        LOG_E ("filter: blacklist_check called with NULL address");
        return 0;
    }

    hash = blacklist_hash_func (addr);
    now = get_current_time_seconds ();

    hev_task_mutex_lock (&blacklist_mutex);
    current = &blacklist_table[hash];
    prev = NULL;

    while (*current) {
        HevBlacklistedIP *bip = *current;

        /* Remove expired entries */
        if (now > bip->expiry) {
            *current = bip->next;
            if (prev)
                prev->next = bip->next;

            to_delete = bip;
            blacklist_count--;
            expired_count++;

            /* Continue with next entry */
            continue;
        }

        /* Check if this is the address we're looking for */
        if (ip_addr_cmp (&bip->addr, addr)) {
            found = 1;
            ipaddr_ntoa_r (addr, ip_str, sizeof (ip_str));
            time_t time_remaining = bip->expiry - now;
            LOG_D ("filter: IP %s found in blacklist (expires in %ld seconds)",
                   ip_str, time_remaining);
        }

        prev = bip;
        current = &bip->next;
    }

    hev_task_mutex_unlock (&blacklist_mutex);

    /* Free expired entries outside of mutex lock */
    if (to_delete) {
        /* This is simplified - in production, we'd collect all expired entries
         * and free them in a batch to avoid multiple malloc/free calls */
        hev_free (to_delete);
    }

    if (expired_count > 0) {
        LOG_D ("filter: Cleaned up %d expired blacklist entries", expired_count);
    }

    return found;
}

void
hev_filter_blacklist_clear (void)
{
    HevBlacklistedIP *current, *next;
    int cleared_count = 0;

    hev_task_mutex_lock (&blacklist_mutex);

    for (int i = 0; i < BLACKLIST_HASH_SIZE; i++) {
        current = blacklist_table[i];
        while (current) {
            next = current->next;
            hev_free (current);
            current = next;
            cleared_count++;
        }
        blacklist_table[i] = NULL;
    }

    blacklist_count = 0;
    hev_task_mutex_unlock (&blacklist_mutex);

    LOG_I ("filter: Cleared %d blacklist entries", cleared_count);
}

size_t
hev_filter_blacklist_get_count (void)
{
    return blacklist_count;
}


