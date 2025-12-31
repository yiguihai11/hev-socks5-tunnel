/*
 ============================================================================
 Name        : hev-filter.c
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2025 hev
 Description : High-Performance Filter Implementation
 ============================================================================
 */

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

/* FreeBSD compatibility */
#if defined(__FreeBSD__)
#define __BSD_VISIBLE 1
#ifndef AF_INET6
#define AF_INET6 28
#endif
#endif

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
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

typedef struct _RadixNode
{
    struct _RadixNode *left; /* 0 bit */
    struct _RadixNode *right; /* 1 bit */
    uint8_t is_leaf; /* Leaf node flag */
    uint8_t blocked; /* Blocked flag for ACL (legacy, for chnroutes) */
    HevACLAction action; /* ACL action: ALLOW, BLOCK, or DEFAULT */
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

typedef struct _HostnameEntry
{
    char hostname[MAX_HOSTNAME_LENGTH + 1];
    struct _HostnameEntry *next;
} HostnameEntry;

static HostnameEntry *hostname_table[HOSTNAME_HASH_SIZE];

/* ============================================================================
   CIDR Ranges for Routing (Binary Search - O(log n))
   ============================================================================ */

typedef struct _CIDRRange4
{
    uint32_t start;
    uint32_t end;
} CIDRRange4;

typedef struct _CIDRRange6
{
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

static HevBlacklistEntry *blacklist_table[BLACKLIST_HASH_SIZE];
static size_t blacklist_count = 0;
static HevTaskMutex blacklist_mutex;

/* ============================================================================
   ACL Hash Functions (defined before use)
   ============================================================================ */

/* Simple hash function for domain names (1024 buckets) */
static unsigned int
domain_hash_func (const char *str)
{
    unsigned int hash = 5381;
    int c;
    while ((c = *str++)) {
        c = tolower (c);
        hash = ((hash << 5) + hash) + c;
    }
    return hash % 1024;
}

/* ============================================================================
   New ACL Rules Storage (Two-Stage Matching)
   ============================================================================ */

/* Port rules array (indexed by port number) */
static HevACLRule *acl_port_rules[65536] = { NULL };

/* IP rules list (for two-stage ACL matching) */
static HevACLRule *acl_ip_rules = NULL;

/* CIDR rules list (for two-stage ACL matching) */
static HevACLRule *acl_cidr_rules = NULL;

/* Domain rules with three hash tables */
static HevACLRule *acl_domain_exact[1024] = { NULL }; /* exact match */
static HevACLRule *acl_domain_wildcard[1024] = { NULL }; /* *.example.com */
static HevACLRule *acl_domain_suffix[1024] = { NULL }; /* .example.com */

/* ============================================================================ */

/* 黑名单统计 */
static uint64_t total_hits = 0;
static uint64_t total_blocked_bytes = 0;

static void
radix_tree_insert_ipv4 (uint32_t ip, uint8_t prefix, HevACLAction action)
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
    (*current)->blocked = (action == HEV_ACL_ACTION_BLOCK);
    (*current)->action = action;
}

static void __attribute__ ((unused))
radix_tree_insert_ipv6 (const uint8_t *ip, uint8_t prefix, HevACLAction action)
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
    (*current)->blocked = (action == HEV_ACL_ACTION_BLOCK);
    (*current)->action = action;
}

static HevACLAction
radix_tree_lookup_ipv4 (uint32_t ip)
{
    RadixNode *current = acl_ipv4_tree;
    HevACLAction found_action = HEV_ACL_ACTION_DEFAULT;

    for (int i = 0; i < 32 && current; i++) {
        if (current->is_leaf && current->action != HEV_ACL_ACTION_DEFAULT) {
            found_action = current->action;
        }

        uint8_t bit = (ip >> (31 - i)) & 1;
        current = bit ? current->right : current->left;
    }

    if (current && current->is_leaf &&
        current->action != HEV_ACL_ACTION_DEFAULT) {
        found_action = current->action;
    }

    return found_action;
}

static HevACLAction
radix_tree_lookup_ipv6 (const uint8_t *ip)
{
    RadixNode *current = acl_ipv6_tree;
    HevACLAction found_action = HEV_ACL_ACTION_DEFAULT;

    for (int i = 0; i < 128 && current; i++) {
        if (current->is_leaf && current->action != HEV_ACL_ACTION_DEFAULT) {
            found_action = current->action;
        }

        uint8_t byte = i / 8;
        uint8_t bit_in_byte = 7 - (i % 8);
        uint8_t bit = (ip[byte] >> bit_in_byte) & 1;

        current = bit ? current->right : current->left;
    }

    if (current && current->is_leaf &&
        current->action != HEV_ACL_ACTION_DEFAULT) {
        found_action = current->action;
    }

    return found_action;
}

/* ============================================================================
   Hash Table Operations
   ============================================================================ */

/* Helper Functions - must be declared before use */
static void safe_str_copy (char *dest, const char *src, size_t max_len);
static void debug_free_and_clear (void *ptr, size_t size, const char *name);
static time_t get_current_time_seconds (void);

/* Safe string copy with null termination */
static void
safe_str_copy (char *dest, const char *src, size_t max_len)
{
    if (max_len == 0)
        return;

    size_t src_len = strlen (src);
    size_t copy_len = (src_len < max_len - 1) ? src_len : max_len - 1;

    memcpy (dest, src, copy_len);
    dest[copy_len] = '\0';
}

/* Enhanced memory cleanup with debugging */
static void
debug_free_and_clear (void *ptr, size_t size, const char *name)
{
    if (ptr) {
        memset (ptr, 0, size); /* Clear sensitive data */
        LOG_D ("filter: Freed %s (%p)", name, ptr);
        hev_free (ptr);
    }
}

/* 时间函数 */
static time_t
get_current_time_seconds (void)
{
    struct timeval tv;
    gettimeofday (&tv, NULL);
    return tv.tv_sec;
}

/* ============================================================================
   ACL Helper Functions
   ============================================================================ */

/* 解析 action 字符串为枚举 */
static int
parse_acl_action (const char *action_str, HevACLAction *action_out)
{
    if (strcasecmp (action_str, "allow") == 0) {
        *action_out = HEV_ACL_ACTION_ALLOW;
        return 1;
    } else if (strcasecmp (action_str, "block") == 0) {
        *action_out = HEV_ACL_ACTION_BLOCK;
        return 1;
    }
    return 0;
}

/* 创建 ACL 规则 */
static HevACLRule *
create_acl_rule (HevACLAction action, HevACLType type, const char *pattern)
{
    HevACLRule *rule = hev_malloc (sizeof (HevACLRule));
    rule->action = action;
    rule->type = type;
    strncpy (rule->pattern, pattern, sizeof (rule->pattern) - 1);
    rule->pattern[sizeof (rule->pattern) - 1] = '\0';
    return rule;
}

/* ============================================================================
   Enhanced Blacklist Helper Functions
   ============================================================================ */

/* 前向声明 */
static uint32_t hostname_hash (const char *hostname);

/* 生成唯一ID */
static void
generate_entry_id (char *id, size_t id_size, HevBlacklistEntryType type,
                   const ip_addr_t *ip_addr, int port, const char *hostname)
{
    struct timespec ts;
    clock_gettime (CLOCK_REALTIME, &ts);

    switch (type) {
    case HEV_BLACKLIST_ENTRY_IP:
        if (ip_addr) {
            char ip_str[INET6_ADDRSTRLEN];
            ipaddr_ntoa_r (ip_addr, ip_str, sizeof (ip_str));
            snprintf (id, id_size, "ip_%s_%ld", ip_str, ts.tv_nsec);
        }
        break;
    case HEV_BLACKLIST_ENTRY_PORT:
        snprintf (id, id_size, "port_%d_%ld", port, ts.tv_nsec);
        break;
    case HEV_BLACKLIST_ENTRY_SNI:
    case HEV_BLACKLIST_ENTRY_DOMAIN:
        if (hostname) {
            snprintf (id, id_size, "%s_%s_%ld",
                      (type == HEV_BLACKLIST_ENTRY_SNI) ? "sni" : "domain",
                      hostname, ts.tv_nsec);
        }
        break;
    }
}

/* 多类型哈希函数 */
static unsigned int
blacklist_hash_multi (HevBlacklistEntryType type, const ip_addr_t *ip_addr,
                      int port, const char *hostname)
{
    unsigned int hash = 0;

    hash = (hash << 5) + type; /* 包含类型 */

    if (type == HEV_BLACKLIST_ENTRY_IP && ip_addr) {
        /* 使用原有的IP哈希逻辑 */
        if (IP_IS_V4 (ip_addr)) {
            uint32_t ip = ip4_addr_get_u32 (ip_2_ip4 (ip_addr));
            hash = (hash ^ (ip >> 16)) * 0x85ebca6b;
            hash ^= (hash >> 13);
            hash = hash * 0xc2b2ae35;
        } else if (IP_IS_V6 (ip_addr)) {
            const u32_t *ip = ip_2_ip6 (ip_addr)->addr;
            for (int i = 0; i < 4; i++) {
                hash ^= ip[i] * 0x9e3779b9;
                hash = (hash << 13) | (hash >> 19);
            }
        }
    }

    if (type == HEV_BLACKLIST_ENTRY_PORT) {
        hash ^= port * 0x9e3779b9;
        hash = (hash << 7) | (hash >> 25);
    }

    if ((type == HEV_BLACKLIST_ENTRY_SNI ||
         type == HEV_BLACKLIST_ENTRY_DOMAIN) &&
        hostname) {
        uint32_t h_hash = hostname_hash (hostname);
        hash ^= h_hash * 0x85ebca6b;
    }

    return hash & (BLACKLIST_HASH_SIZE - 1);
}

/* 获取类型字符串 */
static const char *
type_to_string (HevBlacklistEntryType type)
{
    switch (type) {
    case HEV_BLACKLIST_ENTRY_IP:
        return "IP";
    case HEV_BLACKLIST_ENTRY_PORT:
        return "Port";
    case HEV_BLACKLIST_ENTRY_SNI:
        return "SNI";
    case HEV_BLACKLIST_ENTRY_DOMAIN:
        return "Domain";
    default:
        return "Unknown";
    }
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

    return hash &
           (HOSTNAME_HASH_SIZE - 1); /* Faster than modulo for power of 2 */
}

static void __attribute__ ((unused))
hostname_table_insert (const char *hostname)
{
    uint32_t hash = hostname_hash (hostname);
    HostnameEntry *entry = hev_malloc (sizeof (HostnameEntry));

    if (!entry)
        return;

    safe_str_copy (entry->hostname, hostname, MAX_HOSTNAME_LENGTH + 1);
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
            debug_free_and_clear (entry, sizeof (HostnameEntry),
                                  "hostname entry");
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

    printf ("DEBUG IPv6 lookup: count=%u\n", chnroutes_ipv6_count);
    while (left <= right) {
        int mid = left + (right - left) / 2;

        int cmp_start = memcmp (ip, chnroutes_ipv6[mid].start, 16);
        int cmp_end = memcmp (ip, chnroutes_ipv6[mid].end, 16);
        printf ("  mid=%d cmp_start=%d cmp_end=%d\n", mid, cmp_start, cmp_end);

        if (cmp_start >= 0 && cmp_end <= 0)
            return 1;

        if (cmp_start < 0)
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
parse_sni_extension (const unsigned char *data, size_t len, char *sni_out,
                     size_t sni_max)
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
parse_alpn_extension (const unsigned char *data, size_t len, char *alpn_out,
                      size_t alpn_max)
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
            size_t copy_len = (proto_len < alpn_max - 1) ? proto_len :
                                                           alpn_max - 1;
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

    /* ⭐ Borrowed from SmartProxy: stricter length check (43 bytes minimum)
     * This ensures we have enough data to parse SNI */
    if (len < 43) {
        LOG_D ("%p filter: TLS data too short (%zu < 43)", log_data, len);
        return -1;
    }

    /* Check TLS record type (0x16 = Handshake) */
    uint8_t content_type = data[pos++];
    if (content_type != TLS_CONTENT_TYPE_HANDSHAKE) {
        LOG_D ("%p filter: Not TLS handshake (0x%02x)", log_data, content_type);
        return -1;
    }

    /* Read TLS version */
    uint16_t tls_version = read_uint16 (data + pos);
    pos += 2;
    hello->tls_version = tls_version;

    /* ⭐ Borrowed from SmartProxy: validate TLS version
     * SSL 3.0 (0x0300) or TLS 1.0+ (>= 0x0301) */
    if (tls_version < 0x0301 && tls_version != 0x0300) {
        LOG_D ("%p filter: Invalid TLS version (0x%04x)", log_data,
               tls_version);
        return -1;
    }

    /* Read record length */
    uint16_t record_len = read_uint16 (data + pos);
    pos += 2;

    if (pos + record_len > len) {
        LOG_D ("%p filter: Incomplete TLS record", log_data);
        return -1;
    }

    /* Check handshake type (0x01 = ClientHello) at position 5 */
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

    LOG_D ("%p filter: ClientHello detected (version=0x%04x, len=%u)", log_data,
           tls_version, handshake_len);

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
            parse_sni_extension (data + pos, ext_len, hello->hostname,
                                 MAX_HOSTNAME_LENGTH);
            break;

        case TLS_EXT_ALPN:
            LOG_D ("%p filter: Found ALPN extension", log_data);
            parse_alpn_extension (data + pos, ext_len, hello->alpn,
                                  sizeof (hello->alpn));
            break;
        }

        pos += ext_len;
    }

    hello->detected = 1;

    if (hello->hostname[0]) {
        LOG_I ("%p filter: Detected TLS hostname: %s", log_data,
               hello->hostname);
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
hev_filter_parse_http_host (void *log_data, const unsigned char *data,
                            size_t len, char *hostname, size_t hostname_len)
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
                LOG_I ("%p filter: Detected HTTP URL Host: %s", log_data,
                       hostname);
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
    total_hits = 0;
    total_blocked_bytes = 0;

    hev_task_mutex_init (&blacklist_mutex);

    LOG_I ("filter: Initialized with enhanced blacklist support");
    return 0;
}

void
hev_filter_fini (void)
{
    LOG_D ("filter: Cleaning up resources"); // 这行日志会验证函数是否被调用

    // ✅ 释放顺序：和分配顺序完全相反（最后分配的先释放）
    // 1. 释放 chnroutes（最后分配：load_chnroutes）
    if (chnroutes_ipv6) {
        LOG_D ("filter: Freeing chnroutes IPv6 (%u entries)",
               chnroutes_ipv6_count);
        hev_free (chnroutes_ipv6);
        chnroutes_ipv6 = NULL;
        chnroutes_ipv6_count = 0;
    }

    if (chnroutes_ipv4) {
        LOG_D ("filter: Freeing chnroutes IPv4 (%u entries)",
               chnroutes_ipv4_count);
        hev_free (chnroutes_ipv4);
        chnroutes_ipv4 = NULL;
        chnroutes_ipv4_count = 0;
    }

    // 2. 释放 acl 树（中间分配：load_acl）
    if (acl_ipv6_tree) {
        LOG_D ("filter: Freeing ACL IPv6 tree");
        RadixNode *tree = acl_ipv6_tree;
        acl_ipv6_tree = NULL; // 先置空，防重复释放
        radix_tree_free (tree);
    }

    if (acl_ipv4_tree) {
        LOG_D ("filter: Freeing ACL IPv4 tree");
        RadixNode *tree = acl_ipv4_tree;
        acl_ipv4_tree = NULL; // 先置空，防重复释放
        radix_tree_free (tree);
    }

    // 3. 释放 hostname_table（最先分配：hev_filter_init）
    LOG_D ("filter: Freeing hostname table");
    hostname_table_free ();

    // 4. 清理黑名单
    LOG_D ("filter: Freeing blacklist");
    hev_filter_blacklist_clear ();

    // 5. 清零统计信息
    memset (&stats, 0, sizeof (stats));

    LOG_I ("filter: Finalized successfully"); // 验证函数执行完成
}

int
hev_filter_load_acl (const char *file_path)
{
    FILE *fp;
    char line[1024];
    int ip_count = 0, cidr_count = 0, port_count = 0, domain_count = 0;
    int allow_count = 0, block_count = 0;

    if (!file_path || strlen (file_path) == 0) {
        LOG_D ("filter: ACL file path not set");
        return 0;
    }

    fp = safe_fopen (file_path, "r");
    if (!fp) {
        return -1;
    }

    LOG_I ("filter: Loading ACL from %s (new format)", file_path);

    while (fgets (line, sizeof (line), fp)) {
        char *trim = line;
        while (isspace ((unsigned char)*trim))
            trim++;

        char *end = trim + strlen (trim) - 1;
        while (end >= trim && isspace ((unsigned char)*end))
            *end-- = '\0';

        /* Remove comments */
        char *comment = strchr (trim, '#');
        if (comment)
            *comment = '\0';

        if (strlen (trim) == 0)
            continue;

        /* Parse new format: [allow|block] [ip|cidr|port|domain] [value] */
        char action_str[16];
        char type_str[64];
        char value_str[256];

        int parse_result =
            sscanf (trim, "%15s %63s %255s", action_str, type_str, value_str);

        if (parse_result == 2) {
            /* Format: [allow|block] <value>
             * Move value from type_str to value_str, auto-detect type */
            LOG_D (
                "filter: ACL format with 2 tokens detected: %s (parse_result=%d)",
                trim, parse_result);

            /* Copy value from type_str to value_str */
            strncpy (value_str, type_str, sizeof (value_str) - 1);
            value_str[sizeof (value_str) - 1] = '\0';

            /* Auto-detect type from value format */
            if (strchr (value_str, '/') != NULL) {
                /* CIDR notation: 192.168.1.0/24 */
                strcpy (type_str, "cidr");
            } else if (strchr (value_str, '.') != NULL &&
                       !strchr (value_str, '*')) {
                /* Single IP: 1.2.3.4 (no wildcard, no slash) */
                ip_addr_t ip_test;
                if (ipaddr_aton (value_str, &ip_test)) {
                    strcpy (type_str, "ip");
                } else {
                    strcpy (type_str, "domain");
                }
            } else if (atoi (value_str) > 0 && atoi (value_str) < 65536 &&
                       !strchr (value_str, '.')) {
                /* Port number: 80, 443 */
                strcpy (type_str, "port");
            } else {
                /* Default to domain (handles wildcards like *.example.com) */
                strcpy (type_str, "domain");
            }

            /* Verify action is valid, default to block if not */
            if (strcasecmp (action_str, "allow") != 0 &&
                strcasecmp (action_str, "block") != 0) {
                LOG_W ("filter: Invalid action '%s', defaulting to block: %s",
                       action_str, trim);
                strcpy (action_str, "block");
            }

            parse_result = 3; /* Now we have all three parts */
        }

        if (parse_result != 3) {
            /* Invalid format - skip this line */
            LOG_W (
                "filter: Invalid ACL line format: %s (expected: <action> <type> <value>)",
                trim);
            continue;
        }

        /* Convert action string to enum */
        HevACLAction action;
        if (!parse_acl_action (action_str, &action)) {
            LOG_W ("filter: Unknown action '%s' in ACL line: %s", action_str,
                   trim);
            continue;
        }
        if (action == HEV_ACL_ACTION_ALLOW)
            allow_count++;
        else
            block_count++;

        /* Process by type */
        if (strcasecmp (type_str, "port") == 0) {
            /* Port rule */
            int port = atoi (value_str);
            if (port >= 0 && port < 65536) {
                HevACLRule *rule =
                    create_acl_rule (action, HEV_ACL_TYPE_PORT, value_str);
                rule->next = acl_port_rules[port];
                acl_port_rules[port] = rule;
                port_count++;

                LOG_D ("filter: Added port rule: %s %d (%s)",
                       action == HEV_ACL_ACTION_ALLOW ? "ALLOW" : "BLOCK", port,
                       value_str);
            }
        } else if (strcasecmp (type_str, "ip") == 0) {
            /* Single IP rule */
            ip_addr_t ip_test;
            if (ipaddr_aton (value_str, &ip_test)) {
                /* Add to new ACL system (two-stage matching) */
                HevACLRule *rule =
                    create_acl_rule (action, HEV_ACL_TYPE_IP, value_str);
                rule->next = acl_ip_rules;
                acl_ip_rules = rule;
                ip_count++;

                /* Add to radix tree for O(1) lookup */
                if (IP_IS_V4 (&ip_test)) {
                    uint32_t ip = ntohl (ip_2_ip4 (&ip_test)->addr);
                    radix_tree_insert_ipv4 (ip, 32, action);
                } else if (IP_IS_V6 (&ip_test)) {
                    radix_tree_insert_ipv6 (
                        (const uint8_t *)ip_2_ip6 (&ip_test)->addr, 128,
                        action);
                }

                LOG_D ("filter: Added IP rule: %s %s",
                       action == HEV_ACL_ACTION_ALLOW ? "ALLOW" : "BLOCK",
                       value_str);
            }
        } else if (strcasecmp (type_str, "cidr") == 0) {
            /* CIDR rule */
            char ip_str[128];
            int prefix_len;
            if (sscanf (value_str, "%[^/]/%d", ip_str, &prefix_len) == 2) {
                ip_addr_t ip_test;
                if (ipaddr_aton (ip_str, &ip_test)) {
                    /* Add to new ACL system (two-stage matching) */
                    HevACLRule *rule =
                        create_acl_rule (action, HEV_ACL_TYPE_CIDR, value_str);
                    rule->next = acl_cidr_rules;
                    acl_cidr_rules = rule;
                    cidr_count++;

                    /* Add to radix tree for O(prefix) lookup */
                    if (IP_IS_V4 (&ip_test)) {
                        uint32_t ip = ntohl (ip_2_ip4 (&ip_test)->addr);
                        radix_tree_insert_ipv4 (ip, prefix_len, action);
                    } else if (IP_IS_V6 (&ip_test)) {
                        radix_tree_insert_ipv6 (
                            (const uint8_t *)ip_2_ip6 (&ip_test)->addr,
                            prefix_len, action);
                    }

                    LOG_D ("filter: Added CIDR rule: %s %s",
                           action == HEV_ACL_ACTION_ALLOW ? "ALLOW" : "BLOCK",
                           value_str);
                }
            }
        } else if (strcasecmp (type_str, "domain") == 0) {
            /* Domain rule */
            HevACLRule *rule =
                create_acl_rule (action, HEV_ACL_TYPE_DOMAIN, value_str);
            rule->next = NULL;

            /* Determine which hash table to use */
            unsigned int hash = domain_hash_func (value_str);

            if (value_str[0] == '*') {
                /* Wildcard: *.example.com */
                rule->next = acl_domain_wildcard[hash];
                acl_domain_wildcard[hash] = rule;
            } else if (value_str[0] == '.') {
                /* Suffix: .example.com */
                rule->next = acl_domain_suffix[hash];
                acl_domain_suffix[hash] = rule;
            } else {
                /* Exact match */
                rule->next = acl_domain_exact[hash];
                acl_domain_exact[hash] = rule;
            }

            domain_count++;
            LOG_D ("filter: Added domain rule: %s %s",
                   action == HEV_ACL_ACTION_ALLOW ? "ALLOW" : "BLOCK",
                   value_str);
        } else {
            LOG_W ("filter: Unknown type '%s' in ACL line: %s", type_str, trim);
        }
    }

    fclose (fp);
    LOG_I ("filter: Loaded ACL rules (total:%d, allow:%d, block:%d) "
           "[ip:%d, cidr:%d, port:%d, domain:%d]",
           allow_count + block_count, allow_count, block_count, ip_count,
           cidr_count, port_count, domain_count);
    return 0;
}

int
hev_filter_load_chnroutes (const char *file_path)
{
    FILE *fp;
    char line[128];
    uint32_t ipv4_capacity = 20000;
    uint32_t ipv6_capacity = 5000;

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

    /* Pre-allocate memory */
    chnroutes_ipv4 = hev_malloc0 (sizeof (CIDRRange4) * ipv4_capacity);
    chnroutes_ipv6 = hev_malloc0 (sizeof (CIDRRange6) * ipv6_capacity);
    if (!chnroutes_ipv4 || !chnroutes_ipv6) {
        LOG_E ("filter: Failed to pre-allocate memory for chnroutes");
        if (chnroutes_ipv4)
            hev_free (chnroutes_ipv4);
        if (chnroutes_ipv6)
            hev_free (chnroutes_ipv6);
        fclose (fp);
        return -1;
    }

    while (fgets (line, sizeof (line), fp)) {
        char ip_str[128];
        int prefix_len;

        if (sscanf (line, "%[^/]/%d", ip_str, &prefix_len) != 2)
            continue;

        if (strchr (ip_str, ':')) {
            /* IPv6 */
            /* LOG_D ("filter: Parsing IPv6 CIDR: %s/%d", ip_str, prefix_len); */
            if (chnroutes_ipv6_count >= ipv6_capacity) {
                ipv6_capacity *= 2;
                CIDRRange6 *new_ptr = hev_realloc (
                    chnroutes_ipv6, sizeof (CIDRRange6) * ipv6_capacity);
                if (!new_ptr) {
                    LOG_E (
                        "filter: Failed to re-allocate memory for IPv6 chnroutes");
                    break;
                }
                chnroutes_ipv6 = new_ptr;
            }

            struct in6_addr addr;
            inet_pton (AF_INET6, ip_str, &addr);

            CIDRRange6 *range = &chnroutes_ipv6[chnroutes_ipv6_count++];
            memcpy (range->start, &addr, 16);
            memcpy (range->end, &addr, 16);

            int bits_to_mask = 128 - prefix_len;
            int i = 15;
            while (bits_to_mask > 0 && i >= 0) {
                int bits_in_byte = (bits_to_mask > 8) ? 8 : bits_to_mask;
                uint8_t mask =
                    (bits_in_byte == 8) ? 0xFF : (0xFF >> (8 - bits_in_byte));
                range->start[i] &= ~mask;
                range->end[i] |= mask;
                bits_to_mask -= bits_in_byte;
                i--;
            }
        } else {
            /* IPv4 */
            if (chnroutes_ipv4_count >= ipv4_capacity) {
                ipv4_capacity *= 2;
                CIDRRange4 *new_ptr = hev_realloc (
                    chnroutes_ipv4, sizeof (CIDRRange4) * ipv4_capacity);
                if (!new_ptr) {
                    LOG_E (
                        "filter: Failed to re-allocate memory for IPv4 chnroutes");
                    break;
                }
                chnroutes_ipv4 = new_ptr;
            }

            struct in_addr addr;
            inet_aton (ip_str, &addr);
            uint32_t addr_host = ntohl (addr.s_addr);
            uint32_t mask_host =
                (prefix_len == 0) ? 0 : (0xFFFFFFFF << (32 - prefix_len));
            uint32_t start_host = addr_host & mask_host;
            uint32_t end_host = start_host | (~mask_host);

            chnroutes_ipv4[chnroutes_ipv4_count].start = start_host;
            chnroutes_ipv4[chnroutes_ipv4_count].end = end_host;
            chnroutes_ipv4_count++;
        }
    }

    fclose (fp);

    if (chnroutes_ipv4)
        qsort (chnroutes_ipv4, chnroutes_ipv4_count, sizeof (CIDRRange4),
               compare_cidr4);
    if (chnroutes_ipv6)
        qsort (chnroutes_ipv6, chnroutes_ipv6_count, sizeof (CIDRRange6),
               compare_cidr6);

    LOG_I ("filter: Loaded chnroutes (IPv4:%u, IPv6:%u)", chnroutes_ipv4_count,
           chnroutes_ipv6_count);
    LOG_D ("filter: IPv6 routes count = %u", chnroutes_ipv6_count);
    return 0;
}

int
hev_filter_is_blocked_ip (const ip_addr_t *ip)
{
    /* 只检查ACL规则（真正的安全黑名单） */
    if (IP_IS_V4 (ip)) {
        uint32_t addr = ntohl (ip_2_ip4 (ip)->addr);
        HevACLAction action = radix_tree_lookup_ipv4 (addr);
        if (action == HEV_ACL_ACTION_BLOCK) {
            stats.ip_blocked++;
            LOG_D ("filter: IP %s blocked by ACL rule", ipaddr_ntoa (ip));
            return 1;
        }
    } else if (IP_IS_V6 (ip)) {
        HevACLAction action =
            radix_tree_lookup_ipv6 ((const uint8_t *)ip_2_ip6 (ip)->addr);
        if (action == HEV_ACL_ACTION_BLOCK) {
            stats.ip_blocked++;
            LOG_D ("filter: IPv6 %s blocked by ACL rule", ipaddr_ntoa (ip));
            return 1;
        }
    }

    /* 注意：动态黑名单不在这里检查，它用于路由决策，不阻止连接 */
    return 0;
}

int
hev_filter_is_blocked_hostname (const char *hostname)
{
    if (!hostname || strlen (hostname) == 0)
        return 0;

    /* 只检查ACL规则（真正的安全黑名单） */
    if (hostname_table_lookup (hostname)) {
        stats.hostname_blocked++;
        LOG_D ("filter: Hostname '%s' blocked by ACL rule", hostname);
        return 1;
    }

    /* 注意：动态黑名单不在这里检查，它用于路由决策，不阻止连接 */
    return 0;
}

int
hev_filter_is_blocked_port (int port)
{
    /* 端口只有动态黑名单检查 */
    if (hev_filter_blacklist_check_entry (HEV_BLACKLIST_ENTRY_PORT, NULL, port,
                                          NULL)) {
        LOG_D ("filter: Port %d blocked by dynamic blacklist", port);
        return 1;
    }

    return 0;
}

int
hev_filter_check_all_filters (const ip_addr_t *ip, const char *hostname,
                              int port)
{
    /* 只检查ACL规则（真正的安全黑名单） */

    /* 检查IP过滤规则 */
    if (ip && hev_filter_is_blocked_ip (ip)) {
        LOG_D ("filter: IP %s blocked by ACL rule", ipaddr_ntoa (ip));
        return 1;
    }

    /* 检查主机名过滤规则 */
    if (hostname && hev_filter_is_blocked_hostname (hostname)) {
        LOG_D ("filter: Hostname '%s' blocked by ACL rule", hostname);
        return 1;
    }

    /* 检查端口过滤规则 */
    if (port > 0 && hev_filter_is_blocked_port (port)) {
        LOG_D ("filter: Port %d blocked by comprehensive filter check", port);
        return 1;
    }

    /* 注意：这里不检查动态黑名单，动态黑名单用于路由决策，不阻止连接 */
    return 0;
}

int
hev_filter_is_gfw_blocked (const ip_addr_t *ip, const char *hostname, int port)
{
    /* 检查动态黑名单（GFW封锁检测），用于路由决策 */

    /* 检查IP是否被GFW封锁 */
    if (ip && hev_filter_blacklist_check_ip (ip)) {
        LOG_D ("filter: IP %s is GFW blocked (routing decision)",
               ipaddr_ntoa (ip));
        return 1;
    }

    /* 检查SNI是否被GFW封锁 */
    if (hostname && hev_filter_blacklist_check_entry (HEV_BLACKLIST_ENTRY_SNI,
                                                      NULL, 0, hostname)) {
        LOG_D ("filter: SNI '%s' is GFW blocked (routing decision)", hostname);
        return 1;
    }

    /* 检查域名是否被GFW封锁 */
    if (hostname && hev_filter_blacklist_check_entry (
                        HEV_BLACKLIST_ENTRY_DOMAIN, NULL, 0, hostname)) {
        LOG_D ("filter: Domain '%s' is GFW blocked (routing decision)",
               hostname);
        return 1;
    }

    /* 检查端口是否被封锁 */
    if (port > 0 && hev_filter_blacklist_check_entry (HEV_BLACKLIST_ENTRY_PORT,
                                                      NULL, port, NULL)) {
        LOG_D ("filter: Port %d is GFW blocked (routing decision)", port);
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
        if (!chnroutes_ipv6) {
            LOG_D (
                "filter: IPv6 domestic check failed - no IPv6 routes loaded");
            return 0;
        }

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

    /* Unified protocol detection: Try TLS first, fallback to HTTP */
    /* Step 1: Try TLS SNI extraction (works for any port) */
    HevTLSClientHello hello;
    if (hev_filter_parse_tls (pcb, buffer, total_len, &hello) == 0 &&
        hello.hostname[0]) {
        strncpy (hostname, hello.hostname, hostname_len - 1);
        hostname[hostname_len - 1] = '\0';
        return 0;
    }

    /* Step 2: TLS failed, try HTTP Host extraction (works for any port) */
    if (hev_filter_parse_http_host (pcb, buffer, total_len, hostname,
                                    hostname_len) == 0) {
        return 0;
    }

    return -1;
}

void
hev_filter_get_stats (HevFilterStats *out_stats)
{
    if (out_stats) {
        memcpy (out_stats, &stats, sizeof (HevFilterStats));
        /* Add current blacklist count from the filter module */
        out_stats->blacklist_active = blacklist_count;
    }
}

void
hev_filter_reset_stats (void)
{
    memset (&stats, 0, sizeof (stats));
}

/* ============================================================================
   Enhanced Blacklist Implementation
   ============================================================================ */

#include "hev-config.h"

/* Internal helper: add blacklist entry with common logic */
static const char *
blacklist_add_internal (HevBlacklistEntryType type, const ip_addr_t *ip_addr,
                        const char *hostname)
{
    HevBlacklistEntry *entry;
    unsigned int hash;
    time_t now;
    char ip_str[INET6_ADDRSTRLEN] = { 0 };
    const char *reason = "Smart proxy";
    const char *source_str = "Auto";

    /* 获取配置的TTL */
    int ttl_seconds =
        hev_config_get_smart_proxy_blocked_ip_expiry_minutes () * 60;
    if (ttl_seconds <= 0) {
        ttl_seconds = 3600; /* 默认1小时 */
    }

    /* 参数验证 */
    if (type == HEV_BLACKLIST_ENTRY_IP && !ip_addr) {
        LOG_E ("filter: IP type requires valid IP address");
        return NULL;
    }
    if ((type == HEV_BLACKLIST_ENTRY_SNI ||
         type == HEV_BLACKLIST_ENTRY_DOMAIN) &&
        (!hostname || strlen (hostname) == 0)) {
        LOG_E ("filter: Domain type requires valid hostname");
        return NULL;
    }

    entry = hev_malloc0 (sizeof (HevBlacklistEntry));
    if (!entry) {
        LOG_E ("filter: Failed to allocate blacklist entry");
        return NULL;
    }

    now = get_current_time_seconds ();

    /* 初始化基本字段 */
    entry->type = type;
    entry->source = HEV_BLACKLIST_SOURCE_AUTO;
    entry->added_time = now;
    entry->expiry_time = now + ttl_seconds;
    entry->first_seen = now;
    entry->last_seen = now;
    entry->severity = 5;
    entry->is_active = 1;
    entry->ttl_seconds = ttl_seconds;
    entry->auto_refresh = 0;

    /* 初始化网络信息 */
    if (type == HEV_BLACKLIST_ENTRY_IP && ip_addr) {
        ip_addr_copy (entry->ip_addr, *ip_addr);
        ipaddr_ntoa_r (ip_addr, ip_str, sizeof (ip_str));
    }
    if ((type == HEV_BLACKLIST_ENTRY_SNI ||
         type == HEV_BLACKLIST_ENTRY_DOMAIN) &&
        hostname) {
        safe_str_copy (entry->hostname, hostname, sizeof (entry->hostname));
    }

    /* 初始化统计字段 */
    entry->hit_count = 0;
    entry->bytes_blocked = 0;
    entry->session_count = 0;

    /* 初始化元数据 */
    safe_str_copy (entry->reason, reason, sizeof (entry->reason));
    snprintf (entry->source_info, sizeof (entry->source_info), "%s",
              source_str);

    /* 生成唯一ID */
    generate_entry_id (entry->id, sizeof (entry->id), type, ip_addr, 0,
                       hostname);

    /* 计算哈希值并插入 */
    hash = blacklist_hash_multi (type, ip_addr, 0, hostname);

    hev_task_mutex_lock (&blacklist_mutex);
    entry->next = blacklist_table[hash];
    blacklist_table[hash] = entry;
    blacklist_count++;
    stats.blacklist_adds++;
    hev_task_mutex_unlock (&blacklist_mutex);

    /* 记录日志 */
    if (type == HEV_BLACKLIST_ENTRY_IP) {
        LOG_I ("filter: Added IP %s to blacklist (id=%s, ttl=%dm)", ip_str,
               entry->id, ttl_seconds / 60);
    } else {
        LOG_I ("filter: Added domain '%s' to blacklist (id=%s, ttl=%dm)",
               hostname, entry->id, ttl_seconds / 60);
    }

    return entry->id;
}

/* Simplified blacklist add function for IP addresses */
const char *
hev_filter_blacklist_add_ip (const ip_addr_t *addr)
{
    return blacklist_add_internal (HEV_BLACKLIST_ENTRY_IP, addr, NULL);
}

/* Simplified blacklist add function for domain names */
const char *
hev_filter_blacklist_add_domain (const char *domain)
{
    return blacklist_add_internal (HEV_BLACKLIST_ENTRY_DOMAIN, NULL, domain);
}

/* 新的IP检查函数 */
int
hev_filter_blacklist_check_ip (const ip_addr_t *addr)
{
    return hev_filter_blacklist_check_entry (HEV_BLACKLIST_ENTRY_IP, addr, 0,
                                             NULL);
}

/* 新的通用条目检查函数 */
int
hev_filter_blacklist_check_entry (HevBlacklistEntryType type,
                                  const ip_addr_t *ip_addr, int port,
                                  const char *hostname)
{
    HevBlacklistEntry **current, *prev;
    unsigned int hash;
    time_t now;
    int found = 0;
    int expired_count = 0;
    HevBlacklistEntry *to_delete = NULL;
    HevBlacklistEntry *found_entry = NULL;
    char desc[256] = { 0 };

    /* 参数验证 */
    if (type == HEV_BLACKLIST_ENTRY_IP && !ip_addr) {
        return 0;
    }
    if ((type == HEV_BLACKLIST_ENTRY_SNI ||
         type == HEV_BLACKLIST_ENTRY_DOMAIN) &&
        (!hostname || strlen (hostname) == 0)) {
        return 0;
    }
    if (type == HEV_BLACKLIST_ENTRY_PORT && port <= 0) {
        return 0;
    }

    /* 生成描述字符串用于日志 */
    switch (type) {
    case HEV_BLACKLIST_ENTRY_IP:
        if (ip_addr) {
            ipaddr_ntoa_r (ip_addr, desc, sizeof (desc));
        }
        break;
    case HEV_BLACKLIST_ENTRY_PORT:
        snprintf (desc, sizeof (desc), "port %d", port);
        break;
    case HEV_BLACKLIST_ENTRY_SNI:
    case HEV_BLACKLIST_ENTRY_DOMAIN:
        snprintf (desc, sizeof (desc), "%s '%s'",
                  (type == HEV_BLACKLIST_ENTRY_SNI) ? "SNI" : "domain",
                  hostname ? hostname : "");
        break;
    }

    hash = blacklist_hash_multi (type, ip_addr, port, hostname);
    now = get_current_time_seconds ();

    hev_task_mutex_lock (&blacklist_mutex);
    current = &blacklist_table[hash];
    prev = NULL;
    stats.blacklist_hits++;

    while (*current) {
        HevBlacklistEntry *entry = *current;

        /* 检查是否过期 */
        if (now > entry->expiry_time) {
            *current = entry->next;
            if (prev)
                prev->next = entry->next;

            entry->next = to_delete; /* 添加到删除链表 */
            to_delete = entry;
            blacklist_count--;
            expired_count++;

            current = prev ? &prev->next : &blacklist_table[hash];
            continue;
        }

        /* 检查是否匹配 */
        int match = 0;
        switch (type) {
        case HEV_BLACKLIST_ENTRY_IP:
            match = ip_addr && ip_addr_cmp (&entry->ip_addr, ip_addr);
            break;
        case HEV_BLACKLIST_ENTRY_PORT:
            match = entry->port == port;
            break;
        case HEV_BLACKLIST_ENTRY_SNI:
        case HEV_BLACKLIST_ENTRY_DOMAIN:
            match = hostname && strcasecmp (entry->hostname, hostname) == 0;
            break;
        }

        if (match) {
            found = 1;
            found_entry = entry;
            entry->last_seen = now;
            entry->hit_count++;
            entry->is_active = 1;
            total_hits++;
        }

        prev = entry;
        current = &entry->next;
    }

    hev_task_mutex_unlock (&blacklist_mutex);

    /* 释放过期条目 */
    while (to_delete) {
        HevBlacklistEntry *next = to_delete->next;
        LOG_D ("filter: Removed expired %s entry (id=%s)",
               type_to_string (to_delete->type), to_delete->id);
        hev_free (to_delete);
        to_delete = next;
    }

    if (expired_count > 0) {
        LOG_D ("filter: Cleaned up %d expired %s entries", expired_count,
               type_to_string (type));
    }

    if (found && found_entry) {
        time_t time_remaining = found_entry->expiry_time - now;
        LOG_D ("filter: %s found in blacklist (id=%s, hits=%lu, expires in %ld "
               "seconds)",
               desc, found_entry->id, found_entry->hit_count, time_remaining);
    }

    return found;
}

/* 根据ID获取条目 */
HevBlacklistEntry *
hev_filter_blacklist_get_entry (const char *id)
{
    HevBlacklistEntry *entry = NULL;

    if (!id) {
        return NULL;
    }

    hev_task_mutex_lock (&blacklist_mutex);

    /* 线性搜索所有哈希桶 */
    for (int i = 0; i < BLACKLIST_HASH_SIZE; i++) {
        HevBlacklistEntry *current = blacklist_table[i];
        while (current) {
            if (strcmp (current->id, id) == 0) {
                /* 检查是否过期 */
                time_t now = get_current_time_seconds ();
                if (now <= current->expiry_time) {
                    entry = current;
                }
                break;
            }
            current = current->next;
        }
        if (entry) {
            break;
        }
    }

    hev_task_mutex_unlock (&blacklist_mutex);

    return entry;
}

/* 根据ID移除条目 */
int
hev_filter_blacklist_remove_entry (const char *id)
{
    HevBlacklistEntry **current, *prev;
    int removed = 0;

    if (!id) {
        return -1;
    }

    hev_task_mutex_lock (&blacklist_mutex);

    /* 线性搜索所有哈希桶 */
    for (int i = 0; i < BLACKLIST_HASH_SIZE; i++) {
        current = &blacklist_table[i];
        prev = NULL;

        while (*current) {
            HevBlacklistEntry *entry = *current;

            if (strcmp (entry->id, id) == 0) {
                *current = entry->next;
                if (prev)
                    prev->next = entry->next;

                blacklist_count--;
                removed = 1;

                LOG_I ("filter: Removed %s entry (id=%s, %s, hits=%lu)",
                       type_to_string (entry->type), entry->id,
                       entry->hostname[0] ? entry->hostname :
                                            (entry->port > 0 ? "port" : "IP"),
                       entry->hit_count);

                hev_free (entry);
                break;
            }

            prev = entry;
            current = &entry->next;
        }

        if (removed) {
            break;
        }
    }

    hev_task_mutex_unlock (&blacklist_mutex);

    return removed ? 0 : -1;
}

/* 更新命中统计 */
int
hev_filter_blacklist_update_hit (const char *id, uint64_t bytes)
{
    int updated = 0;

    if (!id) {
        return -1;
    }

    hev_task_mutex_lock (&blacklist_mutex);

    /* 线性搜索条目 */
    for (int i = 0; i < BLACKLIST_HASH_SIZE; i++) {
        HevBlacklistEntry *current = blacklist_table[i];
        while (current) {
            if (strcmp (current->id, id) == 0) {
                current->hit_count++;
                current->bytes_blocked += bytes;
                current->last_seen = get_current_time_seconds ();
                total_hits++;
                total_blocked_bytes += bytes;
                updated = 1;
                break;
            }
            current = current->next;
        }
        if (updated) {
            break;
        }
    }

    hev_task_mutex_unlock (&blacklist_mutex);

    if (updated) {
        LOG_D ("filter: Updated hit stats for entry %s (bytes=%lu)", id, bytes);
    }

    return updated ? 0 : -1;
}

/* 清空黑名单 */
void
hev_filter_blacklist_clear (void)
{
    HevBlacklistEntry *current, *next;
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
    total_hits = 0;
    total_blocked_bytes = 0;

    hev_task_mutex_unlock (&blacklist_mutex);

    LOG_I ("filter: Cleared %d enhanced blacklist entries", cleared_count);
}

/* 获取黑名单条目数量 */
size_t
hev_filter_blacklist_get_count (void)
{
    return blacklist_count;
}

/* 获取详细统计信息 */
void
hev_filter_blacklist_get_stats (size_t *total_entries, size_t *active_entries,
                                uint64_t *total_hits_out,
                                uint64_t *total_blocked_out)
{
    time_t now = get_current_time_seconds ();
    size_t active = 0;

    hev_task_mutex_lock (&blacklist_mutex);

    /* 统计活跃条目 */
    for (int i = 0; i < BLACKLIST_HASH_SIZE; i++) {
        HevBlacklistEntry *current = blacklist_table[i];
        while (current) {
            if (now <= current->expiry_time && current->is_active) {
                active++;
            }
            current = current->next;
        }
    }

    hev_task_mutex_unlock (&blacklist_mutex);

    if (total_entries)
        *total_entries = blacklist_count;
    if (active_entries)
        *active_entries = active;
    if (total_hits_out)
        *total_hits_out = total_hits;
    if (total_blocked_out)
        *total_blocked_out = total_blocked_bytes;
}

/* ============================================================================
   Two-Stage ACL Matching Implementation
   ============================================================================ */

/* Check if domain matches pattern (wildcard/suffix) */
static int
match_domain_pattern (const char *pattern, const char *domain)
{
    /* Exact match */
    if (strcasecmp (pattern, domain) == 0)
        return 1;

    /* Wildcard: *.example.com */
    if (pattern[0] == '*') {
        const char *suffix = pattern + 1;
        size_t domain_len = strlen (domain);
        size_t suffix_len = strlen (suffix);
        if (suffix_len > 0 && suffix_len < domain_len) {
            return strcasecmp (domain + domain_len - suffix_len, suffix) == 0;
        }
    }

    /* Suffix: .example.com */
    if (pattern[0] == '.') {
        size_t domain_len = strlen (domain);
        size_t pattern_len = strlen (pattern);
        if (pattern_len > 0 && pattern_len < domain_len) {
            return strcasecmp (domain + domain_len - pattern_len, pattern) == 0;
        }
    }

    return 0;
}

/* Stage 1: Match connection rules (IP/Port/CIDR) */
HevACLResult
hev_acl_match_stage1_connection (const ip_addr_t *ip, int port)
{
    HevACLResult result = { 0, HEV_ACL_ACTION_DEFAULT, NULL };

    if (!ip)
        return result;

    /* 1. Check port rules first (highest priority for connection stage) */
    if (port >= 0 && port < 65536) {
        HevACLRule *rule = acl_port_rules[port];
        while (rule) {
            result.matched = 1;
            result.action = rule->action;
            result.rule_pattern = rule->pattern;
            LOG_D ("ACL Stage1: Port %d matched rule '%s' -> action=%d", port,
                   rule->pattern, rule->action);
            return result;
        }
    }

    /* 2. Check IP/CIDR rules using Radix Tree (O(prefix) instead of O(n)) */
    HevACLAction action = HEV_ACL_ACTION_DEFAULT;
    if (IP_IS_V4 (ip)) {
        uint32_t addr = ntohl (ip_2_ip4 (ip)->addr);
        action = radix_tree_lookup_ipv4 (addr);
    } else if (IP_IS_V6 (ip)) {
        action = radix_tree_lookup_ipv6 ((const uint8_t *)ip_2_ip6 (ip)->addr);
    }

    if (action != HEV_ACL_ACTION_DEFAULT) {
        result.matched = 1;
        result.action = action;
        result.rule_pattern = ipaddr_ntoa (ip); /* Use IP as pattern */
        LOG_D ("ACL Stage1: IP %s matched Radix Tree rule -> action=%d",
               ipaddr_ntoa (ip), action);
        return result;
    }

    return result;
}

/* Stage 2: Match domain rules after hostname detection */
HevACLResult
hev_acl_match_stage2_domain (const char *hostname, int port)
{
    HevACLResult result = { 0, HEV_ACL_ACTION_DEFAULT, NULL };

    if (!hostname || hostname[0] == '\0')
        return result;

    char hostname_lower[MAX_HOSTNAME_LENGTH + 1];
    strncpy (hostname_lower, hostname, MAX_HOSTNAME_LENGTH);
    hostname_lower[MAX_HOSTNAME_LENGTH] = '\0';
    for (char *p = hostname_lower; *p; p++)
        *p = tolower (*p);

    /* 1. Check exact domain match */
    unsigned int hash = domain_hash_func (hostname_lower);
    HevACLRule *rule = acl_domain_exact[hash];
    while (rule) {
        if (strcasecmp (rule->pattern, hostname_lower) == 0) {
            result.matched = 1;
            result.action = rule->action;
            result.rule_pattern = rule->pattern;
            LOG_D (
                "ACL Stage2: Domain '%s' matched exact rule '%s' -> action=%d",
                hostname, rule->pattern, rule->action);
            return result;
        }
        rule = rule->next;
    }

    /* 2. Check wildcard domains (*.example.com) */
    rule = acl_domain_wildcard[hash];
    while (rule) {
        if (match_domain_pattern (rule->pattern, hostname_lower)) {
            result.matched = 1;
            result.action = rule->action;
            result.rule_pattern = rule->pattern;
            LOG_D (
                "ACL Stage2: Domain '%s' matched wildcard rule '%s' -> action=%d",
                hostname, rule->pattern, rule->action);
            return result;
        }
        rule = rule->next;
    }

    /* 3. Check suffix domains (.example.com) */
    rule = acl_domain_suffix[hash];
    while (rule) {
        if (match_domain_pattern (rule->pattern, hostname_lower)) {
            result.matched = 1;
            result.action = rule->action;
            result.rule_pattern = rule->pattern;
            LOG_D (
                "ACL Stage2: Domain '%s' matched suffix rule '%s' -> action=%d",
                hostname, rule->pattern, rule->action);
            return result;
        }
        rule = rule->next;
    }

    return result;
}

/* Combine both stages to get final decision */
HevACLAction
hev_acl_check_final_decision (HevACLResult *stage1_result,
                              HevACLResult *stage2_result)
{
    /* Stage 1 (IP/Port/CIDR) is checked first */
    if (stage1_result && stage1_result->matched) {
        return stage1_result->action;
    }

    /* Stage 2 (domain) is only checked if Stage 1 didn't match */
    if (stage2_result && stage2_result->matched) {
        return stage2_result->action;
    }

    /* Default: use DEFAULT behavior (SOCKS5 proxy) */
    return HEV_ACL_ACTION_DEFAULT;
}

/* ============================================================================ */
