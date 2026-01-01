/*
 ============================================================================
 Name        : hev-dns-cache.c
 Author      : AI Assistant
 Copyright   : Copyright (c) 2025
 Description : DNS Cache with GFW Pollution Detection
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <errno.h>
#include <hev-memory-allocator.h>
#include <hev-task.h>
#include <hev-task-mutex.h>
#include <hev-task-io.h>
#include <hev-task-io-socket.h>
#include <hev-socks5.h>
#include <hev-socks5-client-udp.h>
#include <hev-object-pool.h>

#include "hev-logger.h"
#include "hev-config.h"
#include "hev-filter.h"
#include "hev-utils.h"
#include "hev-dns-cache.h"
#include <hev-socks5-misc.h>

/* DNS 缓存分片锁配置 */
#define DNS_CACHE_SHARD_COUNT 16
#define DNS_CACHE_SHARD_MASK (DNS_CACHE_SHARD_COUNT - 1)

/* DNS 缓存对象池配置 */
#define DNS_ENTRY_POOL_INIT_CAPACITY 32
#define DNS_ENTRY_POOL_MAX_CAPACITY 256

/* DNS 缓存清理配置 */
#define DNS_CACHE_CLEAN_INTERVAL_MS 60000 /* 清理间隔：60秒 */

/* DNS 缓存哈希表 */
static HevDNSCacheEntry *dns_cache_table[DNS_CACHE_HASH_SIZE];
static HevTaskMutex dns_cache_shards[DNS_CACHE_SHARD_COUNT];
static HevObjectPool *dns_entry_pool = NULL;
static size_t total_cache_entries = 0;
static size_t poisoned_cache_entries = 0;
static uint64_t total_cache_hits = 0;

/* 清理任务控制 */
static volatile int cache_cleaner_running = 0;
static volatile int cache_cleaner_started = 0;

/* DNS服务器轮询索引（统一索引，轮询所有配置的DNS服务器） */
static size_t dns_server_rotation_index = 0;

/* IPv6可用性检测结果（-1=未检测, 0=不可用, 1=可用） */
static int ipv6_available = -1;

/* DNS 报文结构 */
typedef struct
{
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__ ((packed)) DNSHeader;

/* 辅助函数：读取大端序 uint16 */
static inline uint16_t
read_uint16 (const uint8_t *p)
{
    return (p[0] << 8) | p[1];
}

/* 辅助函数：读取大端序 uint32 */
static inline uint32_t
read_uint32 (const uint8_t *p)
{
    return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

/* 简单哈希函数（DJB2） */
static uint32_t
dns_hash (const char *str)
{
    uint32_t hash = 5381;
    int c;
    while ((c = *str++)) {
        c = tolower (c);
        hash = ((hash << 5) + hash) + c;
    }
    return hash % DNS_CACHE_HASH_SIZE;
}

/* 获取分片索引（基于哈希值） */
static inline int
dns_cache_get_shard (uint32_t hash)
{
    return hash & DNS_CACHE_SHARD_MASK;
}

/* 获取域名对应的分片索引 */
static inline int
dns_cache_domain_shard (const char *domain)
{
    uint32_t hash = 5381;
    int c;
    while ((c = *domain++)) {
        c = tolower (c);
        hash = ((hash << 5) + hash) + c;
    }
    return hash & DNS_CACHE_SHARD_MASK;
}

/* 解析 DNS 域名（带压缩指针支持） */
static int
parse_dns_name (const uint8_t *data, size_t data_len, size_t *offset,
                char *name_out, size_t name_max)
{
    size_t pos = *offset;
    size_t name_len = 0;
    int jumped = 0;
    size_t jump_pos = 0;

    while (pos < data_len) {
        uint8_t len = data[pos];

        /* 压缩指针 */
        if ((len & 0xC0) == 0xC0) {
            if (pos + 1 >= data_len)
                return -1;
            if (!jumped) {
                jump_pos = pos + 2;
                jumped = 1;
            }
            pos = ((len & 0x3F) << 8) | data[pos + 1];
            continue;
        }

        /* 结束符 */
        if (len == 0) {
            if (!jumped)
                *offset = pos + 1;
            else
                *offset = jump_pos;
            name_out[name_len] = '\0';
            return 0;
        }

        /* 标签 */
        if (pos + 1 + len >= data_len)
            return -1;
        if (name_len + len + 1 >= name_max)
            return -1;

        if (name_len > 0)
            name_out[name_len++] = '.';
        memcpy (name_out + name_len, data + pos + 1, len);
        name_len += len;
        pos += len + 1;
    }

    return -1;
}

/* 检测 IP 是否为国外 IP */
static int
is_foreign_ip (const ip_addr_t *ip)
{
    /* 使用 filter 模块的 is_domestic 函数 */
    return !hev_filter_is_domestic (ip);
}

/* 解析 DNS 响应，检测是否包含国外 IP（污染检测） */
int
hev_dns_detect_pollution (const uint8_t *data, size_t len)
{
    if (len < sizeof (DNSHeader))
        return 0;

    DNSHeader *hdr = (DNSHeader *)data;
    uint16_t ancount = ntohs (hdr->ancount);

    if (ancount == 0)
        return 0;

    /* 跳过查询部分 */
    size_t pos = sizeof (DNSHeader);
    uint16_t qdcount = ntohs (hdr->qdcount);

    for (int i = 0; i < qdcount && pos < len; i++) {
        char domain[256];
        if (parse_dns_name (data, len, &pos, domain, sizeof (domain)) < 0)
            return 0;
        if (pos + 4 > len)
            return 0;
        pos += 4; /* QTYPE + QCLASS */
    }

    /* 解析应答部分 */
    for (int i = 0; i < ancount && pos < len; i++) {
        char domain[256];
        if (parse_dns_name (data, len, &pos, domain, sizeof (domain)) < 0)
            break;

        if (pos + 10 > len)
            break;

        uint16_t rtype = read_uint16 (data + pos);
        uint16_t rdlen = read_uint16 (data + pos + 8);
        pos += 10;

        if (pos + rdlen > len)
            break;

        /* 检查 A 记录 */
        if (rtype == DNS_TYPE_A && rdlen == 4) {
            ip_addr_t ip;
            IP_ADDR4 (&ip, data[pos], data[pos + 1], data[pos + 2],
                      data[pos + 3]);

            if (is_foreign_ip (&ip)) {
                char ip_str[INET_ADDRSTRLEN];
                ipaddr_ntoa_r (&ip, ip_str, sizeof (ip_str));
                LOG_W (
                    "dns-cache: Detected foreign IP in DNS response: %s (pollution suspected)",
                    ip_str);
                return 1; /* 污染 */
            }
        }
        /* 检查 AAAA 记录 */
        else if (rtype == DNS_TYPE_AAAA && rdlen == 16) {
            ip_addr_t ip;
            memcpy (ip_2_ip6 (&ip)->addr, data + pos, 16);
            ip.type = IPADDR_TYPE_V6;

            if (is_foreign_ip (&ip)) {
                char ip_str[INET6_ADDRSTRLEN];
                ipaddr_ntoa_r (&ip, ip_str, sizeof (ip_str));
                LOG_W (
                    "dns-cache: Detected foreign IPv6 in DNS response: %s (pollution suspected)",
                    ip_str);
                return 1; /* 污染 */
            }
        }

        pos += rdlen;
    }

    return 0; /* 未检测到污染 */
}

/* 提取 DNS 响应中的 TTL */
static uint32_t
extract_dns_ttl (const uint8_t *data, size_t len)
{
    if (len < sizeof (DNSHeader))
        return 300; /* 默认 5 分钟 */

    DNSHeader *hdr = (DNSHeader *)data;
    uint16_t ancount = ntohs (hdr->ancount);

    if (ancount == 0)
        return 300;

    size_t pos = sizeof (DNSHeader);
    uint16_t qdcount = ntohs (hdr->qdcount);

    /* 跳过查询部分 */
    for (int i = 0; i < qdcount && pos < len; i++) {
        char domain[256];
        if (parse_dns_name (data, len, &pos, domain, sizeof (domain)) < 0)
            return 300;
        if (pos + 4 > len)
            return 300;
        pos += 4;
    }

    /* 读取第一个应答的 TTL */
    if (ancount > 0 && pos < len) {
        char domain[256];
        if (parse_dns_name (data, len, &pos, domain, sizeof (domain)) < 0)
            return 300;

        if (pos + 10 <= len) {
            uint32_t ttl = read_uint32 (data + pos + 4);
            return ttl > 0 ? ttl : 300;
        }
    }

    return 300;
}

/* 提取 DNS 查询中的域名 */
int
extract_dns_domain (const uint8_t *data, size_t len, char *domain_out,
                    size_t domain_max)
{
    if (len < sizeof (DNSHeader))
        return -1;

    size_t pos = sizeof (DNSHeader);
    return parse_dns_name (data, len, &pos, domain_out, domain_max);
}

/* 检测IPv6是否可用 */
static int
check_ipv6_available (void)
{
    int sock = socket (AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0) {
        LOG_D ("dns-cache: IPv6 not available (socket failed: %s)",
               strerror (errno));
        return 0;
    }

    /* 尝试连接到一个IPv6地址（Google DNS） */
    struct sockaddr_in6 addr;
    memset (&addr, 0, sizeof (addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons (53); /* DNS端口 */
    /* 使用链路本地地址进行简单测试 */
    inet_pton (AF_INET6, "::1", &addr.sin6_addr);

    /* 连接测试（不真正发送数据） */
    int ret = connect (sock, (struct sockaddr *)&addr, sizeof (addr));
    if (ret < 0 && errno != EINPROGRESS) {
        LOG_D ("dns-cache: IPv6 not available (connect failed: %s)",
               strerror (errno));
        close (sock);
        return 0;
    }

    close (sock);
    LOG_D ("dns-cache: IPv6 available");
    return 1;
}

/* DNS 缓存清理任务 */
static void
dns_cache_cleaner_task (void *data)
{
    LOG_I ("dns-cache: Cache cleaner task started");

    while (cache_cleaner_running) {
        /* 清理过期条目 */
        size_t cleaned = hev_dns_cache_clean_expired ();

        if (cleaned > 0) {
            LOG_I ("dns-cache: Cleaner task removed %zu expired entries",
                   cleaned);
        }

        /* 等待下次清理 */
        hev_task_sleep (DNS_CACHE_CLEAN_INTERVAL_MS);
    }

    cache_cleaner_started = 0;
    LOG_I ("dns-cache: Cache cleaner task stopped");
}

/* 启动缓存清理任务（延迟启动，确保任务系统已初始化） */
static void
start_cache_cleaner_if_needed (void)
{
    if (!cache_cleaner_started) {
        cache_cleaner_running = 1;
        cache_cleaner_started = 1;
        int stack_size = hev_config_get_misc_task_stack_size ();
        hev_task_run (hev_task_new (stack_size), dns_cache_cleaner_task, NULL);
        LOG_D ("dns-cache: Cache cleaner task started");
    }
}

size_t
hev_dns_cache_clean_expired (void)
{
    size_t total_cleaned = 0;
    time_t now = time (NULL);

    /* 遍历所有分片 */
    for (int shard = 0; shard < DNS_CACHE_SHARD_COUNT; shard++) {
        hev_task_mutex_lock (&dns_cache_shards[shard]);

        /* 清理属于这个分片的哈希桶 */
        for (int i = shard; i < DNS_CACHE_HASH_SIZE;
             i += DNS_CACHE_SHARD_COUNT) {
            HevDNSCacheEntry **current = &dns_cache_table[i];
            size_t shard_cleaned = 0;

            while (*current) {
                HevDNSCacheEntry *entry = *current;

                /* 检查是否过期 */
                if (now > entry->expire_time) {
                    /* 从链表中移除 */
                    *current = entry->next;

                    if (entry->response_data)
                        hev_free (entry->response_data);
                    if (entry->is_poisoned)
                        poisoned_cache_entries--;
                    if (dns_entry_pool)
                        hev_object_pool_put (dns_entry_pool, entry);
                    else
                        hev_free (entry);

                    total_cache_entries--;
                    shard_cleaned++;
                    total_cleaned++;
                } else {
                    current = &entry->next;
                }
            }
        }

        hev_task_mutex_unlock (&dns_cache_shards[shard]);
    }

    if (total_cleaned > 0) {
        LOG_D ("dns-cache: Cleaned %zu expired entries (total=%zu remaining)",
               total_cleaned, total_cache_entries);
    }

    return total_cleaned;
}

int
hev_dns_cache_init (void)
{
    HevObjectPoolConfig pool_config;

    memset (dns_cache_table, 0, sizeof (dns_cache_table));

    /* 初始化所有分片锁 */
    for (int i = 0; i < DNS_CACHE_SHARD_COUNT; i++) {
        hev_task_mutex_init (&dns_cache_shards[i]);
    }

    /* 创建 DNS 缓存条目对象池 */
    pool_config.obj_size = sizeof (HevDNSCacheEntry);
    pool_config.init_capacity = DNS_ENTRY_POOL_INIT_CAPACITY;
    pool_config.max_capacity = DNS_ENTRY_POOL_MAX_CAPACITY;
    dns_entry_pool = hev_object_pool_new (&pool_config);
    if (!dns_entry_pool) {
        LOG_E ("dns-cache: Failed to create DNS entry object pool");
        return -1;
    }

    total_cache_entries = 0;
    poisoned_cache_entries = 0;
    total_cache_hits = 0;

    /* 注意：不在这里启动清理任务，因为任务系统可能还没初始化
     * 清理任务将在第一次使用时延迟启动 */

    LOG_I (
        "dns-cache: DNS cache module initialized (shards=%d, entry_pool=%d/%d, clean_interval=%dms)",
        DNS_CACHE_SHARD_COUNT, DNS_ENTRY_POOL_INIT_CAPACITY,
        DNS_ENTRY_POOL_MAX_CAPACITY, DNS_CACHE_CLEAN_INTERVAL_MS);
    return 0;
}

void
hev_dns_cache_fini (void)
{
    /* 停止清理任务 */
    cache_cleaner_running = 0;
    LOG_D ("dns-cache: Cache cleaner task stopping...");

    /* 遍历所有分片，清理每个分片的哈希表 */
    for (int shard = 0; shard < DNS_CACHE_SHARD_COUNT; shard++) {
        hev_task_mutex_lock (&dns_cache_shards[shard]);

        /* 清理属于这个分片的哈希桶 */
        for (int i = shard; i < DNS_CACHE_HASH_SIZE;
             i += DNS_CACHE_SHARD_COUNT) {
            HevDNSCacheEntry *entry = dns_cache_table[i];
            while (entry) {
                HevDNSCacheEntry *next = entry->next;
                if (entry->response_data)
                    hev_free (entry->response_data);
                /* 将条目归还到对象池，而非直接释放 */
                if (dns_entry_pool)
                    hev_object_pool_put (dns_entry_pool, entry);
                else
                    hev_free (entry);
                entry = next;
            }
            dns_cache_table[i] = NULL;
        }

        hev_task_mutex_unlock (&dns_cache_shards[shard]);
    }

    /* 最后销毁对象池（会释放池中所有对象） */
    if (dns_entry_pool) {
        hev_object_pool_destroy (dns_entry_pool);
        dns_entry_pool = NULL;
    }

    LOG_I ("dns-cache: DNS cache module finalized (cleared %zu entries)",
           total_cache_entries);
}

int
hev_dns_cache_lookup (const char *domain, uint8_t **response_out,
                      size_t *response_len_out)
{
    uint32_t hash = dns_hash (domain);
    int shard = dns_cache_get_shard (hash);
    time_t now = time (NULL);

    hev_task_mutex_lock (&dns_cache_shards[shard]);

    HevDNSCacheEntry **current = &dns_cache_table[hash];
    while (*current) {
        HevDNSCacheEntry *entry = *current;
        if (strcasecmp (entry->domain, domain) == 0) {
            /* 检查是否过期 */
            if (now > entry->expire_time) {
                LOG_D ("dns-cache: Cache expired for domain: %s, removing",
                       domain);
                /* 惰性删除：从链表中移除过期条目 */
                *current = entry->next;
                if (entry->response_data)
                    hev_free (entry->response_data);
                if (entry->is_poisoned)
                    poisoned_cache_entries--;
                if (dns_entry_pool)
                    hev_object_pool_put (dns_entry_pool, entry);
                else
                    hev_free (entry);
                total_cache_entries--;
                hev_task_mutex_unlock (&dns_cache_shards[shard]);
                return 0;
            }

            /* 命中 */
            *response_out = entry->response_data;
            *response_len_out = entry->response_len;
            entry->hits++;
            total_cache_hits++;

            LOG_I ("dns-cache: Cache hit for domain: %s (hits=%u, poisoned=%d)",
                   domain, entry->hits, entry->is_poisoned);

            hev_task_mutex_unlock (&dns_cache_shards[shard]);
            return 1;
        }
        current = &(*current)->next;
    }

    hev_task_mutex_unlock (&dns_cache_shards[shard]);
    return 0;
}

int
hev_dns_cache_insert (const char *domain, const uint8_t *response_data,
                      size_t response_len, uint32_t ttl, int is_poisoned)
{
    /* 延迟启动清理任务（确保任务系统已初始化） */
    start_cache_cleaner_if_needed ();

    uint32_t hash = dns_hash (domain);
    int shard = dns_cache_get_shard (hash);
    time_t now = time (NULL);

    /* 从对象池分配新条目 */
    HevDNSCacheEntry *new_entry = hev_object_pool_get (dns_entry_pool);
    if (!new_entry) {
        LOG_W ("dns-cache: Object pool empty, falling back to malloc");
        new_entry = hev_malloc0 (sizeof (HevDNSCacheEntry));
    }
    if (!new_entry) {
        LOG_E ("dns-cache: Failed to allocate cache entry");
        return -1;
    }
    /* 对象池返回的内存可能未清零，清零关键字段 */
    if (dns_entry_pool && new_entry) {
        memset (new_entry, 0, sizeof (HevDNSCacheEntry));
    }

    strncpy (new_entry->domain, domain, sizeof (new_entry->domain) - 1);
    new_entry->response_data = hev_malloc (response_len);
    if (!new_entry->response_data) {
        if (dns_entry_pool)
            hev_object_pool_put (dns_entry_pool, new_entry);
        else
            hev_free (new_entry);
        LOG_E ("dns-cache: Failed to allocate response data");
        return -1;
    }

    memcpy (new_entry->response_data, response_data, response_len);
    new_entry->response_len = response_len;
    new_entry->expire_time = now + ttl;
    new_entry->is_poisoned = is_poisoned;
    new_entry->hits = 0;

    hev_task_mutex_lock (&dns_cache_shards[shard]);

    /* 检查是否已存在，如存在则替换 */
    HevDNSCacheEntry **current = &dns_cache_table[hash];
    while (*current) {
        if (strcasecmp ((*current)->domain, domain) == 0) {
            /* 替换旧条目 */
            HevDNSCacheEntry *old = *current;
            new_entry->next = old->next;
            *current = new_entry;

            if (old->response_data)
                hev_free (old->response_data);
            if (old->is_poisoned)
                poisoned_cache_entries--;
            if (dns_entry_pool)
                hev_object_pool_put (dns_entry_pool, old);
            else
                hev_free (old);

            if (is_poisoned)
                poisoned_cache_entries++;

            LOG_I (
                "dns-cache: Updated cache for domain: %s (ttl=%u, poisoned=%d)",
                domain, ttl, is_poisoned);

            hev_task_mutex_unlock (&dns_cache_shards[shard]);
            return 0;
        }
        current = &(*current)->next;
    }

    /* 插入新条目 */
    new_entry->next = dns_cache_table[hash];
    dns_cache_table[hash] = new_entry;
    total_cache_entries++;
    if (is_poisoned)
        poisoned_cache_entries++;

    LOG_I (
        "dns-cache: Inserted cache for domain: %s (ttl=%u, poisoned=%d, total=%zu)",
        domain, ttl, is_poisoned, total_cache_entries);

    hev_task_mutex_unlock (&dns_cache_shards[shard]);
    return 0;
}

/* DNS 响应监控任务 */
static void
dns_response_monitor_task (void *data)
{
    HevDNSPoisonContext *ctx = (HevDNSPoisonContext *)data;
    uint8_t buffer[2048];
    struct sockaddr_storage remote_addr;
    socklen_t addr_len;
    HevTask *task = hev_task_self ();
    int sock = -1;

    LOG_D ("dns-cache: DNS response monitor started for domain: %s",
           ctx->domain);

    /* 创建临时 UDP socket 监听响应 */
    sock = hev_task_io_socket_socket (AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        LOG_E ("dns-cache: Failed to create monitor socket");
        goto cleanup;
    }

    if (hev_task_add_fd (task, sock, POLLIN) < 0) {
        hev_task_mod_fd (task, sock, POLLIN);
    }

    /* 设置超时（5秒） */
    hev_socks5_set_timeout (HEV_SOCKS5 (ctx->base), 5000);

    /* 等待响应 */
    LOG_D ("dns-cache: Waiting for DNS response for domain: %s", ctx->domain);

    addr_len = sizeof (remote_addr);
    ssize_t recv_len = hev_task_io_socket_recvfrom (
        sock, buffer, sizeof (buffer), 0, (struct sockaddr *)&remote_addr,
        &addr_len, hev_socks5_task_io_yielder, ctx->base);

    if (recv_len > 0) {
        LOG_D ("dns-cache: Received DNS response (%zd bytes) for domain: %s",
               recv_len, ctx->domain);

        /* 检测污染 */
        int is_poisoned = hev_dns_detect_pollution (buffer, recv_len);

        if (is_poisoned) {
            LOG_W (
                "dns-cache: DNS pollution detected for domain: %s, querying via SOCKS5...",
                ctx->domain);

            /* 通过 SOCKS5 重新查询 1.1.1.1:53 */
            uint8_t *socks5_response = NULL;
            size_t socks5_response_len = 0;

            /* 从备份的查询包中提取查询数据 */
            if (ctx->original_query && ctx->original_query->payload) {
                uint8_t *query_data = (uint8_t *)ctx->original_query->payload;
                size_t query_len = ctx->original_query->len;

                /* 根据原DNS服务器类型选择对应协议的foreign-dns */
                int prefer_ipv6 = IP_IS_V6 (&ctx->query_dest_ip) ? 1 : 0;

                if (hev_dns_query_via_socks5 (query_data, query_len,
                                              prefer_ipv6, &socks5_response,
                                              &socks5_response_len) == 0) {
                    /* 成功获取干净的响应，缓存它 */
                    uint32_t ttl =
                        extract_dns_ttl (socks5_response, socks5_response_len);
                    hev_dns_cache_insert (ctx->domain, socks5_response,
                                          socks5_response_len, ttl, 0);
                    LOG_I (
                        "dns-cache: Cached clean response from SOCKS5 for domain: %s",
                        ctx->domain);
                    hev_free (socks5_response);
                } else {
                    LOG_E (
                        "dns-cache: Failed to query via SOCKS5 for domain: %s",
                        ctx->domain);
                }
            }
        } else {
            LOG_I (
                "dns-cache: DNS response is clean for domain: %s, caching...",
                ctx->domain);

            /* 提取 TTL 并缓存 */
            uint32_t ttl = extract_dns_ttl (buffer, recv_len);
            hev_dns_cache_insert (ctx->domain, buffer, recv_len, ttl, 0);
        }
    } else {
        LOG_W ("dns-cache: No DNS response received for domain: %s (timeout)",
               ctx->domain);
    }

    hev_task_del_fd (task, sock);
    close (sock);

cleanup:
    /* 清理上下文 */
    if (ctx->original_query)
        pbuf_free (ctx->original_query);
    hev_object_unref (HEV_OBJECT (ctx->base));
    hev_free (ctx);

    LOG_D ("dns-cache: DNS response monitor task finished");
}

int
hev_dns_poison_detect_and_handle (struct udp_pcb *pcb, struct pbuf *p,
                                  const ip_addr_t *addr, u16_t port)
{
    /* 只处理 53 端口的 DNS 查询 */
    if (port != 53)
        return 0;

    /* 提取域名 */
    char domain[256];
    if (extract_dns_domain (p->payload, p->len, domain, sizeof (domain)) < 0) {
        LOG_W ("dns-cache: Failed to extract domain from DNS query");
        return 0;
    }

    LOG_D ("dns-cache: DNS query detected for domain: %s", domain);

    /* 检查缓存 */
    uint8_t *cached_response = NULL;
    size_t cached_len = 0;
    if (hev_dns_cache_lookup (domain, &cached_response, &cached_len)) {
        /* 缓存命中，直接响应 */
        struct pbuf *response =
            pbuf_alloc (PBUF_TRANSPORT, cached_len, PBUF_RAM);
        if (response) {
            memcpy (response->payload, cached_response, cached_len);
            udp_sendto (pcb, response, &pcb->remote_ip, pcb->remote_port);
            pbuf_free (response);
            LOG_I ("dns-cache: Responded from cache for domain: %s", domain);
            return 1; /* 已处理 */
        }
    }

    /* 未命中缓存，创建监控上下文 */
    HevDNSPoisonContext *ctx = hev_malloc0 (sizeof (HevDNSPoisonContext));
    if (!ctx) {
        LOG_E ("dns-cache: Failed to allocate poison context");
        return 0;
    }

    /* 备份查询包 */
    ctx->original_query = pbuf_clone (PBUF_RAW, PBUF_RAM, p);
    if (!ctx->original_query) {
        hev_free (ctx);
        LOG_E ("dns-cache: Failed to clone DNS query");
        return 0;
    }

    ctx->pcb = pcb;
    ip_addr_copy (ctx->client_ip, pcb->remote_ip);
    ctx->client_port = pcb->remote_port;
    ip_addr_copy (ctx->query_dest_ip, *addr);
    ctx->query_dest_port = port;
    ctx->created_time = time (NULL);
    snprintf (ctx->domain, sizeof (ctx->domain), "%s", domain);

    ctx->base = HEV_SOCKS5 (hev_socks5_client_udp_new (HEV_SOCKS5_TYPE_NONE));
    if (!ctx->base) {
        pbuf_free (ctx->original_query);
        hev_free (ctx);
        LOG_E ("dns-cache: Failed to create dummy socks5");
        return 0;
    }

    /* 启动监控任务 */
    int stack_size = hev_config_get_misc_task_stack_size ();
    HevTask *task = hev_task_new (stack_size);
    if (!task) {
        pbuf_free (ctx->original_query);
        hev_object_unref (HEV_OBJECT (ctx->base));
        hev_free (ctx);
        LOG_E ("dns-cache: Failed to create monitor task");
        return 0;
    }

    hev_task_run (task, dns_response_monitor_task, ctx);

    LOG_I ("dns-cache: Started DNS pollution monitor for domain: %s", domain);

    return 1; /* 已启动监控 */
}

/**
 * hev_dns_cache_check_only:
 *
 * 仅检查 DNS 缓存，不启动监控任务
 */
int
hev_dns_cache_check_only (struct udp_pcb *pcb, struct pbuf *p,
                          const ip_addr_t *addr, u16_t port)
{
    /* 只处理 53 端口的 DNS 查询 */
    if (port != 53)
        return 0;

    /* 提取域名 */
    char domain[256];
    if (extract_dns_domain (p->payload, p->len, domain, sizeof (domain)) < 0) {
        LOG_D ("dns-cache: Failed to extract domain from DNS query");
        return 0;
    }

    LOG_D ("dns-cache: Checking cache for domain: %s", domain);

    /* 检查缓存 */
    uint8_t *cached_response = NULL;
    size_t cached_len = 0;
    if (hev_dns_cache_lookup (domain, &cached_response, &cached_len)) {
        /* 缓存命中，直接响应 */
        struct pbuf *response =
            pbuf_alloc (PBUF_TRANSPORT, cached_len, PBUF_RAM);
        if (response) {
            memcpy (response->payload, cached_response, cached_len);
            udp_sendto (pcb, response, &pcb->remote_ip, pcb->remote_port);
            pbuf_free (response);
            LOG_I ("dns-cache: Cache hit for domain: %s", domain);
            total_cache_hits++;
            return 1; /* 缓存命中，已响应 */
        }
    }

    /* 缓存未命中 */
    LOG_D ("dns-cache: Cache miss for domain: %s", domain);
    return 0;
}

void
hev_dns_cache_get_stats (size_t *total_entries, size_t *poisoned_entries,
                         uint64_t *total_hits)
{
    /* 统计数据读取不需要锁（协程环境，单线程执行） */
    if (total_entries)
        *total_entries = total_cache_entries;
    if (poisoned_entries)
        *poisoned_entries = poisoned_cache_entries;
    if (total_hits)
        *total_hits = total_cache_hits;
}

/**
 * hev_dns_query_via_socks5:
 *
 * 通过 SOCKS5 UDP 代理查询 DNS
 * 根据原 DNS 服务器的协议类型选择对应协议的 foreign-dns
 * prefer_ipv6=0: 使用 IPv4 DNS 服务器
 * prefer_ipv6=1: 使用 IPv6 DNS 服务器
 */
int
hev_dns_query_via_socks5 (const uint8_t *query, size_t query_len,
                          int prefer_ipv6, uint8_t **response_out,
                          size_t *response_len_out)
{
    HevSocks5UDP *sock5_udp = NULL;
    HevConfigSocks5Server *srv;
    ip_addr_t dns_server;
    HevSocks5UDPMsg msg;
    HevSocks5Addr addr_storage;
    uint8_t response_buf[512];
    int res;
    int udp_type;
    const char *dns_addr = NULL;

    if (!query || query_len == 0 || !response_out || !response_len_out) {
        LOG_E ("dns-cache: Invalid parameters for socks5 query");
        return -1;
    }

    *response_out = NULL;
    *response_len_out = 0;

    /* 检查DNS分流是否启用 */
    if (!hev_config_get_dns_split_tunnel ()) {
        LOG_D ("dns-cache: DNS split-tunnel disabled, skipping socks5 query");
        return -1;
    }

    /* 获取 SOCKS5 UDP 配置 */
    srv = hev_config_get_socks5_udp_server ();
    if (!srv || srv->addr[0] == '\0' || srv->port == 0) {
        LOG_E ("dns-cache: SOCKS5 UDP server not configured");
        return -1;
    }

    /* 获取UDP类型（根据SOCKS5配置的udp-relay字段） */
    /* udp_relay: 0=tcp(UDP_IN_TCP=2), 1=udp(UDP_IN_UDP=1) */
    udp_type = (srv->udp_relay == 1) ? 1 : 2;

    /* 获取配置的DNS服务器列表 */
    const char **dns_servers = NULL;
    int dns_count = 0;
    size_t *rotation_index = NULL;

    if (prefer_ipv6) {
        /* 原DNS服务器是IPv6，使用IPv6 foreign-dns列表 */
        dns_servers = hev_config_get_foreign_dns_v6 (&dns_count);
        rotation_index = &dns_server_rotation_index;

        if (dns_count == 0) {
            static const char *default_dns_v6[] = { "2606:4700:4700::1111",
                                                    "2001:4860:4860::8888" };
            dns_servers = default_dns_v6;
            dns_count = 2;
        }

        /* 检查 IPv6 是否可用 */
        if (ipv6_available < 0) {
            ipv6_available = check_ipv6_available ();
        }

        if (!ipv6_available) {
            LOG_W ("dns-cache: IPv6 DNS requested but IPv6 not available");
            return -1;
        }

        LOG_D ("dns-cache: Using IPv6 foreign-dns list");
    } else {
        /* 原DNS服务器是IPv4，使用IPv4 foreign-dns列表 */
        dns_servers = hev_config_get_foreign_dns_v4 (&dns_count);
        rotation_index = &dns_server_rotation_index;

        if (dns_count == 0) {
            static const char *default_dns_v4[] = { "1.1.1.1", "8.8.8.8" };
            dns_servers = default_dns_v4;
            dns_count = 2;
        }

        LOG_D ("dns-cache: Using IPv4 foreign-dns list");
    }

    if (dns_count == 0) {
        LOG_E ("dns-cache: No DNS servers configured");
        return -1;
    }

    /* 轮询选择DNS服务器 */
    size_t current_index = (*rotation_index) % dns_count;
    (*rotation_index)++;
    dns_addr = dns_servers[current_index];

    LOG_D ("dns-cache: Selected DNS server: %s", dns_addr);

    /* 创建 SOCKS5 UDP 客户端 */
    sock5_udp = hev_socks5_client_udp_new (udp_type);
    if (!sock5_udp) {
        LOG_E ("dns-cache: Failed to create SOCKS5 UDP client (type=%d)",
               udp_type);
        return -1;
    }

    /* 连接到 SOCKS5 服务器 */
    res = hev_socks5_client_connect (HEV_SOCKS5_CLIENT (sock5_udp), srv->addr,
                                     srv->port);
    if (res < 0) {
        LOG_E ("dns-cache: Failed to connect to SOCKS5 server");
        goto cleanup;
    }

    /* 设置认证 */
    if (srv->user && srv->pass) {
        hev_socks5_client_set_auth (HEV_SOCKS5_CLIENT (sock5_udp), srv->user,
                                    srv->pass);
    }

    /* 握手 */
    res = hev_socks5_client_handshake (HEV_SOCKS5_CLIENT (sock5_udp), 0);
    if (res < 0) {
        LOG_E ("dns-cache: SOCKS5 handshake failed");
        goto cleanup;
    }

    /* 设置目标地址（支持IPv4和IPv6） */
    if (!ipaddr_aton (dns_addr, &dns_server)) {
        LOG_E ("dns-cache: Invalid DNS server address: %s", dns_addr);
        goto cleanup;
    }

    msg.addr = &addr_storage;
    hev_socks5_addr_from_lwip (msg.addr, &dns_server, 53);

    /* 设置消息数据 */
    msg.buf = (void *)query;
    msg.len = query_len;

    LOG_I ("dns-cache: Sending DNS query via SOCKS5 (target=%s:53, type=%d)",
           dns_addr, udp_type);

    /* 发送 DNS 查询 */
    res = hev_socks5_udp_sendmmsg (sock5_udp, &msg, 1);
    if (res < 0) {
        LOG_E ("dns-cache: Failed to send DNS query via SOCKS5 (res=%d)", res);
        goto cleanup;
    }

    /* 接收响应 */
    msg.buf = response_buf;
    msg.len = sizeof (response_buf);
    res = hev_socks5_udp_recvmmsg (sock5_udp, &msg, 1, 0);
    if (res < 0) {
        LOG_W ("dns-cache: Failed to receive DNS response via SOCKS5");
        goto cleanup;
    }

    LOG_I ("dns-cache: Received SOCKS5 DNS response from %s (%zu bytes)",
           dns_addr, msg.len);

    /* 复制响应数据 */
    *response_out = hev_malloc (msg.len);
    if (!*response_out) {
        LOG_E ("dns-cache: Failed to allocate response buffer");
        goto cleanup;
    }
    memcpy (*response_out, msg.buf, msg.len);
    *response_len_out = msg.len;

    hev_object_unref (HEV_OBJECT (sock5_udp));
    return 0;

cleanup:
    if (sock5_udp)
        hev_object_unref (HEV_OBJECT (sock5_udp));
    return -1;
}