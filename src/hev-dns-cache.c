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
#include <errno.h>
#include <hev-memory-allocator.h>
#include <hev-task.h>
#include <hev-task-mutex.h>
#include <hev-task-io.h>
#include <hev-task-io-socket.h>
#include <hev-socks5.h>
#include <hev-socks5-client-udp.h>

#include "hev-logger.h"
#include "hev-config.h"
#include "hev-filter.h"
#include "hev-utils.h"
#include "hev-dns-cache.h"

/* DNS 缓存哈希表 */
static HevDNSCacheEntry *dns_cache_table[DNS_CACHE_HASH_SIZE];
static HevTaskMutex dns_cache_mutex;
static size_t total_cache_entries = 0;
static size_t poisoned_cache_entries = 0;
static uint64_t total_cache_hits = 0;

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
static int
detect_dns_pollution (const uint8_t *data, size_t len)
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
static int
extract_dns_domain (const uint8_t *data, size_t len, char *domain_out,
                    size_t domain_max)
{
    if (len < sizeof (DNSHeader))
        return -1;

    size_t pos = sizeof (DNSHeader);
    return parse_dns_name (data, len, &pos, domain_out, domain_max);
}

int
hev_dns_cache_init (void)
{
    memset (dns_cache_table, 0, sizeof (dns_cache_table));
    hev_task_mutex_init (&dns_cache_mutex);
    total_cache_entries = 0;
    poisoned_cache_entries = 0;
    total_cache_hits = 0;

    LOG_I ("dns-cache: DNS cache module initialized");
    return 0;
}

void
hev_dns_cache_fini (void)
{
    hev_task_mutex_lock (&dns_cache_mutex);

    for (int i = 0; i < DNS_CACHE_HASH_SIZE; i++) {
        HevDNSCacheEntry *entry = dns_cache_table[i];
        while (entry) {
            HevDNSCacheEntry *next = entry->next;
            if (entry->response_data)
                hev_free (entry->response_data);
            hev_free (entry);
            entry = next;
        }
        dns_cache_table[i] = NULL;
    }

    hev_task_mutex_unlock (&dns_cache_mutex);

    LOG_I ("dns-cache: DNS cache module finalized (cleared %zu entries)",
           total_cache_entries);
}

int
hev_dns_cache_lookup (const char *domain, uint8_t **response_out,
                      size_t *response_len_out)
{
    uint32_t hash = dns_hash (domain);
    time_t now = time (NULL);

    hev_task_mutex_lock (&dns_cache_mutex);

    HevDNSCacheEntry *entry = dns_cache_table[hash];
    while (entry) {
        if (strcasecmp (entry->domain, domain) == 0) {
            /* 检查是否过期 */
            if (now > entry->expire_time) {
                LOG_D ("dns-cache: Cache expired for domain: %s", domain);
                hev_task_mutex_unlock (&dns_cache_mutex);
                return 0;
            }

            /* 命中 */
            *response_out = entry->response_data;
            *response_len_out = entry->response_len;
            entry->hits++;
            total_cache_hits++;

            LOG_I ("dns-cache: Cache hit for domain: %s (hits=%u, poisoned=%d)",
                   domain, entry->hits, entry->is_poisoned);

            hev_task_mutex_unlock (&dns_cache_mutex);
            return 1;
        }
        entry = entry->next;
    }

    hev_task_mutex_unlock (&dns_cache_mutex);
    return 0;
}

int
hev_dns_cache_insert (const char *domain, const uint8_t *response_data,
                      size_t response_len, uint32_t ttl, int is_poisoned)
{
    uint32_t hash = dns_hash (domain);
    time_t now = time (NULL);

    /* 分配新条目 */
    HevDNSCacheEntry *new_entry = hev_malloc0 (sizeof (HevDNSCacheEntry));
    if (!new_entry) {
        LOG_E ("dns-cache: Failed to allocate cache entry");
        return -1;
    }

    strncpy (new_entry->domain, domain, sizeof (new_entry->domain) - 1);
    new_entry->response_data = hev_malloc (response_len);
    if (!new_entry->response_data) {
        hev_free (new_entry);
        LOG_E ("dns-cache: Failed to allocate response data");
        return -1;
    }

    memcpy (new_entry->response_data, response_data, response_len);
    new_entry->response_len = response_len;
    new_entry->expire_time = now + ttl;
    new_entry->is_poisoned = is_poisoned;
    new_entry->hits = 0;

    hev_task_mutex_lock (&dns_cache_mutex);

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
            hev_free (old);

            if (is_poisoned)
                poisoned_cache_entries++;

            LOG_I (
                "dns-cache: Updated cache for domain: %s (ttl=%u, poisoned=%d)",
                domain, ttl, is_poisoned);

            hev_task_mutex_unlock (&dns_cache_mutex);
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

    hev_task_mutex_unlock (&dns_cache_mutex);
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

    LOG_D ("dns-cache: DNS response monitor started for domain: %s",
           ctx->domain);

    /* 创建临时 UDP socket 监听响应 */
    int sock = socket (AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        LOG_E ("dns-cache: Failed to create monitor socket");
        goto cleanup;
    }

    /* 设置超时（5秒） */
    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    setsockopt (sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof (tv));

    /* 等待响应（通过拦截 UDP 响应包） */
    /* 注意：这里需要通过 lwIP 的回调机制来监控，暂时简化处理 */
    /* 实际实现中，应该在 UDP 接收处理函数中添加钩子 */

    LOG_D ("dns-cache: Waiting for DNS response for domain: %s", ctx->domain);

    addr_len = sizeof (remote_addr);
    ssize_t recv_len = recvfrom (sock, buffer, sizeof (buffer), 0,
                                 (struct sockaddr *)&remote_addr, &addr_len);

    if (recv_len > 0) {
        LOG_D ("dns-cache: Received DNS response (%zd bytes) for domain: %s",
               recv_len, ctx->domain);

        /* 检测污染 */
        int is_poisoned = detect_dns_pollution (buffer, recv_len);

        if (is_poisoned) {
            LOG_W ("dns-cache: DNS pollution detected for domain: %s, querying via SOCKS5...",
                   ctx->domain);

            /* 通过 SOCKS5 重新查询 1.1.1.1:53 */
            uint8_t *socks5_response = NULL;
            size_t socks5_response_len = 0;

            /* 从备份的查询包中提取查询数据 */
            if (ctx->original_query && ctx->original_query->payload) {
                uint8_t *query_data = (uint8_t *)ctx->original_query->payload;
                size_t query_len = ctx->original_query->len;

                if (hev_dns_query_via_socks5 (query_data, query_len,
                                              &socks5_response, &socks5_response_len) == 0) {
                    /* 成功获取干净的响应，缓存它 */
                    uint32_t ttl = extract_dns_ttl (socks5_response, socks5_response_len);
                    hev_dns_cache_insert (ctx->domain, socks5_response, socks5_response_len,
                                         ttl, 0);
                    LOG_I ("dns-cache: Cached clean response from SOCKS5 for domain: %s",
                           ctx->domain);
                    hev_free (socks5_response);
                } else {
                    LOG_E ("dns-cache: Failed to query via SOCKS5 for domain: %s",
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

    close (sock);

cleanup:
    /* 清理上下文 */
    if (ctx->original_query)
        pbuf_free (ctx->original_query);
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
    strncpy (ctx->domain, domain, sizeof (ctx->domain) - 1);

    /* 启动监控任务 */
    int stack_size = hev_config_get_misc_task_stack_size ();
    HevTask *task = hev_task_new (stack_size);
    if (!task) {
        pbuf_free (ctx->original_query);
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
    hev_task_mutex_lock (&dns_cache_mutex);

    if (total_entries)
        *total_entries = total_cache_entries;
    if (poisoned_entries)
        *poisoned_entries = poisoned_cache_entries;
    if (total_hits)
        *total_hits = total_cache_hits;

    hev_task_mutex_unlock (&dns_cache_mutex);
}

/**
 * hev_dns_query_via_socks5:
 *
 * 通过 SOCKS5 UDP 代理查询 DNS（查询 1.1.1.1:53）
 */
int
hev_dns_query_via_socks5 (const uint8_t *query, size_t query_len,
                          uint8_t **response_out, size_t *response_len_out)
{
    HevSocks5UDP *sock5_udp = NULL;
    HevConfigSocks5Server *srv;
    ip_addr_t dns_server;
    HevSocks5UDPMsg msg;
    int res;

    if (!query || query_len == 0 || !response_out || !response_len_out) {
        LOG_E ("dns-cache: Invalid parameters for socks5 query");
        return -1;
    }

    *response_out = NULL;
    *response_len_out = 0;

    /* 获取 SOCKS5 UDP 配置 */
    srv = hev_config_get_socks5_udp_server ();
    if (!srv || srv->addr[0] == '\0' || srv->port == 0) {
        LOG_E ("dns-cache: SOCKS5 UDP server not configured");
        return -1;
    }

    /* 创建 SOCKS5 UDP 客户端 */
    sock5_udp = hev_socks5_client_udp_new (HEV_SOCKS5_TYPE_UDP_IN_TCP);
    if (!sock5_udp) {
        LOG_E ("dns-cache: Failed to create SOCKS5 UDP client");
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

    /* 设置目标地址：1.1.1.1:53 */
    ipaddr_aton ("1.1.1.1", &dns_server);
    hev_socks5_addr_from_lwip (msg.addr, &dns_server, 53);

    /* 设置消息数据 */
    msg.buf = (void *)query;
    msg.len = query_len;

    /* 发送 DNS 查询 */
    res = hev_socks5_udp_sendmmsg (sock5_udp, &msg, 1);
    if (res < 0) {
        LOG_E ("dns-cache: Failed to send DNS query via SOCKS5");
        goto cleanup;
    }

    LOG_I ("dns-cache: Sent DNS query via SOCKS5 to 1.1.1.1:53");

    /* 接收响应 */
    res = hev_socks5_udp_recvmmsg (sock5_udp, &msg, 1, 1);
    if (res <= 0) {
        LOG_W ("dns-cache: No response from SOCKS5 DNS server");
        goto cleanup;
    }

    /* 复制响应数据 */
    *response_out = hev_malloc (msg.len);
    if (!*response_out) {
        LOG_E ("dns-cache: Failed to allocate response buffer");
        goto cleanup;
    }
    memcpy (*response_out, msg.buf, msg.len);
    *response_len_out = msg.len;

    LOG_I ("dns-cache: Received DNS response via SOCKS5 (%zu bytes)",
           *response_len_out);

    hev_object_unref (HEV_OBJECT (sock5_udp));
    return 0;

cleanup:
    if (sock5_udp)
        hev_object_unref (HEV_OBJECT (sock5_udp));
    return -1;
}