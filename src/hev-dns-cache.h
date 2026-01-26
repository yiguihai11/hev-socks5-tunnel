/*
 ============================================================================
 Name        : hev-dns-cache.h
 Author      : AI Assistant
 Copyright   : Copyright (c) 2025
 Description : DNS Cache with GFW Pollution Detection
 ============================================================================
 */

#ifndef __HEV_DNS_CACHE_H__
#define __HEV_DNS_CACHE_H__

typedef struct _HevSocks5 HevSocks5;

#include <stdint.h>
#include <time.h>
#include <lwip/ip_addr.h>
#include <lwip/pbuf.h>
#include <lwip/udp.h>

#ifdef __cplusplus
extern "C" {
#endif

/* DNS 缓存哈希表大小 */
#define DNS_CACHE_HASH_SIZE 4096

/* DNS 缓存内存限制（3MB） */
#define DNS_CACHE_MAX_MEMORY (3 * 1024 * 1024)

/* DNS 查询类型 */
#define DNS_TYPE_A 1
#define DNS_TYPE_AAAA 28

/* DNS 响应码 */
#define DNS_RCODE_NOERROR 0
#define DNS_RCODE_SERVFAIL 2
#define DNS_RCODE_NXDOMAIN 3

/**
 * DNS 缓存条目
 */
typedef struct _HevDNSCacheEntry
{
    char domain[256]; /* 域名 */
    uint16_t qtype; /* DNS 查询类型 (A=1, AAAA=28) */
    uint8_t *response_data; /* DNS 响应数据 */
    size_t response_len; /* 响应数据长度 */
    time_t expire_time; /* 过期时间 */
    time_t last_access; /* 最后访问时间（LRU） */
    size_t entry_size; /* 条目总大小（内存统计） */
    int is_poisoned; /* 是否被污染 */
    uint32_t hits; /* 命中次数 */
    struct _HevDNSCacheEntry *next; /* 哈希链表 */
    struct _HevDNSCacheEntry *lru_prev; /* LRU 前驱 */
    struct _HevDNSCacheEntry *lru_next; /* LRU 后继 */
} HevDNSCacheEntry;

/**
 * DNS 污染检测上下文
 */
typedef struct _HevDNSPoisonContext
{
    struct udp_pcb *pcb; /* 原始 UDP PCB */
    struct pbuf *original_query; /* 原始查询（备份） */
    ip_addr_t client_ip; /* 客户端 IP */
    u16_t client_port; /* 客户端端口 */
    ip_addr_t query_dest_ip; /* 原查询目标 IP */
    u16_t query_dest_port; /* 原查询目标端口 */
    time_t created_time; /* 创建时间 */
    char domain[256]; /* 查询的域名 */
    HevSocks5 *base;
} HevDNSPoisonContext;

/**
 * hev_dns_cache_init:
 *
 * 初始化 DNS 缓存模块
 *
 * Returns: 0 成功, -1 失败
 */
int hev_dns_cache_init (void);

/**
 * hev_dns_cache_fini:
 *
 * 清理 DNS 缓存模块
 */
void hev_dns_cache_fini (void);

/**
 * hev_dns_cache_clean_expired:
 *
 * 清理所有过期的缓存条目（定期调用）
 *
 * Returns: 清理的条目数量
 */
size_t hev_dns_cache_clean_expired (void);

/**
 * hev_dns_cache_lookup:
 * @domain: 域名
 * @qtype: DNS 查询类型 (A=1, AAAA=28)
 * @response_out: 输出缓存的响应数据
 * @response_len_out: 输出响应数据长度
 *
 * 查找 DNS 缓存
 *
 * Returns: 1 找到, 0 未找到
 */
int hev_dns_cache_lookup (const char *domain, uint16_t qtype,
                          uint8_t **response_out, size_t *response_len_out);

/**
 * hev_dns_cache_insert:
 * @domain: 域名
 * @qtype: DNS 查询类型 (A=1, AAAA=28)
 * @response_data: DNS 响应数据
 * @response_len: 响应数据长度
 * @ttl: TTL（秒）
 * @is_poisoned: 是否被污染
 *
 * 插入 DNS 缓存
 *
 * Returns: 0 成功, -1 失败
 */
int hev_dns_cache_insert (const char *domain, uint16_t qtype,
                          const uint8_t *response_data,
                          size_t response_len, uint32_t ttl, int is_poisoned);

/**
 * hev_dns_poison_detect_and_handle:
 * @pcb: UDP PCB
 * @p: pbuf（DNS 查询包）
 * @addr: 目标地址
 * @port: 目标端口
 *
 * 检测 DNS 污染并处理：
 * 1. 备份 DNS 查询包
 * 2. 监控 DNS 响应
 * 3. 检测是否包含国外 IP（被污染）
 * 4. 如被污染，通过 SOCKS5 代理查询 1.1.1.1:53
 * 5. 缓存结果
 *
 * Returns: 1 已处理（启动监控）, 0 未处理
 */
int hev_dns_poison_detect_and_handle (struct udp_pcb *pcb, struct pbuf *p,
                                      const ip_addr_t *addr, u16_t port);

/**
 * hev_dns_cache_check_only:
 * @pcb: UDP PCB
 * @p: pbuf（DNS 查询包）
 * @addr: 目标地址
 * @port: 目标端口
 *
 * 仅检查 DNS 缓存，不启动监控任务：
 * 1. 提取域名
 * 2. 查询缓存
 * 3. 如果命中，直接响应
 * 4. 如果未命中，返回 0
 *
 * Returns: 1 缓存命中（已响应）, 0 缓存未命中
 */
int hev_dns_cache_check_only (struct udp_pcb *pcb, struct pbuf *p,
                              const ip_addr_t *addr, u16_t port);

/**
 * hev_dns_cache_get_stats:
 * @total_entries: 输出总条目数
 * @poisoned_entries: 输出被污染条目数
 * @total_hits: 输出总命中次数
 * @total_memory: 输出总内存使用（字节）
 * @max_memory: 输出最大内存限制（字节）
 *
 * 获取 DNS 缓存统计信息
 */
void hev_dns_cache_get_stats (size_t *total_entries, size_t *poisoned_entries,
                              uint64_t *total_hits, size_t *total_memory,
                              size_t *max_memory);

/**
 * hev_dns_query_via_socks5:
 * @query: DNS 查询数据
 * @query_len: 查询数据长度
 * @prefer_ipv6: 是否优先使用 IPv6 DNS 服务器（根据原DNS服务器类型决定）
 * @response_out: 输出响应数据（需要调用者 hev_free）
 * @response_len_out: 输出响应数据长度
 *
 * 通过 SOCKS5 UDP 代理查询 DNS
 * prefer_ipv6=0: 使用 foreign-dns 中的 IPv4 服务器
 * prefer_ipv6=1: 使用 foreign-dns 中的 IPv6 服务器
 *
 * Returns: 0 成功, -1 失败
 */
int hev_dns_query_via_socks5 (const uint8_t *query, size_t query_len,
                              int prefer_ipv6, uint8_t **response_out,
                              size_t *response_len_out);

/**
 * hev_dns_detect_pollution:
 * @data: DNS 响应数据
 * @len: 响应数据长度
 *
 * 检测 DNS 响应是否被污染（包含国外IP地址）
 *
 * Returns: 1 污染, 0 干净
 */
int hev_dns_detect_pollution (const uint8_t *data, size_t len);

/**
 * extract_dns_domain:
 * @data: DNS 查询/响应数据
 * @len: 数据长度
 * @domain_out: 输出域名
 * @domain_max: 输出缓冲区大小
 *
 * 从 DNS 数据包中提取域名
 *
 * Returns: 提取的域名长度（不含null）, -1 失败
 */
int extract_dns_domain (const uint8_t *data, size_t len, char *domain_out,
                        size_t domain_max);

/**
 * extract_dns_qtype:
 * @data: DNS 查询/响应数据
 * @len: 数据长度
 *
 * 从 DNS 数据包中提取查询类型（QTYPE）
 *
 * Returns: QTYPE (A=1, AAAA=28), 0 失败
 */
uint16_t extract_dns_qtype (const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* __HEV_DNS_CACHE_H__ */