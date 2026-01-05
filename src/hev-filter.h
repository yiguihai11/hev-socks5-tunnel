/*
 ============================================================================
 Name        : hev-filter.h
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2025 hev
 Description : High-Performance Filter (ACL + TLS Parser + CIDR Router)
 ============================================================================
 */

#ifndef __HEV_FILTER_H__
#define __HEV_FILTER_H__

#include <stdint.h>
#include <stddef.h>
#include <lwip/ip_addr.h>
#include <lwip/tcp.h>

/* TLS Content Type */
#define TLS_CONTENT_TYPE_HANDSHAKE 0x16

/* TLS Handshake Type */
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 0x01

/* TLS Extension Types */
#define TLS_EXT_SERVER_NAME 0x0000
#define TLS_EXT_ALPN 0x0010

/* Maximum hostname length */
#define MAX_HOSTNAME_LENGTH 255

/* ============================================================================
   ACL Rule Types and Actions (Two-Stage Matching)
   ============================================================================ */

/* ACL Action Types */
typedef enum
{
    HEV_ACL_ACTION_ALLOW, /* Allow direct connection */
    HEV_ACL_ACTION_BLOCK, /* Block connection */
    HEV_ACL_ACTION_DEFAULT /* Use default behavior */
} HevACLAction;

/* ACL Rule Types */
typedef enum
{
    HEV_ACL_TYPE_IP, /* Single IP address */
    HEV_ACL_TYPE_CIDR, /* CIDR range */
    HEV_ACL_TYPE_PORT, /* Port number */
    HEV_ACL_TYPE_DOMAIN /* Domain name */
} HevACLType;

/* ACL Rule Structure */
typedef struct _HevACLRule
{
    HevACLAction action;
    HevACLType type;
    char pattern[256]; /* IP, CIDR, domain, or port */
    struct _HevACLRule *next;
} HevACLRule;

/* ACL Match Result */
typedef struct _HevACLResult
{
    int matched;
    HevACLAction action;
    const char *rule_pattern;
} HevACLResult;

/**
 * TLS ClientHello / HTTP Host Information (unified)
 * Hostname from either HTTPS SNI or HTTP Host header
 */
typedef struct _HevTLSClientHello
{
    uint8_t detected; /* TLS/HTTP detected */
    uint16_t tls_version; /* TLS version (0 for HTTP) */
    char hostname[MAX_HOSTNAME_LENGTH + 1]; /* Hostname from SNI or Host header */
    char alpn[64]; /* ALPN protocol (HTTPS only) */
} HevTLSClientHello;

/**
 * Filter Statistics
 */
typedef struct _HevFilterStats
{
    size_t ip_blocked; /* IP blocked count */
    size_t hostname_blocked; /* Hostname blocked count */
    size_t tls_parsed; /* TLS ClientHello parsed */
    size_t http_parsed; /* HTTP Host parsed */
    size_t domestic_hits; /* Domestic IP hits */
    size_t foreign_hits; /* Foreign IP hits */
    size_t blacklist_adds; /* Blacklist additions */
    size_t blacklist_hits; /* Blacklist match attempts */
    size_t blacklist_active; /* Currently active blacklist entries */
} HevFilterStats;

/**
 * hev_filter_init:
 *
 * Initialize the filter module.
 *
 * Returns: 0 on success, -1 on failure.
 */
int hev_filter_init (void);

/**
 * hev_filter_fini:
 *
 * Finalize the filter module and free resources.
 */
void hev_filter_fini (void);

/**
 * hev_filter_load_acl:
 * @file_path: ACL file path
 *
 * Load ACL rules from file (IP addresses and hostnames).
 *
 * Returns: 0 on success, -1 on failure.
 */
int hev_filter_load_acl (const char *file_path);

/**
 * hev_filter_load_chnroutes:
 * @file_path: chnroutes file path
 *
 * Load Chinese IP ranges from file for routing.
 *
 * Returns: 0 on success, -1 on failure.
 */
int hev_filter_load_chnroutes (const char *file_path);

/**
 * hev_filter_is_blocked_ip:
 * @ip: IP address to check
 *
 * Check if an IP address is blocked by ACL.
 *
 * Returns: 1 if blocked, 0 if allowed.
 */
int hev_filter_is_blocked_ip (const ip_addr_t *ip);

/**
 * hev_filter_is_blocked_hostname:
 * @hostname: Hostname/SNI to check
 *
 * Check if a hostname is blocked by ACL or dynamic blacklist (case-insensitive).
 *
 * Returns: 1 if blocked, 0 if allowed.
 */
int hev_filter_is_blocked_hostname (const char *hostname);

/**
 * hev_filter_is_blocked_port:
 * @port: Port number to check
 *
 * Check if a port is blocked by dynamic blacklist.
 *
 * Returns: 1 if blocked, 0 if allowed.
 */
int hev_filter_is_blocked_port (int port);

/* ============================================================================
   Two-Stage ACL Matching (New Implementation)
   ============================================================================ */

/**
 * hev_acl_match_stage1_connection:
 * @ip: IP address to check
 * @port: Port number to check
 *
 * Stage 1: Match connection rules (IP/Port/CIDR) before hostname is known.
 * This is called when establishing connection, before parsing TLS/HTTP.
 *
 * Returns: ACL result (action and whether matched)
 */
HevACLResult hev_acl_match_stage1_connection (const ip_addr_t *ip, int port);

/**
 * hev_acl_match_stage2_domain:
 * @hostname: Hostname to check (from SNI or Host header)
 * @port: Port number to check
 *
 * Stage 2: Match domain rules after hostname is detected.
 * Domain rules have higher priority than Stage 1 connection rules.
 *
 * Returns: ACL result (action and whether matched)
 */
HevACLResult hev_acl_match_stage2_domain (const char *hostname, int port);

/**
 * hev_acl_check_final_decision:
 * @stage1_result: Result from stage 1 (connection)
 * @stage2_result: Result from stage 2 (domain), if available
 *
 * Combine both stages to get final decision.
 * Stage 2 (domain) overrides Stage 1 (connection) if matched.
 *
 * Returns: Final action (ALLOW or BLOCK)
 */
HevACLAction hev_acl_check_final_decision (HevACLResult *stage1_result,
                                           HevACLResult *stage2_result);

/* ============================================================================ */

/**
 * hev_filter_check_all_filters:
 * @ip: IP address to check
 * @hostname: Hostname to check
 * @port: Port number to check
 *
 * Comprehensive filter check against ACL rules only (security blocking).
 * This function checks IP, hostname, and port against ACL blocking rules.
 *
 * Returns: 1 if any ACL filter matches (blocked), 0 if all allowed.
 */
int hev_filter_check_all_filters (const ip_addr_t *ip, const char *hostname,
                                  int port);

/**
 * hev_filter_is_gfw_blocked:
 * @ip: IP address to check
 * @hostname: Hostname to check
 * @port: Port number to check
 *
 * Check if the target is blocked by GFW based on dynamic blacklist.
 * This is used for routing decisions, not for security blocking.
 *
 * Returns: 1 if GFW blocked (should use proxy), 0 if not blocked.
 */
int hev_filter_is_gfw_blocked (const ip_addr_t *ip, const char *hostname,
                               int port);

/**
 * hev_filter_is_domestic:
 * @ip: IP address to check
 *
 * Check if an IP address is in Chinese IP ranges.
 *
 * Returns: 1 if domestic, 0 if foreign.
 */
int hev_filter_is_domestic (const ip_addr_t *ip);

/**
 * hev_filter_parse_tls:
 * @log_data: Logger context pointer
 * @data: Packet data
 * @len: Packet length
 * @hello: Output structure for TLS info
 *
 * Parse TLS ClientHello to extract SNI and ALPN.
 *
 * Returns: 0 on success, -1 if not TLS or parse error.
 */
int hev_filter_parse_tls (void *log_data, const unsigned char *data, size_t len,
                          HevTLSClientHello *hello);

/**
 * hev_filter_parse_http_host:
 * @log_data: Logger context pointer
 * @data: HTTP request data
 * @len: Data length
 * @hostname: Output buffer for hostname
 * @hostname_len: Buffer size
 *
 * Parse HTTP request to extract Host header or full URL.
 *
 * Returns: 0 on success, -1 if not found.
 */
int hev_filter_parse_http_host (void *log_data, const unsigned char *data,
                                size_t len, char *hostname,
                                size_t hostname_len);

/**
 * hev_filter_sniff_pcb_hostname:
 * @pcb: TCP PCB
 * @queue: pbuf queue
 * @hostname: Output buffer
 * @hostname_len: Buffer size
 *
 * Unified protocol detection to sniff hostname from TCP PCB queue.
 * Tries TLS SNI extraction first, falls back to HTTP Host header if TLS fails.
 * Works for any port - not limited to specific protocol ports.
 *
 * Returns: 0 on success, -1 if not detected.
 */
int hev_filter_sniff_pcb_hostname (struct tcp_pcb *pcb, struct pbuf *queue,
                                   char *hostname, size_t hostname_len);

/**
 * hev_filter_get_stats:
 * @stats: Output statistics
 *
 * Retrieve filter statistics.
 */
void hev_filter_get_stats (HevFilterStats *stats);

/**
 * hev_filter_reset_stats:
 *
 * Reset all statistics counters to zero.
 */
void hev_filter_reset_stats (void);

/* 黑名单条目类型 */
typedef enum
{
    HEV_BLACKLIST_ENTRY_IP = 1, /* IP地址黑名单 */
    HEV_BLACKLIST_ENTRY_DOMAIN = 2 /* 域名黑名单 */
} HevBlacklistEntryType;

/**
 * Blacklist Entry (精简版)
 */
typedef struct _HevBlacklistEntry
{
    struct _HevBlacklistEntry *next;
    HevBlacklistEntryType type;
    ip_addr_t ip_addr;
    char hostname[256];
    time_t expiry_time; /* 过期时间，0 表示永不过期 */
    uint64_t hit_count; /* 命中统计 (用于调试) */
    char id[32]; /* 条目唯一标识符 (指针地址字符串) */
} HevBlacklistEntry;

/* 兼容性定义 */
typedef HevBlacklistEntry HevBlacklistedIP;

/**
 * hev_filter_blacklist_add_ip:
 * @addr: IP address to blacklist
 *
 * Add an IP address to the dynamic blacklist.
 * Uses configured expiry time (blocked-ip-expiry-minutes).
 * Entries automatically expire after the configured time.
 *
 * Returns: 新增条目的唯一标识符，失败返回NULL
 */
const char *hev_filter_blacklist_add_ip (const ip_addr_t *addr);

/**
 * hev_filter_blacklist_add_domain:
 * @domain: Domain name to blacklist
 *
 * Add a domain name to the dynamic blacklist.
 * Uses configured expiry time (blocked-ip-expiry-minutes).
 * Entries automatically expire after the configured time.
 *
 * Returns: 新增条目的唯一标识符，失败返回NULL
 */
const char *hev_filter_blacklist_add_domain (const char *domain);

/**
 * hev_filter_blacklist_check_ip:
 * @addr: IP address to check
 *
 * Check if an IP address is currently blacklisted.
 * This will automatically remove expired entries and update statistics.
 *
 * Returns: 1 if blacklisted, 0 if not.
 */
int hev_filter_blacklist_check_ip (const ip_addr_t *addr);

/**
 * hev_filter_blacklist_check_entry:
 * @type: 条目类型
 * @ip_addr: IP地址（可选）
 * @port: 端口（可选）
 * @hostname: 主机名（可选）
 *
 * Check if any matching entry exists in blacklist.
 * This will automatically remove expired entries and update statistics.
 *
 * Returns: 1 if blacklisted, 0 if not.
 */
int hev_filter_blacklist_check_entry (HevBlacklistEntryType type,
                                      const ip_addr_t *ip_addr, int port,
                                      const char *hostname);

/**
 * hev_filter_blacklist_get_entry:
 * @id: 条目唯一标识符
 *
 * 根据ID获取黑名单条目详细信息。
 *
 * Returns: 条目指针，未找到返回NULL
 */
HevBlacklistEntry *hev_filter_blacklist_get_entry (const char *id);

/**
 * hev_filter_blacklist_remove_entry:
 * @id: 条目唯一标识符
 *
 * 根据ID移除黑名单条目。
 *
 * Returns: 0成功，-1失败
 */
int hev_filter_blacklist_remove_entry (const char *id);

/**
 * hev_filter_blacklist_update_hit:
 * @id: 条目唯一标识符
 * @bytes: 阻止的字节数
 *
 * 更新黑名单条目的命中统计信息。
 *
 * Returns: 0成功，-1失败
 */
int hev_filter_blacklist_update_hit (const char *id, uint64_t bytes);

/**
 * hev_filter_blacklist_clear:
 *
 * Clear all blacklist entries (for testing/admin purposes).
 */
void hev_filter_blacklist_clear (void);

/**
 * hev_filter_blacklist_get_count:
 *
 * Get the current number of blacklist entries.
 *
 * Returns: Number of blacklisted entries.
 */
size_t hev_filter_blacklist_get_count (void);

/**
 * hev_filter_blacklist_get_stats:
 * @total_entries: 总条目数输出
 * @active_entries: 激活条目数输出
 * @total_hits: 总命中次数输出
 * @total_blocked: 总阻止字节数输出
 *
 * 获取黑名单的详细统计信息。
 */
void hev_filter_blacklist_get_stats (size_t *total_entries,
                                     size_t *active_entries,
                                     uint64_t *total_hits,
                                     uint64_t *total_blocked);

#endif /* __HEV_FILTER_H__ */