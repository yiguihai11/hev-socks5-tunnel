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

/* Maximum SNI/Host length */
#define MAX_SNI_LENGTH 255
#define MAX_HOST_LENGTH 255

/**
 * TLS ClientHello Information
 */
typedef struct _HevTLSClientHello
{
    uint8_t detected; /* TLS detected */
    uint16_t tls_version; /* TLS version */
    char sni[MAX_SNI_LENGTH + 1]; /* Server Name Indication */
    char alpn[64]; /* ALPN protocol */
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
 * Convenience function to sniff hostname from TCP PCB queue.
 * Automatically detects TLS (443) or HTTP (80/8080).
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
    HEV_BLACKLIST_ENTRY_PORT = 2, /* 端口黑名单 */
    HEV_BLACKLIST_ENTRY_SNI = 3, /* SNI/主机名黑名单 */
    HEV_BLACKLIST_ENTRY_DOMAIN = 4 /* 域名黑名单 */
} HevBlacklistEntryType;

/* 黑名单条目来源 */
typedef enum
{
    HEV_BLACKLIST_SOURCE_MANUAL = 1, /* 手动添加 */
    HEV_BLACKLIST_SOURCE_ACL = 2, /* ACL规则 */
    HEV_BLACKLIST_SOURCE_CHNROUTES = 3, /* 中国路由规则 */
    HEV_BLACKLIST_SOURCE_AUTO = 4, /* 自动检测（如异常行为） */
    HEV_BLACKLIST_SOURCE_API = 5 /* API接口添加 */
} HevBlacklistSource;

/**
 * Enhanced Blacklist Entry
 */
typedef struct _HevBlacklistEntry
{
    struct _HevBlacklistEntry *next;

    /* 基本信息 */
    HevBlacklistEntryType type;
    HevBlacklistSource source;
    char id[64]; /* 唯一标识符 */

    /* 网络信息 */
    ip_addr_t ip_addr;
    int port;
    char hostname[256]; /* SNI/主机名/域名 */

    /* 时间信息 */
    time_t added_time; /* 添加时间 */
    time_t expiry_time; /* 过期时间 */
    time_t last_seen; /* 最后访问时间 */
    time_t first_seen; /* 首次发现时间 */

    /* 统计信息 */
    uint64_t hit_count; /* 命中次数 */
    uint64_t bytes_blocked; /* 阻止的字节数 */
    uint32_t session_count; /* 关联的会话数量 */

    /* 元数据 */
    char reason[128]; /* 添加原因 */
    char source_info[64]; /* 来源详细信息 */
    int severity; /* 严重级别 1-10 */
    int is_active; /* 是否激活 */

    /* TTL 管理 */
    int ttl_seconds; /* 生存时间（秒） */
    int auto_refresh; /* 是否自动刷新 */
} HevBlacklistEntry;

/* 兼容性定义 */
typedef HevBlacklistEntry HevBlacklistedIP;

/**
 * hev_filter_blacklist_add_ip:
 * @addr: IP address to blacklist
 * @reason: 添加原因（可选）
 * @source: 来源类型
 * @ttl_seconds: 生存时间（秒，0表示使用默认值）
 *
 * Add an IP address to the blacklist with detailed information.
 * This will automatically expire old entries.
 *
 * Returns: 新增条目的唯一标识符，失败返回NULL
 */
const char *hev_filter_blacklist_add_ip (const ip_addr_t *addr,
                                         const char *reason,
                                         HevBlacklistSource source,
                                         int ttl_seconds);

/**
 * hev_filter_blacklist_add_entry:
 * @type: 条目类型
 * @ip_addr: IP地址（可选，对于IP类型必须提供）
 * @port: 端口（可选，对于端口类型必须提供）
 * @hostname: 主机名/SNI（可选，对于SNI/域名类型必须提供）
 * @reason: 添加原因
 * @source: 来源类型
 * @severity: 严重级别 (1-10)
 * @ttl_seconds: 生存时间（秒，0表示使用默认值）
 *
 * Add a detailed entry to the blacklist.
 *
 * Returns: 新增条目的唯一标识符，失败返回NULL
 */
const char *hev_filter_blacklist_add_entry (HevBlacklistEntryType type,
                                            const ip_addr_t *ip_addr, int port,
                                            const char *hostname,
                                            const char *reason,
                                            HevBlacklistSource source,
                                            int severity, int ttl_seconds);

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

/**
 * hev_filter_blacklist_export:
 * @buffer: 输出缓冲区
 * @buffer_size: 缓冲区大小
 *
 * 导出黑名单条目为JSON格式字符串。
 *
 * Returns: 实际写入的字节数，缓冲区不足返回-1
 */
int hev_filter_blacklist_export (char *buffer, size_t buffer_size);

/* 兼容性函数 - 保持向后兼容 */
void hev_filter_blacklist_add (const ip_addr_t *addr);
int hev_filter_blacklist_check (const ip_addr_t *addr);

#endif /* __HEV_FILTER_H__ */