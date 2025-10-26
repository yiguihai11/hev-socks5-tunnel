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
 * Check if a hostname is blocked by ACL (case-insensitive).
 *
 * Returns: 1 if blocked, 0 if allowed.
 */
int hev_filter_is_blocked_hostname (const char *hostname);

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

/**
 * Blacklisted IP Entry
 */
typedef struct _HevBlacklistedIP
{
    struct _HevBlacklistedIP *next; /* Hash table chaining */
    ip_addr_t addr; /* IP address */
    time_t expiry; /* Expiration time */
    time_t added_time; /* When added to blacklist */
} HevBlacklistedIP;

/**
 * hev_filter_blacklist_add:
 * @addr: IP address to blacklist
 *
 * Add an IP address to the blacklist with configured expiry time.
 * This will automatically expire old entries.
 */
void hev_filter_blacklist_add (const ip_addr_t *addr);

/**
 * hev_filter_blacklist_check:
 * @addr: IP address to check
 *
 * Check if an IP address is currently blacklisted.
 * This will automatically remove expired entries.
 *
 * Returns: 1 if blacklisted, 0 if not.
 */
int hev_filter_blacklist_check (const ip_addr_t *addr);

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
 * Returns: Number of blacklisted IP entries.
 */
size_t hev_filter_blacklist_get_count (void);

#endif /* __HEV_FILTER_H__ */