/*
 ============================================================================
 Name        : hev-dns-latency.h
 Author      : AI Assistant
 Copyright   : Copyright (c) 2025
 Description : DNS Response Latency Optimization (IPv4/IPv6)
 ============================================================================
 */

#ifndef __HEV_DNS_LATENCY_H__
#define __HEV_DNS_LATENCY_H__

#include <stdint.h>
#include <stddef.h>
#include <lwip/ip_addr.h>
#include <lwip/udp.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _HevSocks5 HevSocks5;

/* DNS record types */
#define DNS_TYPE_A 1
#define DNS_TYPE_AAAA 28
#define DNS_TYPE_CNAME 5

/* IP latency test method */
typedef enum
{
    DNS_LATENCY_METHOD_NONE = -1,
    DNS_LATENCY_METHOD_TCP443 = 0,
    DNS_LATENCY_METHOD_TCP80 = 1,
    DNS_LATENCY_METHOD_ICMP = 2
} DnsLatencyTestMethod;

/* 单个方法的测试结果 */
typedef struct _DnsLatencyMethodResult
{
    int success;
    int64_t latency_us; /* microseconds */
} DnsLatencyMethodResult;

/* IP latency test result (所有方法的测试结果) */
typedef struct _DnsLatencyResult
{
    ip_addr_t ip; /* lwIP ip_addr_t supports IPv4/IPv6 */
    DnsLatencyMethodResult tcp443; /* TCP 443 测试结果 */
    DnsLatencyMethodResult tcp80; /* TCP 80 测试结果 */
    DnsLatencyMethodResult icmp; /* ICMP 测试结果 */
} DnsLatencyResult;

/**
 * hev_dns_latency_init:
 *
 * Initialize DNS latency optimization module
 *
 * Returns: 0 on success, -1 on failure
 */
int hev_dns_latency_init (void);

/**
 * hev_dns_latency_fini:
 *
 * Cleanup DNS latency optimization module
 */
void hev_dns_latency_fini (void);

/**
 * hev_dns_latency_extract_ips:
 * @data: DNS response data
 * @len: response data length
 * @ips_out: output IP array
 * @max_ips: maximum number of IPs to extract
 * @ipv4_count_out: output IPv4 count (can be NULL)
 * @ipv6_count_out: output IPv6 count (can be NULL)
 *
 * Extract all IP addresses from DNS response (A and AAAA records)
 *
 * Returns: number of IPs extracted, -1 on error
 */
int hev_dns_latency_extract_ips (const uint8_t *data, size_t len,
                                 ip_addr_t *ips_out, int max_ips,
                                 int *ipv4_count_out, int *ipv6_count_out);

/**
 * hev_dns_latency_modify_response:
 * @data: DNS response data (will be modified in-place)
 * @len: pointer to response data length (will be updated)
 * @best_ip: the best IP to keep
 *
 * Modify DNS response to keep only the specified IP
 *
 * Returns: 0 on success, -1 on error
 */
int hev_dns_latency_modify_response (uint8_t *data, size_t *len,
                                     const ip_addr_t *best_ip);

/**
 * hev_dns_latency_test_ip:
 * @ip: IP address to test (IPv4 or IPv6)
 * @result_out: output test result
 * @tcp_timeout_ms: TCP connection timeout in milliseconds
 * @icmp_timeout_ms: ICMP ping timeout in milliseconds (unused, uses hardcoded timeout)
 *
 * Test latency for a single IP using: TCP 443 -> TCP 80 -> ICMP
 *
 * Returns: 0 on success (result in result_out), -1 on failure
 */
int hev_dns_latency_test_ip (const ip_addr_t *ip, DnsLatencyResult *result_out,
                             int tcp_timeout_ms, int icmp_timeout_ms);

/**
 * hev_dns_latency_test_ip_all:
 * @ip: IP address to test (IPv4 or IPv6)
 * @results_out: output array for all test results (must have 3 elements)
 * @tcp_timeout_ms: TCP connection timeout in milliseconds
 * @icmp_timeout_ms: ICMP ping timeout in milliseconds (unused, uses hardcoded timeout)
 *
 * Test latency using ALL methods: TCP 443, TCP 80, ICMP
 * Returns results for all methods regardless of success/failure.
 *
 * Returns: 0 on success, -1 on failure
 */
int hev_dns_latency_test_ip_all (const ip_addr_t *ip,
                                 DnsLatencyResult *results_out,
                                 int tcp_timeout_ms, int icmp_timeout_ms);

/**
 * hev_dns_latency_test_concurrent:
 * @ips: IP addresses to test (IPv4 or IPv6)
 * @ip_count: number of IPs
 * @results_out: output array for test results (must have ip_count elements)
 * @timeout_ms: total timeout for all IPs in milliseconds
 *
 * Test latency for multiple IPs concurrently using task system:
 * - Each IP tests in parallel (443 -> 80 -> ICMP)
 * - Total timeout applies to the entire group
 * - Each port has 500ms hardcoded timeout
 * - When timeout occurs, all tests are stopped
 * - Returns best result from successful tests
 *
 * Returns: 0 on success (at least one IP succeeded), -1 on failure
 */
int hev_dns_latency_test_concurrent (const ip_addr_t *ips, int ip_count,
                                     DnsLatencyResult *results_out,
                                     int timeout_ms);

/**
 * hev_dns_latency_optimize_response_async:
 * @response_data: DNS response data (will be copied)
 * @response_len: response data length
 * @domain: domain name
 * @pcb: UDP PCB for sending response
 * @client_ip: client IP address
 * @client_port: client port
 * @base: HevSocks5 base object
 *
 * Asynchronously optimize DNS response:
 * 1. Extract all IPs (IPv4 + IPv6)
 * 2. Test latency for all IPs concurrently
 * 3. Select the fastest IP
 * 4. Modify DNS response to keep only the best IP
 * 5. Cache the optimized response
 * 6. Send optimized response to client
 *
 * Returns: 1 if async task started (caller should skip sending),
 *          0 if failed to start (caller should continue normal flow),
 *          -1 on error
 */
int hev_dns_latency_optimize_response_async (
    const uint8_t *response_data, size_t response_len, const char *domain,
    struct udp_pcb *pcb, const ip_addr_t *client_ip, uint16_t client_port,
    const ip_addr_t *src_ip, uint16_t src_port, HevSocks5 *base);

#ifdef __cplusplus
}
#endif

#endif /* __HEV_DNS_LATENCY_H__ */
