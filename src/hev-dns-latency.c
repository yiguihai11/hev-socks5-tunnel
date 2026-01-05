/*
 ============================================================================
 Name        : hev-dns-latency.c
 Author      : AI Assistant
 Copyright   : Copyright (c) 2025
 Description : DNS Response Latency Optimization (IPv4/IPv6)
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <hev-memory-allocator.h>
#include <hev-task.h>
#include <hev-task-io.h>
#include <hev-task-io-socket.h>
#include <hev-socks5.h>
#include <lwip/pbuf.h>

#include "hev-logger.h"
#include "hev-config.h"
#include "hev-dns-cache.h"
#include "hev-dns-latency.h"

/* Ping command availability (-1=unknown, 0=not available, 1=available) */
static int ping_ipv4_available = -1;
static int ping_ipv6_available = -1;

/* Module state */
static int dns_latency_initialized = 0;
static int dns_latency_shutdown = 0;

/* Task tracking */
#define MAX_TASKS 64
static struct
{
    HevTask *task;
    int active;
} dns_latency_tasks[MAX_TASKS];
static int dns_latency_task_count = 0;

/* Mutex for task list access (simple spinlock since we use hev-task) */
static int dns_latency_task_lock = 0;

/* DNS header structure */
typedef struct
{
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__ ((packed)) DNSHeader;

/* Simple spinlock for task list */
static inline void
task_lock (void)
{
    while (__atomic_test_and_set (&dns_latency_task_lock, __ATOMIC_ACQUIRE))
        hev_task_yield (HEV_TASK_YIELD);
}

static inline void
task_unlock (void)
{
    __atomic_clear (&dns_latency_task_lock, __ATOMIC_RELEASE);
}

/* Add task to tracking list */
static int
add_task (HevTask *task)
{
    int i;
    task_lock ();
    for (i = 0; i < MAX_TASKS; i++) {
        if (!dns_latency_tasks[i].active) {
            dns_latency_tasks[i].task = task;
            dns_latency_tasks[i].active = 1;
            dns_latency_task_count++;
            task_unlock ();
            LOG_D ("dns-latency: Added task %p to tracking list (count=%d)",
                   task, dns_latency_task_count);
            return 0;
        }
    }
    task_unlock ();
    LOG_W ("dns-latency: Task tracking list full!");
    return -1;
}

/* Remove task from tracking list */
static void
remove_task (HevTask *task)
{
    int i;
    task_lock ();
    for (i = 0; i < MAX_TASKS; i++) {
        if (dns_latency_tasks[i].active && dns_latency_tasks[i].task == task) {
            dns_latency_tasks[i].active = 0;
            dns_latency_tasks[i].task = NULL;
            dns_latency_task_count--;
            task_unlock ();
            LOG_D ("dns-latency: Removed task %p from tracking list (count=%d)",
                   task, dns_latency_task_count);
            return;
        }
    }
    task_unlock ();
    LOG_W ("dns-latency: Task %p not found in tracking list", task);
}

/* Check if shutdown is requested */
static inline int
is_shutdown (void)
{
    return __atomic_load_n (&dns_latency_shutdown, __ATOMIC_ACQUIRE);
}

/* Helper: read big-endian uint16 */
static inline uint16_t
read_uint16 (const uint8_t *p)
{
    return (p[0] << 8) | p[1];
}

/* Helper: read big-endian uint32 */
static inline uint32_t
read_uint32 (const uint8_t *p)
{
    return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

/* Parse DNS name with compression pointer support */
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

        /* Compression pointer */
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

        /* End marker */
        if (len == 0) {
            if (!jumped)
                *offset = pos + 1;
            else
                *offset = jump_pos;
            name_out[name_len] = '\0';
            return 0;
        }

        /* Label */
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

/* Extract TTL from DNS response */
static uint32_t
extract_dns_ttl (const uint8_t *data, size_t len)
{
    if (len < sizeof (DNSHeader))
        return 300; /* Default 5 minutes */

    DNSHeader *hdr = (DNSHeader *)data;
    uint16_t ancount = ntohs (hdr->ancount);

    if (ancount == 0)
        return 300;

    size_t pos = sizeof (DNSHeader);
    uint16_t qdcount = ntohs (hdr->qdcount);

    /* Skip query section */
    for (int i = 0; i < qdcount && pos < len; i++) {
        char domain[256];
        if (parse_dns_name (data, len, &pos, domain, sizeof (domain)) < 0)
            return 300;
        if (pos + 4 > len)
            return 300;
        pos += 4;
    }

    /* Read first answer TTL */
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

int
hev_dns_latency_init (void)
{
    FILE *fp;
    int ret;

    /* Initialize module state */
    dns_latency_initialized = 0;
    dns_latency_shutdown = 0;
    dns_latency_task_count = 0;
    memset (dns_latency_tasks, 0, sizeof (dns_latency_tasks));

    /* Detect if 'ping' command exists for IPv4
     * Execute 'ping -h' and check exit status:
     * - 0 or 2 = command exists (2 means invalid usage, but command exists)
     * - 127 = command not found
     */
    fp = popen ("ping -h 2>&1 || true", "r");
    if (fp) {
        ret = pclose (fp);
        if (ret != 127) {
            ping_ipv4_available = 1;
            LOG_I ("dns-latency: ping command available for IPv4");
        } else {
            ping_ipv4_available = 0;
            LOG_W (
                "dns-latency: ping command NOT available for IPv4, ICMP testing disabled");
        }
    } else {
        ping_ipv4_available = 0;
        LOG_W (
            "dns-latency: ping command NOT available for IPv4, ICMP testing disabled");
    }

    /* Detect if 'ping6' command exists for IPv6 */
    fp = popen ("ping6 -h 2>&1 || true", "r");
    if (fp) {
        ret = pclose (fp);
        if (ret != 127) {
            ping_ipv6_available = 1;
            LOG_I ("dns-latency: ping6 command available for IPv6");
        } else {
            ping_ipv6_available = 0;
            LOG_W (
                "dns-latency: ping6 command NOT available for IPv6, ICMP testing disabled");
        }
    } else {
        ping_ipv6_available = 0;
        LOG_W (
            "dns-latency: ping6 command NOT available for IPv6, ICMP testing disabled");
    }

    dns_latency_initialized = 1;
    LOG_I ("dns-latency: DNS latency optimization module initialized");
    return 0;
}

void
hev_dns_latency_fini (void)
{
    int i;
    int wait_count = 0;
    int total_wait_ms = 0;
    const int max_wait_ms = 5000; /* Wait max 5 seconds */

    if (!dns_latency_initialized) {
        return;
    }

    /* Signal shutdown */
    __atomic_store_n (&dns_latency_shutdown, 1, __ATOMIC_RELEASE);
    LOG_I (
        "dns-latency: Shutdown signaled, waiting for %d active tasks to complete",
        dns_latency_task_count);

    /* Wait for all tasks to complete */
    while (dns_latency_task_count > 0 && total_wait_ms < max_wait_ms) {
        /* Check each task and join if active */
        task_lock ();
        for (i = 0; i < MAX_TASKS; i++) {
            if (dns_latency_tasks[i].active && dns_latency_tasks[i].task) {
                HevTask *task = dns_latency_tasks[i].task;
                task_unlock ();

                LOG_D ("dns-latency: Joining task %p...", task);
                hev_task_join (task);
                hev_task_unref (task);
                wait_count++;

                task_lock ();
                /* Task should have removed itself from list, but verify */
                if (dns_latency_tasks[i].active) {
                    dns_latency_tasks[i].active = 0;
                    dns_latency_tasks[i].task = NULL;
                    dns_latency_task_count--;
                }
                task_unlock ();

                hev_task_yield (
                    HEV_TASK_YIELD); /* Give other tasks chance to exit */
                break; /* Start over since list changed */
            }
        }
        task_unlock ();

        if (dns_latency_task_count > 0) {
            hev_task_sleep (100); /* Sleep 100ms */
            total_wait_ms += 100;
        }
    }

    if (dns_latency_task_count > 0) {
        LOG_W (
            "dns-latency: %d tasks still active after %d ms shutdown timeout",
            dns_latency_task_count, total_wait_ms);
    } else {
        LOG_I ("dns-latency: All %d tasks completed during shutdown",
               wait_count);
    }

    dns_latency_initialized = 0;
    LOG_I ("dns-latency: DNS latency optimization module finalized");
}

int
hev_dns_latency_extract_ips (const uint8_t *data, size_t len,
                             ip_addr_t *ips_out, int max_ips,
                             int *ipv4_count_out, int *ipv6_count_out)
{
    if (len < sizeof (DNSHeader) || !ips_out || max_ips <= 0)
        return -1;

    DNSHeader *hdr = (DNSHeader *)data;
    uint16_t ancount = ntohs (hdr->ancount);

    if (ancount == 0)
        return 0;

    int count = 0;
    int ipv4_count = 0;
    int ipv6_count = 0;

    /* Skip query section */
    size_t pos = sizeof (DNSHeader);
    uint16_t qdcount = ntohs (hdr->qdcount);

    for (int i = 0; i < qdcount && pos < len; i++) {
        char domain[256];
        if (parse_dns_name (data, len, &pos, domain, sizeof (domain)) < 0)
            return -1;
        if (pos + 4 > len)
            return -1;
        pos += 4; /* QTYPE + QCLASS */
    }

    /* Parse answer section */
    for (int i = 0; i < ancount && pos < len && count < max_ips; i++) {
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

        /* A record (IPv4) */
        if (rtype == DNS_TYPE_A && rdlen == 4) {
            ip_addr_t ip;
            IP_ADDR4 (&ip, data[pos], data[pos + 1], data[pos + 2],
                      data[pos + 3]);
            ips_out[count++] = ip;
            ipv4_count++;
            LOG_D ("dns-latency: Extracted IPv4: %s", ipaddr_ntoa (&ip));
        }
        /* AAAA record (IPv6) */
        else if (rtype == DNS_TYPE_AAAA && rdlen == 16) {
            ip_addr_t ip;
            memcpy (ip_2_ip6 (&ip)->addr, data + pos, 16);
            ip.type = IPADDR_TYPE_V6;
            ips_out[count++] = ip;
            ipv6_count++;
            LOG_D ("dns-latency: Extracted IPv6: %s", ipaddr_ntoa (&ip));
        }

        pos += rdlen;
    }

    if (ipv4_count_out)
        *ipv4_count_out = ipv4_count;
    if (ipv6_count_out)
        *ipv6_count_out = ipv6_count;

    LOG_I ("dns-latency: Extracted %d IPs (%d IPv4, %d IPv6)", count,
           ipv4_count, ipv6_count);

    return count;
}

int
hev_dns_latency_modify_response (uint8_t *data, size_t *len,
                                 const ip_addr_t *best_ip)
{
    if (!data || !len || !best_ip || *len < sizeof (DNSHeader))
        return -1;

    DNSHeader *hdr = (DNSHeader *)data;
    uint16_t ancount = ntohs (hdr->ancount);

    if (ancount == 0)
        return 0;

    /* Skip query section */
    size_t pos = sizeof (DNSHeader);
    uint16_t qdcount = ntohs (hdr->qdcount);

    for (int i = 0; i < qdcount && pos < *len; i++) {
        char domain[256];
        if (parse_dns_name (data, *len, &pos, domain, sizeof (domain)) < 0)
            return -1;
        if (pos + 4 > *len)
            return -1;
        pos += 4;
    }

    /* Find and keep only the best IP */
    size_t first_answer_pos = pos;
    size_t best_answer_start = 0;
    size_t best_answer_len = 0;
    int found = 0;

    for (int i = 0; i < ancount && pos < *len; i++) {
        size_t answer_start = pos;
        char domain[256];
        if (parse_dns_name (data, *len, &pos, domain, sizeof (domain)) < 0)
            break;

        if (pos + 10 > *len)
            break;

        uint16_t rtype = read_uint16 (data + pos);
        uint16_t rdlen = read_uint16 (data + pos + 8);
        pos += 10;

        if (pos + rdlen > *len)
            break;

        /* Check if this answer matches best_ip */
        int match = 0;
        if (IP_IS_V4 (best_ip) && rtype == DNS_TYPE_A && rdlen == 4) {
            ip_addr_t ip;
            IP_ADDR4 (&ip, data[pos], data[pos + 1], data[pos + 2],
                      data[pos + 3]);
            if (ip_addr_cmp (&ip, best_ip))
                match = 1;
        } else if (IP_IS_V6 (best_ip) && rtype == DNS_TYPE_AAAA &&
                   rdlen == 16) {
            ip_addr_t ip;
            memset (&ip, 0, sizeof (ip));
            memcpy (ip_2_ip6 (&ip)->addr, data + pos, 16);
            ip.type = IPADDR_TYPE_V6;
            if (ip_addr_cmp (&ip, best_ip))
                match = 1;
        }

        if (match) {
            best_answer_start = answer_start;
            best_answer_len = (pos + rdlen) - answer_start;
            found = 1;
            break;
        }

        pos += rdlen;
    }

    if (!found) {
        LOG_W ("dns-latency: Best IP not found in DNS response");
        return -1;
    }

    /* Move the best answer to replace all answers */
    if (best_answer_start > first_answer_pos) {
        memmove (data + first_answer_pos, data + best_answer_start,
                 best_answer_len);
    }

    /* Update length and ancount */
    *len = first_answer_pos + best_answer_len;
    hdr->ancount = htons (1);

    LOG_I ("dns-latency: Modified DNS response to keep only %s (len=%zu)",
           ipaddr_ntoa (best_ip), *len);

    return 0;
}

static int
tcp_connect_test (const ip_addr_t *ip, uint16_t port, int64_t *latency_us_out)
{
    int sock = -1;
    int ret = -1;
    struct timespec start_time, end_time;

    /* Create socket based on IP type */
    int family = IP_IS_V6 (ip) ? AF_INET6 : AF_INET;
    sock = socket (family, SOCK_STREAM, 0);
    if (sock < 0) {
        LOG_D ("dns-latency: Failed to create socket: %s", strerror (errno));
        return -1;
    }

    /* Set non-blocking */
    int flags = fcntl (sock, F_GETFL, 0);
    fcntl (sock, F_SETFL, flags | O_NONBLOCK);

    /* Build address */
    struct sockaddr_storage addr;
    memset (&addr, 0, sizeof (addr));
    if (IP_IS_V6 (ip)) {
        struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&addr;
        a6->sin6_family = AF_INET6;
        a6->sin6_port = htons (port);
        memcpy (&a6->sin6_addr, ip_2_ip6 (ip)->addr, 16);
    } else {
        struct sockaddr_in *a4 = (struct sockaddr_in *)&addr;
        a4->sin_family = AF_INET;
        a4->sin_port = htons (port);
        a4->sin_addr.s_addr = ip_2_ip4 (ip)->addr;
    }

    /* Start timing */
    clock_gettime (CLOCK_MONOTONIC, &start_time);

    /* Connect */
    int connect_ret = connect (sock, (struct sockaddr *)&addr,
                               IP_IS_V6 (ip) ? sizeof (struct sockaddr_in6) :
                                               sizeof (struct sockaddr_in));

    if (connect_ret < 0 && errno != EINPROGRESS) {
        LOG_D ("dns-latency: TCP connect to %s:%d failed: %s", ipaddr_ntoa (ip),
               port, strerror (errno));
        goto cleanup;
    }

    /* Wait for connection with timeout */
    struct pollfd pfd;
    pfd.fd = sock;
    pfd.events = POLLOUT;

    int poll_ret = poll (&pfd, 1, 500); /* 500ms timeout per port */
    if (poll_ret <= 0) {
        LOG_D ("dns-latency: TCP connect to %s:%d timeout/no event",
               ipaddr_ntoa (ip), port);
        goto cleanup;
    }

    /* Check for errors */
    int error = 0;
    socklen_t len = sizeof (error);
    if (getsockopt (sock, SOL_SOCKET, SO_ERROR, &error, &len) < 0 ||
        error != 0) {
        LOG_D ("dns-latency: TCP connect to %s:%d failed: %s", ipaddr_ntoa (ip),
               port, strerror (error));
        goto cleanup;
    }

    /* Calculate latency */
    clock_gettime (CLOCK_MONOTONIC, &end_time);
    *latency_us_out = (end_time.tv_sec - start_time.tv_sec) * 1000000 +
                      (end_time.tv_nsec - start_time.tv_nsec) / 1000;

    LOG_I ("dns-latency: TCP connect to %s:%d succeeded, latency=%lld us",
           ipaddr_ntoa (ip), port, (long long)*latency_us_out);

    ret = 0;

cleanup:
    if (sock >= 0)
        close (sock);
    return ret;
}

static int
icmp_ping_test (const ip_addr_t *ip, int64_t *latency_us_out)
{
    /* Use system ping command instead of raw socket (requires root) */
    char ip_str[INET6_ADDRSTRLEN];
    char cmd[256];
    struct timespec start_time, end_time;
    int ret;
    FILE *fp;

    /* Check if shutdown is in progress - skip ping during shutdown */
    if (is_shutdown ()) {
        LOG_D ("dns-latency: Shutdown in progress, skipping ICMP ping");
        return -1;
    }

    /* Check if ping command is available */
    if (IP_IS_V6 (ip)) {
        if (ping_ipv6_available == 0) {
            LOG_D (
                "dns-latency: ping6 not available, skipping ICMP test for IPv6");
            return -1;
        }
    } else {
        if (ping_ipv4_available == 0) {
            LOG_D (
                "dns-latency: ping not available, skipping ICMP test for IPv4");
            return -1;
        }
    }

    ipaddr_ntoa_r (ip, ip_str, sizeof (ip_str));

    /* Build ping command:
     * - ping -c 1 -W 1 <IPv4> for IPv4 addresses
     * - ping6 -c 1 -W 1 <IPv6> for IPv6 addresses
     * Note: Add -W 1 (1 second timeout) to prevent hanging
     */
    if (IP_IS_V6 (ip)) {
        snprintf (cmd, sizeof (cmd), "ping6 -c 1 -W 1 %s", ip_str);
    } else {
        snprintf (cmd, sizeof (cmd), "ping -c 1 -W 1 %s", ip_str);
    }

    LOG_D ("dns-latency: Running ICMP ping: %s", cmd);

    /* Start timing */
    clock_gettime (CLOCK_MONOTONIC, &start_time);

    /* Execute ping command */
    fp = popen (cmd, "r");
    if (!fp) {
        LOG_D ("dns-latency: Failed to execute ping command: %s",
               strerror (errno));
        return -1;
    }

    /* Read output with shutdown check
     * Check shutdown periodically to avoid blocking on slow popen */
    char buffer[256];
    int line_count = 0;
    while (fgets (buffer, sizeof (buffer), fp) != NULL) {
        /* Check shutdown every few lines */
        if (++line_count % 10 == 0 && is_shutdown ()) {
            LOG_W ("dns-latency: Shutdown during ping, aborting");
            pclose (fp); /* Clean up the pipe */
            return -1;
        }
    }

    ret = pclose (fp);

    /* End timing */
    clock_gettime (CLOCK_MONOTONIC, &end_time);

    /* Check exit status */
    if (ret == 0) {
        *latency_us_out = (end_time.tv_sec - start_time.tv_sec) * 1000000 +
                          (end_time.tv_nsec - start_time.tv_nsec) / 1000;
        LOG_I ("dns-latency: ICMP ping to %s succeeded, latency=%lld us",
               ip_str, (long long)*latency_us_out);
        return 0;
    }

    LOG_D ("dns-latency: ICMP ping to %s failed (exit=%d)", ip_str, ret);
    return -1;
}

int
hev_dns_latency_test_ip (const ip_addr_t *ip, DnsLatencyResult *result_out,
                         int timeout_ms)
{
    if (!ip || !result_out)
        return -1;

    memset (result_out, 0, sizeof (DnsLatencyResult));
    ip_addr_copy (result_out->ip, *ip);

    /* Try TCP 443 first */
    if (tcp_connect_test (ip, 443, &result_out->latency_us) == 0) {
        result_out->method = DNS_LATENCY_METHOD_TCP443;
        result_out->success = 1;
        return 0;
    }

    /* Try TCP 80 */
    if (tcp_connect_test (ip, 80, &result_out->latency_us) == 0) {
        result_out->method = DNS_LATENCY_METHOD_TCP80;
        result_out->success = 1;
        return 0;
    }

    /* Try ICMP ping */
    if (icmp_ping_test (ip, &result_out->latency_us) == 0) {
        result_out->method = DNS_LATENCY_METHOD_ICMP;
        result_out->success = 1;
        return 0;
    }

    LOG_W ("dns-latency: All latency tests failed for %s", ipaddr_ntoa (ip));
    result_out->success = 0;
    return -1;
}

int
hev_dns_latency_test_ip_all (const ip_addr_t *ip, DnsLatencyResult *results_out,
                             int timeout_ms)
{
    if (!ip || !results_out)
        return -1;

    /* Test TCP 443 */
    memset (&results_out[0], 0, sizeof (DnsLatencyResult));
    ip_addr_copy (results_out[0].ip, *ip);
    results_out[0].method = DNS_LATENCY_METHOD_TCP443;
    if (tcp_connect_test (ip, 443, &results_out[0].latency_us) == 0) {
        results_out[0].success = 1;
    } else {
        results_out[0].success = 0;
        results_out[0].latency_us = -1;
    }

    /* Test TCP 80 */
    memset (&results_out[1], 0, sizeof (DnsLatencyResult));
    ip_addr_copy (results_out[1].ip, *ip);
    results_out[1].method = DNS_LATENCY_METHOD_TCP80;
    if (tcp_connect_test (ip, 80, &results_out[1].latency_us) == 0) {
        results_out[1].success = 1;
    } else {
        results_out[1].success = 0;
        results_out[1].latency_us = -1;
    }

    /* Test ICMP ping */
    memset (&results_out[2], 0, sizeof (DnsLatencyResult));
    ip_addr_copy (results_out[2].ip, *ip);
    results_out[2].method = DNS_LATENCY_METHOD_ICMP;
    if (icmp_ping_test (ip, &results_out[2].latency_us) == 0) {
        results_out[2].success = 1;
    } else {
        results_out[2].success = 0;
        results_out[2].latency_us = -1;
    }

    return 0;
}

/* Context for async optimization task */
typedef struct _DnsLatencyOptimizeContext
{
    uint8_t *response_data;
    size_t response_len;
    char domain[256];
    struct udp_pcb *pcb;
    ip_addr_t client_ip;
    uint16_t client_port;
    HevSocks5 *base;
} DnsLatencyOptimizeContext;

/* Async optimization task */
static void
dns_latency_optimize_task (void *data)
{
    DnsLatencyOptimizeContext *ctx = (DnsLatencyOptimizeContext *)data;
    ip_addr_t ips[32]; /* Max 32 IPs */
    DnsLatencyResult results[32];
    int ip_count;
    int best_tcp_idx = -1;
    int64_t best_tcp_latency = INT64_MAX;
    int tcp_success_count = 0;
    HevTask *self = hev_task_self ();

    /* Register this task */
    hev_task_ref (self);
    if (add_task (self) < 0) {
        hev_task_unref (self);
        goto cleanup;
    }

    LOG_I ("dns-latency: Starting latency optimization for domain: %s",
           ctx->domain);

    /* Check if shutdown was requested */
    if (is_shutdown ()) {
        LOG_W ("dns-latency: Shutdown requested, skipping optimization for %s",
               ctx->domain);
        goto send_response;
    }

    /* Extract all IPs */
    int ipv4_count, ipv6_count;
    ip_count = hev_dns_latency_extract_ips (ctx->response_data,
                                            ctx->response_len, ips, 32,
                                            &ipv4_count, &ipv6_count);

    if (ip_count <= 0) {
        LOG_W ("dns-latency: No IPs extracted from DNS response for %s",
               ctx->domain);
        goto cleanup;
    }

    if (ip_count == 1) {
        LOG_I ("dns-latency: Only 1 IP in response, no optimization needed: %s",
               ipaddr_ntoa (&ips[0]));
        /* Still cache the response for consistency */
        uint32_t ttl = extract_dns_ttl (ctx->response_data, ctx->response_len);
        hev_dns_cache_insert (ctx->domain, ctx->response_data,
                              ctx->response_len, ttl, 0);
        goto send_response;
    }

    /* First round: Test TCP latency for all IPs */
    int timeout_ms = hev_config_get_dns_latency_timeout_ms ();
    int per_ip_timeout = timeout_ms / ip_count;

    LOG_I ("dns-latency: Testing TCP latency for %d IPs (timeout=%dms each)",
           ip_count, per_ip_timeout);

    for (int i = 0; i < ip_count; i++) {
        /* Check shutdown before each test */
        if (is_shutdown ()) {
            LOG_W (
                "dns-latency: Shutdown requested during testing, using best result so far for %s",
                ctx->domain);
            break;
        }

        if (hev_dns_latency_test_ip (&ips[i], &results[i], per_ip_timeout) ==
            0) {
            if (results[i].success &&
                results[i].method <= DNS_LATENCY_METHOD_TCP80) {
                /* TCP test successful (443 or 80) */
                tcp_success_count++;
                if (results[i].latency_us < best_tcp_latency) {
                    best_tcp_latency = results[i].latency_us;
                    best_tcp_idx = i;
                }
                LOG_I ("dns-latency: IP %s TCP latency=%lld us (port=%d)",
                       ipaddr_ntoa (&ips[i]), (long long)results[i].latency_us,
                       results[i].method == DNS_LATENCY_METHOD_TCP443 ? 443 :
                                                                        80);
            }
        }
    }

    int best_idx = -1;
    int64_t best_latency = INT64_MAX;

    if (tcp_success_count > 0) {
        /* Use best TCP result */
        best_idx = best_tcp_idx;
        best_latency = best_tcp_latency;
        LOG_I ("dns-latency: Using best TCP result: %s with latency=%lld us",
               ipaddr_ntoa (&ips[best_idx]), (long long)best_latency);
    } else {
        /* All TCP tests failed, try ICMP ping */
        LOG_W ("dns-latency: All TCP tests failed, trying ICMP ping...");

        for (int i = 0; i < ip_count; i++) {
            /* Check shutdown before each test */
            if (is_shutdown ()) {
                LOG_W (
                    "dns-latency: Shutdown requested during ICMP testing, using best result so far for %s",
                    ctx->domain);
                break;
            }

            if (hev_dns_latency_test_ip (&ips[i], &results[i],
                                         per_ip_timeout) == 0) {
                if (results[i].success &&
                    results[i].method == DNS_LATENCY_METHOD_ICMP) {
                    if (results[i].latency_us < best_latency) {
                        best_latency = results[i].latency_us;
                        best_idx = i;
                    }
                    LOG_I ("dns-latency: IP %s ICMP latency=%lld us",
                           ipaddr_ntoa (&ips[i]),
                           (long long)results[i].latency_us);
                }
            }
        }
    }

    if (best_idx < 0) {
        LOG_W (
            "dns-latency: No reachable IP found for %s, sending original response",
            ctx->domain);
        goto send_response;
    }

    LOG_I ("dns-latency: Best IP for %s is %s with latency=%lld us",
           ctx->domain, ipaddr_ntoa (&ips[best_idx]), (long long)best_latency);

    /* Modify DNS response to keep only the best IP */
    uint8_t *modified_response = hev_malloc (ctx->response_len);
    if (!modified_response) {
        LOG_E ("dns-latency: Failed to allocate buffer for modified response");
        goto send_response;
    }

    memcpy (modified_response, ctx->response_data, ctx->response_len);
    size_t modified_len = ctx->response_len;

    if (hev_dns_latency_modify_response (modified_response, &modified_len,
                                         &ips[best_idx]) == 0) {
        /* Cache the optimized response */
        uint32_t ttl = extract_dns_ttl (modified_response, modified_len);
        hev_dns_cache_insert (ctx->domain, modified_response, modified_len, ttl,
                              0);

        /* Send optimized response */
        struct pbuf *p = pbuf_alloc (PBUF_TRANSPORT, modified_len, PBUF_RAM);
        if (p) {
            memcpy (p->payload, modified_response, modified_len);
            udp_sendto (ctx->pcb, p, &ctx->client_ip, ctx->client_port);
            pbuf_free (p);
            LOG_I (
                "dns-latency: Sent optimized DNS response to client (%zu bytes)",
                modified_len);
        }

        hev_free (modified_response);
    } else {
        hev_free (modified_response);
        goto send_response;
    }

    goto cleanup;

send_response:
    /* Send original response if optimization failed */
    {
        struct pbuf *p =
            pbuf_alloc (PBUF_TRANSPORT, ctx->response_len, PBUF_RAM);
        if (p) {
            memcpy (p->payload, ctx->response_data, ctx->response_len);
            udp_sendto (ctx->pcb, p, &ctx->client_ip, ctx->client_port);
            pbuf_free (p);
            LOG_I (
                "dns-latency: Sent original DNS response to client (%zu bytes)",
                ctx->response_len);
        }
    }

cleanup:
    /* Remove task from tracking list */
    remove_task (self);
    hev_task_unref (self);

    if (ctx->response_data)
        hev_free (ctx->response_data);
    hev_object_unref (HEV_OBJECT (ctx->base));
    hev_free (ctx);

    LOG_I ("dns-latency: Optimization task finished for domain: %s",
           ctx->domain);
}

int
hev_dns_latency_optimize_response_async (const uint8_t *response_data,
                                         size_t response_len,
                                         const char *domain,
                                         struct udp_pcb *pcb,
                                         const ip_addr_t *client_ip,
                                         uint16_t client_port, HevSocks5 *base)
{
    if (!response_data || response_len == 0 || !domain || !pcb || !client_ip ||
        !base) {
        LOG_E ("dns-latency: Invalid parameters for async optimization");
        return -1;
    }

    /* Check if shutdown is in progress */
    if (is_shutdown ()) {
        LOG_D (
            "dns-latency: Shutdown in progress, skipping optimization for %s",
            domain);
        return 0; /* Let caller continue normal flow */
    }

    /* Allocate context */
    DnsLatencyOptimizeContext *ctx =
        hev_malloc0 (sizeof (DnsLatencyOptimizeContext));
    if (!ctx) {
        LOG_E ("dns-latency: Failed to allocate optimization context");
        return -1;
    }

    /* Copy response data */
    ctx->response_data = hev_malloc (response_len);
    if (!ctx->response_data) {
        hev_free (ctx);
        LOG_E ("dns-latency: Failed to allocate response buffer");
        return -1;
    }
    memcpy (ctx->response_data, response_data, response_len);
    ctx->response_len = response_len;

    strncpy (ctx->domain, domain, sizeof (ctx->domain) - 1);
    ctx->pcb = pcb;
    ip_addr_copy (ctx->client_ip, *client_ip);
    ctx->client_port = client_port;
    ctx->base = base;
    hev_object_ref (HEV_OBJECT (base));

    /* Create and run async task */
    int stack_size = hev_config_get_misc_task_stack_size ();
    HevTask *task = hev_task_new (stack_size);
    if (!task) {
        hev_free (ctx->response_data);
        hev_object_unref (HEV_OBJECT (base));
        hev_free (ctx);
        LOG_E ("dns-latency: Failed to create optimization task");
        return 0; /* Return 0 to let caller continue normal flow */
    }

    hev_task_run (task, dns_latency_optimize_task, ctx);
    LOG_I ("dns-latency: Started async optimization task for domain: %s",
           domain);

    return 1; /* Return 1 to indicate async task started */
}
