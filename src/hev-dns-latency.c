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
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <hev-memory-allocator.h>
#include <hev-task.h>
#include <hev-task-mutex.h>
#include <hev-task-cond.h>
#include <hev-task-io.h>
#include <hev-task-io-socket.h>
#include <hev-socks5.h>
#include <lwip/pbuf.h>

#include "hev-logger.h"
#include "hev-config.h"
#include "hev-dns-cache.h"
#include "hev-dns-latency.h"
#include "hev-socks5-tunnel.h"

/* Ping command availability (-1=unknown, 0=not available, 1=available) */
static int ping_ipv4_available = -1;
static int ping_ipv6_available = -1;

/* Module state */
static volatile int dns_latency_initialized = 0;
static volatile int dns_latency_shutdown = 0;

/* 测试阶段 */
typedef enum
{
    TEST_STAGE_TCP443 = 0,
    TEST_STAGE_TCP80 = 1,
    TEST_STAGE_ICMP = 2
} TestStage;

/* ⭐ 并发测试上下文（竞争式） */
typedef struct _ConcurrentTestContext
{
    ip_addr_t *ips;
    DnsLatencyResult *results;
    int ip_count;
    int64_t start_time_ms; /* 测试开始时间（毫秒） */
    int64_t timeout_ms; /* 总超时时间（毫秒） */
    volatile int completed_count; /* 已完成的任务数 */
    volatile int should_stop; /* 停止标志 */
    volatile int winner_index; /* 赢家 IP 索引 (-1 表示无赢家） */
    volatile int winner_method; /* 赢家使用的方法 (TCP443/TCP80/ICMP) */
    HevTaskMutex mutex;
    HevTaskCond cond;
} ConcurrentTestContext;

/* ⭐ 单IP测试任务参数 */
typedef struct _SingleIPTestParam
{
    ConcurrentTestContext *ctx;
    int ip_index;
} SingleIPTestParam;

/* Task tracking */
#define MAX_TASKS 64
static struct
{
    HevTask *task;
    int active;
} dns_latency_tasks[MAX_TASKS];
static int dns_latency_task_count = 0;

/* Mutex for task list access - using pthread_mutex for compatibility */
static pthread_mutex_t dns_latency_task_mutex = PTHREAD_MUTEX_INITIALIZER;

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

/* Simple mutex lock for task list */
static inline void
task_lock (void)
{
    pthread_mutex_lock (&dns_latency_task_mutex);
}

static inline void
task_unlock (void)
{
    pthread_mutex_unlock (&dns_latency_task_mutex);
}

/* Add task to tracking list */
static int
add_task (HevTask *task)
{
    int i;
    task_lock ();
    for (i = 0; i < MAX_TASKS; i++) {
        if (!dns_latency_tasks[i].active) {
            dns_latency_tasks[i].task = hev_task_ref (task);
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
            HevTask *t = dns_latency_tasks[i].task;
            dns_latency_tasks[i].active = 0;
            dns_latency_tasks[i].task = NULL;
            dns_latency_task_count--;
            task_unlock ();
            hev_task_unref (t);
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
    return dns_latency_shutdown;
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

/* Helper: get current time in milliseconds */
static inline int64_t
get_time_ms (void)
{
    struct timespec ts;
    clock_gettime (CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
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
    int max_wait_ms;

    if (!dns_latency_initialized) {
        return;
    }

    /* Calculate max wait time: config timeout + 500ms buffer */
    max_wait_ms = hev_config_get_dns_latency_timeout_ms () + 500;

    /* Signal shutdown */
    dns_latency_shutdown = 1;
    LOG_I (
        "dns-latency: Shutdown signaled, waiting for %d active tasks to complete",
        dns_latency_task_count);

    /* Wait for all tasks to complete */
    while (dns_latency_task_count > 0 && total_wait_ms < max_wait_ms) {
        /* Check each task and join if active */
        task_lock ();
        for (i = 0; i < MAX_TASKS; i++) {
            if (dns_latency_tasks[i].active && dns_latency_tasks[i].task) {
                HevTask *task = hev_task_ref (dns_latency_tasks[i].task);
                task_unlock ();

                LOG_D ("dns-latency: Joining task %p...", task);
                hev_task_join (task);
                hev_task_unref (task);
                wait_count++;

                task_lock ();
                /* Task should have removed itself from list via remove_task,
                 * but if it didn't (e.g. error before cleanup), we do it here.
                 */
                if (dns_latency_tasks[i].active &&
                    dns_latency_tasks[i].task == task) {
                    HevTask *t = dns_latency_tasks[i].task;
                    dns_latency_tasks[i].active = 0;
                    dns_latency_tasks[i].task = NULL;
                    dns_latency_task_count--;
                    task_unlock ();
                    hev_task_unref (t);
                    task_lock ();
                }
                task_unlock ();

                hev_task_yield (
                    HEV_TASK_YIELD); /* Give other tasks chance to exit */
                task_lock ();
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

    /* 显示所有提取到的 IP 地址列表（INFO 级别） */
    if (count > 0) {
        char ip_list[512] = { 0 };
        int offset = 0;
        for (int i = 0; i < count && offset < (int)sizeof (ip_list) - 20; i++) {
            offset += snprintf (ip_list + offset, sizeof (ip_list) - offset,
                                "%s%s", i > 0 ? ", " : "",
                                ipaddr_ntoa (&ips_out[i]));
        }
        LOG_I ("dns-latency: IP list: [%s]", ip_list);
    }

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

    /* 遍历所有Answer，找到目标IP并统计 */
    int target_answer_count = 0; /* 目标Answer之前需要保留的Answer数量 */
    int found = 0;

    for (int i = 0; i < ancount && pos < *len; i++) {
        char domain[256];
        size_t answer_start = pos;

        if (parse_dns_name (data, *len, &pos, domain, sizeof (domain)) < 0)
            break;

        if (pos + 10 > *len)
            break;

        uint16_t rtype = read_uint16 (data + pos);
        uint16_t rdlen = read_uint16 (data + pos + 8);
        pos += 10;

        if (pos + rdlen > *len)
            break;

        /* 检查是否匹配目标IP */
        int is_target = 0;
        if (IP_IS_V4 (best_ip) && rtype == DNS_TYPE_A && rdlen == 4) {
            ip_addr_t ip;
            IP_ADDR4 (&ip, data[pos], data[pos + 1], data[pos + 2],
                      data[pos + 3]);
            if (ip_addr_cmp (&ip, best_ip)) {
                is_target = 1;
                found = 1;
            }
        } else if (IP_IS_V6 (best_ip) && rtype == DNS_TYPE_AAAA &&
                   rdlen == 16) {
            ip_addr_t ip;
            memset (&ip, 0, sizeof (ip));
            memcpy (ip_2_ip6 (&ip)->addr, data + pos, 16);
            ip.type = IPADDR_TYPE_V6;
            if (ip_addr_cmp (&ip, best_ip)) {
                is_target = 1;
                found = 1;
            }
        }

        /* 如果是CNAME，需要保留 */
        if (rtype == DNS_TYPE_CNAME) {
            target_answer_count++;
        }

        /* 如果是目标IP，记录位置并停止 */
        if (is_target) {
            /* 简单方案：记录目标Answer的结束位置 */
            *len = answer_start + 10 + rdlen; /* Answer开始 + 头部 + 数据 */
            hdr->ancount = htons (target_answer_count + 1);
            break;
        }

        pos += rdlen;
    }

    if (!found) {
        LOG_W ("dns-latency: Best IP not found in DNS response");
        return -1;
    }

    LOG_I ("dns-latency: Modified DNS response, kept %d answers (len=%zu)",
           target_answer_count + 1, *len);

    return 0;
}

/* ⭐ TCP连接测试（带超时控制） */
static int
tcp_connect_test (const ip_addr_t *ip, uint16_t port, int64_t *latency_us_out,
                  int timeout_ms, ConcurrentTestContext *ctx,
                  int initial_failed_count)
{
    int sock = -1;
    int ret = -1;
    struct timespec start_time, end_time;
    int flags;
    struct pollfd pfd;

    (void)ctx; /* 保留参数以保持接口一致 */
    (void)initial_failed_count; /* 保留参数以保持接口一致 */

    /* Create socket based on IP type */
    int family = IP_IS_V6 (ip) ? AF_INET6 : AF_INET;
    sock = socket (family, SOCK_STREAM, 0);
    if (sock < 0) {
        LOG_D ("dns-latency: Failed to create socket: %s", strerror (errno));
        return -1;
    }

    /* 设置为非阻塞模式 */
    flags = fcntl (sock, F_GETFL, 0);
    if (flags < 0 || fcntl (sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        LOG_D ("dns-latency: Failed to set non-blocking: %s", strerror (errno));
        goto cleanup;
    }

    /* Build address */
    struct sockaddr_storage addr;
    memset (&addr, 0, sizeof (addr));
    socklen_t addr_len;
    if (IP_IS_V6 (ip)) {
        struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&addr;
        a6->sin6_family = AF_INET6;
        a6->sin6_port = htons (port);
        memcpy (&a6->sin6_addr, ip_2_ip6 (ip)->addr, 16);
        addr_len = sizeof (struct sockaddr_in6);
    } else {
        struct sockaddr_in *a4 = (struct sockaddr_in *)&addr;
        a4->sin_family = AF_INET;
        a4->sin_port = htons (port);
        a4->sin_addr.s_addr = ip_2_ip4 (ip)->addr;
        addr_len = sizeof (struct sockaddr_in);
    }

    /* Start timing */
    clock_gettime (CLOCK_MONOTONIC, &start_time);

    /* 发起非阻塞connect */
    int connect_ret = connect (sock, (struct sockaddr *)&addr, addr_len);
    if (connect_ret < 0 && errno != EINPROGRESS) {
        LOG_D ("dns-latency: TCP connect to %s:%d failed immediately: %s",
               ipaddr_ntoa (ip), port, strerror (errno));
        goto cleanup;
    }

    /* 等待连接完成（带超时） */
    pfd.fd = sock;
    pfd.events = POLLOUT;
    pfd.revents = 0;

    int poll_ret = poll (&pfd, 1, timeout_ms);
    if (poll_ret <= 0) {
        if (poll_ret == 0) {
            LOG_D ("dns-latency: TCP connect to %s:%d timeout after %dms",
                   ipaddr_ntoa (ip), port, timeout_ms);
        } else {
            LOG_D ("dns-latency: TCP connect poll error: %s", strerror (errno));
        }
        goto cleanup;
    }

    /* 检查连接是否成功 */
    int error = 0;
    socklen_t len = sizeof (error);
    if (getsockopt (sock, SOL_SOCKET, SO_ERROR, &error, &len) < 0 ||
        error != 0) {
        LOG_D ("dns-latency: TCP connect to %s:%d failed: %s", ipaddr_ntoa (ip),
               port, error ? strerror (error) : "unknown");
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
     * - ping -c 1 -W 0.2 <IPv4> for IPv4 addresses
     * - ping6 -c 1 -W 0.2 <IPv6> for IPv6 addresses
     * Note: -W 0.2 (200ms timeout) for ICMP testing
     */
    if (IP_IS_V6 (ip)) {
        snprintf (cmd, sizeof (cmd), "ping6 -c 1 -W 0.2 %s", ip_str);
    } else {
        snprintf (cmd, sizeof (cmd), "ping -c 1 -W 0.2 %s", ip_str);
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
                         int tcp_timeout_ms, int icmp_timeout_ms)
{
    if (!ip || !result_out)
        return -1;

    (void)icmp_timeout_ms; /* ICMP timeout handled separately */

    memset (result_out, 0, sizeof (DnsLatencyResult));
    ip_addr_copy (result_out->ip, *ip);

    /* Initialize all methods as failed */
    result_out->tcp443.success = 0;
    result_out->tcp443.latency_us = -1;
    result_out->tcp80.success = 0;
    result_out->tcp80.latency_us = -1;
    result_out->icmp.success = 0;
    result_out->icmp.latency_us = -1;

    /* Try TCP 443 first */
    if (tcp_connect_test (ip, 443, &result_out->tcp443.latency_us,
                          tcp_timeout_ms, NULL, 0) == 0) {
        result_out->tcp443.success = 1;
        return 0;
    }

    /* Try TCP 80 */
    if (tcp_connect_test (ip, 80, &result_out->tcp80.latency_us, tcp_timeout_ms,
                          NULL, 0) == 0) {
        result_out->tcp80.success = 1;
        return 0;
    }

    /* Try ICMP ping */
    if (icmp_ping_test (ip, &result_out->icmp.latency_us) == 0) {
        result_out->icmp.success = 1;
        return 0;
    }

    LOG_W ("dns-latency: All latency tests failed for %s", ipaddr_ntoa (ip));
    return -1;
}

int
hev_dns_latency_test_ip_all (const ip_addr_t *ip, DnsLatencyResult *results_out,
                             int tcp_timeout_ms, int icmp_timeout_ms)
{
    if (!ip || !results_out)
        return -1;

    (void)icmp_timeout_ms; /* ICMP timeout handled separately */

    /* Test TCP 443 */
    memset (results_out, 0, sizeof (DnsLatencyResult));
    ip_addr_copy (results_out->ip, *ip);
    results_out->tcp443.success = 0;
    results_out->tcp443.latency_us = -1;
    if (tcp_connect_test (ip, 443, &results_out->tcp443.latency_us,
                          tcp_timeout_ms, NULL, 0) == 0) {
        results_out->tcp443.success = 1;
    }

    /* Test TCP 80 */
    results_out->tcp80.success = 0;
    results_out->tcp80.latency_us = -1;
    if (tcp_connect_test (ip, 80, &results_out->tcp80.latency_us,
                          tcp_timeout_ms, NULL, 0) == 0) {
        results_out->tcp80.success = 1;
    }

    /* Test ICMP ping */
    results_out->icmp.success = 0;
    results_out->icmp.latency_us = -1;
    if (icmp_ping_test (ip, &results_out->icmp.latency_us) == 0) {
        results_out->icmp.success = 1;
    }

    return 0;
}

/* ⭐ 单IP竞争式测试任务（依次测试443/80/ICMP，谁先成功赢） */
static void
single_ip_test_task (void *data)
{
    SingleIPTestParam *param = (SingleIPTestParam *)data;
    ConcurrentTestContext *ctx = param->ctx;
    int ip_index = param->ip_index;

    ip_addr_t *ip = &ctx->ips[ip_index];
    DnsLatencyResult *result = &ctx->results[ip_index];

    LOG_D ("dns-latency: [%d] Starting race test for %s", ip_index,
           ipaddr_ntoa (ip));

    /* 初始化结果 */
    memset (result, 0, sizeof (DnsLatencyResult));
    ip_addr_copy (result->ip, *ip);
    result->tcp443.success = 0;
    result->tcp443.latency_us = -1;
    result->tcp80.success = 0;
    result->tcp80.latency_us = -1;
    result->icmp.success = 0;
    result->icmp.latency_us = -1;

    /* ⭐ 测试 TCP443 */
    hev_task_mutex_lock (&ctx->mutex);
    int has_winner = (ctx->winner_index >= 0);
    int64_t elapsed_ms = get_time_ms () - ctx->start_time_ms;
    int is_timeout = (elapsed_ms >= ctx->timeout_ms);
    hev_task_mutex_unlock (&ctx->mutex);

    if (!has_winner && !is_timeout) {
        int64_t remaining_ms =
            ctx->timeout_ms - (get_time_ms () - ctx->start_time_ms);
        if (remaining_ms > 0) {
            LOG_D ("dns-latency: [%d] Testing TCP443 (remaining %lldms)",
                   ip_index, (long long)remaining_ms);

            int test_timeout = (remaining_ms < 1000) ? remaining_ms : 1000;
            if (tcp_connect_test (ip, 443, &result->tcp443.latency_us,
                                  test_timeout, NULL, 0) == 0) {
                result->tcp443.success = 1;
                LOG_I (
                    "dns-latency: [%d] IP %s TCP443 succeeded, latency=%lld us",
                    ip_index, ipaddr_ntoa (ip),
                    (long long)result->tcp443.latency_us);

                /* 尝试成为赢家 */
                hev_task_mutex_lock (&ctx->mutex);
                if (ctx->winner_index < 0) {
                    ctx->winner_index = ip_index;
                    ctx->winner_method = DNS_LATENCY_METHOD_TCP443;
                    LOG_I ("dns-latency: [%d] IP %s became winner via TCP443!",
                           ip_index, ipaddr_ntoa (ip));
                    hev_task_cond_signal (&ctx->cond);
                    hev_task_mutex_unlock (&ctx->mutex);
                    goto done;
                }
                hev_task_mutex_unlock (&ctx->mutex);
            }
        }
    }

    /* ⭐ 测试 TCP80 */
    hev_task_mutex_lock (&ctx->mutex);
    has_winner = (ctx->winner_index >= 0);
    elapsed_ms = get_time_ms () - ctx->start_time_ms;
    is_timeout = (elapsed_ms >= ctx->timeout_ms);
    hev_task_mutex_unlock (&ctx->mutex);

    if (!has_winner && !is_timeout) {
        int64_t remaining_ms =
            ctx->timeout_ms - (get_time_ms () - ctx->start_time_ms);
        if (remaining_ms > 0) {
            LOG_D ("dns-latency: [%d] Testing TCP80 (remaining %lldms)",
                   ip_index, (long long)remaining_ms);

            int test_timeout = (remaining_ms < 1000) ? remaining_ms : 1000;
            if (tcp_connect_test (ip, 80, &result->tcp80.latency_us,
                                  test_timeout, NULL, 0) == 0) {
                result->tcp80.success = 1;
                LOG_I (
                    "dns-latency: [%d] IP %s TCP80 succeeded, latency=%lld us",
                    ip_index, ipaddr_ntoa (ip),
                    (long long)result->tcp80.latency_us);

                hev_task_mutex_lock (&ctx->mutex);
                if (ctx->winner_index < 0) {
                    ctx->winner_index = ip_index;
                    ctx->winner_method = DNS_LATENCY_METHOD_TCP80;
                    LOG_I ("dns-latency: [%d] IP %s became winner via TCP80!",
                           ip_index, ipaddr_ntoa (ip));
                    hev_task_cond_signal (&ctx->cond);
                    hev_task_mutex_unlock (&ctx->mutex);
                    goto done;
                }
                hev_task_mutex_unlock (&ctx->mutex);
            }
        }
    }

    /* ⭐ 测试 ICMP */
    hev_task_mutex_lock (&ctx->mutex);
    has_winner = (ctx->winner_index >= 0);
    elapsed_ms = get_time_ms () - ctx->start_time_ms;
    is_timeout = (elapsed_ms >= ctx->timeout_ms);
    hev_task_mutex_unlock (&ctx->mutex);

    if (!has_winner && !is_timeout) {
        int64_t remaining_ms =
            ctx->timeout_ms - (get_time_ms () - ctx->start_time_ms);
        if (remaining_ms > 0) {
            LOG_D ("dns-latency: [%d] Testing ICMP (remaining %lldms)",
                   ip_index, (long long)remaining_ms);

            if (icmp_ping_test (ip, &result->icmp.latency_us) == 0) {
                result->icmp.success = 1;
                LOG_I (
                    "dns-latency: [%d] IP %s ICMP succeeded, latency=%lld us",
                    ip_index, ipaddr_ntoa (ip),
                    (long long)result->icmp.latency_us);

                hev_task_mutex_lock (&ctx->mutex);
                if (ctx->winner_index < 0) {
                    ctx->winner_index = ip_index;
                    ctx->winner_method = DNS_LATENCY_METHOD_ICMP;
                    LOG_I ("dns-latency: [%d] IP %s became winner via ICMP!",
                           ip_index, ipaddr_ntoa (ip));
                    hev_task_cond_signal (&ctx->cond);
                    hev_task_mutex_unlock (&ctx->mutex);
                    goto done;
                }
                hev_task_mutex_unlock (&ctx->mutex);
            }
        }
    }

    /* 所有测试都失败了 */
    LOG_D ("dns-latency: [%d] IP %s all tests failed", ip_index,
           ipaddr_ntoa (ip));

done:
    /* 通知完成 */
    hev_task_mutex_lock (&ctx->mutex);
    ctx->completed_count++;
    LOG_D ("dns-latency: [%d] Task completed (%d/%d)", ip_index,
           ctx->completed_count, ctx->ip_count);
    hev_task_cond_signal (&ctx->cond);
    hev_task_mutex_unlock (&ctx->mutex);

    /* 释放参数 */
    hev_free (param);
}

/* ⭐ 并发测试多IP（竞争式：谁先成功赢，超时返回原始） */
int
hev_dns_latency_test_concurrent (const ip_addr_t *ips, int ip_count,
                                 DnsLatencyResult *results_out, int timeout_ms)
{
    if (!ips || !results_out || ip_count <= 0 || ip_count > 32)
        return -1;

    ConcurrentTestContext *ctx = hev_malloc0 (sizeof (ConcurrentTestContext));
    if (!ctx)
        return -1;

    HevTask *tasks[32];
    int created_count = 0;

    ctx->ips = (ip_addr_t *)ips;
    ctx->results = results_out;
    ctx->ip_count = ip_count;
    ctx->completed_count = 0;
    ctx->should_stop = 0;
    ctx->winner_index = -1;
    ctx->winner_method = DNS_LATENCY_METHOD_NONE;
    ctx->start_time_ms = get_time_ms ();
    ctx->timeout_ms = timeout_ms;

    /* 初始化同步原语 */
    if (hev_task_mutex_init (&ctx->mutex) != 0) {
        LOG_E ("dns-latency: Failed to init mutex");
        hev_free (ctx);
        return -1;
    }
    if (hev_task_cond_init (&ctx->cond) != 0) {
        LOG_E ("dns-latency: Failed to init cond");
        hev_free (ctx);
        return -1;
    }

    LOG_I ("dns-latency: Starting race test for %d IPs (timeout=%dms)",
           ip_count, timeout_ms);

    /* 创建并发任务 */
    for (int i = 0; i < ip_count; i++) {
        HevTask *task = hev_task_new (-1);
        if (!task) {
            LOG_E ("dns-latency: Failed to create task for IP %d", i);
            continue;
        }

        SingleIPTestParam *param = hev_malloc (sizeof (SingleIPTestParam));
        if (!param) {
            LOG_E ("dns-latency: Failed to alloc param for IP %d", i);
            hev_task_unref (task);
            continue;
        }

        param->ctx = ctx;
        param->ip_index = i;

        /* ⭐ 增加引用计数，因为 tasks 数组要持有它直到 Join 完成 */
        tasks[created_count++] = hev_task_ref (task);
        hev_task_run (task, single_ip_test_task, param);
        LOG_D ("dns-latency: Created task for IP %d", i);
    }

    /* ⭐ 等待：有赢家 OR 全部完成 OR 超时 */
    int total_wait_ms = 0;
    int max_wait_ms = ctx->timeout_ms + 2000;

    while (ctx->winner_index < 0 && ctx->completed_count < created_count &&
           total_wait_ms < max_wait_ms) {
        if (!hev_socks5_tunnel_is_running ()) {
            LOG_W ("dns-latency: Tunnel shutting down, stopping latency test");
            ctx->should_stop = 1;
            break;
        }

        hev_task_mutex_lock (&ctx->mutex);
        int64_t elapsed_ms = get_time_ms () - ctx->start_time_ms;
        if (elapsed_ms >= ctx->timeout_ms) {
            LOG_W ("dns-latency: Race timeout after %lldms",
                   (long long)elapsed_ms);
            ctx->should_stop = 1;
            hev_task_mutex_unlock (&ctx->mutex);
            break;
        }
        hev_task_mutex_unlock (&ctx->mutex);

        hev_task_sleep (50);
        total_wait_ms += 50;
    }

    ctx->should_stop = 1;

    /* ⭐ 显式 Join 所有任务，并释放引用 */
    for (int i = 0; i < created_count; i++) {
        hev_task_join (tasks[i]);
        hev_task_unref (tasks[i]);
    }

    /* 检查结果 */
    int winner_index = ctx->winner_index;
    int winner_method = ctx->winner_method;
    int64_t total_elapsed_ms = get_time_ms () - ctx->start_time_ms;

    hev_free (ctx);

    if (winner_index >= 0) {
        const char *method_name =
            (winner_method == DNS_LATENCY_METHOD_TCP443) ? "TCP443" :
            (winner_method == DNS_LATENCY_METHOD_TCP80)  ? "TCP80" :
                                                           "ICMP";
        const ip_addr_t *winner_ip = &ips[winner_index];
        LOG_I ("dns-latency: Race winner: %s (IP %d, %s), total time=%lldms",
               ipaddr_ntoa (winner_ip), winner_index, method_name,
               (long long)total_elapsed_ms);
        return 0;
    }

    LOG_W ("dns-latency: No winner in race (timeout), total time=%lldms",
           (long long)total_elapsed_ms);
    return -1;
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
    ip_addr_t src_ip; /* DNS server IP (source address for response) */
    uint16_t src_port; /* DNS server port (source port for response) */
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
        uint16_t qtype =
            extract_dns_qtype (ctx->response_data, ctx->response_len);
        hev_dns_cache_insert (ctx->domain, qtype, ctx->response_data,
                              ctx->response_len, ttl, 0);
        goto send_response;
    }

    /* ⭐ 并发测试所有IP (超时控制在总timeout内) */
    int timeout_ms = hev_config_get_dns_latency_timeout_ms ();

    LOG_I ("dns-latency: Concurrent testing %d IPs (total timeout=%dms)",
           ip_count, timeout_ms);

    /* 使用并发测试 */
    LOG_D ("dns-latency: Before concurrent test, response_len=%zu",
           ctx->response_len);
    LOG_D (
        "dns-latency: Original response data (first 20 bytes): %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
        ctx->response_data[0], ctx->response_data[1], ctx->response_data[2],
        ctx->response_data[3], ctx->response_data[4], ctx->response_data[5],
        ctx->response_data[6], ctx->response_data[7], ctx->response_data[8],
        ctx->response_data[9], ctx->response_data[10], ctx->response_data[11],
        ctx->response_data[12], ctx->response_data[13], ctx->response_data[14],
        ctx->response_data[15], ctx->response_data[16], ctx->response_data[17],
        ctx->response_data[18], ctx->response_data[19]);

    if (hev_dns_latency_test_concurrent (ips, ip_count, results, timeout_ms) !=
        0) {
        LOG_W ("dns-latency: Concurrent test failed for all IPs");
        LOG_W ("dns-latency: Sending original response (len=%zu)",
               ctx->response_len);
        goto send_response;
    }

    LOG_I ("dns-latency: Concurrent test returned successfully");

    /* ⭐ 竞争式：直接选择第一个成功的 IP */
    int best_idx = -1;
    int64_t best_latency = INT64_MAX;
    DnsLatencyTestMethod best_method = DNS_LATENCY_METHOD_NONE;

    /* 按优先级查找第一个成功的 IP 和方法 */
    for (int i = 0; i < ip_count; i++) {
        if (results[i].tcp443.success) {
            best_idx = i;
            best_latency = results[i].tcp443.latency_us;
            best_method = DNS_LATENCY_METHOD_TCP443;
            LOG_I (
                "dns-latency: Found winner IP %d via TCP443 (latency=%lld us)",
                i, (long long)best_latency);
            break;
        }
    }

    if (best_idx < 0) {
        for (int i = 0; i < ip_count; i++) {
            if (results[i].tcp80.success) {
                best_idx = i;
                best_latency = results[i].tcp80.latency_us;
                best_method = DNS_LATENCY_METHOD_TCP80;
                LOG_I (
                    "dns-latency: Found winner IP %d via TCP80 (latency=%lld us)",
                    i, (long long)best_latency);
                break;
            }
        }
    }

    if (best_idx < 0) {
        for (int i = 0; i < ip_count; i++) {
            if (results[i].icmp.success) {
                best_idx = i;
                best_latency = results[i].icmp.latency_us;
                best_method = DNS_LATENCY_METHOD_ICMP;
                LOG_I (
                    "dns-latency: Found winner IP %d via ICMP (latency=%lld us)",
                    i, (long long)best_latency);
                break;
            }
        }
    }

    if (best_idx < 0) {
        LOG_W (
            "dns-latency: No IP succeeded any test, sending original response");
        goto send_response;
    }

    LOG_I (
        "dns-latency: Best IP for %s is %s with latency=%lld us (method: %s)",
        ctx->domain, ipaddr_ntoa (&ips[best_idx]), (long long)best_latency,
        best_method == DNS_LATENCY_METHOD_TCP443 ? "TCP443" :
        best_method == DNS_LATENCY_METHOD_TCP80  ? "TCP80" :
                                                   "ICMP");

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
        uint16_t qtype = extract_dns_qtype (modified_response, modified_len);
        hev_dns_cache_insert (ctx->domain, qtype, modified_response,
                              modified_len, ttl, 0);

        /* Send optimized response */
        struct pbuf *p = pbuf_alloc (PBUF_TRANSPORT, modified_len, PBUF_RAM);
        if (p) {
            memcpy (p->payload, modified_response, modified_len);

            /* Set PCB remote address to client for sending */
            ip_addr_copy (ctx->pcb->remote_ip, ctx->client_ip);
            ctx->pcb->remote_port = ctx->client_port;

            /* Use separate buffers for each address to avoid static buffer reuse */
            char src_str[INET6_ADDRSTRLEN], dst_str[INET6_ADDRSTRLEN];
            ipaddr_ntoa_r (&ctx->src_ip, src_str, sizeof (src_str));
            ipaddr_ntoa_r (&ctx->client_ip, dst_str, sizeof (dst_str));
            LOG_I (
                "dns-latency: Sending DNS response to %s:%d (spoofed src: %s:%d)",
                dst_str, ctx->client_port, src_str, ctx->src_port);

            /* Use udp_sendfrom: sends to PCB remote_ip (client) with specified source */
            err_t err = udp_sendfrom (ctx->pcb, p, &ctx->src_ip, ctx->src_port);
            if (err != ERR_OK) {
                LOG_E (
                    "dns-latency: udp_sendfrom failed: %d (to %s:%d from %s:%d)",
                    err, dst_str, ctx->client_port, src_str, ctx->src_port);
            } else {
                LOG_I (
                    "dns-latency: Sent optimized DNS response to client (%zu bytes)",
                    modified_len);
            }
            pbuf_free (p);
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
            /* Set PCB remote address to client for sending */
            ip_addr_copy (ctx->pcb->remote_ip, ctx->client_ip);
            ctx->pcb->remote_port = ctx->client_port;

            /* Use udp_sendfrom to send with spoofed source address */
            char src_str[INET6_ADDRSTRLEN], dst_str[INET6_ADDRSTRLEN];
            ipaddr_ntoa_r (&ctx->src_ip, src_str, sizeof (src_str));
            ipaddr_ntoa_r (&ctx->client_ip, dst_str, sizeof (dst_str));
            LOG_I (
                "dns-latency: Sending original response: src=%s:%d, dst=%s:%d",
                src_str, ctx->src_port, dst_str, ctx->client_port);

            udp_sendfrom (ctx->pcb, p, &ctx->src_ip, ctx->src_port);
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
hev_dns_latency_optimize_response_async (
    const uint8_t *response_data, size_t response_len, const char *domain,
    struct udp_pcb *pcb, const ip_addr_t *client_ip, uint16_t client_port,
    const ip_addr_t *src_ip, uint16_t src_port, HevSocks5 *base)
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

    LOG_I (
        "dns-latency: Before copy: *client_ip=%s (ptr=%p), *src_ip=%s (ptr=%p)",
        ipaddr_ntoa (client_ip), client_ip, ipaddr_ntoa (src_ip), src_ip);
    LOG_I (
        "dns-latency: Raw memory: client_ip[0-7]=%02x%02x%02x%02x%02x%02x%02x%02x, src_ip[0-7]=%02x%02x%02x%02x%02x%02x%02x%02x",
        ((uint8_t *)client_ip)[0], ((uint8_t *)client_ip)[1],
        ((uint8_t *)client_ip)[2], ((uint8_t *)client_ip)[3],
        ((uint8_t *)client_ip)[4], ((uint8_t *)client_ip)[5],
        ((uint8_t *)client_ip)[6], ((uint8_t *)client_ip)[7],
        ((uint8_t *)src_ip)[0], ((uint8_t *)src_ip)[1], ((uint8_t *)src_ip)[2],
        ((uint8_t *)src_ip)[3], ((uint8_t *)src_ip)[4], ((uint8_t *)src_ip)[5],
        ((uint8_t *)src_ip)[6], ((uint8_t *)src_ip)[7]);

    ip_addr_copy (ctx->client_ip, *client_ip);
    ctx->client_port = client_port;
    ip_addr_copy (ctx->src_ip, *src_ip);
    ctx->src_port = src_port;
    ctx->base = base;
    hev_object_ref (HEV_OBJECT (base));

    /* Verify the copy using raw memory access */
    LOG_I (
        "dns-latency: After copy: ctx->client_ip raw=%02x%02x%02x%02x, ctx->src_ip raw=%02x%02x%02x%02x",
        ((uint8_t *)&ctx->client_ip)[0], ((uint8_t *)&ctx->client_ip)[1],
        ((uint8_t *)&ctx->client_ip)[2], ((uint8_t *)&ctx->client_ip)[3],
        ((uint8_t *)&ctx->src_ip)[0], ((uint8_t *)&ctx->src_ip)[1],
        ((uint8_t *)&ctx->src_ip)[2], ((uint8_t *)&ctx->src_ip)[3]);

    /* Use separate buffers to avoid static buffer reuse issues */
    char client_ip_buf[INET6_ADDRSTRLEN], src_ip_buf[INET6_ADDRSTRLEN];
    ipaddr_ntoa_r (&ctx->client_ip, client_ip_buf, sizeof (client_ip_buf));
    ipaddr_ntoa_r (&ctx->src_ip, src_ip_buf, sizeof (src_ip_buf));
    LOG_I ("dns-latency: Context init: client=%s:%d, src=%s:%d", client_ip_buf,
           ctx->client_port, src_ip_buf, ctx->src_port);

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
