/*
 ============================================================================
 Name        : hev-socks5-misc.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2021 - 2025 hev
 Description : Socks5 Misc
 ============================================================================
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>

#include <hev-task.h>
#include <hev-task-io.h>
#include <hev-task-io-socket.h>
#include <hev-task-dns.h>
#include <hev-memory-allocator.h>

#include "hev-socks5.h"
#include "hev-socks5-logger-priv.h"

#include "hev-socks5-misc.h"
#include "hev-socks5-misc-priv.h"

static int task_stack_size = 8192;
static int udp_recv_buffer_size = 512 * 1024;

/* 智能缓冲区管理 */
static int udp_buffer_min_size = 64 * 1024; // 最小64KB
static int udp_buffer_max_size = 2 * 1024 * 1024; // 最大2MB
static int udp_buffer_default_size = 512 * 1024; // 默认512KB

/* 网络状态监控 */
static struct
{
    int current_buffer_size;
    unsigned long total_rx_bytes;
    unsigned long total_rx_packets;
    time_t last_adjust_time;
    double avg_latency_ms;
    int congestion_level; // 0=正常, 1=轻微拥塞, 2=严重拥塞
} buffer_stats = { 0 };

int
hev_socks5_task_io_yielder (HevTaskYieldType type, void *data)
{
    HevSocks5 *self = data;

    if (type == HEV_TASK_YIELD) {
        hev_task_yield (HEV_TASK_YIELD);
        return 0;
    }

    if (self->timeout < 0) {
        hev_task_yield (HEV_TASK_WAITIO);
    } else {
        int timeout = self->timeout;
        timeout = hev_task_sleep (timeout);
        if (timeout <= 0) {
            LOG_I ("%p io timeout", self);
            return -1;
        }
    }

    return 0;
}

int
hev_socks5_socket (int type)
{
    HevTask *task = hev_task_self ();
    int fd, res, zero = 0;

    fd = hev_task_io_socket_socket (AF_INET6, type, 0);
    if (fd < 0)
        return -1;

    res = setsockopt (fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof (zero));
    if (res < 0) {
        close (fd);
        return -1;
    }

    res = hev_task_add_fd (task, fd, POLLIN | POLLOUT);
    if (res < 0)
        hev_task_mod_fd (task, fd, POLLIN | POLLOUT);

    if (type == SOCK_DGRAM) {
        res = udp_recv_buffer_size;
        setsockopt (fd, SOL_SOCKET, SO_RCVBUF, &res, sizeof (res));
    }

    return fd;
}

const char *
hev_socks5_addr_into_str (const HevSocks5Addr *addr, char *buf, int len)
{
    const char *res = buf;
    uint16_t port;
    char sa[256];

    switch (addr->atype) {
    case HEV_SOCKS5_ADDR_TYPE_IPV4:
        port = ntohs (addr->ipv4.port);
        inet_ntop (AF_INET, addr->ipv4.addr, sa, sizeof (sa));
        break;
    case HEV_SOCKS5_ADDR_TYPE_IPV6:
        port = ntohs (addr->ipv6.port);
        inet_ntop (AF_INET6, addr->ipv6.addr, sa, sizeof (sa));
        break;
    case HEV_SOCKS5_ADDR_TYPE_NAME:
        memcpy (sa, addr->domain.addr, addr->domain.len);
        sa[addr->domain.len] = '\0';
        memcpy (&port, addr->domain.addr + addr->domain.len, 2);
        port = ntohs (port);
        break;
    default:
        return NULL;
    }

    snprintf (buf, len, "[%s]:%u", sa, port);
    return res;
}

int
hev_socks5_addr_len (const HevSocks5Addr *addr)
{
    switch (addr->atype) {
    case HEV_SOCKS5_ADDR_TYPE_IPV4:
        return 7;
    case HEV_SOCKS5_ADDR_TYPE_IPV6:
        return 19;
    case HEV_SOCKS5_ADDR_TYPE_NAME:
        return 4 + addr->domain.len;
    default:
        return -1;
    }
}

int
hev_socks5_addr_from_name (HevSocks5Addr *addr, const char *name, int _port)
{
    uint16_t port = _port;
    addr->atype = HEV_SOCKS5_ADDR_TYPE_NAME;
    strncpy ((char *)addr->domain.addr, name, 256);
    addr->domain.len = strlen ((char *)addr->domain.addr);
    memcpy ((char *)addr->domain.addr + addr->domain.len, &port, 2);
    return 4 + addr->domain.len;
}

int
hev_socks5_addr_from_ipv4 (HevSocks5Addr *addr, const void *ipv4, int port)
{
    addr->atype = HEV_SOCKS5_ADDR_TYPE_IPV4;
    memcpy (addr->ipv4.addr, ipv4, sizeof (addr->ipv4.addr));
    addr->ipv4.port = port;
    return 7;
}

int
hev_socks5_addr_from_ipv6 (HevSocks5Addr *addr, const void *ipv6, int port)
{
    addr->atype = HEV_SOCKS5_ADDR_TYPE_IPV6;
    memcpy (addr->ipv6.addr, ipv6, sizeof (addr->ipv6.addr));
    addr->ipv6.port = port;
    return 19;
}

int
hev_socks5_addr_from_sockaddr6 (HevSocks5Addr *addr, struct sockaddr_in6 *saddr)
{
    if (IN6_IS_ADDR_V4MAPPED (&saddr->sin6_addr)) {
        addr->atype = HEV_SOCKS5_ADDR_TYPE_IPV4;
        addr->ipv4.port = saddr->sin6_port;
        memcpy (addr->ipv4.addr, &saddr->sin6_addr.s6_addr[12], 4);
        return 7;
    }

    addr->atype = HEV_SOCKS5_ADDR_TYPE_IPV6;
    addr->ipv6.port = saddr->sin6_port;
    memcpy (addr->ipv6.addr, &saddr->sin6_addr, 16);
    return 19;
}

static void
hev_socks5_ipv4_into_sockaddr6 (const HevSocks5Addr *addr,
                                struct sockaddr_in6 *saddr)
{
    saddr->sin6_family = AF_INET6;
    saddr->sin6_port = addr->ipv4.port;
    memset (&saddr->sin6_addr, 0, 10);
    saddr->sin6_addr.s6_addr[10] = 0xff;
    saddr->sin6_addr.s6_addr[11] = 0xff;
    memcpy (&saddr->sin6_addr.s6_addr[12], addr->ipv4.addr, 4);
}

static void
hev_socks5_ipv6_into_sockaddr6 (const HevSocks5Addr *addr,
                                struct sockaddr_in6 *saddr)
{
    saddr->sin6_family = AF_INET6;
    saddr->sin6_port = addr->ipv6.port;
    memcpy (&saddr->sin6_addr, addr->ipv6.addr, 16);
}

int
hev_socks5_addr_into_sockaddr6 (const HevSocks5Addr *addr,
                                struct sockaddr_in6 *saddr, int *family)
{
    switch (addr->atype) {
    case HEV_SOCKS5_ADDR_TYPE_IPV4: {
        hev_socks5_ipv4_into_sockaddr6 (addr, saddr);
        *family = HEV_SOCKS5_ADDR_FAMILY_IPV4;
        break;
    }
    case HEV_SOCKS5_ADDR_TYPE_IPV6: {
        hev_socks5_ipv6_into_sockaddr6 (addr, saddr);
        *family = HEV_SOCKS5_ADDR_FAMILY_IPV6;
        break;
    }
    case HEV_SOCKS5_ADDR_TYPE_NAME: {
        char name[256];
        uint16_t port;
        memcpy (name, addr->domain.addr, addr->domain.len);
        name[addr->domain.len] = '\0';
        memcpy (&port, addr->domain.addr + addr->domain.len, 2);
        return hev_socks5_name_into_sockaddr6 (name, ntohs (port), saddr,
                                               family);
    }
    default:
        return -1;
    }

    return 0;
}

static int
hev_socks5_name_resolve_ipv4 (const char *name, struct sockaddr_in6 *saddr)
{
    int res;

    memset (&saddr->sin6_addr, 0, 10);
    res = inet_pton (AF_INET, name, &saddr->sin6_addr.s6_addr[12]);
    if (res == 0)
        return -1;

    saddr->sin6_addr.s6_addr[10] = 0xff;
    saddr->sin6_addr.s6_addr[11] = 0xff;

    return 0;
}

static int
hev_socks5_name_resolve_ipv6 (const char *name, struct sockaddr_in6 *saddr)
{
    int res;

    res = inet_pton (AF_INET6, name, &saddr->sin6_addr);
    if (res == 0)
        return -1;

    return 0;
}

static int
hev_socks5_name_resolve_name (const char *name, struct sockaddr_in6 *saddr,
                              int *family)
{
    struct addrinfo *result = NULL;
    struct addrinfo hints = { 0 };
    int res = 0;

    hints.ai_family = *family;
    hints.ai_socktype = SOCK_STREAM;

    hev_task_dns_getaddrinfo (name, NULL, &hints, &result);
    if (!result)
        return -1;

    switch (result->ai_family) {
    case AF_INET: {
        struct sockaddr_in *sa = (struct sockaddr_in *)result->ai_addr;
        memset (&saddr->sin6_addr, 0, 10);
        saddr->sin6_addr.s6_addr[10] = 0xff;
        saddr->sin6_addr.s6_addr[11] = 0xff;
        memcpy (&saddr->sin6_addr.s6_addr[12], &sa->sin_addr, 4);
        *family = HEV_SOCKS5_ADDR_FAMILY_IPV4;
        break;
    }
    case AF_INET6: {
        struct sockaddr_in6 *sa = (struct sockaddr_in6 *)result->ai_addr;
        memcpy (&saddr->sin6_addr, &sa->sin6_addr, 16);
        *family = HEV_SOCKS5_ADDR_FAMILY_IPV6;
        break;
    }
    default:
        res = -1;
    }

    freeaddrinfo (result);
    return res;
}

int
hev_socks5_name_into_sockaddr6 (const char *name, int port,
                                struct sockaddr_in6 *saddr, int *family)
{
    int res;

    saddr->sin6_family = AF_INET6;
    saddr->sin6_port = htons (port);

    res = hev_socks5_name_resolve_ipv4 (name, saddr);
    if (res == 0) {
        *family = HEV_SOCKS5_ADDR_FAMILY_IPV4;
        return 0;
    }

    res = hev_socks5_name_resolve_ipv6 (name, saddr);
    if (res == 0) {
        *family = HEV_SOCKS5_ADDR_FAMILY_IPV6;
        return 0;
    }

    res = hev_socks5_name_resolve_name (name, saddr, family);
    return res;
}

void
hev_socks5_set_task_stack_size (int stack_size)
{
    task_stack_size = stack_size;
}

int
hev_socks5_get_task_stack_size (void)
{
    return task_stack_size;
}

void
hev_socks5_set_udp_recv_buffer_size (int buffer_size)
{
    udp_recv_buffer_size = buffer_size;
}

/* 智能缓冲区管理：初始化 */
void
hev_socks5_init_smart_buffer (void)
{
    buffer_stats.current_buffer_size = udp_buffer_default_size;
    buffer_stats.total_rx_bytes = 0;
    buffer_stats.total_rx_packets = 0;
    buffer_stats.last_adjust_time = time (NULL);
    buffer_stats.avg_latency_ms = 50.0; // 默认50ms
    buffer_stats.congestion_level = 0;

    /* 设置初始缓冲区大小 */
    udp_recv_buffer_size = buffer_stats.current_buffer_size;

    LOG_D ("smart_buffer: Initialized with size %d bytes",
           buffer_stats.current_buffer_size);
}

/* 智能缓冲区管理：更新网络统计 */
void
hev_socks5_update_buffer_stats (unsigned long rx_bytes, double latency_ms)
{
    buffer_stats.total_rx_bytes += rx_bytes;
    buffer_stats.total_rx_packets++;

    /* 更新平均延迟（指数加权移动平均） */
    if (buffer_stats.avg_latency_ms == 0.0) {
        buffer_stats.avg_latency_ms = latency_ms;
    } else {
        buffer_stats.avg_latency_ms =
            0.8 * buffer_stats.avg_latency_ms + 0.2 * latency_ms;
    }

    /* 根据延迟判断拥塞程度 */
    if (latency_ms > 200.0) {
        buffer_stats.congestion_level = 2; // 严重拥塞
    } else if (latency_ms > 100.0) {
        buffer_stats.congestion_level = 1; // 轻微拥塞
    } else {
        buffer_stats.congestion_level = 0; // 正常
    }

    LOG_D (
        "smart_buffer: Stats updated - bytes=%lu, packets=%lu, latency=%.2fms, congestion=%d",
        buffer_stats.total_rx_bytes, buffer_stats.total_rx_packets,
        buffer_stats.avg_latency_ms, buffer_stats.congestion_level);
}

/* 智能缓冲区管理：动态调整缓冲区大小 */
void
hev_socks5_adjust_buffer_size (void)
{
    time_t current_time = time (NULL);
    int new_size = buffer_stats.current_buffer_size;

    /* 调整间隔：至少60秒 */
    if (current_time - buffer_stats.last_adjust_time < 60) {
        return;
    }

    /* 根据网络状况调整缓冲区大小 */
    if (buffer_stats.congestion_level == 2) {
        /* 严重拥塞：增加缓冲区大小，减少丢包 */
        new_size = (int)(buffer_stats.current_buffer_size * 1.5);
        if (new_size > udp_buffer_max_size) {
            new_size = udp_buffer_max_size;
        }
        LOG_I (
            "smart_buffer: Expanding buffer due to congestion: %d -> %d bytes",
            buffer_stats.current_buffer_size, new_size);
    } else if (buffer_stats.congestion_level == 0 &&
               buffer_stats.avg_latency_ms < 30.0) {
        /* 网络良好且延迟低：可以适当减少缓冲区节省内存 */
        new_size = (int)(buffer_stats.current_buffer_size * 0.8);
        if (new_size < udp_buffer_min_size) {
            new_size = udp_buffer_min_size;
        }
        LOG_I (
            "smart_buffer: Shrinking buffer due to good network: %d -> %d bytes",
            buffer_stats.current_buffer_size, new_size);
    }

    /* 应用新的缓冲区大小 */
    if (new_size != buffer_stats.current_buffer_size) {
        buffer_stats.current_buffer_size = new_size;
        udp_recv_buffer_size = new_size;
        buffer_stats.last_adjust_time = current_time;
    }
}

/* 智能缓冲区管理：获取当前缓冲区统计 */
void
hev_socks5_get_buffer_stats (int *current_size, double *avg_latency,
                             int *congestion_level)
{
    if (current_size)
        *current_size = buffer_stats.current_buffer_size;
    if (avg_latency)
        *avg_latency = buffer_stats.avg_latency_ms;
    if (congestion_level)
        *congestion_level = buffer_stats.congestion_level;
}
