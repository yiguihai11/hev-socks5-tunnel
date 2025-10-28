/*
 ============================================================================
 Name        : hev-session-manager.c (修复版 - 支持长连接 + SOCKS5 SNI)
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2024 hev
 Description : Session Manager (支持长连接的超时保护 + 增强日志 + SOCKS5 SNI)
 ============================================================================
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <stddef.h>
#include <time.h>
#include <strings.h> /* For strcasestr */

/* memmem compatibility for systems without _GNU_SOURCE */
#ifndef _GNU_SOURCE
static void *
memmem_compat (const void *haystack, size_t haystacklen, const void *needle,
               size_t needlelen)
{
    const char *h = haystack;
    const char *n = needle;
    size_t i;

    if (needlelen == 0)
        return (void *)haystack;
    if (haystacklen < needlelen)
        return NULL;

    for (i = 0; i <= haystacklen - needlelen; i++) {
        if (memcmp (h + i, n, needlelen) == 0)
            return (void *)(h + i);
    }
    return NULL;
}

#define memmem memmem_compat
#endif

/* ⬇️ TCP Keep-Alive 跨平台兼容性 - 修改顺序,先包含系统头文件 */
#if defined(__linux__)
/* 先包含系统头文件,然后保存需要的宏 */
#include <netinet/tcp.h>
/* 保存 TCP Keep-Alive 相关的宏值 */
#ifdef TCP_KEEPIDLE
#define HEV_TCP_KEEPIDLE TCP_KEEPIDLE
#endif
#ifdef TCP_KEEPINTVL
#define HEV_TCP_KEEPINTVL TCP_KEEPINTVL
#endif
#ifdef TCP_KEEPCNT
#define HEV_TCP_KEEPCNT TCP_KEEPCNT
#endif

/* 取消可能与 lwIP 冲突的宏定义 */
#ifdef TCP_MSS
#undef TCP_MSS
#endif

#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__NetBSD__)
#include <netinet/tcp.h>
/* BSD 系统宏保存 */
#ifdef TCP_KEEPALIVE
#define HEV_TCP_KEEPIDLE TCP_KEEPALIVE
#endif
#ifdef TCP_KEEPINTVL
#define HEV_TCP_KEEPINTVL TCP_KEEPINTVL
#endif
#ifdef TCP_KEEPCNT
#define HEV_TCP_KEEPCNT TCP_KEEPCNT
#endif

/* 取消冲突宏 */
#ifdef TCP_MSS
#undef TCP_MSS
#endif

#elif defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#define HEV_TCP_KEEPIDLE TCP_KEEPALIVE
#endif

/* 如果系统不支持 TCP Keep-Alive,禁用该功能 */
#ifndef HEV_TCP_KEEPIDLE
#define TCP_KEEPALIVE_UNSUPPORTED
#endif

/* ⬇️ 现在包含 hev 项目的头文件(包括 lwIP) */
#include <hev-task.h>
#include <hev-task-system.h>
#include <hev-task-io-socket.h>
#include <hev-memory-allocator.h>
#include <hev-object.h>
#include <hev-socks5.h>
#include <hev-socks5-misc.h>

#include "hev-config.h"
#include "hev-logger.h"
#include "hev-compiler.h"
#include "hev-socks5-session.h"
#include "hev-socks5-session-tcp.h"
#include "hev-socks5-tunnel.h"
#include "hev-traffic-router.h"
#include "hev-filter.h"

#include "hev-session-manager.h"

/* container_of macro */
#ifndef container_of
#define container_of(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof (type, member)))
#endif

/* ============================================================================
   空闲超时检查机制
   ============================================================================ */

typedef struct _HevIdleTimer
{
    time_t last_activity;
    int idle_timeout; /* 秒, 0 = 禁用空闲超时 */
} HevIdleTimer;

typedef struct _HevSpliceTaskData
{
    HevSocks5SessionTCP *session;
    HevIdleTimer *timer;
} HevSpliceTaskData;

/* Forward declarations */
static void run_direct_connect_task (void *data);
static void run_smart_proxy_task (void *data);
static void tcp_direct_splice_task_b (void *data);
static void smart_proxy_splice_task_b (void *data);
static int sniff_client_hello (HevSocks5SessionTCP *self,
                               HevTLSClientHello *hello);
static int extract_http_host_from_queue (HevSocks5SessionTCP *self, char *hostname_buffer,
                                          size_t buffer_len);



/* ============================================================================
   High-Precision Time Functions
   ============================================================================ */

static time_t
get_current_time_ms (void)
{
    struct timeval tv;
    gettimeofday (&tv, NULL);
    return (time_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static time_t
get_current_time_seconds (void)
{
    struct timeval tv;
    gettimeofday (&tv, NULL);
    return tv.tv_sec;
}

/* High-precision timeout check for smart proxy (placeholder for future use) */
/* static int check_smart_proxy_timeout_ms (time_t start_time_ms, int timeout_ms); */

/* ============================================================================
   辅助函数:设置 TCP Keep-Alive
   ⬇️ 使用我们保存的 HEV_TCP_KEEPIDLE 等宏
   ============================================================================ */
static void
set_tcp_keepalive (void *session, int fd)
{
#ifndef TCP_KEEPALIVE_UNSUPPORTED
    int enable = 1;
    int keepidle = 60; // 60秒后开始探测
    int keepintvl = 10; // 每10秒探测一次
    int keepcnt = 3; // 3次失败后断开

    if (setsockopt (fd, SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof (enable)) <
        0) {
        LOG_W ("%p session: Failed to enable TCP Keep-Alive: %s", session,
               strerror (errno));
        return;
    }

    /* ⬇️ 使用重命名后的宏 */
#ifdef HEV_TCP_KEEPIDLE
    setsockopt (fd, IPPROTO_TCP, HEV_TCP_KEEPIDLE, &keepidle,
                sizeof (keepidle));
#endif

#ifdef HEV_TCP_KEEPINTVL
    setsockopt (fd, IPPROTO_TCP, HEV_TCP_KEEPINTVL, &keepintvl,
                sizeof (keepintvl));
#endif

#ifdef HEV_TCP_KEEPCNT
    setsockopt (fd, IPPROTO_TCP, HEV_TCP_KEEPCNT, &keepcnt, sizeof (keepcnt));
#endif

    LOG_D (
        "%p session: TCP Keep-Alive enabled (idle=%ds, interval=%ds, count=%d)",
        session, keepidle, keepintvl, keepcnt);
#else
    LOG_D ("%p session: TCP Keep-Alive not supported on this platform",
           session);
#endif
}

static void
idle_timer_init (HevIdleTimer *timer, int timeout_seconds)
{
    timer->last_activity = get_current_time_seconds ();
    timer->idle_timeout = timeout_seconds;
}

static void
idle_timer_update (HevIdleTimer *timer)
{
    timer->last_activity = get_current_time_seconds ();
}

static int
idle_timer_check (HevIdleTimer *timer)
{
    if (timer->idle_timeout <= 0)
        return 0; /* 空闲超时禁用 */

    time_t now = time (NULL);
    if (now - timer->last_activity > timer->idle_timeout) {
        return -1; /* 超时 */
    }
    return 0;
}

void
hev_session_manager_init (void)
{
}

void
hev_session_manager_fini (void)
{
}

/* ============================================================================
   SOCKS5 TCP 任务入口 - 在这里嗅探 SNI
   ============================================================================ */

static void
hev_socks5_session_task_entry (void *data)
{
    HevSocks5Session *s = data;
    HevSocks5SessionTCP *tcp = HEV_SOCKS5_SESSION_TCP (s);
    struct tcp_pcb *pcb = tcp->pcb;
    HevTLSClientHello client_hello;
    char dst_ip[INET6_ADDRSTRLEN];
    char http_hostname[256]; // Buffer for HTTP hostname

    LOG_D ("%p session: socks5 proxy task entry", s);

    /* 🔍 在任务内部嗅探 TLS ClientHello（针对端口 443） */
    if (pcb && pcb->local_port == 443) {
        /* 等待数据到达 */
        if (!tcp->queue) {
            LOG_D (
                "%p session: SOCKS5 task waiting for TLS ClientHello data...",
                tcp);
            for (int i = 0; i < 150 && !tcp->queue; i++) { /* 延长等待时间 */
                hev_task_sleep (10);
            }
            if (!tcp->queue) {
                LOG_W (
                    "%p session: SOCKS5 task timed out waiting for TLS ClientHello data (1500ms)",
                    tcp);
            }
        }

        /* 尝试嗅探 */
        if (tcp->queue) {
            LOG_D (
                "%p session: SOCKS5 task attempting to sniff TLS ClientHello (%d bytes in queue)",
                tcp, tcp->queue->tot_len);

            if (sniff_client_hello (tcp, &client_hello) == 0 &&
                client_hello.detected) {
                ipaddr_ntoa_r (&pcb->local_ip, dst_ip, sizeof (dst_ip));

                if (client_hello.sni[0]) {
                    LOG_I (
                        "%p session: SOCKS5 proxy detected TLS SNI: %s (target: %s:%d)",
                        tcp, client_hello.sni, dst_ip, pcb->local_port);
                    // --- SNI-based ACL check ---
                    if (hev_filter_is_blocked_hostname (client_hello.sni)) {
                        LOG_W (
                            "%p session: SOCKS5 proxy blocked connection to SNI: %s (target: %s:%d)",
                            tcp, client_hello.sni, dst_ip, pcb->local_port);
                        goto exit_cleanup; // Terminate session
                    }
                }
                if (client_hello.alpn[0]) {
                    LOG_I ("%p session: SOCKS5 proxy detected ALPN: %s", tcp,
                           client_hello.alpn);
                }
            } else {
                LOG_D (
                    "%p session: SOCKS5 TLS ClientHello not detected or parsing failed",
                    tcp);
            }
        }
    }
    // --- HTTP Hostname-based ACL check for ports 80/8080 ---
    else if (pcb && (pcb->local_port == 80 || pcb->local_port == 8080)) {
        // Wait for data (similar to SNI)
        if (!tcp->queue) {
            LOG_D ("%p session: SOCKS5 task waiting for HTTP data...", tcp);
            for (int i = 0; i < 150 && !tcp->queue; i++) {
                hev_task_sleep (10);
            }
            if (!tcp->queue) {
                LOG_W (
                    "%p session: SOCKS5 task timed out waiting for HTTP data (1500ms)",
                    tcp);
            }
        }
        if (tcp->queue &&
            extract_http_host_from_queue (tcp, http_hostname, sizeof (http_hostname)) == 0) {
            ipaddr_ntoa_r (&pcb->local_ip, dst_ip, sizeof (dst_ip));
            LOG_I (
                "%p session: SOCKS5 proxy detected HTTP Host: %s (target: %s:%d)",
                tcp, http_hostname, dst_ip, pcb->local_port);
            if (hev_filter_is_blocked_hostname (http_hostname)) {
                LOG_W (
                    "%p session: SOCKS5 proxy blocked connection to HTTP Host: %s (target: %s:%d)",
                    tcp, http_hostname, dst_ip, pcb->local_port);
                goto exit_cleanup; // Terminate session
            }
        }
    }

    hev_socks5_session_run (s);

    LOG_D ("%p session: socks5 proxy task exit", s);

exit_cleanup: // New label for cleanup
    hev_socks5_tunnel_delete_session (hev_socks5_session_get_node (s));
    hev_object_unref (HEV_OBJECT (s));
}

void
hev_session_manager_start_socks5_tcp (struct tcp_pcb *pcb)
{
    HevSocks5SessionTCP *tcp;
    HevListNode *node;
    int stack_size;
    HevTask *task;
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];

    tcp = hev_socks5_session_tcp_new (pcb, &mutex);
    if (!tcp) {
        tcp_abort (pcb);
        return;
    }

    ipaddr_ntoa_r (&pcb->remote_ip, src_ip, sizeof (src_ip));
    ipaddr_ntoa_r (&pcb->local_ip, dst_ip, sizeof (dst_ip));
    LOG_I ("%p session: SOCKS5 proxy started %s:%d -> %s:%d", tcp, src_ip,
           pcb->remote_port, dst_ip, pcb->local_port);

    stack_size = hev_config_get_misc_task_stack_size ();
    task = hev_task_new (stack_size);
    if (!task) {
        LOG_E ("%p session: failed to create SOCKS5 task", tcp);
        hev_object_unref (HEV_OBJECT (tcp));
        return;
    }

    hev_socks5_session_set_task (HEV_SOCKS5_SESSION (tcp), task);
    node = hev_socks5_session_get_node (HEV_SOCKS5_SESSION (tcp));
    hev_socks5_tunnel_insert_session (node);
    hev_task_run (task, hev_socks5_session_task_entry, tcp);
}

void
hev_session_manager_start_direct_tcp (struct tcp_pcb *pcb)
{
    HevSocks5SessionTCP *tcp;
    HevListNode *node;
    int stack_size;
    HevTask *task;
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];

    tcp = hev_socks5_session_tcp_new (pcb, &mutex);
    if (!tcp) {
        tcp_abort (pcb);
        return;
    }

    ipaddr_ntoa_r (&pcb->remote_ip, src_ip, sizeof (src_ip));
    ipaddr_ntoa_r (&pcb->local_ip, dst_ip, sizeof (dst_ip));
    LOG_I ("%p session: Direct connect started %s:%d -> %s:%d", tcp, src_ip,
           pcb->remote_port, dst_ip, pcb->local_port);

    stack_size = hev_config_get_misc_task_stack_size ();
    task = hev_task_new (stack_size);
    if (!task) {
        LOG_E ("%p session: failed to create direct connect task", tcp);
        hev_object_unref (HEV_OBJECT (tcp));
        return;
    }

    hev_socks5_session_set_task (HEV_SOCKS5_SESSION (tcp), task);
    node = hev_socks5_session_get_node (HEV_SOCKS5_SESSION (tcp));
    hev_socks5_tunnel_insert_session (node);
    hev_task_run (task, run_direct_connect_task, tcp);
}

void
hev_session_manager_start_smart_proxy (struct tcp_pcb *pcb)
{
    HevSocks5SessionTCP *tcp;
    HevListNode *node;
    int stack_size;
    HevTask *task;
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];

    tcp = hev_socks5_session_tcp_new (pcb, &mutex);
    if (!tcp) {
        tcp_abort (pcb);
        return;
    }

    ipaddr_ntoa_r (&pcb->remote_ip, src_ip, sizeof (src_ip));
    ipaddr_ntoa_r (&pcb->local_ip, dst_ip, sizeof (dst_ip));
    LOG_I ("%p session: Smart proxy started %s:%d -> %s:%d", tcp, src_ip,
           pcb->remote_port, dst_ip, pcb->local_port);

    stack_size = hev_config_get_misc_task_stack_size ();
    task = hev_task_new (stack_size);
    if (!task) {
        LOG_E ("%p session: failed to create smart proxy task", tcp);
        hev_object_unref (HEV_OBJECT (tcp));
        return;
    }

    hev_socks5_session_set_task (HEV_SOCKS5_SESSION (tcp), task);
    node = hev_socks5_session_get_node (HEV_SOCKS5_SESSION (tcp));
    hev_socks5_tunnel_insert_session (node);
    hev_task_run (task, run_smart_proxy_task, tcp);
}

/* ============================================================================
   TCP Direct Connect Splice Implementation
   ============================================================================ */

static int
tcp_direct_splice_f (HevSocks5SessionTCP *self, HevIdleTimer *timer)
{
    struct iovec iov[64];
    struct pbuf *p;
    int iovc = 0;
    int res = 1;

    if (self->queue) {
        for (p = self->queue; p && (iovc < 64); p = p->next, iovc++) {
            iov[iovc].iov_base = p->payload;
            iov[iovc].iov_len = p->len;
        }
    } else if (self->pcb_eof) {
        res = -1;
    } else {
        res = 0;
    }

    if (iovc) {
        ssize_t s = writev (HEV_SOCKS5 (self)->fd, iov, iovc);
        if (0 >= s) {
            if ((0 > s) && (EAGAIN == errno))
                res = 0;
            else
                res = -1;
        } else {
            /* 有数据传输,更新活动时间 */
            if (timer)
                idle_timer_update (timer);

            LOG_D ("%p session: forward sent %zd bytes", self, s);

            hev_task_mutex_lock (self->mutex);
            self->queue = pbuf_free_header (self->queue, s);
            if (self->pcb)
                tcp_recved (self->pcb, s);
            hev_task_mutex_unlock (self->mutex);
            res = 1;
        }
    } else if (res < 0) {
        LOG_D ("%p session: forward EOF, shutting down write", self);
        shutdown (HEV_SOCKS5 (self)->fd, SHUT_WR);
    }

    return res;
}

static int
tcp_direct_splice_b (HevSocks5SessionTCP *self, HevIdleTimer *timer)
{
    struct iovec iov[2];
    err_t err = ERR_OK;
    int res = 1, iovc;

    iovc = hev_ring_buffer_writing (self->buffer, iov);
    if (iovc) {
        ssize_t s = readv (HEV_SOCKS5 (self)->fd, iov, iovc);
        if (0 >= s) {
            if ((0 > s) && (EAGAIN == errno))
                res = 0;
            else
                res = -1;
        } else {
            /* 有数据传输,更新活动时间 */
            if (timer)
                idle_timer_update (timer);

            LOG_D ("%p session: backward received %zd bytes", self, s);

            hev_ring_buffer_write_finish (self->buffer, s);
            self->initial_data_received = 1;
        }
    }

    hev_task_mutex_lock (self->mutex);
    if (self->pcb) {
        iovc = hev_ring_buffer_reading (self->buffer, iov);
        if (iovc) {
            ssize_t s = 0;
            int i;
            for (i = 0; i < iovc; i++) {
                void *ptr = iov[i].iov_base;
                size_t len = iov[i].iov_len;
                err |= tcp_write (self->pcb, ptr, len, 0);
                s += len;
            }
            hev_ring_buffer_read_finish (self->buffer, s);
            err |= tcp_output (self->pcb);
            res = 1;
        } else if (res < 0) {
            LOG_D ("%p session: backward EOF, shutting down pcb write", self);
            tcp_shutdown (self->pcb, 0, 1);
        }
    }
    hev_task_mutex_unlock (self->mutex);
    if (!self->pcb || (err != ERR_OK))
        res = -1;

    return res;
}

static void
tcp_direct_splice_task_b (void *data)
{
    HevSpliceTaskData *task_data = data;
    HevSocks5SessionTCP *self = task_data->session;
    HevIdleTimer *timer = task_data->timer;
    HevTask *task = hev_task_self ();
    int fd;

    LOG_D ("%p session: backward splice task start", self);

    fd = hev_task_io_dup (HEV_SOCKS5 (self)->fd);
    if (fd < 0) {
        LOG_E ("%p session: failed to dup fd for backward splice", self);
        hev_free (task_data);
        return;
    }

    if (hev_task_add_fd (task, fd, POLLIN) < 0)
        hev_task_mod_fd (task, fd, POLLIN);

    for (;;) {
        if (tcp_direct_splice_b (self, timer) < 0)
            break;
        hev_task_yield (HEV_TASK_WAITIO);
    }

    hev_task_del_fd (task, fd);
    close (fd);
    hev_free (task_data);

    LOG_D ("%p session: backward splice task end", self);
}

/* Extract HTTP Host from pbuf queue using filter module */
static int
extract_http_host_from_queue (HevSocks5SessionTCP *self, char *hostname_buffer,
                              size_t buffer_len)
{
    struct pbuf *p = self->queue;
    unsigned char buffer[2048]; /* Use larger buffer for better compatibility */
    size_t total_len = 0;

    if (!p) {
        return -1; // No data
    }

    /* Copy data from pbuf queue to linear buffer */
    for (p = self->queue; p && total_len < sizeof (buffer) - 1; p = p->next) {
        size_t copy_len = p->len;
        if (total_len + copy_len >= sizeof (buffer))
            copy_len = sizeof (buffer) - 1 - total_len;

        memcpy (buffer + total_len, p->payload, copy_len);
        total_len += copy_len;
    }
    buffer[total_len] = '\0';

    if (total_len == 0) {
        return -1; // No data
    }

    LOG_D ("%p session: extracted %zu bytes from pbuf queue for HTTP parsing",
           self, total_len);

    /* Use filter module's HTTP parser */
    return hev_filter_parse_http_host (self, buffer, total_len,
                                       hostname_buffer, buffer_len);
}

/* 嗅探并解析 ClientHello */
static int
sniff_client_hello (HevSocks5SessionTCP *self, HevTLSClientHello *hello)
{
    struct pbuf *p = self->queue;

    if (!p) {
        return -1; // No data
    }

    /* Try zero-copy optimization first if enabled */
    if (hev_session_manager_is_protocol_zerocopy_enabled ()) {
        LOG_D ("%p session: using zero-copy TLS SNI parsing", self);

        /* For TLS ClientHello, we still need to linearize the data for
         * hev_filter_parse_tls, but we can minimize the copy size */
        if (p->tot_len >= 5 && p->tot_len <= 1024) {
            unsigned char buffer[1024]; /* ClientHello 通常在第一个包内 */
            size_t total_len = 0;

            /* Copy only necessary data */
            for (p = self->queue;
                 p && total_len < sizeof (buffer) && total_len < 1024;
                 p = p->next) {
                size_t copy_len = p->len;
                if (total_len + copy_len > sizeof (buffer))
                    copy_len = sizeof (buffer) - total_len;

                memcpy (buffer + total_len, p->payload, copy_len);
                total_len += copy_len;
            }

            if (total_len >= 5) { /* 至少需要 TLS Record Header */
                int result =
                    hev_filter_parse_tls (self, buffer, total_len, hello);
                if (result == 0 && hello->detected && hello->sni[0]) {
                    LOG_D ("%p session: zero-copy TLS SNI found: %s", self,
                           hello->sni);
                }
                return result;
            }
        }
    }

    /* Fallback to traditional method with memory copy */
    LOG_D ("%p session: using traditional TLS SNI parsing", self);
    {
        unsigned char buffer[1024]; /* ClientHello 通常在第一个包内 */
        size_t total_len = 0;

        /* 从队列中复制数据(不消费) */
        for (p = self->queue; p && total_len < sizeof (buffer); p = p->next) {
            size_t copy_len = p->len;
            if (total_len + copy_len > sizeof (buffer))
                copy_len = sizeof (buffer) - total_len;

            memcpy (buffer + total_len, p->payload, copy_len);
            total_len += copy_len;
        }

        if (total_len < 5) /* 至少需要 TLS Record Header */
            return -1;

        return hev_filter_parse_tls (self, buffer, total_len, hello);
    }
}

static void
run_direct_connect_task (void *data)
{
    HevSocks5SessionTCP *self = data;
    HevSocks5Session *s = HEV_SOCKS5_SESSION (self);
    HevObjectClass *klass = HEV_OBJECT_GET_CLASS (s);
    HevSocks5SessionIface *iface =
        klass->iface (HEV_OBJECT (s), HEV_SOCKS5_SESSION_TYPE);
    struct tcp_pcb *pcb = self->pcb;
    HevTask *task = iface->get_task (s);
    HevTask *task_b = NULL;
    HevListNode *node = iface->get_node (s);
    struct sockaddr_storage saddr;
    socklen_t saddr_len;
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    int tcp_buffer_size;
    int connect_timeout;
    int read_write_timeout;
    int fd = -1;
    int stack_size;
    HevIdleTimer idle_timer;
    time_t connect_start = 0;
    time_t session_duration = 0;
    HevTLSClientHello client_hello;
    char http_hostname[256]; // Buffer for HTTP hostname

    /* 获取源和目标地址用于日志 */
    ipaddr_ntoa_r (&pcb->remote_ip, src_ip, sizeof (src_ip));
    ipaddr_ntoa_r (&pcb->local_ip, dst_ip, sizeof (dst_ip));

    LOG_D ("%p session: direct connect task run %s:%d -> %s:%d", self, src_ip,
           pcb->remote_port, dst_ip, pcb->local_port);

    /* 等待一小段时间让数据到达队列 (仅对端口443) */
    if (pcb->local_port == 443 && !self->queue) {
        LOG_D ("%p session: Waiting for TLS ClientHello data...", self);
        for (int i = 0; i < 150 && !self->queue; i++) { /* 延长等待时间 */
            hev_task_sleep (10);
        }
        if (!self->queue) {
            LOG_W (
                "%p session: Direct connect task timed out waiting for TLS ClientHello data (1500ms)",
                self);
        }
    }

    /* 尝试嗅探 TLS ClientHello (端口443) */
    if (self->queue && pcb->local_port == 443) {
        LOG_D (
            "%p session: Attempting to sniff TLS ClientHello (%d bytes in queue)",
            self, self->queue ? self->queue->tot_len : 0);

        if (sniff_client_hello (self, &client_hello) == 0 &&
            client_hello.detected) {
            if (client_hello.sni[0]) {
                LOG_I (
                    "%p session: Direct connect detected TLS SNI: %s (target: %s:%d)",
                    self, client_hello.sni, dst_ip, pcb->local_port);
                // --- SNI-based ACL check ---
                if (hev_filter_is_blocked_hostname (client_hello.sni)) {
                    LOG_W (
                        "%p session: Direct connect blocked connection to SNI: %s (target: %s:%d)",
                        self, client_hello.sni, dst_ip, pcb->local_port);
                    goto exit_cleanup; // Terminate session
                }
            }
            if (client_hello.alpn[0]) {
                LOG_I ("%p session: Direct connect detected ALPN: %s", self,
                       client_hello.alpn);
            }
        } else {
            LOG_D ("%p session: TLS ClientHello not detected or parsing failed",
                   self);
        }
    }
    // --- HTTP Hostname-based ACL check for ports 80/8080 ---
    else if (self->queue &&
             (pcb->local_port == 80 || pcb->local_port == 8080)) {
        if (extract_http_host_from_queue (self, http_hostname, sizeof (http_hostname)) ==
            0) {
            LOG_I (
                "%p session: Direct connect detected HTTP Host: %s (target: %s:%d)",
                self, http_hostname, dst_ip, pcb->local_port);
            if (hev_filter_is_blocked_hostname (http_hostname)) {
                LOG_W (
                    "%p session: Direct connect blocked connection to HTTP Host: %s (target: %s:%d)",
                    self, http_hostname, dst_ip, pcb->local_port);
                goto exit_cleanup; // Terminate session
            }
        }
    }

    /* 获取超时配置 */
    connect_timeout = hev_config_get_misc_connect_timeout ();
    read_write_timeout = hev_config_get_misc_read_write_timeout ();

    /* 初始化空闲超时计时器 */
    idle_timer_init (&idle_timer, read_write_timeout / 1000);

    /* Build address structure */
    struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&saddr;
    saddr_len = sizeof (struct sockaddr_in6);
    memset (sa6, 0, saddr_len);
    sa6->sin6_family = AF_INET6;
    sa6->sin6_port = htons (pcb->local_port);

    if (IP_IS_V6 (&pcb->local_ip)) {
        memcpy (&sa6->sin6_addr, ip_2_ip6 (&pcb->local_ip), 16);
    } else {
        u8_t *addr_bytes = (u8_t *)&sa6->sin6_addr;
        addr_bytes[10] = 0xff;
        addr_bytes[11] = 0xff;
        memcpy (&addr_bytes[12], ip_2_ip4 (&pcb->local_ip), 4);
    }

    /* Create socket */
    fd = hev_task_io_socket_socket (AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        LOG_E ("%p session: failed to create socket: %s", self,
               strerror (errno));
        goto exit_cleanup;
    }

    /* 设置 TCP Keep-Alive(使用辅助函数) */
    set_tcp_keepalive (self, fd);

    int zero = 0;
    setsockopt (fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof (zero));

    if (hev_task_add_fd (task, fd, POLLIN | POLLOUT) < 0)
        hev_task_mod_fd (task, fd, POLLIN | POLLOUT);

    /* 连接阶段:使用 connect_timeout */
    connect_start = time (NULL);
    hev_socks5_set_timeout (s, connect_timeout);

    LOG_D ("%p session: connecting to %s:%d (timeout=%dms)", self, dst_ip,
           pcb->local_port, connect_timeout);

    if (hev_task_io_socket_connect (fd, (struct sockaddr *)&saddr, saddr_len,
                                    hev_socks5_task_io_yielder, s) < 0) {
        time_t connect_duration = time (NULL) - connect_start;
        LOG_E ("%p session: direct connect failed after %ld seconds: %s", self,
               connect_duration, strerror (errno));
        hev_task_del_fd (task, fd);
        close (fd);
        goto exit_cleanup;
    }

    LOG_I ("%p session: Direct connect established %s:%d -> %s:%d", self,
           src_ip, pcb->remote_port, dst_ip, pcb->local_port);

    /* Allocate ring buffer */
    tcp_buffer_size = hev_config_get_misc_tcp_buffer_size ();
    self->buffer = hev_ring_buffer_alloca (tcp_buffer_size);
    if (!self->buffer) {
        LOG_E ("%p session: failed to allocate ring buffer", self);
        hev_task_del_fd (task, fd);
        close (fd);
        goto exit_cleanup;
    }

    HEV_SOCKS5 (s)->fd = fd;

    /* 数据传输阶段:清除超时,依赖空闲检查 */
    hev_socks5_set_timeout (s, 0);

    /* Create backward splice task */
    stack_size = hev_config_get_misc_task_stack_size ();
    task_b = hev_task_new (stack_size);
    if (!task_b) {
        LOG_E ("%p session: failed to create backward splice task", self);
        goto cleanup_splice;
    }

    /* 分配 task 参数 */
    HevSpliceTaskData *task_data = hev_malloc (sizeof (HevSpliceTaskData));
    if (!task_data) {
        LOG_E ("%p session: failed to allocate task data", self);
        hev_task_unref (task_b);
        goto cleanup_splice;
    }
    task_data->session = self;
    task_data->timer = &idle_timer;

    hev_task_ref (task_b);
    hev_task_run (task_b, tcp_direct_splice_task_b, task_data);

    /* Forward splice:只检查空闲超时 */
    if (hev_task_mod_fd (task, fd, POLLOUT) < 0)
        hev_task_add_fd (task, fd, POLLOUT);

    LOG_D ("%p session: starting data transfer loop", self);

    for (;;) {
        int res_f = tcp_direct_splice_f (self, &idle_timer);
        if (res_f < 0) {
            LOG_D ("%p session: forward splice ended", self);
            break;
        }

        /* 只在无数据时检查空闲超时 */
        if (res_f == 0) {
            if (idle_timer_check (&idle_timer) < 0) {
                time_t idle_duration = time (NULL) - idle_timer.last_activity;
                LOG_I (
                    "%p session: Direct connect %s:%d -> %s:%d idle timeout (no activity for %ld seconds)",
                    self, src_ip, pcb->remote_port, dst_ip, pcb->local_port,
                    idle_duration);
                break;
            }
        }

        HevTaskYieldType type = (res_f > 0) ? HEV_TASK_YIELD : HEV_TASK_WAITIO;
        hev_task_yield (type);
    }

    LOG_D ("%p session: waiting for backward splice task", self);

    /* Wait for backward task */
    hev_task_join (task_b);
    hev_task_unref (task_b);

cleanup_splice:
    LOG_D ("%p session: cleaning up connection", self);

    HEV_SOCKS5 (s)->fd = -1;

    /* 优雅关闭 */
    shutdown (fd, SHUT_RDWR);
    hev_task_del_fd (task, fd);
    close (fd);

exit_cleanup:
    if (connect_start > 0) {
        session_duration = time (NULL) - connect_start;
        LOG_I (
            "%p session: Direct connect %s:%d -> %s:%d ended (duration=%ld seconds)",
            self, src_ip, pcb->remote_port, dst_ip, pcb->local_port,
            session_duration);
    } else {
        LOG_I (
            "%p session: Direct connect %s:%d -> %s:%d ended (failed before connection)",
            self, src_ip, pcb->remote_port, dst_ip, pcb->local_port);
    }

    hev_socks5_session_terminate (s);
    hev_socks5_tunnel_delete_session (node);
    hev_object_unref (HEV_OBJECT (self));
}

/* ============================================================================
   Smart Proxy Splice Implementation
   ============================================================================ */

static void
smart_proxy_splice_task_b (void *data)
{
    HevSpliceTaskData *task_data = data;
    HevSocks5SessionTCP *self = task_data->session;
    HevIdleTimer *timer = task_data->timer;
    HevTask *task = hev_task_self ();
    int fd;

    LOG_D ("%p session: smart proxy backward splice task start", self);

    fd = hev_task_io_dup (HEV_SOCKS5 (self)->fd);
    if (fd < 0) {
        LOG_E ("%p session: failed to dup fd for smart proxy backward splice",
               self);
        hev_free (task_data);
        return;
    }

    if (hev_task_add_fd (task, fd, POLLIN) < 0)
        hev_task_mod_fd (task, fd, POLLIN);

    for (;;) {
        if (tcp_direct_splice_b (self, timer) < 0)
            break;
        hev_task_yield (HEV_TASK_WAITIO);
    }

    hev_task_del_fd (task, fd);
    close (fd);
    hev_free (task_data);

    LOG_D ("%p session: smart proxy backward splice task end", self);
}

static void
run_smart_proxy_task (void *data)
{
    HevSocks5SessionTCP *self = data;
    HevSocks5Session *s = HEV_SOCKS5_SESSION (self);
    HevObjectClass *klass = HEV_OBJECT_GET_CLASS (s);
    HevSocks5SessionIface *iface =
        klass->iface (HEV_OBJECT (s), HEV_SOCKS5_SESSION_TYPE);
    struct tcp_pcb *pcb = self->pcb;
    HevTask *task = iface->get_task (s);
    HevTask *task_b = NULL;
    HevListNode *node = iface->get_node (s);
    struct sockaddr_storage saddr;
    socklen_t saddr_len;
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    int tcp_buffer_size;
    int read_write_timeout;
    int fd = -1;
    int timeout;
    int stack_size;
    HevIdleTimer idle_timer;
    time_t connect_start = 0;
    time_t connect_success_time = 0;
    time_t session_duration = 0;
    HevTLSClientHello client_hello;
    char http_hostname[256]; // Buffer for HTTP hostname
    int gfw_detected = 0;
    int first_loop = 1;
    int probe_success = 0; /* ✅ 新增：探测成功标志 */
    self->is_smart_proxy_probe = 1; //一个开关标记

    ipaddr_ntoa_r (&pcb->remote_ip, src_ip, sizeof (src_ip));
    ipaddr_ntoa_r (&pcb->local_ip, dst_ip, sizeof (dst_ip));

    LOG_D ("%p session: smart proxy task run %s:%d -> %s:%d", self, src_ip,
           pcb->remote_port, dst_ip, pcb->local_port);

    /* 等待数据到达队列（用于 SNI 检测） */
    if (pcb->local_port == 443 && !self->queue) {
        LOG_D ("%p session: Waiting for TLS ClientHello data...", self);
        for (int i = 0; i < 150 && !self->queue; i++) { /* 延长等待时间 */
            hev_task_sleep (10);
        }
        if (!self->queue) {
            LOG_W (
                "%p session: Smart proxy task timed out waiting for TLS ClientHello data (1500ms)",
                self);
        }
    }

    /* 尝试嗅探 TLS ClientHello */
    if (self->queue && pcb->local_port == 443) {
        LOG_D (
            "%p session: Attempting to sniff TLS ClientHello (%d bytes in queue)",
            self, self->queue ? self->queue->tot_len : 0);

        if (sniff_client_hello (self, &client_hello) == 0 &&
            client_hello.detected) {
            if (client_hello.sni[0]) {
                LOG_I (
                    "%p session: Smart proxy detected TLS SNI: %s (target: %s:%d)",
                    self, client_hello.sni, dst_ip, pcb->local_port);
                // --- SNI-based ACL check ---
                if (hev_filter_is_blocked_hostname (client_hello.sni)) {
                    LOG_W (
                        "%p session: Smart proxy blocked connection to SNI: %s (target: %s:%d)",
                        self, client_hello.sni, dst_ip, pcb->local_port);
                    goto exit_cleanup; // Terminate session
                }
            }
            if (client_hello.alpn[0]) {
                LOG_I ("%p session: Smart proxy detected ALPN: %s", self,
                       client_hello.alpn);
            }
        }
    }
    // --- HTTP Hostname-based ACL check for ports 80/8080 ---
    else if (self->queue &&
             (pcb->local_port == 80 || pcb->local_port == 8080)) {
        if (extract_http_host_from_queue (self, http_hostname, sizeof (http_hostname)) ==
            0) {
            LOG_I (
                "%p session: Smart proxy detected HTTP Host: %s (target: %s:%d)",
                self, http_hostname, dst_ip, pcb->local_port);
            if (hev_filter_is_blocked_hostname (http_hostname)) {
                LOG_W (
                    "%p session: Smart proxy blocked connection to HTTP Host: %s (target: %s:%d)",
                    self, http_hostname, dst_ip, pcb->local_port);
                goto exit_cleanup; // Terminate session
            }
        }
    }

    read_write_timeout = hev_config_get_misc_read_write_timeout ();
    idle_timer_init (&idle_timer, read_write_timeout / 1000);

    /* Build address */
    struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&saddr;
    saddr_len = sizeof (struct sockaddr_in6);
    memset (sa6, 0, saddr_len);
    sa6->sin6_family = AF_INET6;
    sa6->sin6_port = htons (pcb->local_port);
    if (IP_IS_V6 (&pcb->local_ip)) {
        memcpy (&sa6->sin6_addr, ip_2_ip6 (&pcb->local_ip), 16);
    } else {
        u8_t *addr_bytes = (u8_t *)&sa6->sin6_addr;
        addr_bytes[10] = 0xff;
        addr_bytes[11] = 0xff;
        memcpy (&addr_bytes[12], ip_2_ip4 (&pcb->local_ip), 4);
    }

    /* Create socket */
    fd = hev_task_io_socket_socket (AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        LOG_E ("%p session: smart proxy failed to create socket", self);
        goto fallback_socks5;
    }

    set_tcp_keepalive (self, fd);

    int zero = 0;
    setsockopt (fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof (zero));
    if (hev_task_add_fd (task, fd, POLLIN | POLLOUT) < 0)
        hev_task_mod_fd (task, fd, POLLIN | POLLOUT);

    /* ====================================================================
       🔍 阶段 1：TCP 三次握手
       ==================================================================== */
    timeout = hev_config_get_smart_proxy_timeout_ms ();
    hev_socks5_set_timeout (s, timeout);
    connect_start = time (NULL);

    LOG_D (
        "%p session: smart proxy attempting TCP handshake to %s:%d (timeout=%dms)",
        self, dst_ip, pcb->local_port, timeout);

    if (hev_task_io_socket_connect (fd, (struct sockaddr *)&saddr, saddr_len,
                                    hev_socks5_task_io_yielder, s) < 0) {
        time_t connect_duration = time (NULL) - connect_start;

        LOG_W (
            "%p session: Smart proxy TCP handshake FAILED to %s:%d after %ld ms, "
            "fallback to SOCKS5 (NOT blacklisting - may be temporary network issue)",
            self, dst_ip, pcb->local_port, connect_duration * 1000);

        hev_task_del_fd (task, fd);
        close (fd);
        goto fallback_socks5;
    }

    connect_success_time = time (NULL);
    LOG_I (
        "%p session: Smart proxy TCP handshake SUCCESS %s:%d -> %s:%d (took %ld ms)",
        self, src_ip, pcb->remote_port, dst_ip, pcb->local_port,
        (connect_success_time - connect_start) * 1000);

    /* ====================================================================
       🔍 阶段 2：等待服务器数据并验证
       ==================================================================== */
    tcp_buffer_size = hev_config_get_misc_tcp_buffer_size ();
    self->buffer = hev_ring_buffer_alloca (tcp_buffer_size);
    if (!self->buffer) {
        LOG_E ("%p session: smart proxy failed to allocate ring buffer", self);
        gfw_detected = 1;
        hev_task_del_fd (task, fd);
        close (fd);
        goto fallback_socks5;
    }

    HEV_SOCKS5 (s)->fd = fd;

    /* Create backward task */
    stack_size = hev_config_get_misc_task_stack_size ();
    task_b = hev_task_new (stack_size);
    if (!task_b) {
        LOG_E ("%p session: smart proxy failed to create backward splice task",
               self);
        goto cleanup_splice;
    }

    HevSpliceTaskData *task_data = hev_malloc (sizeof (HevSpliceTaskData));
    if (!task_data) {
        LOG_E ("%p session: smart proxy failed to allocate task data", self);
        hev_task_unref (task_b);
        goto cleanup_splice;
    }
    task_data->session = self;
    task_data->timer = &idle_timer;

    hev_task_ref (task_b);
    hev_task_run (task_b, smart_proxy_splice_task_b, task_data);

    /* Forward splice */
    if (hev_task_mod_fd (task, fd, POLLOUT) < 0)
        hev_task_add_fd (task, fd, POLLOUT);

    LOG_D (
        "%p session: smart proxy waiting for initial data from server (timeout=%dms)",
        self, timeout);

    /* ====================================================================
       🔍 数据传输循环，检测真实数据
       ==================================================================== */
    for (;;) {
        int res_f = tcp_direct_splice_f (self, &idle_timer);

        /* ====================================================================
           🔧 关键修复：先验证数据，再处理连接结束
           ==================================================================== */

        /* 🔍 关键检测点:收到数据后验证是否为真实应用数据 */
        if (first_loop && self->initial_data_received &&
            self->is_smart_proxy_probe) {
            time_t elapsed_ms = (time (NULL) - connect_success_time) * 1000;
            struct iovec iov[2];
            int iovc = hev_ring_buffer_reading (self->buffer, iov);
            int is_valid_response = 0;

            if (iovc > 0 && iov[0].iov_len > 0) {
                unsigned char *data = (unsigned char *)iov[0].iov_base;
                unsigned char first_byte = data[0];

                /* 🔍 检测 HTTP (端口 80, 8080) */
                if (pcb->local_port == 80 || pcb->local_port == 8080) {
                    if (iov[0].iov_len >= 7 &&
                        (memcmp (data, "HTTP/1.", 7) == 0 ||
                         memcmp (data, "HTTP/2", 6) == 0)) {
                        LOG_I (
                            "%p session: ✅ Smart proxy SUCCESS for HTTP port %d: "
                            "Valid HTTP response from %s (data received in %ld ms)",
                            self, pcb->local_port, dst_ip, elapsed_ms);
                        is_valid_response = 1;
                    } else {
                        LOG_W (
                            "%p session: ❌ Smart proxy received INVALID HTTP response on port %d from %s "
                            "(expected 'HTTP/', got %d bytes starting with 0x%02x), BLACKLIST",
                            self, pcb->local_port, dst_ip, (int)iov[0].iov_len,
                            first_byte);
                        hev_filter_blacklist_add (&pcb->local_ip);
                        gfw_detected = 1;
                        break;
                    }
                }
                /* 🔍 检测 HTTPS (端口 443) */
                else if (pcb->local_port == 443) {
                    if (first_byte == 0x14 || first_byte == 0x16 ||
                        first_byte == 0x17) {
                        /* ✅ Valid TLS: ChangeCipherSpec (0x14), Handshake (0x16), Application Data (0x17) */
                        const char *tls_type =
                            (first_byte == 0x14) ? "ChangeCipherSpec" :
                            (first_byte == 0x16) ? "Handshake (ServerHello)" :
                                                   "Application Data";
                        LOG_I (
                            "%p session: ✅ Smart proxy SUCCESS for HTTPS: "
                            "Valid TLS %s (0x%02x) from %s:%d (data received in %ld ms)",
                            self, tls_type, first_byte, dst_ip, pcb->local_port,
                            elapsed_ms);
                        is_valid_response = 1;
                    } else if (first_byte == 0x15) {
                        /* ❌ TLS Alert (服务器拒绝,如 SNI 不匹配) */
                        LOG_W (
                            "%p session: ❌ Smart proxy received TLS Alert (0x15) from %s:%d "
                            "(likely SNI mismatch or certificate error), BLACKLIST",
                            self, dst_ip, pcb->local_port);
                        hev_filter_blacklist_add (&pcb->local_ip);
                        gfw_detected = 1;
                        break;
                    } else {
                        /* ❌ Invalid TLS response */
                        LOG_W (
                            "%p session: ❌ Smart proxy received INVALID TLS response (0x%02x) from %s:%d "
                            "(expected 0x14/0x16/0x17), BLACKLIST",
                            self, first_byte, dst_ip, pcb->local_port);
                        hev_filter_blacklist_add (&pcb->local_ip);
                        gfw_detected = 1;
                        break;
                    }
                }
                /* 🔍 其他端口:任意数据都算成功 */
                else {
                    LOG_I (
                        "%p session: ✅ Smart proxy SUCCESS for port %d: "
                        "Received %zu bytes from %s (data received in %ld ms)",
                        self, pcb->local_port, iov[0].iov_len, dst_ip,
                        elapsed_ms);
                    is_valid_response = 1;
                }
            }

            if (is_valid_response) {
                /* ✅ 收到真实数据,标记探测成功 */
                probe_success = 1; /* 🔧 关键修复:设置成功标志 */
                LOG_I ("%p session: ✅ Smart proxy probe SUCCESS for %s:%d "
                       "(handshake OK + valid application data in %ld ms), "
                       "NOT blacklisting, continue direct connection",
                       self, dst_ip, pcb->local_port, elapsed_ms);
                hev_socks5_set_timeout (s, 0);
                first_loop = 0; /* 🔧 退出探测循环 */
            } else if (elapsed_ms >= timeout) {
                /* ❌ 超时无数据(严格按照 timeout-ms 判断) */
                LOG_W ("%p session: ❌ Smart proxy TIMEOUT for %s:%d "
                       "(handshake OK but NO valid data received in %d ms), "
                       "fallback to SOCKS5 and BLACKLIST",
                       self, dst_ip, pcb->local_port, timeout);
                hev_filter_blacklist_add (&pcb->local_ip);
                gfw_detected = 1;
                break;
            }
            /* 否则继续等待数据 */
        }

        /* ====================================================================
           🔧 关键修复：处理连接结束，但区分探测成功和失败
           ==================================================================== */
        if (res_f < 0) {
            if (probe_success) {
                /* ✅ 探测已成功，客户端关闭是正常的（HTTP 短连接） */
                LOG_D (
                    "%p session: forward splice ended after successful probe "
                    "(HTTP short connection is normal behavior)",
                    self);
            } else if (first_loop) {
                /* ❌ 探测未完成就结束，认为失败 */
                LOG_D (
                    "%p session: forward splice ended during probe (probe incomplete, considered failed)",
                    self);
            } else {
                /* 正常结束 */
                LOG_D ("%p session: forward splice ended normally", self);
            }
            break;
        }

        /* 正常的空闲超时检查（仅在收到数据后生效） */
        if (!first_loop && res_f == 0) {
            if (idle_timer_check (&idle_timer) < 0) {
                time_t idle_duration = time (NULL) - idle_timer.last_activity;
                LOG_I ("%p session: Smart proxy %s:%d -> %s:%d idle timeout "
                       "(no activity for %ld seconds)",
                       self, src_ip, pcb->remote_port, dst_ip, pcb->local_port,
                       idle_duration);
                break;
            }
        }

        HevTaskYieldType type = (res_f > 0) ? HEV_TASK_YIELD : HEV_TASK_WAITIO;
        hev_task_yield (type);
    }

    /* Wait for backward task */
    hev_task_join (task_b);
    hev_task_unref (task_b);

cleanup_splice:
    HEV_SOCKS5 (s)->fd = -1;
    shutdown (fd, SHUT_RDWR);
    hev_task_del_fd (task, fd);
    close (fd);

    if (connect_success_time > 0) {
        session_duration = time (NULL) - connect_success_time;

        if (gfw_detected) {
            LOG_I ("%p session: ❌ Smart proxy FAILED %s:%d -> %s:%d "
                   "(detected issue, fallback to SOCKS5)",
                   self, src_ip, pcb->remote_port, dst_ip, pcb->local_port);
        } else if (probe_success) {
            LOG_I (
                "%p session: ✅ Smart proxy direct connect %s:%d -> %s:%d ended "
                "(duration=%ld seconds, probe was successful)",
                self, src_ip, pcb->remote_port, dst_ip, pcb->local_port,
                session_duration);
        } else {
            LOG_I (
                "%p session: Smart proxy direct connect %s:%d -> %s:%d ended "
                "(duration=%ld seconds)",
                self, src_ip, pcb->remote_port, dst_ip, pcb->local_port,
                session_duration);
        }
    }

    /* ====================================================================
       🔧 关键修复：只有真正失败才走 fallback，探测成功就正常结束
       ==================================================================== */
    if (gfw_detected) {
        goto fallback_socks5;
    }

    /* ✅ 探测成功或正常结束，不走 SOCKS5 回退 */
    goto exit_cleanup; // Replaced return with goto exit_cleanup

fallback_socks5:
    LOG_I ("%p session: Smart proxy falling back to SOCKS5 for %s:%d -> %s:%d",
           self, src_ip, pcb->remote_port, dst_ip, pcb->local_port);

    /* 重置 buffer 指针，让 SOCKS5 可以复用 */
    if (self->buffer) {
        LOG_D ("%p session: Smart proxy buffer will be reused by SOCKS5", self);
    }

    hev_socks5_session_run (s);

    LOG_I ("%p session: SOCKS5 proxy session ended %s:%d -> %s:%d", self,
           src_ip, pcb->remote_port, dst_ip, pcb->local_port);

exit_cleanup: // Added exit_cleanup label
    hev_socks5_session_terminate (s);
    hev_socks5_tunnel_delete_session (node);
    hev_object_unref (HEV_OBJECT (self));
}

/* ============================================================================
   UDP Direct Connect Implementation (继续保持完整...)
   ============================================================================ */

typedef struct _HevDirectUDPSession
{
    struct udp_pcb *pcb;
    HevTaskMutex *mutex;
    HevTask *task_main;
    HevTask *task_recv;
    HevListNode node;
    int fd;
    int alive;

    HevList packet_queue;
    int queue_count;

    ip_addr_t dest_ip;
    u16_t dest_port;
    ip_addr_t src_ip;
    u16_t src_port;

    time_t last_activity;
    time_t session_start;
    ip_addr_t orig_dest_ip;
    u16_t orig_dest_port;
} HevDirectUDPSession;

#define UDP_ALIVE_SEND 0x01
#define UDP_ALIVE_RECV 0x02
#define UDP_IDLE_TIMEOUT 300

typedef struct _HevUDPPacket
{
    HevListNode node;
    struct pbuf *data;
} HevUDPPacket;

static void
direct_udp_cleanup (HevDirectUDPSession *session)
{
    HevListNode *node;
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    time_t session_duration;

    ipaddr_ntoa_r (&session->src_ip, src_ip, sizeof (src_ip));
    ipaddr_ntoa_r (&session->dest_ip, dst_ip, sizeof (dst_ip));
    session_duration = time (NULL) - session->session_start;

    LOG_D ("%p session: UDP cleanup started %s:%d -> %s:%d", session, src_ip,
           session->src_port, dst_ip, session->dest_port);

    if (session->fd >= 0) {
        if (session->task_main)
            hev_task_del_fd (session->task_main, session->fd);
        shutdown (session->fd, SHUT_RDWR);
        close (session->fd);
        session->fd = -1;
    }

    hev_task_mutex_lock (session->mutex);
    if (session->pcb) {
        udp_recv (session->pcb, NULL, NULL);
        udp_remove (session->pcb);
        session->pcb = NULL;
    }
    hev_task_mutex_unlock (session->mutex);

    int dropped_packets = 0;
    for (node = hev_list_first (&session->packet_queue); node;
         node = hev_list_first (&session->packet_queue)) {
        HevUDPPacket *pkt = container_of (node, HevUDPPacket, node);
        hev_list_del (&session->packet_queue, node);
        pbuf_free (pkt->data);
        hev_free (pkt);
        dropped_packets++;
    }

    if (dropped_packets > 0) {
        LOG_W ("%p session: UDP dropped %d queued packets during cleanup",
               session, dropped_packets);
    }

    LOG_I (
        "%p session: UDP Direct connect %s:%d -> %s:%d ended (duration=%ld seconds, packets_dropped=%d)",
        session, src_ip, session->src_port, dst_ip, session->dest_port,
        session_duration, dropped_packets);

    hev_socks5_tunnel_delete_session (&session->node);
    hev_free (session);
}

static void
direct_udp_recv_handler (void *arg, struct udp_pcb *pcb, struct pbuf *p,
                         const ip_addr_t *addr, u16_t port)
{
    HevDirectUDPSession *session = arg;
    HevUDPPacket *pkt;

    if (!p) {
        LOG_D (
            "%p session: UDP recv_handler got NULL pbuf, closing send direction",
            session);
        session->alive &= ~UDP_ALIVE_SEND;
        if (session->task_main)
            hev_task_wakeup (session->task_main);
        return;
    }

    session->last_activity = time (NULL);

    if (session->queue_count > 100) {
        LOG_W (
            "%p session: UDP queue full (%d packets), dropping packet of %d bytes",
            session, session->queue_count, p->tot_len);
        pbuf_free (p);
        return;
    }

    pkt = hev_malloc (sizeof (HevUDPPacket));
    if (!pkt) {
        LOG_E ("%p session: UDP failed to allocate packet structure", session);
        pbuf_free (p);
        return;
    }

    pkt->data = p;
    memset (&pkt->node, 0, sizeof (pkt->node));

    session->queue_count++;
    hev_list_add_tail (&session->packet_queue, &pkt->node);

    LOG_D ("%p session: UDP queued packet (%d bytes, queue_size=%d)", session,
           p->tot_len, session->queue_count);

    if (session->task_main)
        hev_task_wakeup (session->task_main);
}

static void
direct_udp_recv_task (void *data)
{
    HevDirectUDPSession *session = data;
    HevTask *task = hev_task_self ();
    unsigned char buffer[2048];
    struct sockaddr_storage remote_addr;
    socklen_t addr_len;
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    int fd;
    size_t total_received_bytes = 0;
    size_t total_received_packets = 0;

    ipaddr_ntoa_r (&session->src_ip, src_ip, sizeof (src_ip));
    ipaddr_ntoa_r (&session->dest_ip, dst_ip, sizeof (dst_ip));

    LOG_D ("%p session: UDP recv task start %s:%d <- %s:%d", session, src_ip,
           session->src_port, dst_ip, session->dest_port);

    fd = hev_task_io_dup (session->fd);
    if (fd < 0) {
        LOG_E ("%p session: UDP recv task failed to dup fd: %s", session,
               strerror (errno));
        session->alive &= ~UDP_ALIVE_RECV;
        return;
    }

    if (hev_task_add_fd (task, fd, POLLIN) < 0) {
        LOG_E ("%p session: UDP recv task failed to add fd", session);
        hev_task_mod_fd (task, fd, POLLIN);
    }

    session->alive |= UDP_ALIVE_RECV;

    while (session->alive & UDP_ALIVE_RECV) {
        addr_len = sizeof (remote_addr);

        time_t now = time (NULL);
        time_t idle_time = now - session->last_activity;
        if (idle_time > UDP_IDLE_TIMEOUT) {
            LOG_I (
                "%p session: UDP recv task idle timeout (no activity for %ld seconds)",
                session, idle_time);
            break;
        }

        ssize_t received = recvfrom (fd, buffer, sizeof (buffer), 0,
                                     (struct sockaddr *)&remote_addr,
                                     &addr_len);

        if (received < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                hev_task_yield (HEV_TASK_WAITIO);
                continue;
            }
            LOG_E ("%p session: UDP recvfrom failed: %s", session,
                   strerror (errno));
            break;
        }

        if (received == 0) {
            LOG_W ("%p session: UDP recvfrom returned 0", session);
            break;
        }

        session->last_activity = now;
        total_received_bytes += received;
        total_received_packets++;

        LOG_D (
            "%p session: UDP received %zd bytes from server (total=%zu packets, %zu bytes)",
            session, received, total_received_packets, total_received_bytes);

        struct pbuf *p = pbuf_alloc (PBUF_TRANSPORT, received, PBUF_RAM);
        if (p) {
            memcpy (p->payload, buffer, received);

            hev_task_mutex_lock (session->mutex);
            if (session->pcb) {
                char orig_dst_ip[INET6_ADDRSTRLEN];
                ipaddr_ntoa_r (&session->orig_dest_ip, orig_dst_ip,
                               sizeof (orig_dst_ip));
                LOG_D ("%p session: UDP sending from spoofed source %s:%d",
                       session, orig_dst_ip, session->orig_dest_port);
                err_t err = udp_sendfrom (session->pcb, p,
                                          &session->orig_dest_ip,
                                          session->orig_dest_port);
                if (err != ERR_OK) {
                    LOG_E ("%p session: UDP udp_sendfrom failed: %d", session,
                           err);
                } else {
                    LOG_D ("%p session: UDP forwarded %d bytes to client %s:%d",
                           session, received, src_ip, session->src_port);
                }
            } else {
                LOG_W ("%p session: UDP pcb is NULL, cannot forward packet",
                       session);
            }
            hev_task_mutex_unlock (session->mutex);
            pbuf_free (p);
        } else {
            LOG_E ("%p session: UDP failed to allocate pbuf for %zd bytes",
                   session, received);
        }
    }

    session->alive &= ~UDP_ALIVE_RECV;
    hev_task_del_fd (task, fd);
    close (fd);

    LOG_D ("%p session: UDP recv task end (received %zu packets, %zu bytes)",
           session, total_received_packets, total_received_bytes);
}

static void
run_direct_udp_task (void *data)
{
    HevDirectUDPSession *session = data;
    struct sockaddr_storage dest_addr;
    socklen_t addr_len;
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    int stack_size;
    size_t total_sent_bytes = 0;
    size_t total_sent_packets = 0;

    ipaddr_ntoa_r (&session->src_ip, src_ip, sizeof (src_ip));
    ipaddr_ntoa_r (&session->dest_ip, dst_ip, sizeof (dst_ip));

    LOG_D ("%p session: UDP send task start %s:%d -> %s:%d", session, src_ip,
           session->src_port, dst_ip, session->dest_port);

    session->last_activity = get_current_time_seconds ();
    session->session_start = get_current_time_seconds ();

    /* Log with millisecond precision for debugging */
    time_t current_ms = get_current_time_ms ();
    LOG_D ("%p session: UDP session created at %ld ms", session,
           current_ms % 1000);

    session->fd = hev_task_io_socket_socket (AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (session->fd < 0) {
        LOG_E ("%p session: UDP failed to create socket: %s", session,
               strerror (errno));
        goto cleanup;
    }

    int zero = 0;
    setsockopt (session->fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof (zero));

    if (hev_task_add_fd (hev_task_self (), session->fd, POLLOUT) < 0)
        hev_task_mod_fd (hev_task_self (), session->fd, POLLOUT);

    hev_task_mutex_lock (session->mutex);
    if (session->pcb) {
        udp_recv (session->pcb, direct_udp_recv_handler, session);
    }
    hev_task_mutex_unlock (session->mutex);

    struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&dest_addr;
    addr_len = sizeof (struct sockaddr_in6);
    memset (sa6, 0, addr_len);
    sa6->sin6_family = AF_INET6;
    sa6->sin6_port = htons (session->dest_port);

    if (IP_IS_V6 (&session->dest_ip)) {
        memcpy (&sa6->sin6_addr, ip_2_ip6 (&session->dest_ip), 16);
        LOG_D ("%p session: UDP target is IPv6: %s:%d", session, dst_ip,
               session->dest_port);
    } else {
        u8_t *addr_bytes = (u8_t *)&sa6->sin6_addr;
        addr_bytes[10] = 0xff;
        addr_bytes[11] = 0xff;
        memcpy (&addr_bytes[12], ip_2_ip4 (&session->dest_ip), 4);
        LOG_D ("%p session: UDP target is IPv4 (mapped to IPv6): %s:%d",
               session, dst_ip, session->dest_port);
    }

    stack_size = hev_config_get_misc_task_stack_size ();
    session->task_recv = hev_task_new (stack_size);
    if (!session->task_recv) {
        LOG_E ("%p session: UDP failed to create recv task", session);
        goto cleanup;
    }

    hev_task_ref (session->task_recv);
    hev_task_run (session->task_recv, direct_udp_recv_task, session);

    session->alive = UDP_ALIVE_SEND | UDP_ALIVE_RECV;

    LOG_I ("%p session: UDP Direct connect established %s:%d -> %s:%d", session,
           src_ip, session->src_port, dst_ip, session->dest_port);

    for (;;) {
        HevListNode *node = hev_list_first (&session->packet_queue);
        if (!node) {
            if (!(session->alive & UDP_ALIVE_SEND)) {
                LOG_D ("%p session: UDP send direction closed", session);
                break;
            }

            time_t now = get_current_time_seconds ();
            time_t idle_time = now - session->last_activity;
            if (idle_time > UDP_IDLE_TIMEOUT) {
                LOG_I (
                    "%p session: UDP send task idle timeout (no activity for %ld seconds)",
                    session, idle_time);
                break;
            }

            hev_task_yield (HEV_TASK_WAITIO);
            continue;
        }

        HevUDPPacket *pkt = container_of (node, HevUDPPacket, node);
        struct pbuf *p = pkt->data;

        if (p->len > 8) {
            unsigned char *data = (unsigned char *)p->payload;
            uint16_t check_port = (data[2] << 8) | data[3];
            if (check_port == session->dest_port) {
                if (pbuf_remove_header (p, 8) != 0) {
                    LOG_E ("%p session: UDP failed to remove header", session);
                    hev_list_del (&session->packet_queue, node);
                    pbuf_free (p);
                    hev_free (pkt);
                    session->queue_count--;
                    continue;
                }
                LOG_D ("%p session: UDP removed 8-byte header", session);
            }
        }

        ssize_t sent = sendto (session->fd, p->payload, p->len, 0,
                               (struct sockaddr *)&dest_addr, addr_len);

        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                hev_task_yield (HEV_TASK_WAITIO);
                continue;
            }
            LOG_W ("%p session: UDP sendto failed: %s", session,
                   strerror (errno));
        } else {
            session->last_activity = get_current_time_seconds ();
            total_sent_bytes += sent;
            total_sent_packets++;

            LOG_D (
                "%p session: UDP sent %zd bytes to server (total=%zu packets, %zu bytes)",
                session, sent, total_sent_packets, total_sent_bytes);
        }

        hev_list_del (&session->packet_queue, node);
        pbuf_free (p);
        hev_free (pkt);
        session->queue_count--;
    }

    session->alive &= ~UDP_ALIVE_SEND;

    LOG_D ("%p session: UDP waiting for recv task to complete", session);

    hev_task_join (session->task_recv);
    hev_task_unref (session->task_recv);

cleanup:
    LOG_I (
        "%p session: UDP Direct connect cleanup (sent %zu packets/%zu bytes, alive=0x%02x)",
        session, total_sent_packets, total_sent_bytes, session->alive);
    direct_udp_cleanup (session);
}

void
hev_session_manager_start_direct_udp (struct udp_pcb *pcb,
                                      const ip_addr_t *addr, u16_t port,
                                      const ip_addr_t *orig_addr,
                                      u16_t orig_port, struct pbuf *p)
{
    HevDirectUDPSession *session;
    HevUDPPacket *pkt;
    int stack_size;
    HevTask *task;
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];

    session = hev_malloc0 (sizeof (HevDirectUDPSession));
    if (!session) {
        pbuf_free (p);
        udp_remove (pcb);
        return;
    }

    stack_size = hev_config_get_misc_task_stack_size ();
    task = hev_task_new (stack_size);
    if (!task) {
        LOG_E ("session: UDP failed to create task");
        hev_free (session);
        pbuf_free (p);
        udp_remove (pcb);
        return;
    }

    session->pcb = pcb;
    session->mutex = &mutex;
    session->task_main = task;
    session->fd = -1;

    ip_addr_copy (session->dest_ip, *addr);
    session->dest_port = port;
    ip_addr_copy (session->orig_dest_ip, *orig_addr);
    session->orig_dest_port = orig_port;
    ip_addr_copy (session->src_ip, pcb->remote_ip);
    session->src_port = pcb->remote_port;

    pkt = hev_malloc (sizeof (HevUDPPacket));
    if (pkt) {
        pkt->data = p;
        memset (&pkt->node, 0, sizeof (pkt->node));
        hev_list_add_tail (&session->packet_queue, &pkt->node);
        session->queue_count = 1;
    } else {
        LOG_W ("%p session: UDP failed to allocate first packet structure",
               session);
        pbuf_free (p);
    }

    ipaddr_ntoa_r (&session->src_ip, src_ip, sizeof (src_ip));
    ipaddr_ntoa_r (&session->dest_ip, dst_ip, sizeof (dst_ip));

    LOG_I (
        "%p session: UDP Direct connect started %s:%d -> %s:%d (first_packet=%d bytes)",
        session, src_ip, session->src_port, dst_ip, port, p ? p->tot_len : 0);

    hev_socks5_tunnel_insert_session (&session->node);
    hev_task_run (task, run_direct_udp_task, session);
}

/*
 * ============================================================================
 * Zero-Copy Protocol Parsing Optimization Functions
 * ============================================================================
 */

/**
 * @brief 零拷贝优化控制变量
 */
static int protocol_zerocopy_enabled = 0;


/**
 * @brief 启用协议解析零拷贝优化
 *
 * @return int 成功返回0，失败返回-1
 */
int
hev_session_manager_enable_protocol_zerocopy (void)
{
    protocol_zerocopy_enabled = 1;
    LOG_I ("Session manager: protocol zero-copy optimization enabled");
    return 0;
}

/**
 * @brief 禁用协议解析零拷贝优化
 */
void
hev_session_manager_disable_protocol_zerocopy (void)
{
    protocol_zerocopy_enabled = 0;
    LOG_I ("Session manager: protocol zero-copy optimization disabled");
}

/**
 * @brief 检查协议解析零拷贝优化是否启用
 *
 * @return int 启用返回1，未启用返回0
 */
int
hev_session_manager_is_protocol_zerocopy_enabled (void)
{
    return protocol_zerocopy_enabled;
}