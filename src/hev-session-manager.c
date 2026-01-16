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
#include <poll.h>
#include <arpa/inet.h>
#include <stddef.h>
#include <time.h>
#include <strings.h> /* For strcasestr */
#include <fcntl.h> /* For fcntl, O_NONBLOCK */

/* memmem compatibility for systems without _GNU_SOURCE */

/* ⬇️ Include hev project headers (including lwIP) */
#include <hev-task.h>
#include <hev-task-system.h>
#include <hev-task-io.h>
#include <hev-task-io-socket.h>
#include <hev-memory-allocator.h>
#include <hev-object.h>
#include <hev-socks5.h>
#include <hev-socks5-misc.h>
#include <hev-socks5-client-udp.h>

#include "hev-config.h"
#include "hev-utils.h"
#include "hev-logger.h"
#include "hev-compiler.h"
#include "hev-socks5-session.h"
#include "hev-socks5-session-tcp.h"
#include "hev-socks5-tunnel.h"
#include "hev-traffic-router.h"
#include "hev-filter.h"
#include "hev-dns-cache.h"
#include "hev-dns-latency.h"

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
    const char *task_name;
} HevSpliceTaskData;

/* Forward declarations */
static void run_direct_connect_task (void *data);
static void run_smart_proxy_task (void *data);
static void run_domain_first_task (void *data);
static void hev_socks5_session_task_entry (void *data);
static void tcp_splice_task_b (void *data);

/* ============================================================================
   High-Precision Time Functions
   Note: get_current_time_ms and get_current_time_seconds are now in hev-utils.c
   ============================================================================ */

/* High-precision timeout check for smart proxy (placeholder for future use) */
/* static int check_smart_proxy_timeout_ms (time_t start_time_ms, int timeout_ms); */

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

    time_t now = get_current_time_seconds ();
    if (now - timer->last_activity > timer->idle_timeout) {
        return -1; /* 超时 */
    }
    return 0;
}

/* ============================================================================
   Common Helper Functions - Extracted to Reduce Code Duplication
   ============================================================================ */

/**
 * get_session_addresses - Get source and destination IP addresses as strings
 * @pcb: TCP PCB
 * @src_ip: Output buffer for source IP (must be INET6_ADDRSTRLEN bytes)
 * @dst_ip: Output buffer for destination IP (must be INET6_ADDRSTRLEN bytes)
 */
static void
get_session_addresses (struct tcp_pcb *pcb, char *src_ip, char *dst_ip)
{
    ipaddr_ntoa_r (&pcb->remote_ip, src_ip, INET6_ADDRSTRLEN);
    ipaddr_ntoa_r (&pcb->local_ip, dst_ip, INET6_ADDRSTRLEN);
}

/**
 * get_udp_session_addresses - Get UDP session source and destination IP addresses
 * @src_ip: Source IP address
 * @src_port: Source port
 * @dst_ip: Destination IP address
 * @dst_port: Destination port
 * @out_src_ip: Output buffer for source IP (must be INET6_ADDRSTRLEN bytes)
 * @out_dst_ip: Output buffer for destination IP (must be INET6_ADDRSTRLEN bytes)
 */
static void
get_udp_session_addresses (const ip_addr_t *src_ip, u16_t src_port,
                           const ip_addr_t *dst_ip, u16_t dst_port,
                           char *out_src_ip, char *out_dst_ip)
{
    ipaddr_ntoa_r (src_ip, out_src_ip, INET6_ADDRSTRLEN);
    ipaddr_ntoa_r (dst_ip, out_dst_ip, INET6_ADDRSTRLEN);
}

/**
 * ipaddr_to_str - Convert ip_addr_t to string for logging
 * @ip: IP address
 * @buf: Output buffer (must be INET6_ADDRSTRLEN bytes)
 */
static void
ipaddr_to_str (const ip_addr_t *ip, char *buf)
{
    ipaddr_ntoa_r (ip, buf, INET6_ADDRSTRLEN);
}

/**
 * build_ipv6_sockaddr - Build IPv6 socket address structure from ip_addr_t
 * @ip: IP address (can be IPv4 or IPv6)
 * @port: Port number (host byte order)
 * @saddr: Output socket address storage
 * @saddr_len: Output length of socket address
 */
static void
build_ipv6_sockaddr (const ip_addr_t *ip, u16_t port,
                     struct sockaddr_storage *saddr, socklen_t *saddr_len)
{
    struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)saddr;
    *saddr_len = sizeof (struct sockaddr_in6);
    memset (sa6, 0, *saddr_len);
    sa6->sin6_family = AF_INET6;
    sa6->sin6_port = htons (port);

    if (IP_IS_V6 (ip)) {
        memcpy (&sa6->sin6_addr, ip_2_ip6 (ip), 16);
    } else {
        u8_t *addr_bytes = (u8_t *)&sa6->sin6_addr;
        addr_bytes[10] = 0xff;
        addr_bytes[11] = 0xff;
        memcpy (&addr_bytes[12], ip_2_ip4 (ip), 4);
    }
}

/**
 * create_tcp_socket - Create and configure a TCP socket
 * @task: Task for file descriptor management
 * @session_name: Session name for logging
 * @return: Socket file descriptor or -1 on error
 */
static int
create_tcp_socket (HevTask *task, const char *session_name)
{
    int fd = hev_task_io_socket_socket (AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        LOG_E ("session: %s failed to create socket: %s", session_name,
               strerror (errno));
        return -1;
    }

    int zero = 0;
    setsockopt (fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof (zero));

    if (hev_task_add_fd (task, fd, POLLIN | POLLOUT) < 0)
        hev_task_mod_fd (task, fd, POLLIN | POLLOUT);

    return fd;
}

/**
 * cleanup_socket - Clean up a socket properly
 * @s: Socks5 session
 * @task: Task for file descriptor management
 * @fd: Socket file descriptor
 */
static void
cleanup_socket (HevSocks5Session *s, HevTask *task, int fd)
{
    HEV_SOCKS5 (s)->fd = -1;
    shutdown (fd, SHUT_RDWR);
    hev_task_del_fd (task, fd);
    close (fd);
}

/**
 * init_session_idle_timer - Initialize idle timer with TCP read-write timeout
 * @timer: Idle timer to initialize
 */
static void
init_session_idle_timer (HevIdleTimer *timer)
{
    int timeout = hev_config_get_misc_tcp_read_write_timeout ();
    idle_timer_init (timer, timeout / 1000);
}

/**
 * create_splice_task_data - Create task data for splice tasks
 * @session: TCP session
 * @timer: Idle timer
 * @task_name: Task name for logging
 * @return: Allocated task data or NULL on failure
 */
static HevSpliceTaskData *
create_splice_task_data (HevSocks5SessionTCP *session, HevIdleTimer *timer,
                         const char *task_name)
{
    HevSpliceTaskData *task_data = hev_malloc (sizeof (HevSpliceTaskData));
    if (!task_data) {
        LOG_E ("%p session: failed to allocate task data", session);
        return NULL;
    }

    task_data->session = session;
    task_data->timer = timer;
    task_data->task_name = task_name;
    return task_data;
}

/**
 * cleanup_session - Clean up session resources
 * @s: Socks5 session
 * @node: Session list node
 */
static void
cleanup_session (HevSocks5Session *s, HevListNode *node)
{
    hev_socks5_session_terminate (s);
    hev_socks5_tunnel_delete_session (node);
    hev_object_unref (HEV_OBJECT (s));
}

/**
 * log_session_end_with_duration - Log session end with duration info
 * @self: TCP session
 * @connect_start: Connection start time (ms)
 * @session_type: Session type name
 * @src_ip: Source IP address
 * @src_port: Source port
 * @dst_ip: Destination IP address
 * @dst_port: Destination port
 */
static void
log_session_end_with_duration (HevSocks5SessionTCP *self, time_t connect_start,
                               const char *session_type, const char *src_ip,
                               int src_port, const char *dst_ip, int dst_port)
{
    if (connect_start > 0) {
        time_t duration = get_current_time_ms () - connect_start;
        LOG_I ("%p session: %s %s:%d -> %s:%d ended (duration=%ld ms)", self,
               session_type, src_ip, src_port, dst_ip, dst_port, duration);
    } else {
        LOG_I ("%p session: %s %s:%d -> %s:%d ended (failed before connection)",
               self, session_type, src_ip, src_port, dst_ip, dst_port);
    }
}

/* ============================================================================
   Domain-First Routing Task - Refactored for Clarity
   ============================================================================ */

static void
run_domain_first_task (void *data)
{
    HevSocks5SessionTCP *self = data;
    struct tcp_pcb *pcb = self->pcb;
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];

    get_session_addresses (pcb, src_ip, dst_ip);

    LOG_I ("%p [DOMAIN-FIRST] Routing %s:%d -> %s:%d", self, src_ip,
           pcb->remote_port, dst_ip, pcb->local_port);

    /*
     * Phase 1: Data Sniffing
     * Wait for the client's first data packet (e.g., ClientHello or HTTP GET)
     * and try to extract the hostname from it.
     */
    char http_hostname[256] = { 0 };
    int hostname_found = 0;
    int is_probe_port = hev_config_is_smart_proxy_probe_port (pcb->local_port);

    if (unlikely (is_probe_port)) {
        if (!self->queue) {
            LOG_D ("%p [DOMAIN-FIRST] Waiting for protocol data on port %d...",
                   self, pcb->local_port);
            for (int i = 0; i < 150 && !self->queue; i++) {
                hev_task_sleep (10);
            }
            if (!self->queue) {
                LOG_W (
                    "%p [DOMAIN-FIRST] Timed out waiting for protocol data on port %d (1500ms)",
                    self, pcb->local_port);
            }
        }

        if (self->queue) {
            if (hev_filter_sniff_pcb_hostname (pcb, self->queue, http_hostname,
                                               sizeof (http_hostname)) == 0) {
                hostname_found = 1;
                /* Save hostname for use in subsequent tasks */
                snprintf (self->detected_hostname,
                          sizeof (self->detected_hostname), "%s",
                          http_hostname);
                LOG_I (
                    "%p [DOMAIN-FIRST] Detected hostname: %s (target: %s:%d)",
                    self, http_hostname, dst_ip, pcb->local_port);
            }
        }
    }

    /*
     * Phase 2: Routing Decision
     * Combine IP/Port (Stage 1) and Domain (Stage 2) ACL results to determine
     * the final routing action.
     */
    typedef enum
    {
        NEXT_ACTION_DIRECT,
        NEXT_ACTION_SOCKS5,
        NEXT_ACTION_BLOCK,
    } NextAction;
    NextAction next_action;

    HevACLResult stage1_result =
        hev_acl_match_stage1_connection (&pcb->local_ip, pcb->local_port);
    HevACLResult stage2_result = { .matched = 0 };

    if (hostname_found) {
        stage2_result =
            hev_acl_match_stage2_domain (http_hostname, pcb->local_port);
    }

    HevACLAction final_action =
        hev_acl_check_final_decision (&stage1_result, &stage2_result);

    switch (final_action) {
    case HEV_ACL_ACTION_ALLOW:
        LOG_D ("%p [DOMAIN-FIRST] ACL ALLOW -> Direct", self);
        next_action = NEXT_ACTION_DIRECT;
        break;

    case HEV_ACL_ACTION_BLOCK:
        LOG_W ("%p [DOMAIN-FIRST] ACL BLOCK -> Reject", self);
        next_action = NEXT_ACTION_BLOCK;
        break;

    case HEV_ACL_ACTION_DEFAULT:
    default:
        if (hev_filter_is_domestic (&pcb->local_ip)) {
            LOG_D ("%p [DOMAIN-FIRST] Domestic IP -> Direct", self);
            next_action = NEXT_ACTION_DIRECT;
        } else {
            LOG_D ("%p [DOMAIN-FIRST] Foreign IP -> SOCKS5", self);
            next_action = NEXT_ACTION_SOCKS5;
        }
        break;
    }

    /*
     * Phase 3: Session Transition
     * Based on the decision, either block the connection or clean up the
     * current session and hand over to the next one (Direct or SOCKS5).
     */
    if (next_action == NEXT_ACTION_BLOCK) {
        tcp_abort (pcb);
    } else {
        /* Common logic for both DIRECT and SOCKS5 transitions */
        struct pbuf *saved_queue = self->queue;

        if (saved_queue) {
            LOG_D (
                "%p [DOMAIN-FIRST] Preserving %d bytes of queued data for next session",
                self, saved_queue->tot_len);
            self->queue =
                NULL; /* Detach queue to prevent it from being freed */
        }

        /* Detach PCB to prevent it from being aborted */
        self->pcb = NULL;

        /* Hand over to the next session manager */
        const char *hostname_to_pass = hostname_found ? http_hostname : NULL;
        if (next_action == NEXT_ACTION_DIRECT) {
            LOG_I ("%p [DOMAIN-FIRST] Route: Direct", self);
            hev_session_manager_start_task (
                pcb, saved_queue, HEV_SESSION_DIRECT, hostname_to_pass);
        } else { /* NEXT_ACTION_SOCKS5 */
            /* Priority 4: Smart proxy for foreign IPs on probe ports */
            int smart_proxy_enabled =
                hev_config_get_smart_proxy_enabled () &&
                hev_config_get_smart_proxy_timeout_ms () > 0 &&
                hev_config_get_smart_proxy_blocked_ip_expiry_minutes () > 0;
            int is_gfw_blocked = hev_filter_is_gfw_blocked (
                &pcb->local_ip, hostname_found ? http_hostname : NULL,
                pcb->local_port);

            if (unlikely (smart_proxy_enabled && is_probe_port &&
                          !is_gfw_blocked)) {
                LOG_I ("%p [DOMAIN-FIRST] Route: Smart Proxy (probe mode)",
                       self);
                hev_session_manager_start_task (pcb, saved_queue,
                                                HEV_SESSION_SMART_PROXY,
                                                hostname_to_pass);
            } else {
                LOG_I ("%p [DOMAIN-FIRST] Route: SOCKS5", self);
                hev_session_manager_start_task (
                    pcb, saved_queue, HEV_SESSION_SOCKS5, hostname_to_pass);
            }
        }
    }

    /* Finally, clean up the current domain-first session object */
    hev_socks5_tunnel_delete_session (
        hev_socks5_session_get_node (HEV_SOCKS5_SESSION (self)));
    hev_object_unref (HEV_OBJECT (self));
}

/* ============================================================================
   SOCKS5 TCP 任务入口 - 在这里嗅探 SNI
   ============================================================================ */

static void
hev_socks5_session_task_entry (void *data)
{
    HevSocks5Session *s = data;

    LOG_D ("%p session: socks5 proxy task entry", s);

    /*
     * Note: ACL checking and hostname detection are already done in
     * run_domain_first_task before reaching here. No redundant checks needed.
     */
    hev_socks5_session_run (s);

    LOG_D ("%p session: socks5 proxy task exit", s);

    hev_socks5_tunnel_delete_session (hev_socks5_session_get_node (s));
    hev_object_unref (HEV_OBJECT (s));
}

/* Internal helper to get task entry and name from session type */
static struct
{
    HevTaskEntry task_entry;
    const char *name;
} session_type_info[] = {
    { hev_socks5_session_task_entry, "SOCKS5" },
    { run_direct_connect_task, "direct" },
    { run_smart_proxy_task, "smart-proxy" },
    { run_domain_first_task, "domain-first" },
};

/* Internal helper to start a session with a specific task entry */
void
hev_session_manager_start_task (struct tcp_pcb *pcb, struct pbuf *queue,
                                HevSessionType session_type,
                                const char *hostname)
{
    HevSocks5SessionTCP *tcp;
    HevTask *task;
    HevListNode *node;
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    HevTaskEntry task_entry;
    const char *session_name;
    int stack_size;

    if (session_type < 0 || session_type >= sizeof (session_type_info) /
                                                sizeof (session_type_info[0])) {
        tcp_abort (pcb);
        if (queue)
            pbuf_free (queue);
        return;
    }

    task_entry = session_type_info[session_type].task_entry;
    session_name = session_type_info[session_type].name;

    tcp = hev_socks5_session_tcp_new (pcb, &mutex);
    if (!tcp) {
        tcp_abort (pcb);
        if (queue)
            pbuf_free (queue);
        return;
    }

    /* Transfer saved queue data to new session */
    if (queue) {
        tcp->queue = queue;
    }

    /* Transfer detected hostname to new session (for blacklist usage) */
    if (hostname && hostname[0]) {
        snprintf (tcp->detected_hostname, sizeof (tcp->detected_hostname), "%s",
                  hostname);
        LOG_D ("%p [%s] Transferred hostname '%s' to new session", tcp,
               session_name, hostname);
    }

    get_session_addresses (pcb, src_ip, dst_ip);
    LOG_I ("%p [%s] started %s:%d -> %s:%d", tcp, session_name, src_ip,
           pcb->remote_port, dst_ip, pcb->local_port);

    /* Create and run task */
    stack_size = hev_config_get_misc_task_stack_size ();
    task = hev_task_new (stack_size);
    if (!task) {
        LOG_E ("%p [%s] Failed to create task", tcp, session_name);
        hev_object_unref (HEV_OBJECT (tcp));
        return;
    }

    hev_socks5_session_set_task (HEV_SOCKS5_SESSION (tcp), task);
    node = hev_socks5_session_get_node (HEV_SOCKS5_SESSION (tcp));
    hev_socks5_tunnel_insert_session (node);
    hev_task_run (task, task_entry, tcp);
}

/* ============================================================================
   TCP Direct Connect Splice Implementation
   ============================================================================ */

static int
tcp_direct_splice_f (HevSocks5SessionTCP *self, HevIdleTimer *timer)
{
    struct iovec iov[128]; /* 增加到 128 以批量处理更多 pbuf */
    struct pbuf *p;
    int iovc = 0;
    int res = 1;

    if (self->queue) {
        /* 批量收集所有可用的 pbuf */
        for (p = self->queue; p && (iovc < 128); p = p->next, iovc++) {
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

            LOG_D ("%p [SPLICE] forward sent %zd bytes (iovc=%d)", self, s,
                   iovc);

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
    struct iovec iov[16]; /* 增加到 16 以批量处理更多数据 */
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

            LOG_D ("%p [SPLICE] backward received %zd bytes (iovc=%d)", self, s,
                   iovc);

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
            /* 批量写入 lwIP PCB，减少 tcp_output 调用次数 */
            for (i = 0; i < iovc; i++) {
                void *ptr = iov[i].iov_base;
                size_t len = iov[i].iov_len;
                err |= tcp_write (self->pcb, ptr, len, 0);
                s += len;
            }
            hev_ring_buffer_read_finish (self->buffer, s);
            err |= tcp_output (self->pcb); /* 只调用一次 tcp_output */
            res = 1;
        } else if (res < 0) {
            LOG_D ("%p [SPLICE] backward EOF, shutting down pcb write", self);
            tcp_shutdown (self->pcb, 0, 1);
        }
    }
    hev_task_mutex_unlock (self->mutex);
    if (!self->pcb || (err != ERR_OK))
        res = -1;

    return res;
}

static void
tcp_splice_task_b (void *data)
{
    HevSpliceTaskData *task_data = data;
    HevSocks5SessionTCP *self = task_data->session;
    HevIdleTimer *timer = task_data->timer;
    const char *task_name = task_data->task_name;
    HevTask *task = hev_task_self ();
    int fd;

    LOG_D ("%p [SPLICE-B] %s backward splice task start", self, task_name);

    fd = hev_task_io_dup (HEV_SOCKS5 (self)->fd);
    if (fd < 0) {
        LOG_E ("%p session: failed to dup fd for %s backward splice", self,
               task_name);
        hev_free (task_data);
        return;
    }

    if (hev_task_add_fd (task, fd, POLLIN) < 0)
        hev_task_mod_fd (task, fd, POLLIN);

    for (;;) {
        /* 检查隧道是否已停止，如果是则退出后台任务 */
        if (!hev_socks5_tunnel_is_running ()) {
            LOG_D ("%p [SPLICE-B] %s tunnel stopped, exiting", self, task_name);
            break;
        }
        if (tcp_direct_splice_b (self, timer) < 0)
            break;
        hev_task_yield (HEV_TASK_WAITIO);
    }

    hev_task_del_fd (task, fd);
    close (fd);
    hev_free (task_data);

    LOG_D ("%p [SPLICE-B] %s backward splice task end", self, task_name);
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
    int fd = -1;
    int stack_size;
    HevIdleTimer idle_timer;
    time_t connect_start = 0;

    get_session_addresses (pcb, src_ip, dst_ip);

    LOG_D ("%p [DIRECT] Task run %s:%d -> %s:%d", self, src_ip,
           pcb->remote_port, dst_ip, pcb->local_port);

    /*
     * Note: ACL checking and hostname detection are already done in
     * run_domain_first_task before reaching here. No redundant checks needed.
     */

    connect_timeout = hev_config_get_misc_connect_timeout ();
    init_session_idle_timer (&idle_timer);

    build_ipv6_sockaddr (&pcb->local_ip, pcb->local_port, &saddr, &saddr_len);

    fd = create_tcp_socket (task, "direct connect");
    if (fd < 0) {
        goto exit_cleanup;
    }

    /* 连接阶段:使用 connect_timeout */
    connect_start = get_current_time_ms ();
    hev_socks5_set_timeout (s, connect_timeout);

    LOG_D ("%p [DIRECT] Connecting to %s:%d (timeout=%dms)", self, dst_ip,
           pcb->local_port, connect_timeout);

    if (hev_task_io_socket_connect (fd, (struct sockaddr *)&saddr, saddr_len,
                                    hev_socks5_task_io_yielder, s) < 0) {
        time_t connect_duration_ms = get_current_time_ms () - connect_start;
        LOG_E ("%p [DIRECT] Connect failed after %ld ms: %s", self,
               connect_duration_ms, strerror (errno));
        hev_task_del_fd (task, fd);
        close (fd);
        goto exit_cleanup;
    }

    LOG_I ("%p [DIRECT] Connected %s:%d -> %s:%d", self, src_ip,
           pcb->remote_port, dst_ip, pcb->local_port);

    /* Allocate ring buffer */
    tcp_buffer_size = hev_config_get_misc_tcp_buffer_size ();
    self->buffer = hev_ring_buffer_alloca (tcp_buffer_size);
    if (!self->buffer) {
        LOG_E ("%p [DIRECT] Failed to allocate ring buffer", self);
        cleanup_socket (s, task, fd);
        goto exit_cleanup;
    }

    HEV_SOCKS5 (s)->fd = fd;

    /* 数据传输阶段:清除超时,依赖空闲检查 */
    hev_socks5_set_timeout (s, 0);

    /* Create backward splice task */
    stack_size = hev_config_get_misc_task_stack_size ();
    task_b = hev_task_new (stack_size);
    if (!task_b) {
        LOG_E ("%p [DIRECT] Failed to create backward splice task", self);
        goto cleanup_splice;
    }

    HevSpliceTaskData *task_data =
        create_splice_task_data (self, &idle_timer, "direct connect");
    if (!task_data) {
        hev_task_unref (task_b);
        goto cleanup_splice;
    }

    hev_task_ref (task_b);
    hev_task_run (task_b, tcp_splice_task_b, task_data);

    /* Forward splice:只检查空闲超时 */
    if (hev_task_mod_fd (task, fd, POLLOUT) < 0)
        hev_task_add_fd (task, fd, POLLOUT);

    LOG_D ("%p [DIRECT] Starting data transfer loop", self);

    for (;;) {
        /* 检查隧道是否已停止 */
        if (!hev_socks5_tunnel_is_running ()) {
            LOG_D ("%p [DIRECT] tunnel stopped, exiting", self);
            break;
        }
        int res_f = tcp_direct_splice_f (self, &idle_timer);
        if (res_f < 0) {
            LOG_D ("%p [DIRECT] Forward splice ended", self);
            break;
        }

        /* 只在无数据时检查空闲超时 */
        if (res_f == 0) {
            if (idle_timer_check (&idle_timer) < 0) {
                time_t idle_duration =
                    get_current_time_seconds () - idle_timer.last_activity;
                LOG_I (
                    "%p [DIRECT] Idle timeout %s:%d -> %s:%d (no activity for %ld seconds)",
                    self, src_ip, pcb->remote_port, dst_ip, pcb->local_port,
                    idle_duration);
                break;
            }
        }

        HevTaskYieldType type = (res_f > 0) ? HEV_TASK_YIELD : HEV_TASK_WAITIO;
        hev_task_yield (type);
    }

    LOG_D ("%p [DIRECT] Waiting for backward splice task", self);

    /* Wait for backward task */
    if (hev_socks5_tunnel_is_running ()) {
        /* Only join if tunnel is still running. During shutdown, the
         * background task has already exited due to tunnel status check. */
        hev_task_join (task_b);
    } else {
        LOG_D ("%p [DIRECT] Tunnel stopped, skipping task join", self);
    }
    hev_task_unref (task_b);

cleanup_splice:
    LOG_D ("%p [DIRECT] Cleaning up connection", self);

    cleanup_socket (s, task, fd);

exit_cleanup:
    log_session_end_with_duration (self, connect_start, "Direct connect",
                                   src_ip, pcb->remote_port, dst_ip,
                                   pcb->local_port);

    cleanup_session (s, node);
}

/* ============================================================================
   Smart Proxy Independent Probe Implementation
   ============================================================================ */

/* Probe result enumeration */
typedef enum
{
    PROBE_UNKNOWN = 0,
    PROBE_SUCCESS, /* Received valid response from server */
    PROBE_RESET, /* Connection reset (likely GFW RST) */
    PROBE_TIMEOUT, /* Timeout without response */
    PROBE_ERROR /* Other error (network, system, etc.) */
} ProbeResult;

/* Probe result enumeration with connection fd */
typedef struct
{
    ProbeResult result;
    int fd; /* Probe connection fd (-1 if closed) */
    time_t duration_ms; /* Probe duration in milliseconds */
} ProbeOutcome;

/* Forward declarations for probe functions */
static ProbeOutcome probe_target_connection (HevSocks5SessionTCP *self,
                                             struct sockaddr *saddr,
                                             socklen_t saddr_len,
                                             struct pbuf *data_queue,
                                             int timeout_ms, HevTask *task);
static int send_browser_data_queue (int fd, struct pbuf *queue);
static int wait_for_probe_response (int fd, int timeout_ms);
static int continue_with_direct_connection (HevSocks5SessionTCP *self,
                                            HevSocks5Session *s, HevTask *task,
                                            int fd, struct sockaddr *saddr,
                                            socklen_t saddr_len);
static int create_direct_connection_fd (struct sockaddr *saddr,
                                        socklen_t saddr_len);

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
    HevListNode *node = iface->get_node (s);
    struct sockaddr_storage saddr;
    socklen_t saddr_len;
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    ip_addr_t dst_ip_copy;
    u16_t dst_port_copy;
    int timeout;
    int probe_timeout;
    ProbeOutcome probe_outcome;
    int direct_fd = -1;
    int gfw_blocked = 0;
    time_t task_start_time, task_end_time;
    time_t socks5_start_time = 0, socks5_end_time;

    task_start_time = get_current_time_ms ();

    /*
     * Note: ACL checking and hostname detection are already done in
     * run_domain_first_task. The detected hostname is saved in self->detected_hostname
     * for blacklist usage when fallback occurs.
     */

    get_session_addresses (pcb, src_ip, dst_ip);

    /* Save target IP and port for fallback (pcb may be freed later) */
    LOG_D ("%p [SMART-PROXY-V2] Before copy: pcb->local_ip=%s", self,
           ipaddr_ntoa (&pcb->local_ip));
    ip_addr_copy (dst_ip_copy, pcb->local_ip);
    dst_port_copy = pcb->local_port;
    LOG_D ("%p [SMART-PROXY-V2] After copy: dst_ip_copy=%s", self,
           ipaddr_ntoa (&dst_ip_copy));

    LOG_D ("%p [SMART-PROXY-V2] Task run %s:%d -> %s:%d", self, src_ip,
           pcb->remote_port, dst_ip, pcb->local_port);

    build_ipv6_sockaddr (&pcb->local_ip, pcb->local_port, &saddr, &saddr_len);

    timeout = hev_config_get_smart_proxy_timeout_ms ();
    probe_timeout = timeout / 2;
    if (probe_timeout < 500)
        probe_timeout = 500;

    /* ====================================================================
       Step 1: Independent probe with connection reuse
       ==================================================================== */

    LOG_I ("%p [SMART-PROXY-V2] Starting probe to %s:%d (timeout=%dms)", self,
           dst_ip, pcb->local_port, probe_timeout);

    /* Create probe connection and test */
    probe_outcome = probe_target_connection (self, (struct sockaddr *)&saddr,
                                             saddr_len, self->queue,
                                             probe_timeout, task);

    LOG_D ("%p [SMART-PROXY-V2] After probe: dst_ip_copy=%s, pcb->local_ip=%s",
           self, ipaddr_ntoa (&dst_ip_copy), ipaddr_ntoa (&pcb->local_ip));
    LOG_I ("%p [SMART-PROXY-V2] Probe result: %d (duration=%ldms)", self,
           probe_outcome.result, probe_outcome.duration_ms);

    /* ====================================================================
       Step 2: Decision based on probe result
       ==================================================================== */

    switch (probe_outcome.result) {
    case PROBE_SUCCESS:
        /* Probe succeeded! Direct connection is available.
         *
         * We don't reuse the probe connection (it's already closed).
         * Instead, we establish a fresh direct connection for data transfer.
         * This ensures proper TLS handshake completion.
         */
        LOG_I (
            "%p [SMART-PROXY-V2] Probe SUCCESS in %ldms, establishing new direct connection",
            self, probe_outcome.duration_ms);

        /* Establish new direct connection (probe_fd is already closed) */
        direct_fd =
            create_direct_connection_fd ((struct sockaddr *)&saddr, saddr_len);
        if (direct_fd < 0) {
            LOG_W (
                "%p [SMART-PROXY-V2] Failed to create direct connection, using SOCKS5",
                self);
            gfw_blocked = 1;
            break;
        }

        /* Continue with the new direct connection */
        if (continue_with_direct_connection (self, s, task, direct_fd,
                                             (struct sockaddr *)&saddr,
                                             saddr_len) < 0) {
            LOG_W ("%p [SMART-PROXY-V2] Direct connection failed, using SOCKS5",
                   self);
            gfw_blocked = 1;
        }
        break;

    case PROBE_RESET:
        /* Probe received RST - likely GFW blocking */
        LOG_W ("%p [SMART-PROXY-V2] Probe received RST in %ldms (GFW blocked), "
               "using SOCKS5",
               self, probe_outcome.duration_ms);
        gfw_blocked = 1;
        break;

    case PROBE_TIMEOUT:
        /* Probe timeout - server not responding */
        LOG_W ("%p [SMART-PROXY-V2] Probe timeout after %ldms, using SOCKS5",
               self, probe_outcome.duration_ms);
        gfw_blocked = 1;
        break;

    case PROBE_ERROR:
    default:
        /* Probe error - network or system error */
        LOG_E ("%p [SMART-PROXY-V2] Probe error, using SOCKS5", self);
        gfw_blocked = 1;
        break;
    }

    /* ====================================================================
       Step 3: Fallback to SOCKS5 if needed
       ==================================================================== */

    if (gfw_blocked) {
        char fallback_dst_ip[INET6_ADDRSTRLEN];
        ipaddr_ntoa_r (&dst_ip_copy, fallback_dst_ip, sizeof (fallback_dst_ip));

        LOG_I ("%p [SMART-PROXY-V2] Falling back to SOCKS5 for %s:%d -> %s:%d",
               self, src_ip, pcb ? pcb->remote_port : 0, fallback_dst_ip,
               dst_port_copy);

        socks5_start_time = get_current_time_ms ();
        hev_socks5_session_run (s);
        socks5_end_time = get_current_time_ms ();

        LOG_I ("%p [SMART-PROXY-V2] SOCKS5 fallback ended (socks5_time=%ldms)",
               self, socks5_end_time - socks5_start_time);

        /* Add to blacklist if SOCKS5 succeeded */
        if (self->socks5_success && self->detected_hostname[0]) {
            hev_filter_blacklist_add_domain (self->detected_hostname);
            LOG_W ("%p [SMART-PROXY-V2] Added domain '%s' to blacklist", self,
                   self->detected_hostname);
        } else if (self->socks5_success) {
            hev_filter_blacklist_add_ip (&dst_ip_copy);
            LOG_W ("%p [SMART-PROXY-V2] Added IP '%s' to blacklist", self,
                   fallback_dst_ip);
        }
    }

    /* ====================================================================
       Cleanup
       ==================================================================== */

    if (direct_fd >= 0) {
        close (direct_fd);
    }

    task_end_time = get_current_time_ms ();
    LOG_I ("%p [SMART-PROXY-V2] Task ended (total_time=%ldms, path=%s)", self,
           task_end_time - task_start_time, gfw_blocked ? "SOCKS5" : "DIRECT");

    cleanup_session (s, node);
}

/* ============================================================================
   Independent Probe Implementation
   ============================================================================ */

/**
 * send_browser_data_queue - Send browser's pbuf queue to socket
 * @fd: socket file descriptor
 * @queue: pbuf queue to send
 *
 * Returns: bytes sent on success, -1 on error
 */
static int
send_browser_data_queue (int fd, struct pbuf *queue)
{
    struct iovec iov[128];
    int iovc = 0;
    struct pbuf *p;

    if (!queue)
        return -1;

    /* Build iovec from pbuf queue */
    for (p = queue; p && (iovc < 128); p = p->next, iovc++) {
        iov[iovc].iov_base = p->payload;
        iov[iovc].iov_len = p->len;
    }

    if (iovc == 0)
        return 0;

    /* Send data using writev */
    ssize_t sent = writev (fd, iov, iovc);
    if (sent < 0) {
        LOG_D ("[PROBE] writev failed: errno=%d (%s)", errno, strerror (errno));
        return -1;
    }

    LOG_D ("[PROBE] Sent %zd bytes (%d iovs)", sent, iovc);
    return sent;
}

/**
 * wait_for_probe_response - Wait for server response on probe connection
 * @fd: socket file descriptor
 * @timeout_ms: timeout in milliseconds
 *
 * Returns: PROBE_SUCCESS, PROBE_RESET, PROBE_TIMEOUT, or PROBE_ERROR
 */
static int
wait_for_probe_response (int fd, int timeout_ms)
{
    struct pollfd pfd;
    char buf[16];
    int ret;

    pfd.fd = fd;
    pfd.events = POLLIN;

    LOG_D ("[PROBE] Waiting for response (timeout=%dms)...", timeout_ms);

    /* Wait for data with timeout */
    ret = poll (&pfd, 1, timeout_ms);

    if (ret < 0) {
        /* Poll error */
        LOG_D ("[PROBE] poll error: errno=%d (%s)", errno, strerror (errno));
        return PROBE_ERROR;
    } else if (ret == 0) {
        /* Timeout - no response */
        LOG_D ("[PROBE] Timeout waiting for response");
        return PROBE_TIMEOUT;
    }

    /* Check for error events */
    if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
        int error = 0;
        socklen_t len = sizeof (error);
        getsockopt (fd, SOL_SOCKET, SO_ERROR, &error, &len);

        LOG_D ("[PROBE] Socket error event: error=%d (%s)", error,
               strerror (error));
        return PROBE_RESET;
    }

    /* Try to peek at data to verify connection is alive */
    ssize_t n = recv (fd, buf, sizeof (buf), MSG_PEEK | MSG_DONTWAIT);

    if (n > 0) {
        /* Received data from server - connection is valid */
        LOG_I ("[PROBE] Received %zd bytes from server", n);
        return PROBE_SUCCESS;
    } else if (n == 0) {
        /* Connection closed by server */
        LOG_D ("[PROBE] Connection closed by server");
        return PROBE_RESET;
    } else {
        /* Error or EAGAIN */
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            /* No data available yet, but connection is still valid */
            LOG_D ("[PROBE] No data yet, connection valid");
            return PROBE_SUCCESS;
        } else {
            /* Connection error (likely ECONNRESET) */
            LOG_D ("[PROBE] recv error: errno=%d (%s)", errno,
                   strerror (errno));
            return PROBE_RESET;
        }
    }
}

/**
 * probe_target_connection - Create independent probe connection to target
 * @self: session context
 * @saddr: target address
 * @saddr_len: address length
 * @data_queue: browser data to send (contains SNI)
 * @timeout_ms: probe timeout in milliseconds
 * @task: task context for yielding
 *
 * This function creates an independent TCP connection to the target server
 * and sends the browser's actual data (including SNI for TLS).
 *
 * **Key behavior for connection reuse (方案 B):**
 * - If probe SUCCESS: returns fd open, caller should reuse it for data transfer
 * - If probe FAIL (RST/timeout/error): closes fd, returns -1
 *
 * This way:
 * - When probe succeeds: no data re-send, zero waste, zero latency penalty
 * - When probe fails: browser connection is completely isolated from RST
 *
 * Returns: ProbeOutcome with result code and possibly open fd
 */

/**
 * create_direct_connection_fd - Create and connect a socket for direct connection
 * @saddr: target address
 * @saddr_len: address length
 *
 * This function creates a TCP socket and connects to the target.
 * Used after successful probe to establish a fresh connection.
 *
 * Returns: socket fd on success, -1 on error
 */
static int
create_direct_connection_fd (struct sockaddr *saddr, socklen_t saddr_len)
{
    int fd = -1;
    int ret;
    int connect_timeout_ms =
        10000; /* 10 second timeout for direct connection */

    /* Create socket */
    fd = socket (saddr->sa_family, SOCK_STREAM, 0);
    if (fd < 0) {
        LOG_E ("Failed to create direct connection socket: errno=%d", errno);
        return -1;
    }

    /* Enable IPv4-mapped IPv6 for dual-stack support */
    if (saddr->sa_family == AF_INET6) {
        int zero = 0;
        setsockopt (fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof (zero));
    }

    /* Set non-blocking */
    int flags = fcntl (fd, F_GETFL, 0);
    fcntl (fd, F_SETFL, flags | O_NONBLOCK);

    /* Connect to target */
    ret = connect (fd, saddr, saddr_len);

    if (ret < 0 && errno != EINPROGRESS) {
        LOG_W ("Direct connect failed immediately: errno=%d", errno);
        close (fd);
        return -1;
    }

    /* Wait for connection to complete */
    if (errno == EINPROGRESS) {
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLOUT;

        ret = poll (&pfd, 1, connect_timeout_ms);
        if (ret < 0) {
            LOG_E ("Poll error during direct connect");
            close (fd);
            return -1;
        } else if (ret == 0) {
            LOG_W ("Direct connect timeout");
            close (fd);
            return -1;
        }

        /* Check for socket errors */
        int error = 0;
        socklen_t len = sizeof (error);
        if (getsockopt (fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0 ||
            error != 0) {
            LOG_W ("Direct connect failed: error=%d", error);
            close (fd);
            return -1;
        }
    }

    LOG_D ("Direct connection established (fd=%d)", fd);
    return fd;
}

static ProbeOutcome
probe_target_connection (HevSocks5SessionTCP *self, struct sockaddr *saddr,
                         socklen_t saddr_len, struct pbuf *data_queue,
                         int timeout_ms, HevTask *task)
{
    ProbeOutcome outcome = { PROBE_ERROR, -1, 0 };
    int probe_fd = -1;
    int ret;
    time_t start_time;

    start_time = get_current_time_ms ();

    LOG_I ("%p [PROBE] Creating independent probe socket", self);

    /* Create probe socket */
    probe_fd = socket (saddr->sa_family, SOCK_STREAM, 0);
    if (probe_fd < 0) {
        LOG_E ("%p [PROBE] Failed to create socket: errno=%d", self, errno);
        return outcome;
    }

    /* Enable IPv4-mapped IPv6 for dual-stack support */
    if (saddr->sa_family == AF_INET6) {
        int zero = 0;
        setsockopt (probe_fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof (zero));
    }

    /* Set non-blocking */
    int flags = fcntl (probe_fd, F_GETFL, 0);
    fcntl (probe_fd, F_SETFL, flags | O_NONBLOCK);

    /* Connect to target */
    LOG_D ("%p [PROBE] Connecting to target...", self);

    /* Debug: print the address we're connecting to */
    if (saddr->sa_family == AF_INET6) {
        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)saddr;
        char addr_str[INET6_ADDRSTRLEN];
        inet_ntop (AF_INET6, &sa6->sin6_addr, addr_str, sizeof (addr_str));
        LOG_D ("%p [PROBE] Connecting to [%s]:%d (IPv6 socket, addrlen=%d)", self,
               addr_str, ntohs (sa6->sin6_port), saddr_len);
    } else if (saddr->sa_family == AF_INET) {
        struct sockaddr_in *sa4 = (struct sockaddr_in *)saddr;
        char addr_str[INET_ADDRSTRLEN];
        inet_ntop (AF_INET, &sa4->sin_addr, addr_str, sizeof (addr_str));
        LOG_D ("%p [PROBE] Connecting to %s:%d (IPv4 socket, addrlen=%d)", self,
               addr_str, ntohs (sa4->sin_port), saddr_len);
    } else {
        LOG_D ("%p [PROBE] Unknown address family: %d", self, saddr->sa_family);
    }

    ret = connect (probe_fd, saddr, saddr_len);

    if (ret < 0 && errno != EINPROGRESS) {
        LOG_W ("%p [PROBE] Connect failed immediately: errno=%d", self, errno);
        close (probe_fd);
        outcome.duration_ms = get_current_time_ms () - start_time;
        return outcome;
    }

    /* Wait for connection to complete */
    if (errno == EINPROGRESS) {
        struct pollfd pfd;
        pfd.fd = probe_fd;
        pfd.events = POLLOUT;

        ret = poll (&pfd, 1, timeout_ms);
        if (ret < 0) {
            LOG_E ("%p [PROBE] Poll error during connect", self);
            close (probe_fd);
            outcome.duration_ms = get_current_time_ms () - start_time;
            return outcome;
        } else if (ret == 0) {
            LOG_W ("%p [PROBE] Connect timeout", self);
            close (probe_fd);
            outcome.result = PROBE_TIMEOUT;
            outcome.duration_ms = get_current_time_ms () - start_time;
            return outcome;
        }

        /* Check for socket errors */
        int error = 0;
        socklen_t len = sizeof (error);
        if (getsockopt (probe_fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0 ||
            error != 0) {
            LOG_W ("%p [PROBE] Connect failed: error=%d", self, error);
            close (probe_fd);
            outcome.result = PROBE_ERROR;
            outcome.duration_ms = get_current_time_ms () - start_time;
            return outcome;
        }
    }

    LOG_I ("%p [PROBE] TCP handshake successful", self);

    /* Send browser's actual data (contains SNI for TLS) */
    LOG_I ("%p [PROBE] Sending browser data (%d bytes)...", self,
           data_queue ? data_queue->tot_len : 0);

    ret = send_browser_data_queue (probe_fd, data_queue);
    if (ret < 0) {
        LOG_W ("%p [PROBE] Failed to send data", self);
        close (probe_fd);
        outcome.result = PROBE_ERROR;
        outcome.duration_ms = get_current_time_ms () - start_time;
        return outcome;
    }

    LOG_I ("%p [PROBE] Sent %d bytes, waiting for response...", self, ret);

    /* Wait for server response */
    ProbeResult result = wait_for_probe_response (probe_fd, timeout_ms);

    outcome.duration_ms = get_current_time_ms () - start_time;
    outcome.result = result;

    if (result == PROBE_SUCCESS) {
        /* Probe succeeded! Close the connection.
         *
         * We cannot reuse the probe connection because:
         * 1. The probe connection already completed TLS handshake with server
         * 2. The client still needs to complete its side of TLS handshake
         * 3. Reusing the connection causes TLS state mismatch
         * 4. Server receives duplicate handshake messages and closes connection
         *
         * By closing the probe connection, the client will establish a fresh
         * connection with a complete, consistent TLS handshake.
         */
        LOG_I ("%p [PROBE] Probe SUCCESS in %ldms, closing probe connection",
               self, outcome.duration_ms);
        close (probe_fd);
        outcome.fd = -1;
    } else {
        /* Probe failed, close connection */
        LOG_W ("%p [PROBE] Probe failed (%d) in %ldms, closing connection",
               self, result, outcome.duration_ms);
        close (probe_fd);
        outcome.fd = -1;
    }

    return outcome;
}

/**
 * continue_with_direct_connection - Continue using the probe connection
 * @self: session context
 * @s: socks5 session
 * @task: task context
 * @fd: probe connection fd (from successful probe)
 * @saddr: target address
 * @saddr_len: address length
 *
 * This function continues data transfer using the probe connection.
 * It sets up bidirectional splice between the tun device and the server.
 *
 * Returns: 0 on success, -1 on error
 */
static int
continue_with_direct_connection (HevSocks5SessionTCP *self, HevSocks5Session *s,
                                 HevTask *task, int fd, struct sockaddr *saddr,
                                 socklen_t saddr_len)
{
    HevTask *task_b = NULL;
    HevIdleTimer idle_timer;
    HevSpliceTaskData *task_data;
    int stack_size;
    int tcp_buffer_size;
    int res = 0;
    time_t start_time, end_time;
    time_t total_time_ms;

    start_time = get_current_time_ms ();
    LOG_I ("%p [DIRECT] Setting up splice with probe connection fd=%d", self,
           fd);

    init_session_idle_timer (&idle_timer);

    /* Allocate ring buffer */
    tcp_buffer_size = hev_config_get_misc_tcp_buffer_size ();
    self->buffer = hev_ring_buffer_alloca (tcp_buffer_size);
    if (!self->buffer) {
        LOG_E ("%p [DIRECT] Failed to allocate ring buffer", self);
        return -1;
    }

    HEV_SOCKS5 (s)->fd = fd;

    /* Create backward splice task */
    stack_size = hev_config_get_misc_task_stack_size ();
    task_b = hev_task_new (stack_size);
    if (!task_b) {
        LOG_E ("%p [DIRECT] Failed to create backward splice task", self);
        return -1;
    }

    task_data = create_splice_task_data (self, &idle_timer, "direct");
    if (!task_data) {
        hev_task_unref (task_b);
        return -1;
    }

    hev_task_ref (task_b);
    hev_task_run (task_b, tcp_splice_task_b, task_data);

    if (hev_task_mod_fd (task, fd, POLLOUT) < 0)
        hev_task_add_fd (task, fd, POLLOUT);

    LOG_I ("%p [DIRECT] Starting bidirectional splice", self);

    /* Main splice loop */
    for (;;) {
        if (!hev_socks5_tunnel_is_running ()) {
            LOG_D ("%p [DIRECT] Tunnel stopped, exiting", self);
            break;
        }

        res = tcp_direct_splice_f (self, &idle_timer);

        if (res < 0) {
            LOG_D ("%p [DIRECT] Forward splice ended", self);
            break;
        }

        if (res == 0) {
            if (idle_timer_check (&idle_timer) < 0) {
                LOG_I ("%p [DIRECT] Idle timeout", self);
                break;
            }
        }

        HevTaskYieldType type = (res > 0) ? HEV_TASK_YIELD : HEV_TASK_WAITIO;
        hev_task_yield (type);
    }

    /* Wait for backward task */
    if (hev_socks5_tunnel_is_running ()) {
        hev_task_join (task_b);
    }
    hev_task_unref (task_b);

    end_time = get_current_time_ms ();
    total_time_ms = end_time - start_time;
    LOG_I ("%p [DIRECT] Splice ended (total_time=%ldms)", self, total_time_ms);

    return 0;
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
    struct pbuf *dns_query;
} HevDirectUDPSession;

#define UDP_ALIVE_SEND 0x01
#define UDP_ALIVE_RECV 0x02

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

    get_udp_session_addresses (&session->src_ip, session->src_port,
                               &session->dest_ip, session->dest_port, src_ip,
                               dst_ip);
    session_duration =
        (get_current_time_seconds () - session->session_start) * 1000;

    LOG_D ("%p [UDP] Cleanup started %s:%d -> %s:%d", session, src_ip,
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
        LOG_W ("%p [UDP] dropped %d queued packets during cleanup", session,
               dropped_packets);
    }

    if (session->dns_query)
        pbuf_free (session->dns_query);

    LOG_I (
        "%p [UDP] Direct connect %s:%d -> %s:%d ended (duration=%ld ms, packets_dropped=%d)",
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
        LOG_D ("%p [UDP] recv_handler got NULL pbuf, closing send direction",
               session);
        session->alive &= ~UDP_ALIVE_SEND;
        if (session->task_main)
            hev_task_wakeup (session->task_main);
        return;
    }

    session->last_activity = get_current_time_seconds ();

    if (session->queue_count > 100) {
        LOG_W ("%p [UDP] queue full (%d packets), dropping packet of %d bytes",
               session, session->queue_count, p->tot_len);
        pbuf_free (p);
        return;
    }

    pkt = hev_malloc (sizeof (HevUDPPacket));
    if (!pkt) {
        LOG_E ("%p [UDP] failed to allocate packet structure", session);
        pbuf_free (p);
        return;
    }

    pkt->data = p;
    memset (&pkt->node, 0, sizeof (pkt->node));

    session->queue_count++;
    hev_list_add_tail (&session->packet_queue, &pkt->node);

    LOG_D ("%p [UDP] queued packet (%d bytes, queue_size=%d)", session,
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
    HevSocks5 *s5;
    int fd;
    size_t total_received_bytes = 0;
    size_t total_received_packets = 0;

    s5 = HEV_SOCKS5 (hev_socks5_client_udp_new (HEV_SOCKS5_TYPE_NONE));
    if (!s5) {
        LOG_E ("%p [UDP] recv task failed to create dummy socks5", session);
        session->alive &= ~UDP_ALIVE_RECV;
        return;
    }

    get_udp_session_addresses (&session->src_ip, session->src_port,
                               &session->dest_ip, session->dest_port, src_ip,
                               dst_ip);

    LOG_D ("%p [UDP] recv task start %s:%d <- %s:%d", session, src_ip,
           session->src_port, dst_ip, session->dest_port);

    fd = hev_task_io_dup (session->fd);
    if (fd < 0) {
        LOG_E ("%p [UDP] recv task failed to dup fd: %s", session,
               strerror (errno));
        session->alive &= ~UDP_ALIVE_RECV;
        hev_object_unref (HEV_OBJECT (s5));
        return;
    }

    if (hev_task_add_fd (task, fd, POLLIN) < 0) {
        LOG_E ("%p [UDP] recv task failed to add fd", session);
        hev_task_mod_fd (task, fd, POLLIN);
    }

    session->alive |= UDP_ALIVE_RECV;

    while (session->alive & UDP_ALIVE_RECV) {
        addr_len = sizeof (remote_addr);

        hev_socks5_set_timeout (s5,
                                hev_config_get_misc_udp_read_write_timeout ());
        ssize_t received = hev_task_io_socket_recvfrom (
            fd, buffer, sizeof (buffer), 0, (struct sockaddr *)&remote_addr,
            &addr_len, hev_socks5_task_io_yielder, s5);

        if (received <= 0) {
            LOG_I ("%p [UDP] recv task idle timeout", session);
            break;
        }

        session->last_activity = get_current_time_seconds ();
        total_received_bytes += received;
        total_received_packets++;

        LOG_D (
            "%p [UDP] received %zd bytes from server (total=%zu packets, %zu bytes)",
            session, received, total_received_packets, total_received_bytes);

        /* ⭐ DNS 响应污染检测与处理（仅在 split-tunnel 启用时执行） */
        if (unlikely (session->dest_port == 53)) {
            int should_optimize = 0; /* 默认不优化 */

            /* 检查 DNS 分流是否启用 */
            if (!hev_config_get_dns_split_tunnel ()) {
                /* DNS 分流禁用，不进行污染检测 */
                LOG_D (
                    "%p session: DNS split-tunnel disabled, skip pollution detection",
                    session);
                should_optimize = 1; /* 分流禁用 → 需要优化 */
            } else {
                /* DNS 分流启用，进行污染检测 */
                int is_poisoned = hev_dns_detect_pollution (buffer, received);
                if (is_poisoned) {
                    LOG_W (
                        "%p session: DNS pollution detected from %s:%d, querying via SOCKS5 proxy (using configured foreign-dns)",
                        session, dst_ip, session->dest_port);

                    /* 通过 SOCKS5 重新查询 */
                    uint8_t *socks5_response = NULL;
                    size_t socks5_response_len = 0;
                    const uint8_t *query_payload = NULL;
                    size_t query_len = 0;

                    if (session->dns_query) {
                        query_payload = session->dns_query->payload;
                        query_len = session->dns_query->len;

                        /* Check for and strip the 8-byte header */
                        if (query_len > 8) {
                            uint16_t check_port = (query_payload[2] << 8) |
                                                  query_payload[3];
                            if (check_port == session->dest_port) {
                                LOG_D (
                                    "%p session: Stripping 8-byte header from SOCKS5 DNS query",
                                    session);
                                query_payload += 8;
                                query_len -= 8;
                            }
                        }
                    }

                    if (query_payload &&
                        hev_dns_query_via_socks5 (
                            query_payload, query_len,
                            IP_IS_V6 (&session->dest_ip) ? 1 : 0,
                            &socks5_response, &socks5_response_len) == 0) {
                        /* 替换响应数据 */
                        if (socks5_response_len > 0 &&
                            socks5_response_len <= sizeof (buffer)) {
                            memcpy (buffer, socks5_response,
                                    socks5_response_len);
                            received = socks5_response_len;
                            LOG_I (
                                "%p session: Replaced poisoned response with clean response from SOCKS5 (%zu bytes)",
                                session, received);

                            /* ⭐ 缓存干净的DNS响应 */
                            char domain[256];
                            if (extract_dns_domain (buffer, received, domain,
                                                    sizeof (domain)) > 0) {
                                hev_dns_cache_insert (domain, buffer, received,
                                                      time (NULL) + 300, 0);
                                LOG_I (
                                    "%p session: Cached clean DNS response for domain '%s' (from SOCKS5)",
                                    session, domain);
                            }
                        }
                        hev_free (socks5_response);
                    } else {
                        LOG_E (
                            "%p session: Failed to query via SOCKS5, using original poisoned response",
                            session);
                    }
                    /* 污染响应已替换为 SOCKS5 查询结果（国外IP），不优化 */
                    should_optimize = 0;
                } else {
                    LOG_I ("%p session: DNS response is clean from %s:%d",
                           session, dst_ip, session->dest_port);
                    should_optimize = 1; /* 干净响应 → 需要优化 */
                }
            } /* split-tunnel 启用的 else 块结束 */

            /* ⭐ DNS 延迟优化（干净的国内 DNS 响应或 split-tunnel 禁用时） */
            if (should_optimize && hev_config_get_dns_latency_optimize ()) {
                char domain[256];

                /* 提取域名 */
                if (extract_dns_domain (buffer, received, domain,
                                        sizeof (domain)) >= 0) {
                    /* 启动异步优化任务 */
                    int ret = hev_dns_latency_optimize_response_async (
                        buffer, received, domain, session->pcb,
                        &session->src_ip,
                        session->src_port, // client_ip, client_port（客户端）
                        &session->dest_ip,
                        session->dest_port, // src_ip, src_port（DNS 服务器）
                        s5);

                    if (ret > 0) {
                        LOG_I (
                            "%p session: DNS latency optimization started for domain: %s",
                            session, domain);
                        /* 异步任务已启动，跳过发送流程 */
                        received = 0; /* 设置为0以跳过后续发送 */
                    }
                    /* 失败则继续正常流程 */
                }
            }
        }

        /* 如果DNS响应已被异步任务处理，跳过发送 */
        if (received == 0) {
            LOG_D (
                "%p session: DNS response handled by async task, skipping send",
                session);
        } else {
            struct pbuf *p = pbuf_alloc (PBUF_TRANSPORT, received, PBUF_RAM);
            if (p) {
                memcpy (p->payload, buffer, received);

                hev_task_mutex_lock (session->mutex);
                if (session->pcb) {
                    char orig_dst_ip[INET6_ADDRSTRLEN];
                    ipaddr_to_str (&session->orig_dest_ip, orig_dst_ip);
                    LOG_D ("%p [UDP] sending from spoofed source %s:%d",
                           session, orig_dst_ip, session->orig_dest_port);
                    err_t err = udp_sendfrom (session->pcb, p,
                                              &session->orig_dest_ip,
                                              session->orig_dest_port);
                    if (err != ERR_OK) {
                        LOG_E ("%p [UDP] udp_sendfrom failed: %d", session,
                               err);
                    } else {
                        LOG_D ("%p [UDP] forwarded %d bytes to client %s:%d",
                               session, received, src_ip, session->src_port);
                    }
                } else {
                    LOG_W ("%p [UDP] pcb is NULL, cannot forward packet",
                           session);
                }
                hev_task_mutex_unlock (session->mutex);
                pbuf_free (p);
            } else {
                LOG_E ("%p [UDP] failed to allocate pbuf for %zd bytes",
                       session, received);
            }
        }
    } /* closes if (port == 53) */

    session->alive &= ~UDP_ALIVE_RECV;
    hev_task_del_fd (task, fd);
    close (fd);

    LOG_D ("%p [UDP] recv task end (received %zu packets, %zu bytes)", session,
           total_received_packets, total_received_bytes);
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
    HevSocks5 *s5;
    size_t total_sent_bytes = 0;
    size_t total_sent_packets = 0;

    s5 = HEV_SOCKS5 (hev_socks5_client_udp_new (HEV_SOCKS5_TYPE_NONE));
    if (!s5) {
        LOG_E ("%p [UDP] send task failed to create dummy socks5", session);
        goto cleanup;
    }

    get_udp_session_addresses (&session->src_ip, session->src_port,
                               &session->dest_ip, session->dest_port, src_ip,
                               dst_ip);

    LOG_D ("%p [UDP] send task start %s:%d -> %s:%d", session, src_ip,
           session->src_port, dst_ip, session->dest_port);
    LOG_D ("%p [UDP] session created at %ld ms", session,
           get_current_time_ms () % 1000);

    session->fd = hev_task_io_socket_socket (AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (session->fd < 0) {
        LOG_E ("%p [UDP] failed to create socket: %s", session,
               strerror (errno));
        hev_object_unref (HEV_OBJECT (s5));
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

    build_ipv6_sockaddr (&session->dest_ip, session->dest_port, &dest_addr,
                         &addr_len);

    if (IP_IS_V6 (&session->dest_ip)) {
        LOG_D ("%p [UDP] target is IPv6: %s:%d", session, dst_ip,
               session->dest_port);
    } else {
        LOG_D ("%p [UDP] target is IPv4 (mapped to IPv6): %s:%d", session,
               dst_ip, session->dest_port);
    }

    stack_size = hev_config_get_misc_task_stack_size ();
    session->task_recv = hev_task_new (stack_size);
    if (!session->task_recv) {
        LOG_E ("%p [UDP] failed to create recv task", session);
        hev_object_unref (HEV_OBJECT (s5));
        goto cleanup;
    }

    hev_task_ref (session->task_recv);
    hev_task_run (session->task_recv, direct_udp_recv_task, session);

    session->alive = UDP_ALIVE_SEND | UDP_ALIVE_RECV;

    LOG_I ("%p [UDP] Direct connect established %s:%d -> %s:%d", session,
           src_ip, session->src_port, dst_ip, session->dest_port);

    for (;;) {
        HevListNode *node = hev_list_first (&session->packet_queue);
        if (!node) {
            if (!(session->alive & UDP_ALIVE_SEND)) {
                LOG_D ("%p [UDP] send direction closed", session);
                break;
            }

            hev_socks5_set_timeout (
                s5, hev_config_get_misc_udp_read_write_timeout ());
            if (hev_socks5_task_io_yielder (HEV_TASK_WAITIO, s5) < 0) {
                LOG_I ("%p [UDP] send task idle timeout", session);
                break;
            }
            continue;
        }

        HevUDPPacket *pkt = container_of (node, HevUDPPacket, node);
        struct pbuf *p = pkt->data;

        if (p->len > 8) {
            unsigned char *data = (unsigned char *)p->payload;
            uint16_t check_port = (data[2] << 8) | data[3];
            if (check_port == session->dest_port) {
                if (pbuf_remove_header (p, 8) != 0) {
                    LOG_E ("%p [UDP] failed to remove header", session);
                    hev_list_del (&session->packet_queue, node);
                    pbuf_free (p);
                    hev_free (pkt);
                    session->queue_count--;
                    continue;
                }
                LOG_D ("%p [UDP] removed 8-byte header", session);
            }
        }

        ssize_t sent = hev_task_io_socket_sendto (
            session->fd, p->payload, p->len, 0,
            (const struct sockaddr *)&dest_addr, addr_len,
            hev_socks5_task_io_yielder, s5);

        if (sent <= 0) {
            LOG_W ("%p [UDP] sendto failed or timeout", session);
        } else {
            total_sent_bytes += sent;
            total_sent_packets++;

            LOG_D (
                "%p [UDP] sent %zd bytes to server (total=%zu packets, %zu bytes)",
                session, sent, total_sent_packets, total_sent_bytes);
        }

        hev_list_del (&session->packet_queue, node);
        pbuf_free (p);
        hev_free (pkt);
        session->queue_count--;
    }

    session->alive &= ~UDP_ALIVE_SEND;

    LOG_D ("%p [UDP] waiting for recv task to complete", session);

    hev_task_join (session->task_recv);
    hev_task_unref (session->task_recv);
    hev_object_unref (HEV_OBJECT (s5));

cleanup:
    LOG_I (
        "%p [UDP] Direct connect cleanup (sent %zu packets/%zu bytes, alive=0x%02x)",
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

    session->dns_query = NULL;
    if (port == 53) {
        session->dns_query = pbuf_clone (PBUF_RAW, PBUF_RAM, p);
        if (!session->dns_query)
            LOG_W ("%p [UDP] failed to clone dns query", session);
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

    session->session_start = get_current_time_seconds ();

    pkt = hev_malloc (sizeof (HevUDPPacket));
    if (pkt) {
        pkt->data = p;
        memset (&pkt->node, 0, sizeof (pkt->node));
        hev_list_add_tail (&session->packet_queue, &pkt->node);
        session->queue_count = 1;
    } else {
        LOG_W ("%p [UDP] failed to allocate first packet structure", session);
        pbuf_free (p);
    }

    get_udp_session_addresses (&session->src_ip, session->src_port,
                               &session->dest_ip, port, src_ip, dst_ip);

    LOG_I (
        "%p [UDP] Direct connect started %s:%d -> %s:%d (first_packet=%d bytes)",
        session, src_ip, session->src_port, dst_ip, port, p ? p->tot_len : 0);

    hev_socks5_tunnel_insert_session (&session->node);
    hev_task_run (task, run_direct_udp_task, session);
}
