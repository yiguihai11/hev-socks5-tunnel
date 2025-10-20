/*
 ============================================================================
 Name        : hev-session-manager.c (修复版 - 支持长连接)
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2024 hev
 Description : Session Manager (支持长连接的超时保护)
 ============================================================================
 */

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <stddef.h>
#include <time.h>

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

#include "hev-session-manager.h"

/* container_of macro */
#ifndef container_of
#define container_of(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))
#endif

/* ============================================================================
   🔧 新增：支持长连接的空闲超时检查
   ============================================================================ */

/* 
 * 空闲超时检查机制：
 * - 只有在连接空闲（无数据传输）时才计时
 * - 有数据传输时自动重置计时器
 * - 适用于长连接场景（如 WebSocket, HTTP/2）
 */
typedef struct _HevIdleTimer {
    time_t last_activity;
    int idle_timeout;  /* 秒，0 = 禁用空闲超时 */
} HevIdleTimer;

/* 🔧 新增：用于向 backward task 传递参数 */
typedef struct _HevSpliceTaskData {
    HevSocks5SessionTCP *session;
    HevIdleTimer *timer;
} HevSpliceTaskData;

/* Forward declarations */
static void run_direct_connect_task (void *data);
static void run_smart_proxy_task (void *data);
static void tcp_direct_splice_task_b (void *data);
static void smart_proxy_splice_task_b (void *data);

static void
idle_timer_init (HevIdleTimer *timer, int timeout_seconds)
{
    timer->last_activity = time (NULL);
    timer->idle_timeout = timeout_seconds;
}

static void
idle_timer_update (HevIdleTimer *timer)
{
    timer->last_activity = time (NULL);
}

static int
idle_timer_check (HevIdleTimer *timer)
{
    if (timer->idle_timeout <= 0)
        return 0;  /* 空闲超时禁用 */

    time_t now = time (NULL);
    if (now - timer->last_activity > timer->idle_timeout) {
        return -1;  /* 超时 */
    }
    return 0;
}

void
hev_session_manager_init (void)
{
    /* Nothing to do */
}

void
hev_session_manager_fini (void)
{
    /* Nothing to do */
}

static void
hev_socks5_session_task_entry (void *data)
{
    HevSocks5Session *s = data;

    hev_socks5_session_run (s);

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

    tcp = hev_socks5_session_tcp_new (pcb, &mutex);
    if (!tcp) {
        tcp_abort (pcb);
        return;
    }

    stack_size = hev_config_get_misc_task_stack_size ();
    task = hev_task_new (stack_size);
    if (!task) {
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

    tcp = hev_socks5_session_tcp_new (pcb, &mutex);
    if (!tcp) {
        tcp_abort (pcb);
        return;
    }

    stack_size = hev_config_get_misc_task_stack_size ();
    task = hev_task_new (stack_size);
    if (!task) {
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

    tcp = hev_socks5_session_tcp_new (pcb, &mutex);
    if (!tcp) {
        tcp_abort (pcb);
        return;
    }

    stack_size = hev_config_get_misc_task_stack_size ();
    task = hev_task_new (stack_size);
    if (!task) {
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
            /* 🔧 有数据传输，更新活动时间 */
            if (timer)
                idle_timer_update (timer);
            
            hev_task_mutex_lock (self->mutex);
            self->queue = pbuf_free_header (self->queue, s);
            if (self->pcb)
                tcp_recved (self->pcb, s);
            hev_task_mutex_unlock (self->mutex);
            res = 1;
        }
    } else if (res < 0) {
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
            /* 🔧 有数据传输，更新活动时间 */
            if (timer)
                idle_timer_update (timer);
            
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

    LOG_D ("router: tcp direct splice task B start");

    fd = hev_task_io_dup (HEV_SOCKS5 (self)->fd);
    if (fd < 0) {
        LOG_E ("router: failed to dup fd for splice B");
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

    LOG_D ("router: tcp direct splice task B end");
}

/* 🔧 修复：run_direct_connect_task 支持长连接 */
static void
run_direct_connect_task (void *data)
{
    HevSocks5SessionTCP *self = data;
    HevSocks5Session *s = HEV_SOCKS5_SESSION (self);
    HevObjectClass *klass = HEV_OBJECT_GET_CLASS (s);
    HevSocks5SessionIface *iface = klass->iface (HEV_OBJECT (s), HEV_SOCKS5_SESSION_TYPE);
    struct tcp_pcb *pcb = self->pcb;
    HevTask *task = iface->get_task (s);
    HevTask *task_b = NULL;
    HevListNode *node = iface->get_node (s);
    struct sockaddr_storage saddr;
    socklen_t saddr_len;
    char ip_str[INET6_ADDRSTRLEN];
    int tcp_buffer_size;
    int connect_timeout;
    int read_write_timeout;
    int fd = -1;
    int stack_size;
    HevIdleTimer idle_timer;

    LOG_D ("router: direct connect task run");

    /* 获取超时配置 */
    connect_timeout = hev_config_get_misc_connect_timeout ();
    read_write_timeout = hev_config_get_misc_read_write_timeout ();

    /* 🔧 关键修改：read_write_timeout 用于空闲超时，不影响数据传输 */
    idle_timer_init (&idle_timer, read_write_timeout / 1000);  /* 毫秒转秒 */

    /* Build address structure */
    struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&saddr;
    saddr_len = sizeof (struct sockaddr_in6);
    memset (sa6, 0, saddr_len);
    sa6->sin6_family = AF_INET6;
    sa6->sin6_port = htons(pcb->local_port);

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
        LOG_E ("router: failed to create socket: %s", strerror (errno));
        goto exit_cleanup;
    }

    int zero = 0;
    setsockopt (fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof (zero));

    if (hev_task_add_fd (task, fd, POLLIN | POLLOUT) < 0)
        hev_task_mod_fd (task, fd, POLLIN | POLLOUT);

    /* 🔧 连接阶段：使用 connect_timeout */
    hev_socks5_set_timeout (s, connect_timeout);
    if (hev_task_io_socket_connect (fd, (struct sockaddr *)&saddr, saddr_len,
                                    hev_socks5_task_io_yielder, s) < 0) {
        LOG_E ("router: direct connect failed: %s", strerror (errno));
        hev_task_del_fd (task, fd);
        close (fd);
        goto exit_cleanup;
    }

    ipaddr_ntoa_r (&pcb->local_ip, ip_str, sizeof (ip_str));
    LOG_I ("router: Direct connect established to %s:%d", ip_str, pcb->local_port);

    /* Allocate ring buffer */
    tcp_buffer_size = hev_config_get_misc_tcp_buffer_size ();
    self->buffer = hev_ring_buffer_alloca (tcp_buffer_size);
    if (!self->buffer) {
        LOG_E ("router: failed to allocate ring buffer");
        hev_task_del_fd (task, fd);
        close (fd);
        goto exit_cleanup;
    }

    HEV_SOCKS5 (s)->fd = fd;

    /* 🔧 数据传输阶段：清除超时，依赖空闲检查 */
    hev_socks5_set_timeout (s, 0);  /* 禁用固定超时 */

    /* 🔧 修改：Create backward splice task with proper data structure */
    stack_size = hev_config_get_misc_task_stack_size ();
    task_b = hev_task_new (stack_size);
    if (!task_b) {
        LOG_E ("router: failed to create splice task B");
        goto cleanup_splice;
    }

    /* 分配 task 参数 */
    HevSpliceTaskData *task_data = hev_malloc (sizeof (HevSpliceTaskData));
    if (!task_data) {
        LOG_E ("router: failed to allocate task data");
        hev_task_unref (task_b);
        goto cleanup_splice;
    }
    task_data->session = self;
    task_data->timer = &idle_timer;

    hev_task_ref (task_b);
    hev_task_run (task_b, tcp_direct_splice_task_b, task_data);

    /* 🔧 Forward splice：只检查空闲超时 */
    if (hev_task_mod_fd (task, fd, POLLOUT) < 0)
        hev_task_add_fd (task, fd, POLLOUT);

    for (;;) {
        int res_f = tcp_direct_splice_f (self, &idle_timer);
        if (res_f < 0)
            break;

        /* 🔧 关键：只在无数据时检查空闲超时 */
        if (res_f == 0) {  /* 无数据传输 */
            if (idle_timer_check (&idle_timer) < 0) {
                LOG_I ("router: direct connect idle timeout (no activity for %d seconds)",
                       idle_timer.idle_timeout);
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
    hev_task_del_fd (task, fd);
    close (fd);

exit_cleanup:
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

    LOG_D ("router: smart proxy splice task B start");

    fd = hev_task_io_dup (HEV_SOCKS5 (self)->fd);
    if (fd < 0) {
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

    LOG_D ("router: smart proxy splice task B end");
}

/* 🔧 修复：run_smart_proxy_task 支持长连接 */
static void
run_smart_proxy_task (void *data)
{
    HevSocks5SessionTCP *self = data;
    HevSocks5Session *s = HEV_SOCKS5_SESSION (self);
    HevObjectClass *klass = HEV_OBJECT_GET_CLASS (s);
    HevSocks5SessionIface *iface = klass->iface (HEV_OBJECT (s), HEV_SOCKS5_SESSION_TYPE);
    struct tcp_pcb *pcb = self->pcb;
    HevTask *task = iface->get_task (s);
    HevTask *task_b = NULL;
    HevListNode *node = iface->get_node (s);
    struct sockaddr_storage saddr;
    socklen_t saddr_len;
    char ip_str[INET6_ADDRSTRLEN];
    int tcp_buffer_size;
    int read_write_timeout;
    int fd = -1;
    int timeout;
    int stack_size;
    HevIdleTimer idle_timer;

    LOG_D ("router: smart proxy task run");

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
    if (fd < 0)
        goto fallback_socks5;

    int zero = 0;
    setsockopt (fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof (zero));
    if (hev_task_add_fd (task, fd, POLLIN | POLLOUT) < 0)
        hev_task_mod_fd (task, fd, POLLIN | POLLOUT);

    /* Connect with timeout (智能代理使用专用的短超时) */
    timeout = hev_config_get_smart_proxy_timeout_ms ();
    hev_socks5_set_timeout (s, timeout);
    if (hev_task_io_socket_connect (fd, (struct sockaddr *)&saddr, saddr_len,
                                    hev_socks5_task_io_yielder, s) < 0) {
        LOG_W ("router: smart proxy direct connect failed, fallback to SOCKS5");
        hev_traffic_router_blacklist_add (&pcb->local_ip);
        hev_task_del_fd (task, fd);
        close (fd);
        goto fallback_socks5;
    }

    ipaddr_ntoa_r (&pcb->local_ip, ip_str, sizeof (ip_str));
    LOG_I ("router: Smart proxy direct connect established to %s:%d", ip_str, pcb->local_port);

    /* 🔧 数据传输阶段：清除超时 */
    hev_socks5_set_timeout (s, 0);

    /* Initialize splice */
    tcp_buffer_size = hev_config_get_misc_tcp_buffer_size ();
    self->buffer = hev_ring_buffer_alloca (tcp_buffer_size);
    if (!self->buffer) {
        hev_task_del_fd (task, fd);
        close (fd);
        goto fallback_socks5;
    }

    HEV_SOCKS5 (s)->fd = fd;

    /* 🔧 Create backward task with proper data structure */
    stack_size = hev_config_get_misc_task_stack_size ();
    task_b = hev_task_new (stack_size);
    if (!task_b) {
        goto cleanup_splice;
    }

    /* 分配 task 参数 */
    HevSpliceTaskData *task_data = hev_malloc (sizeof (HevSpliceTaskData));
    if (!task_data) {
        LOG_E ("router: failed to allocate task data for smart proxy");
        hev_task_unref (task_b);
        goto cleanup_splice;
    }
    task_data->session = self;
    task_data->timer = &idle_timer;

    hev_task_ref (task_b);
    hev_task_run (task_b, smart_proxy_splice_task_b, task_data);

    /* 🔧 Forward splice：只检查空闲超时 */
    if (hev_task_mod_fd (task, fd, POLLOUT) < 0)
        hev_task_add_fd (task, fd, POLLOUT);

    for (;;) {
        int res_f = tcp_direct_splice_f (self, &idle_timer);
        if (res_f < 0)
            break;

        if (res_f == 0) {
            if (idle_timer_check (&idle_timer) < 0) {
                LOG_I ("router: smart proxy idle timeout");
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
    hev_task_del_fd (task, fd);
    close (fd);
    hev_socks5_session_terminate (s);
    hev_socks5_tunnel_delete_session (node);
    hev_object_unref (HEV_OBJECT (self));
    return;

fallback_socks5:
    hev_socks5_session_run (s);
    hev_socks5_tunnel_delete_session (node);
    hev_object_unref (HEV_OBJECT (self));
}

/* ============================================================================
   UDP Direct Connect Splice Implementation
   ============================================================================ */

typedef struct _HevDirectUDPSession {
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
} HevDirectUDPSession;

#define UDP_ALIVE_SEND 0x01
#define UDP_ALIVE_RECV 0x02
#define UDP_IDLE_TIMEOUT 300  /* UDP空闲超时: 5分钟 */

typedef struct _HevUDPPacket {
    HevListNode node;
    struct pbuf *data;
} HevUDPPacket;

static void
direct_udp_cleanup (HevDirectUDPSession *session)
{
    HevListNode *node;

    if (session->fd >= 0) {
        if (session->task_main)
            hev_task_del_fd (session->task_main, session->fd);
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

    for (node = hev_list_first (&session->packet_queue); node;
         node = hev_list_first (&session->packet_queue)) {
        HevUDPPacket *pkt = container_of (node, HevUDPPacket, node);
        hev_list_del (&session->packet_queue, node);
        pbuf_free (pkt->data);
        hev_free (pkt);
    }

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
        session->alive &= ~UDP_ALIVE_SEND;
        if (session->task_main)
            hev_task_wakeup (session->task_main);
        return;
    }

    /* 更新活动时间 */
    session->last_activity = time (NULL);

    if (session->queue_count > 100) {
        pbuf_free (p);
        return;
    }

    pkt = hev_malloc (sizeof (HevUDPPacket));
    if (!pkt) {
        pbuf_free (p);
        return;
    }

    pkt->data = p;
    memset (&pkt->node, 0, sizeof (pkt->node));

    session->queue_count++;
    hev_list_add_tail (&session->packet_queue, &pkt->node);
    
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
    int fd;

    LOG_D ("router: direct UDP recv task start");

    fd = hev_task_io_dup (session->fd);
    if (fd < 0) {
        LOG_E ("router: hev_task_io_dup failed: %s", strerror(errno));
        session->alive &= ~UDP_ALIVE_RECV;
        return;
    }

    if (hev_task_add_fd (task, fd, POLLIN) < 0) {
        LOG_E ("router: failed to add fd to recv task");
        hev_task_mod_fd (task, fd, POLLIN);
    }

    session->alive |= UDP_ALIVE_RECV;

    while (session->alive & UDP_ALIVE_RECV) {
        addr_len = sizeof (remote_addr);
        
        /* 检查空闲超时 */
        time_t now = time (NULL);
        if (now - session->last_activity > UDP_IDLE_TIMEOUT) {
            LOG_I ("router: UDP session idle timeout (no activity for %d seconds)", 
                   UDP_IDLE_TIMEOUT);
            break;
        }

        ssize_t received = recvfrom (fd, buffer, sizeof (buffer), 0,
                                    (struct sockaddr *)&remote_addr, &addr_len);

        if (received < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                hev_task_yield (HEV_TASK_WAITIO);
                continue;
            }
            LOG_E ("router: recvfrom failed: %s", strerror (errno));
            break;
        }

        if (received == 0) {
            LOG_W ("router: recvfrom returned 0");
            break;
        }

        /* 更新活动时间 */
        session->last_activity = now;

        LOG_D ("router: UDP received %zd bytes from server", received);

        struct pbuf *p = pbuf_alloc (PBUF_TRANSPORT, received, PBUF_RAM);
        if (p) {
            memcpy (p->payload, buffer, received);
            
            hev_task_mutex_lock (session->mutex);
            if (session->pcb) {
                err_t err = udp_sendfrom (session->pcb, p,
                                         &session->dest_ip,
                                         session->dest_port);
                if (err != ERR_OK) {
                    LOG_E ("router: udp_sendfrom failed: %d", err);
                } else {
                    LOG_D ("router: forwarded to client");
                }
            }
            hev_task_mutex_unlock (session->mutex);
            pbuf_free (p);
        }
    }

    session->alive &= ~UDP_ALIVE_RECV;
    hev_task_del_fd (task, fd);
    close (fd);
    
    LOG_D ("router: direct UDP recv task end");
}

static void
run_direct_udp_task (void *data)
{
    HevDirectUDPSession *session = data;
    struct sockaddr_storage dest_addr;
    socklen_t addr_len;
    int stack_size;

    LOG_D ("router: direct UDP send task start");

    /* 初始化活动时间 */
    session->last_activity = time (NULL);

    session->fd = hev_task_io_socket_socket (AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (session->fd < 0) {
        LOG_E ("router: failed to create UDP socket: %s", strerror (errno));
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
        
        char dest_ip_str[INET6_ADDRSTRLEN];
        ipaddr_ntoa_r (&session->dest_ip, dest_ip_str, sizeof (dest_ip_str));
        LOG_D ("router: Target is IPv6: %s:%d", dest_ip_str, session->dest_port);
    } else {
        u8_t *addr_bytes = (u8_t *)&sa6->sin6_addr;
        addr_bytes[10] = 0xff;
        addr_bytes[11] = 0xff;
        memcpy (&addr_bytes[12], ip_2_ip4 (&session->dest_ip), 4);
        
        char dest_ip_str[INET6_ADDRSTRLEN];
        ipaddr_ntoa_r (&session->dest_ip, dest_ip_str, sizeof (dest_ip_str));
        LOG_D ("router: Target is IPv4 (mapped to IPv6): %s:%d", dest_ip_str, session->dest_port);
    }

    stack_size = hev_config_get_misc_task_stack_size ();
    session->task_recv = hev_task_new (stack_size);
    if (!session->task_recv) {
        LOG_E ("router: failed to create recv task");
        goto cleanup;
    }

    hev_task_ref (session->task_recv);
    hev_task_run (session->task_recv, direct_udp_recv_task, session);

    session->alive = UDP_ALIVE_SEND | UDP_ALIVE_RECV;

    /* 发送循环 */
    for (;;) {
        HevListNode *node = hev_list_first (&session->packet_queue);
        if (!node) {
            if (!(session->alive & UDP_ALIVE_SEND))
                break;
            
            /* 检查空闲超时 */
            time_t now = time (NULL);
            if (now - session->last_activity > UDP_IDLE_TIMEOUT) {
                LOG_I ("router: UDP session idle timeout (send side, no activity for %d seconds)", 
                       UDP_IDLE_TIMEOUT);
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
                if (pbuf_remove_header(p, 8) != 0) {
                    LOG_E ("router: Failed to remove UDP header before sending");
                    hev_list_del (&session->packet_queue, node);
                    pbuf_free (p);
                    hev_free (pkt);
                    session->queue_count--;
                    continue;
                }
                LOG_D ("router: Removed 8-byte UDP header before sending to server");
            }
        }

        ssize_t sent = sendto (session->fd, p->payload, p->len, 0,
                              (struct sockaddr *)&dest_addr, addr_len);

        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                hev_task_yield (HEV_TASK_WAITIO);
                continue;
            }
            LOG_W ("router: UDP sendto failed: %s", strerror (errno));
        } else {
            /* 更新活动时间 */
            session->last_activity = time (NULL);
            LOG_D ("router: UDP sent %zd bytes to server", sent);
        }

        hev_list_del (&session->packet_queue, node);
        pbuf_free (p);
        hev_free (pkt);
        session->queue_count--;
    }

    session->alive &= ~UDP_ALIVE_SEND;

    hev_task_join (session->task_recv);
    hev_task_unref (session->task_recv);

cleanup:
    LOG_I ("router: Direct UDP session ended");
    direct_udp_cleanup (session);
}

void
hev_session_manager_start_direct_udp (struct udp_pcb *pcb,
                                     const ip_addr_t *dest_addr,
                                     u16_t dest_port,
                                     struct pbuf *first_packet)
{
    HevDirectUDPSession *session;
    HevUDPPacket *pkt;
    int stack_size;
    HevTask *task;

    session = hev_malloc0 (sizeof (HevDirectUDPSession));
    if (!session) {
        pbuf_free (first_packet);
        udp_remove (pcb);
        return;
    }

    stack_size = hev_config_get_misc_task_stack_size ();
    task = hev_task_new (stack_size);
    if (!task) {
        hev_free (session);
        pbuf_free (first_packet);
        udp_remove (pcb);
        return;
    }

    session->pcb = pcb;
    session->mutex = &mutex;
    session->task_main = task;
    session->fd = -1;

    ip_addr_copy (session->dest_ip, *dest_addr);
    session->dest_port = dest_port;
    ip_addr_copy (session->src_ip, pcb->remote_ip);
    session->src_port = pcb->remote_port;

    pkt = hev_malloc (sizeof (HevUDPPacket));
    if (pkt) {
        pkt->data = first_packet;
        memset (&pkt->node, 0, sizeof (pkt->node));
        hev_list_add_tail (&session->packet_queue, &pkt->node);
        session->queue_count = 1;
    } else {
        pbuf_free (first_packet);
    }

    hev_socks5_tunnel_insert_session (&session->node);
    hev_task_run (task, run_direct_udp_task, session);
}