/*
 ============================================================================
 Name        : hev-session-manager.c
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2024 hev
 Description : Session Manager
 ============================================================================
 */

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include <hev-task.h>
#include <hev-task-system.h>
#include <hev-task-io-socket.h>
#include <hev-memory-allocator.h>
#include <hev-object.h>
#include <hev-socks5.h>
#include <hev-socks5-misc.h>

#include "hev-config.h"
#include "hev-logger.h"
#include "hev-socks5-session.h"
#include "hev-socks5-session-tcp.h"
#include "hev-socks5-tunnel.h"
#include "hev-traffic-router.h"

#include "hev-session-manager.h"

/* Forward declarations */
static void run_direct_connect_task (void *data);
static void run_smart_proxy_task (void *data);

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

static void
run_direct_connect_task (void *data)
{
    HevSocks5SessionTCP *self = data;
    HevSocks5Session *s = HEV_SOCKS5_SESSION (self);
    HevObjectClass *klass = HEV_OBJECT_GET_CLASS (s);
    HevSocks5SessionIface *iface = klass->iface (HEV_OBJECT (s), HEV_SOCKS5_SESSION_TYPE);
    struct tcp_pcb *pcb = self->pcb;
    HevTask *task = iface->get_task (s);
    HevListNode *node = iface->get_node (s);
    struct sockaddr_storage saddr;
    socklen_t saddr_len;
    char ip_str[INET6_ADDRSTRLEN];
    int fd = -1;

    LOG_D ("router: direct connect task run");

    /* Build address structure for dual-stack socket */
    struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&saddr;
    saddr_len = sizeof (struct sockaddr_in6);
    memset (sa6, 0, saddr_len);
    sa6->sin6_family = AF_INET6;

    /* pcb->local_port is in host byte order in this environment;
       sockaddr expects network byte order, so convert with htons(). */
    sa6->sin6_port = htons(pcb->local_port);

    if (IP_IS_V6 (&pcb->local_ip)) {
        memcpy (&sa6->sin6_addr, ip_2_ip6 (&pcb->local_ip), 16);
    } else {
        u8_t *addr_bytes = (u8_t *)&sa6->sin6_addr;
        addr_bytes[10] = 0xff;
        addr_bytes[11] = 0xff;
        memcpy (&addr_bytes[12], ip_2_ip4 (&pcb->local_ip), 4);
    }

    /* Create a dual-stack socket, mimicking hev_socks5_socket */
    fd = hev_task_io_socket_socket (AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        goto exit_cleanup;
    }

    int zero = 0;
    setsockopt (fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof (zero));

    /* Register fd robustly for read/write events */
    if (hev_task_add_fd (task, fd, POLLIN | POLLOUT) < 0)
        hev_task_mod_fd (task, fd, POLLIN | POLLOUT);

    if (hev_task_io_socket_connect (fd, (struct sockaddr *)&saddr, saddr_len,
                                    NULL, NULL) < 0) {
        LOG_E ("router: direct connect failed: %s", strerror (errno));
        close (fd);
        goto exit_cleanup;
    }

    ipaddr_ntoa_r (&pcb->local_ip, ip_str, sizeof (ip_str));
    /* pcb->local_port is host order; print it directly (不要在这里再做 ntohs) */
    LOG_I ("router: Direct connect established to %s:%d", ip_str,
           pcb->local_port);

    /* Splice with GFW detection */
    self->is_smart_proxy_probe = 1;
    self->initial_data_received = 0;

    HEV_SOCKS5 (s)->fd = fd;

    if (iface->splicer (s) < 0) {
        LOG_W ("router: smart proxy splice timed out (GFW?), fallback to SOCKS5");
        hev_traffic_router_blacklist_add (&pcb->local_ip);
        HEV_SOCKS5 (s)->fd = -1;
        close (fd);
        hev_socks5_session_run (s);
        hev_socks5_tunnel_delete_session (node);
        hev_object_unref (HEV_OBJECT (self));
        return;
    }

    /* Cleanup */
    HEV_SOCKS5 (s)->fd = -1;
    close (fd);

exit_cleanup:
    hev_socks5_session_terminate (s);
    hev_socks5_tunnel_delete_session (node);
    hev_object_unref (HEV_OBJECT (self));
}

static void
run_smart_proxy_task (void *data)
{
    HevSocks5SessionTCP *self = data;
    HevSocks5Session *s = HEV_SOCKS5_SESSION (self);
    HevObjectClass *klass = HEV_OBJECT_GET_CLASS (s);
    HevSocks5SessionIface *iface = klass->iface (HEV_OBJECT (s), HEV_SOCKS5_SESSION_TYPE);
    struct tcp_pcb *pcb = self->pcb;
    HevTask *task = iface->get_task (s);
    HevListNode *node = iface->get_node (s);
    struct sockaddr_storage saddr;
    socklen_t saddr_len;
    char ip_str[INET6_ADDRSTRLEN];
    int fd = -1;
    int timeout;

    LOG_D ("router: smart proxy task run");

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
        goto fallback_socks5;
    }

    int zero = 0;
    setsockopt (fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof (zero));
    if (hev_task_add_fd (task, fd, POLLIN | POLLOUT) < 0)
        hev_task_mod_fd (task, fd, POLLIN | POLLOUT);

    /* Connect with timeout */
    timeout = hev_config_get_smart_proxy_timeout_ms ();
    hev_socks5_set_timeout (s, timeout);
    if (hev_task_io_socket_connect (fd, (struct sockaddr *)&saddr, saddr_len,
                                    hev_socks5_task_io_yielder, s) < 0) {
        LOG_W ("router: smart proxy direct connect failed, fallback to SOCKS5");
        hev_traffic_router_blacklist_add (&pcb->local_ip);
        close (fd);
        goto fallback_socks5;
    }

    ipaddr_ntoa_r (&pcb->local_ip, ip_str, sizeof (ip_str));
    LOG_I ("router: Smart proxy direct connect established to %s:%d", ip_str,
           pcb->local_port);

    /* Splice */
    HEV_SOCKS5 (s)->fd = fd;
    iface->splicer (s);

    /* Cleanup */
    HEV_SOCKS5 (s)->fd = -1;
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
   UDP Direct Connect Session 实现
   用于国内 IP 的 UDP 直连,避免通过 SOCKS5 代理
   ============================================================================ */

/* UDP Direct Session Structure */
typedef struct _HevDirectUDPSession {
    struct udp_pcb *pcb;
    HevTaskMutex *mutex;
    HevTask *task;
    HevListNode node;
    int fd;
    int alive;
    struct pbuf *first_packet;
    /* 保存真实的目标地址和源地址 */
    ip_addr_t dest_ip;     /* 真实目标地址,如 114.114.114.114 */
    u16_t dest_port;       /* 真实目标端口,如 53 */
    ip_addr_t src_ip;      /* 真实源地址,如 198.18.0.1 */
    u16_t src_port;        /* 真实源端口,如 1234 */
} HevDirectUDPSession;

static void
direct_udp_cleanup (HevDirectUDPSession *session)
{
    if (session->fd >= 0) {
        hev_task_del_fd (session->task, session->fd);
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

    if (session->first_packet) {
        pbuf_free (session->first_packet);
        session->first_packet = NULL;
    }

    hev_socks5_tunnel_delete_session (&session->node);
    hev_free (session);
}

static void
direct_udp_recv_handler (void *arg, struct udp_pcb *pcb, struct pbuf *p,
                        const ip_addr_t *addr, u16_t port)
{
    HevDirectUDPSession *session = arg;

    if (!p) {
        session->alive = 0;
        hev_task_wakeup (session->task);
        return;
    }

    /* 构建真实的目标地址(服务器地址) */
    struct sockaddr_storage dest_addr;
    socklen_t addr_len;

    if (IP_IS_V6 (&session->dest_ip)) {
        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&dest_addr;
        addr_len = sizeof (struct sockaddr_in6);
        memset (sa6, 0, addr_len);
        sa6->sin6_family = AF_INET6;
        sa6->sin6_port = htons (session->dest_port);
        memcpy (&sa6->sin6_addr, ip_2_ip6 (&session->dest_ip), 16);
    } else {
        struct sockaddr_in *sa4 = (struct sockaddr_in *)&dest_addr;
        addr_len = sizeof (struct sockaddr_in);
        memset (sa4, 0, addr_len);
        sa4->sin_family = AF_INET;
        sa4->sin_port = htons (session->dest_port);
        sa4->sin_addr.s_addr = ip_2_ip4 (&session->dest_ip)->addr;
    }

    /* 发送 UDP 数据包到真实目标(如 114.114.114.114:53) */
    ssize_t sent = sendto (session->fd, p->payload, p->len, 0,
                          (struct sockaddr *)&dest_addr, addr_len);
    
    if (sent < 0) {
        LOG_W ("router: direct UDP send failed: %s", strerror (errno));
    } else {
        LOG_D ("router: Direct UDP sent %zd bytes to server", sent);
    }

    pbuf_free (p);  // 在使用完 p 之后立即释放
    hev_task_wakeup (session->task);
}

static void
run_direct_udp_task (void *data)
{
    HevDirectUDPSession *session = data;
    unsigned char buffer[2048];
    struct sockaddr_storage remote_addr;
    socklen_t addr_len;

    LOG_D ("router: direct UDP task run");

    // 创建 socket
    session->fd = hev_task_io_socket_socket (AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (session->fd < 0) {
        LOG_E ("router: failed to create UDP socket");
        goto cleanup;
    }

    int zero = 0;
    setsockopt (session->fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof (zero));

    if (hev_task_add_fd (session->task, session->fd, POLLIN) < 0) {
        LOG_E ("router: failed to add fd to task");
        goto cleanup;
    }

    // 设置 UDP 接收处理器(用于接收从应用程序发来的后续 UDP 包)
    hev_task_mutex_lock (session->mutex);
    if (session->pcb) {
        udp_recv (session->pcb, direct_udp_recv_handler, session);
    }
    hev_task_mutex_unlock (session->mutex);

    // 处理第一个数据包
    if (session->first_packet) {
        struct sockaddr_storage dest_addr;
        socklen_t addr_len;

        LOG_D ("router: Processing first packet - len: %u, tot_len: %u", 
               session->first_packet->len, 
               session->first_packet->tot_len);

        if (IP_IS_V6 (&session->dest_ip)) {
            struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&dest_addr;
            addr_len = sizeof (struct sockaddr_in6);
            memset (sa6, 0, addr_len);
            sa6->sin6_family = AF_INET6;
            sa6->sin6_port = htons (session->dest_port);
            memcpy (&sa6->sin6_addr, ip_2_ip6 (&session->dest_ip), 16);
        } else {
            struct sockaddr_in *sa4 = (struct sockaddr_in *)&dest_addr;
            addr_len = sizeof (struct sockaddr_in);
            memset (sa4, 0, addr_len);
            sa4->sin_family = AF_INET;
            sa4->sin_port = htons (session->dest_port);
            sa4->sin_addr.s_addr = ip_2_ip4 (&session->dest_ip)->addr;
        }

        // 发送第一个包到真实目标
        ssize_t sent = sendto (session->fd, session->first_packet->payload, 
                              session->first_packet->len, 0,
                              (struct sockaddr *)&dest_addr, addr_len);
        
        if (sent < 0) {
            LOG_W ("router: direct UDP send first packet failed: %s", strerror (errno));
            goto cleanup;
        } else {
            LOG_D ("router: Direct UDP sent first packet: %zd bytes", sent);
        }

        pbuf_free (session->first_packet);
        session->first_packet = NULL;
    }

    session->alive = 1;

    char dest_ip_str[INET6_ADDRSTRLEN];
    char src_ip_str[INET6_ADDRSTRLEN];
    ipaddr_ntoa_r (&session->dest_ip, dest_ip_str, sizeof (dest_ip_str));
    ipaddr_ntoa_r (&session->src_ip, src_ip_str, sizeof (src_ip_str));
    LOG_I ("router: Direct UDP session started: %s:%d <-> %s:%d",
           src_ip_str, session->src_port, dest_ip_str, session->dest_port);

    // 接收循环 - 等待服务器响应
    while (session->alive) {
        addr_len = sizeof (remote_addr);
        ssize_t received = recvfrom (session->fd, buffer, sizeof (buffer), 0,
                                    (struct sockaddr *)&remote_addr, &addr_len);

        if (received < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                hev_task_yield (HEV_TASK_WAITIO);
                continue;
            }
            LOG_W ("router: direct UDP recv failed: %s", strerror (errno));
            break;
        }

        if (received == 0) {
            break;
        }

        LOG_D ("router: Direct UDP received %zd bytes from server", received);

        // 分配 pbuf 并复制接收到的数据
        struct pbuf *p = pbuf_alloc (PBUF_TRANSPORT, received, PBUF_RAM);
        if (!p) {
            LOG_W ("router: failed to allocate pbuf for response");
            continue;
        }

        memcpy (p->payload, buffer, received);

        // 发送响应回客户端
        hev_task_mutex_lock (session->mutex);
        if (session->pcb) {
            // 使用 udp_sendto 发送到客户端地址
            err_t err = udp_sendto (session->pcb, p, 
                                   &session->src_ip,
                                   session->src_port);
            if (err != ERR_OK) {
                LOG_W ("router: failed to send UDP response to client, error: %d", err);
            } else {
                LOG_D ("router: Direct UDP forwarded %zd bytes to client", received);
            }
        }
        hev_task_mutex_unlock (session->mutex);

        pbuf_free (p);
    }

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
    int stack_size;
    HevTask *task;

    session = hev_malloc0 (sizeof (HevDirectUDPSession));
    if (!session) {
        pbuf_free (first_packet);
        udp_remove (pcb);
        return;
    }

    // 创建任务
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
    session->task = task;
    session->fd = -1;
    session->first_packet = first_packet;
    
    // 保存地址信息
    ip_addr_copy (session->dest_ip, *dest_addr);
    session->dest_port = dest_port;
    ip_addr_copy (session->src_ip, pcb->remote_ip);
    session->src_port = pcb->remote_port;

    hev_socks5_tunnel_insert_session (&session->node);
    hev_task_run (task, run_direct_udp_task, session);
}