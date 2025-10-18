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
