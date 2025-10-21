/*
 ============================================================================
 Name        : hev-socks5-tunnel.c
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2019 - 2025 hev
 Description : Socks5 Tunnel
 ============================================================================
 */

#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <string.h>
#include <sys/ioctl.h>

#include <lwip/tcp.h>
#include <lwip/udp.h>
#include <lwip/nd6.h>
#include <lwip/netif.h>
#include <lwip/ip4_frag.h>
#include <lwip/ip6_frag.h>
#include <lwip/priv/tcp_priv.h>

#include <hev-task.h>
#include <hev-task-io.h>
#include <hev-task-mutex.h>
#include <hev-task-system.h>
#include <hev-memory-allocator.h>

#include "hev-exec.h"
#include "hev-config.h"
#include "hev-logger.h"
#include "hev-tunnel.h"
#include "hev-compiler.h"
#include "hev-mapped-dns.h"
#include "hev-config-const.h"
#include "hev-socks5-session-tcp.h"
#include "hev-socks5-session-udp.h"
#include "hev-traffic-router.h"
#include "hev-session-manager.h"



#include "hev-socks5-tunnel.h"

static int run;
static int tun_fd = -1;
static int tun_fd_local;
static int session_count;
static int event_fds[2] = { -1, -1 };

static size_t stat_tx_packets;
static size_t stat_rx_packets;
static size_t stat_tx_bytes;
static size_t stat_rx_bytes;

static struct netif netif;
static struct tcp_pcb *tcp;
static struct udp_pcb *udp;

HevTaskMutex mutex;
static HevTask *task_event;
static HevTask *task_lwip_io;
static HevTask *task_lwip_timer;
static HevList session_set;

static int
task_io_yielder (HevTaskYieldType type, void *data)
{
    hev_task_yield (type);

    return run ? 0 : -1;
}

static err_t
netif_output_handler (struct netif *netif, struct pbuf *p)
{
    ssize_t s;

    s = hev_tunnel_write (tun_fd, p);
    if (s <= 0) {
        if (errno == EAGAIN)
            return ERR_WOULDBLOCK;
        LOG_W ("socks5 tunnel write");
        return ERR_IF;
    }

    stat_rx_packets++;
    stat_rx_bytes += s;

    return ERR_OK;
}

static err_t
netif_output_v4_handler (struct netif *netif, struct pbuf *p,
                         const ip4_addr_t *ipaddr)
{
    return netif_output_handler (netif, p);
}

static err_t
netif_output_v6_handler (struct netif *netif, struct pbuf *p,
                         const ip6_addr_t *ipaddr)
{
    return netif_output_handler (netif, p);
}

static err_t
netif_init_handler (struct netif *netif)
{
    netif->output = netif_output_v4_handler;
    netif->output_ip6 = netif_output_v6_handler;

    return ERR_OK;
}

void
hev_socks5_tunnel_insert_session (HevListNode *node)
{
    HevSocks5SessionData *sd;
    int max_session_count;

    hev_list_add_tail (&session_set, node);
    session_count++;

    max_session_count = hev_config_get_misc_max_session_count ();
    if (!max_session_count || session_count < max_session_count)
        return;

    node = hev_list_first (&session_set);
    sd = container_of (node, HevSocks5SessionData, node);
    hev_socks5_session_terminate (sd->self);
}

void
hev_socks5_tunnel_delete_session (HevListNode *node)
{
    hev_list_del (&session_set, node);
    session_count--;
}

void
hev_socks5_tunnel_update_session (HevListNode *node)
{
    int max_session_count;

    max_session_count = hev_config_get_misc_max_session_count ();
    if (!max_session_count)
        return;

    hev_list_del (&session_set, node);
    hev_list_add_tail (&session_set, node);
}

static void
hev_socks5_session_task_entry (void *data)
{
    HevSocks5Session *s = data;

    hev_socks5_session_run (s);

    hev_socks5_tunnel_delete_session (hev_socks5_session_get_node (s));
    hev_object_unref (HEV_OBJECT (s));
}

static err_t
tcp_accept_handler (void *arg, struct tcp_pcb *pcb, err_t err)
{
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    
    ipaddr_ntoa_r (&pcb->remote_ip, src_ip, sizeof (src_ip));
    ipaddr_ntoa_r (&pcb->local_ip, dst_ip, sizeof (dst_ip));
    
    if (err != ERR_OK) {
        LOG_W ("socks5 tunnel: TCP accept failed for %s:%d -> %s:%d, error code: %d",
               src_ip, pcb->remote_port, dst_ip, pcb->local_port, err);
        return err;
    }

    if (!run) {
        LOG_W ("socks5 tunnel: TCP accept rejected for %s:%d -> %s:%d, tunnel is not running",
               src_ip, pcb->remote_port, dst_ip, pcb->local_port);
        return ERR_RST;
    }

    LOG_D ("socks5 tunnel: TCP connection accepted from %s:%d to %s:%d",
           src_ip, pcb->remote_port, dst_ip, pcb->local_port);

    hev_traffic_router_handle_tcp (pcb);

    return ERR_OK;
}

static void
dns_recv_handler (void *arg, struct udp_pcb *pcb, struct pbuf *p,
                  const ip_addr_t *addr, u16_t port)
{
    HevMappedDNS *dns = arg;
    struct pbuf *b;
    char src_ip[INET6_ADDRSTRLEN];
    int res;

    ipaddr_ntoa_r (addr, src_ip, sizeof (src_ip));
    LOG_D ("%p mapped dns: Received DNS query from %s:%d (size=%d bytes)",
           dns, src_ip, port, p ? p->tot_len : 0);

    b = pbuf_alloc (PBUF_TRANSPORT, UDP_BUF_SIZE, PBUF_RAM);
    if (!b) {
        LOG_E ("%p mapped dns: Failed to allocate response buffer", dns);
        goto exit;
    }

    res = hev_mapped_dns_handle (dns, p->payload, p->len, b->payload, b->len);
    if (res < 0) {
        LOG_W ("%p mapped dns: Failed to process DNS query from %s:%d",
               dns, src_ip, port);
        goto free;
    }

    b->len = res;
    b->tot_len = res;
    
    LOG_D ("%p mapped dns: Sending DNS response to %s:%d (size=%d bytes)",
           dns, src_ip, port, res);
    
    udp_sendfrom (pcb, b, &pcb->local_ip, pcb->local_port);

free:
    pbuf_free (b);
exit:
    pbuf_free (p);
    udp_recv (pcb, NULL, NULL);
    udp_remove (pcb);
}

static void
udp_recv_handler (void *arg, struct udp_pcb *pcb, struct pbuf *p,
                  const ip_addr_t *addr, u16_t port)
{
    HevSocks5SessionUDP *udp;
    HevListNode *node;
    HevMappedDNS *dns;
    int stack_size;
    HevTask *task;
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];

    if (!p) {
        LOG_D ("socks5 tunnel: UDP recv_handler got NULL pbuf, removing pcb");
        udp_remove (pcb);
        return;
    }

    ipaddr_ntoa_r (addr, dst_ip, sizeof (dst_ip));
    ipaddr_ntoa_r (&pcb->remote_ip, src_ip, sizeof (src_ip));
    
    LOG_D ("socks5 tunnel: UDP packet received from %s:%d to %s:%d (size=%d bytes)",
           src_ip, pcb->remote_port, dst_ip, port, p->tot_len);

    if (!run) {
        LOG_W ("socks5 tunnel: UDP packet dropped, tunnel is not running");
        pbuf_free (p);
        udp_remove (pcb);
        return;
    }

    /* 检查是否是国内 IP，如果是则使用直连 */
    if (hev_traffic_router_handle_udp (pcb, p, addr, port)) {
        /* hev_traffic_router_handle_udp 内部会复制 pbuf
         * 原始 pbuf 会由 lwIP 自动释放，所以这里不要调用 pbuf_free(p)
         * 也不要 remove pcb，因为 direct UDP session 会接管它 */
        LOG_D ("socks5 tunnel: UDP packet handled by traffic router (direct connect or DNS forward)");
        return;
    }

    /* 检查是否是 mapped DNS */
    dns = hev_mapped_dns_get ();
    if (dns && addr->type == IPADDR_TYPE_V4) {
        int faddr = hev_config_get_mapdns_address ();
        int fport = hev_config_get_mapdns_port ();
        if (fport == port && faddr == ip_2_ip4 (addr)->addr) {
            LOG_I ("socks5 tunnel: UDP packet is mapped DNS query from %s:%d",
                   src_ip, pcb->remote_port);
            udp_recv (pcb, dns_recv_handler, dns);
            return;
        }
    }

    /* 默认：通过 SOCKS5 代理 */
    LOG_I ("socks5 tunnel: UDP packet will use SOCKS5 proxy from %s:%d to %s:%d",
           src_ip, pcb->remote_port, dst_ip, port);

    udp = hev_socks5_session_udp_new (pcb, &mutex);
    if (!udp) {
        LOG_E ("socks5 tunnel: Failed to create UDP SOCKS5 session");
        pbuf_free (p);
        udp_remove (pcb);
        return;
    }

    stack_size = hev_config_get_misc_task_stack_size ();
    task = hev_task_new (stack_size);
    if (!task) {
        LOG_E ("socks5 tunnel: Failed to create task for UDP SOCKS5 session");
        pbuf_free (p);
        hev_object_unref (HEV_OBJECT (udp));
        return;
    }

    hev_socks5_session_set_task (HEV_SOCKS5_SESSION (udp), task);
    node = hev_socks5_session_get_node (HEV_SOCKS5_SESSION (udp));
    hev_socks5_tunnel_insert_session (node);
    hev_task_run (task, hev_socks5_session_task_entry, udp);
    hev_task_wakeup (task_lwip_timer);
}

static void
event_task_entry (void *data)
{
    HevListNode *node;
    int val;
    int session_count = 0;

    LOG_D ("socks5 tunnel event task run");

    hev_task_add_fd (task_event, event_fds[0], POLLIN);

    hev_task_io_read (event_fds[0], &val, sizeof (val), NULL, NULL);

    LOG_I ("socks5 tunnel: Received stop signal, shutting down...");

    run = 0;
    
    /* 统计并终止所有会话 */
    node = hev_list_first (&session_set);
    for (; node; node = hev_list_node_next (node)) {
        HevSocks5SessionData *sd;

        sd = container_of (node, HevSocks5SessionData, node);
        hev_socks5_session_terminate (sd->self);
        session_count++;
    }

    LOG_I ("socks5 tunnel: Terminated %d active sessions", session_count);

    hev_task_join (task_lwip_io);
    hev_task_join (task_lwip_timer);
    hev_task_del_fd (task_event, event_fds[0]);
    
    LOG_I ("socks5 tunnel: Event task completed");
}

static void
lwip_io_task_entry (void *data)
{
    const unsigned int mtu = hev_config_get_tunnel_mtu ();
    size_t packet_count = 0;

    LOG_D ("socks5 tunnel lwip task run");

    hev_tunnel_add_task (tun_fd, task_lwip_io);

    for (; run;) {
        struct pbuf *buf;

        buf = hev_tunnel_read (tun_fd, mtu, task_io_yielder, NULL);
        if (!buf)
            continue;

        stat_tx_packets++;
        stat_tx_bytes += buf->tot_len;
        packet_count++;

        if (packet_count % 1000 == 0) {
            LOG_D ("socks5 tunnel: Processed %zu packets (tx_packets=%zu, tx_bytes=%zu)",
                   packet_count, stat_tx_packets, stat_tx_bytes);
        }

        hev_task_mutex_lock (&mutex);
        if (netif.input (buf, &netif) != ERR_OK) {
            LOG_W ("socks5 tunnel: Failed to input packet to netif");
            pbuf_free (buf);
        }
        hev_task_mutex_unlock (&mutex);
    }

    hev_tunnel_del_task (tun_fd, task_lwip_io);
    
    LOG_I ("socks5 tunnel: lwip IO task completed (processed %zu packets)", packet_count);
}

static void
lwip_timer_task_entry (void *data)
{
    unsigned int i;
    unsigned int timer_count = 0;

    LOG_D ("socks5 tunnel timer task run");

    for (i = 1; run; i++) {
        hev_task_mutex_lock (&mutex);
        tcp_tmr ();

        if ((i & 3) == 0) {
#if IP_REASSEMBLY
            ip_reass_tmr ();
#endif
#if LWIP_IPV6
            nd6_tmr ();
#if LWIP_IPV6_REASS
            ip6_reass_tmr ();
#endif
#endif
        }
        hev_task_mutex_unlock (&mutex);

        timer_count++;
        
        if (timer_count % 1000 == 0) {
            HevListNode *node = hev_list_first (&session_set);
            int active_sessions = 0;
            while (node) {
                active_sessions++;
                node = hev_list_node_next (node);
            }
            LOG_D ("socks5 tunnel: Timer tick %u (active_sessions=%d)", 
                   timer_count, active_sessions);
        }

        if (hev_list_first (&session_set))
            hev_task_sleep (TCP_TMR_INTERVAL);
        else
            hev_task_yield (HEV_TASK_WAITIO);
    }
    
    LOG_I ("socks5 tunnel: Timer task completed (%u ticks)", timer_count);
}

static int
tunnel_init (int extern_tun_fd)
{
    const char *script_path, *name, *ipv4, *ipv6;
    int multi_queue, res;
    unsigned int mtu;

    if (extern_tun_fd >= 0) {
        int nonblock = 1;

        res = ioctl (extern_tun_fd, FIONBIO, (char *)&nonblock);
        if (res < 0) {
            LOG_E ("socks5 tunnel non-blocking");
            return -1;
        }

        tun_fd = extern_tun_fd;
        return 0;
    }

    name = hev_config_get_tunnel_name ();
    multi_queue = hev_config_get_tunnel_multi_queue ();
    tun_fd = hev_tunnel_open (name, multi_queue);
    if (tun_fd < 0) {
        LOG_E ("socks5 tunnel open (%s)", strerror (errno));
        return -1;
    }

    mtu = hev_config_get_tunnel_mtu ();
    res = hev_tunnel_set_mtu (mtu);
    if (res < 0) {
        LOG_E ("socks5 tunnel mtu");
        return -1;
    }

    ipv4 = hev_config_get_tunnel_ipv4_address ();
    if (ipv4) {
        res = hev_tunnel_set_ipv4 (ipv4, 32);
        if (res < 0) {
            LOG_E ("socks5 tunnel ipv4");
            return -1;
        }
    }

    ipv6 = hev_config_get_tunnel_ipv6_address ();
    if (ipv6) {
        res = hev_tunnel_set_ipv6 (ipv6, 128);
        if (res < 0) {
            LOG_E ("socks5 tunnel ipv6");
            return -1;
        }
    }

    res = hev_tunnel_set_state (1);
    if (res < 0) {
        LOG_E ("socks5 tunnel state");
        return -1;
    }

    script_path = hev_config_get_tunnel_post_up_script ();
    if (script_path)
        hev_exec_run (script_path, hev_tunnel_get_name (),
                      hev_tunnel_get_index (), 0);

    tun_fd_local = 1;
    return 0;
}

static void
tunnel_fini (void)
{
    const char *script_path;

    if (!tun_fd_local)
        return;

    script_path = hev_config_get_tunnel_pre_down_script ();
    if (script_path)
        hev_exec_run (script_path, hev_tunnel_get_name (),
                      hev_tunnel_get_index (), 1);

    hev_tunnel_close (tun_fd);
    tun_fd_local = 0;
    tun_fd = -1;
}

static int
gateway_init (void)
{
    ip4_addr_t addr4, mask, gw;
    ip6_addr_t addr6;

    netif_add_noaddr (&netif, NULL, netif_init_handler, ip_input);

    ip4_addr_set_loopback (&addr4);
    ip4_addr_set_any (&mask);
    ip4_addr_set_any (&gw);
    netif_set_addr (&netif, &addr4, &mask, &gw);

    ip6_addr_set_loopback (&addr6);
    netif_add_ip6_address (&netif, &addr6, NULL);

    netif_set_up (&netif);
    netif_set_link_up (&netif);
    netif_set_default (&netif);
    netif_set_flags (&netif, NETIF_FLAG_PRETEND_TCP | NETIF_FLAG_PRETEND_UDP);

    tcp = tcp_new_ip_type (IPADDR_TYPE_ANY);
    tcp_bind_netif (tcp, &netif);
    tcp_bind (tcp, NULL, 0);
    tcp = tcp_listen (tcp);
    tcp_accept (tcp, tcp_accept_handler);

    udp = udp_new_ip_type (IPADDR_TYPE_ANY);
    udp_bind_netif (udp, &netif);
    udp_bind (udp, NULL, 0);
    udp_recv (udp, udp_recv_handler, NULL);

    return 0;
}

static void
gateway_fini (void)
{
    udp_remove (udp);
    tcp_close (tcp);
    netif_remove (&netif);
}

static int
event_task_init (void)
{
    int nonblock = 1;
    int res;

    res = socketpair (PF_LOCAL, SOCK_STREAM, 0, event_fds);
    if (res < 0) {
        LOG_E ("socks5 tunnel event");
        return -1;
    }

    res = ioctl (event_fds[0], FIONBIO, (char *)&nonblock);
    if (res < 0) {
        LOG_E ("socks5 tunnel event nonblock");
        return -1;
    }

    task_event = hev_task_new (-1);
    if (!task_event) {
        LOG_E ("socks5 tunnel task event");
        return -1;
    }

    return 0;
}

static void
event_task_fini (void)
{
    if (task_event) {
        hev_task_unref (task_event);
        task_event = NULL;
    }

    if (event_fds[0] >= 0) {
        close (event_fds[0]);
        event_fds[0] = -1;
    }
    if (event_fds[1] >= 0) {
        close (event_fds[1]);
        event_fds[1] = -1;
    }
}

static int
lwip_io_task_init (void)
{
    task_lwip_io = hev_task_new (-1);
    if (!task_lwip_io) {
        LOG_E ("socks5 tunnel task lwip");
        return -1;
    }
    hev_task_set_priority (task_lwip_io, 1);

    return 0;
}

static void
lwip_io_task_fini (void)
{
    if (task_lwip_io) {
        hev_task_unref (task_lwip_io);
        task_lwip_io = NULL;
    }
}

static int
lwip_timer_task_init (void)
{
    task_lwip_timer = hev_task_new (-1);
    if (!task_lwip_timer) {
        LOG_E ("socks5 tunnel task timer");
        return -1;
    }
    hev_task_set_priority (task_lwip_timer, 1);

    return 0;
}

static void
lwip_timer_task_fini (void)
{
    if (task_lwip_timer) {
        hev_task_unref (task_lwip_timer);
        task_lwip_timer = NULL;
    }
}

static int
mapped_dns_init (void)
{
    HevMappedDNS *dns;
    int cache_size;
    int network;
    int netmask;

    network = hev_config_get_mapdns_network ();
    netmask = hev_config_get_mapdns_netmask ();
    cache_size = hev_config_get_mapdns_cache_size ();

    if (!cache_size)
        return 0;

    dns = hev_mapped_dns_new (network, netmask, cache_size);
    if (!dns)
        return -1;

    hev_mapped_dns_put (dns);

    return 0;
}

static void
mapped_dns_fini (void)
{
    HevMappedDNS *dns;

    dns = hev_mapped_dns_get ();
    if (dns) {
        hev_object_unref (HEV_OBJECT (dns));
        hev_mapped_dns_put (NULL);
    }
}

int
hev_socks5_tunnel_init (int tun_fd)
{
    int res;

    LOG_I ("socks5 tunnel: Initializing tunnel (tun_fd=%d)", tun_fd);

    res = tunnel_init (tun_fd);
    if (res < 0) {
        LOG_E ("socks5 tunnel: Failed to initialize tunnel device");
        goto exit;
    }

    res = gateway_init ();
    if (res < 0) {
        LOG_E ("socks5 tunnel: Failed to initialize gateway");
        goto exit;
    }

    res = event_task_init ();
    if (res < 0) {
        LOG_E ("socks5 tunnel: Failed to initialize event task");
        goto exit;
    }

    res = lwip_io_task_init ();
    if (res < 0) {
        LOG_E ("socks5 tunnel: Failed to initialize lwip IO task");
        goto exit;
    }

    res = lwip_timer_task_init ();
    if (res < 0) {
        LOG_E ("socks5 tunnel: Failed to initialize lwip timer task");
        goto exit;
    }

    res = mapped_dns_init ();
    if (res < 0) {
        LOG_E ("socks5 tunnel: Failed to initialize mapped DNS");
        goto exit;
    }

    signal (SIGPIPE, SIG_IGN);

    hev_task_mutex_init (&mutex);

    LOG_I ("socks5 tunnel: Initialization completed successfully");

    return 0;

exit:
    hev_socks5_tunnel_fini ();
    return -1;
}

void
hev_socks5_tunnel_fini (void)
{
    LOG_I ("socks5 tunnel: Finalizing tunnel");
    LOG_I ("socks5 tunnel: Statistics - TX: %zu packets/%zu bytes, RX: %zu packets/%zu bytes",
           stat_tx_packets, stat_tx_bytes, stat_rx_packets, stat_rx_bytes);

    mapped_dns_fini ();
    lwip_timer_task_fini ();
    lwip_io_task_fini ();
    event_task_fini ();
    gateway_fini ();
    tunnel_fini ();

    stat_tx_packets = 0;
    stat_rx_packets = 0;
    stat_tx_bytes = 0;
    stat_rx_bytes = 0;
    
    LOG_I ("socks5 tunnel: Finalization completed");
}

int
hev_socks5_tunnel_run (void)
{
    LOG_I ("socks5 tunnel: Starting tunnel operation");

    task_event = hev_task_ref (task_event);
    hev_task_run (task_event, event_task_entry, NULL);

    task_lwip_io = hev_task_ref (task_lwip_io);
    hev_task_run (task_lwip_io, lwip_io_task_entry, NULL);

    task_lwip_timer = hev_task_ref (task_lwip_timer);
    hev_task_run (task_lwip_timer, lwip_timer_task_entry, NULL);

    run = 1;
    
    LOG_I ("socks5 tunnel: Tunnel is now running");
    
    hev_task_system_run ();

    LOG_I ("socks5 tunnel: Tunnel operation stopped");

    return 0;
}

void
hev_socks5_tunnel_stop (void)
{
    int res;
    int fd;

    LOG_I ("socks5 tunnel: Stop requested");

    for (;;) {
        fd = READ_ONCE (event_fds[1]);
        if (fd >= 0)
            break;
        /* Wait for async initialization */
        usleep (100 * 1000);
    }

    res = write (fd, &res, 1);
    assert (res > 0 && "socks5 tunnel write event");
    
    LOG_D ("socks5 tunnel: Stop signal sent");
}

void
hev_socks5_tunnel_stats (size_t *tx_packets, size_t *tx_bytes,
                         size_t *rx_packets, size_t *rx_bytes)
{
    LOG_D ("socks5 tunnel: Statistics requested");

    if (tx_packets)
        *tx_packets = stat_tx_packets;

    if (tx_bytes)
        *tx_bytes = stat_tx_bytes;

    if (rx_packets)
        *rx_packets = stat_rx_packets;

    if (rx_bytes)
        *rx_bytes = stat_rx_bytes;
}
