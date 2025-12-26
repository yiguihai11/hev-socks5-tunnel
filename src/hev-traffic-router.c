/*
 ============================================================================
 Name        : hev-traffic-router.c
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2024 hev
 Description : Traffic Router (增强日志版本)
 ============================================================================
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "misc/hev-list.h"
#include <time.h>
#include "hev-compiler.h"
#include <hev-task.h>
#include <hev-task-mutex.h>
#include <hev-memory-allocator.h>
#include "misc/hev-list.h"
#include "hev-config.h"
#include "hev-logger.h"
#include "hev-session-manager.h"
#include "hev-traffic-router.h"
#include "hev-filter.h"

/* Blacklist functionality moved to hev-filter.c for unified management */

static int
handle_dns_forward_hijack (const ip_addr_t *addr, u16_t port,
                           ip_addr_t *target_ip, u16_t *target_port)
{
    const char *dns_fwd_virtual_ip4 =
        hev_config_get_dns_forwarder_virtual_ip4 ();
    const char *dns_fwd_virtual_ip6 =
        hev_config_get_dns_forwarder_virtual_ip6 ();
    const char *dns_fwd_target_ip4 = hev_config_get_dns_forwarder_target_ip4 ();
    const char *dns_fwd_target_ip6 = hev_config_get_dns_forwarder_target_ip6 ();

    if (port != 53)
        return 0;

    /* IPv4 hijack check */
    if (dns_fwd_virtual_ip4 && dns_fwd_target_ip4 && IP_IS_V4 (addr)) {
        ip_addr_t virtual_ip4;
        if (ipaddr_aton (dns_fwd_virtual_ip4, &virtual_ip4)) {
            if (ip_addr_cmp (addr, &virtual_ip4)) {
                char target_buf[128];
                strncpy (target_buf, dns_fwd_target_ip4,
                         sizeof (target_buf) - 1);

                char *colon = strchr (target_buf, ':');
                if (colon) {
                    *colon = '\0';
                    *target_port = atoi (colon + 1);
                } else {
                    *target_port = 53;
                }

                if (ipaddr_aton (target_buf, target_ip)) {
                    LOG_D ("router: DNS forward IPv4 hijack detected");
                    return 1;
                }
            }
        }
    }

    /* IPv6 hijack check */
    if (dns_fwd_virtual_ip6 && dns_fwd_target_ip6 && IP_IS_V6 (addr)) {
        ip_addr_t virtual_ip6;
        if (ipaddr_aton (dns_fwd_virtual_ip6, &virtual_ip6)) {
            if (ip_addr_cmp (addr, &virtual_ip6)) {
                char target_buf[128];
                strncpy (target_buf, dns_fwd_target_ip6,
                         sizeof (target_buf) - 1);

                char *bracket_end = strrchr (target_buf, ']');
                if (bracket_end && *(bracket_end + 1) == ':') {
                    *target_port = atoi (bracket_end + 2);
                    *bracket_end = '\0';
                    if (ipaddr_aton (target_buf + 1, target_ip)) {
                        LOG_D ("router: DNS forward IPv6 hijack detected");
                        return 1;
                    }
                } else {
                    *target_port = 53;
                    if (ipaddr_aton (target_buf, target_ip)) {
                        LOG_D ("router: DNS forward IPv6 hijack detected");
                        return 1;
                    }
                }
            }
        }
    }

    return 0;
}

static void
terminate_pcb_task (void *data)
{
    struct tcp_pcb *pcb = data;
    LOG_D ("router: Terminating PCB %p in deferred task", pcb);
    tcp_arg (pcb, NULL);
    tcp_recv (pcb, NULL);
    tcp_sent (pcb, NULL);
    tcp_err (pcb, NULL);
    tcp_abort (pcb);
    LOG_D ("router: PCB %p terminated.", pcb);
}

int
hev_traffic_router_init (void)
{
    LOG_D ("router: Initializing traffic router");

    /* Blacklist functionality now handled by filter module */

    LOG_I ("router: Traffic router initialized successfully");
    return 0;
}

void
hev_traffic_router_fini (void)
{
    LOG_D ("router: Finalizing traffic router");

    /* Blacklist functionality now handled by filter module */

    LOG_I ("router: Traffic router finalized");
}

int
hev_traffic_router_handle_tcp (struct tcp_pcb *pcb)
{
    const ip_addr_t *local_ip = &pcb->local_ip;
    char dst_ip[INET6_ADDRSTRLEN];
    char src_ip[INET6_ADDRSTRLEN];
    int is_probe_port;

    ipaddr_ntoa_r (local_ip, dst_ip, sizeof (dst_ip));
    ipaddr_ntoa_r (&pcb->remote_ip, src_ip, sizeof (src_ip));

    LOG_D ("%p router: TCP routing decision for %s:%d -> %s:%d", pcb, src_ip,
           pcb->remote_port, dst_ip, pcb->local_port);

    // --- Priority 1: ACL IP block check ---
    if (hev_filter_is_blocked_ip (local_ip)) {
        LOG_W (
            "%p router: TCP connection blocked to IP: %s:%d (from %s:%d) by ACL. Deferring termination.",
            pcb, dst_ip, pcb->local_port, src_ip, pcb->remote_port);
        int stack_size = hev_config_get_misc_task_stack_size ();
        hev_task_run (hev_task_new (stack_size), terminate_pcb_task,
                      pcb); // Create a new task to terminate the PCB
        return 1;
    }

    /* Check if this is a probe port (for domain-first routing) */
    is_probe_port = hev_config_is_smart_proxy_probe_port (pcb->local_port);

    // --- Priority 2: Domain-first routing for probe ports ---
    // Domain-first sends fake reply to quickly get hostname, then decides routing
    if (is_probe_port) {
        LOG_I (
            "%p router: TCP routing %s:%d -> %s:%d via DOMAIN-FIRST (probe port, quick hostname detection)",
            pcb, src_ip, pcb->remote_port, dst_ip, pcb->local_port);
        hev_session_manager_start_domain_first_tcp (pcb);
        return 1;
    }

    // --- Priority 3: chnroutes (domestic IP check) for non-probe ports ---
    if (hev_filter_is_domestic (local_ip)) {
        LOG_I ("%p router: TCP routing %s:%d -> %s:%d via DIRECT (domestic IP, non-probe port)",
               pcb, src_ip, pcb->remote_port, dst_ip, pcb->local_port);
        hev_session_manager_start_direct_tcp (pcb, NULL);
        return 1;
    }

    // --- Priority 4: Smart proxy for foreign IPs ---
    if (hev_config_get_smart_proxy_timeout_ms () > 0 &&
        hev_config_get_smart_proxy_blocked_ip_expiry_minutes () > 0 &&
        !hev_filter_blacklist_check (local_ip)) {
        LOG_I (
            "%p router: TCP routing %s:%d -> %s:%d via SMART_PROXY (foreign IP, non-probe port, trying direct first)",
            pcb, src_ip, pcb->remote_port, dst_ip, pcb->local_port);
        hev_session_manager_start_smart_proxy (pcb);
        return 1;
    }

    // --- Priority 5: Fallback to SOCKS5 ---
    if (hev_filter_blacklist_check (local_ip)) {
        LOG_I (
            "%p router: TCP routing %s:%d -> %s:%d via SOCKS5 (IP is blacklisted)",
            pcb, src_ip, pcb->remote_port, dst_ip, pcb->local_port);
    } else {
        LOG_I (
            "%p router: TCP routing %s:%d -> %s:%d via SOCKS5 (smart proxy disabled)",
            pcb, src_ip, pcb->remote_port, dst_ip, pcb->local_port);
    }
    hev_session_manager_start_socks5_tcp (pcb, NULL);
    return 1;
}

int
hev_traffic_router_handle_udp (struct udp_pcb *pcb, struct pbuf *p,
                               const ip_addr_t *addr, u16_t port)
{
    char dst_ip[INET6_ADDRSTRLEN];
    char src_ip[INET6_ADDRSTRLEN];

    ipaddr_ntoa_r (addr, dst_ip, sizeof (dst_ip));
    ipaddr_ntoa_r (&pcb->remote_ip, src_ip, sizeof (src_ip));

    LOG_D (
        "%p router: UDP routing decision for %s:%d -> %s:%d (packet_size=%d)",
        pcb, src_ip, pcb->remote_port, dst_ip, port, p ? p->tot_len : 0);

    // --- IP-based ACL check ---
    if (hev_filter_is_blocked_ip (addr)) {
        LOG_W ("%p router: UDP packet blocked to IP: %s:%d (from %s:%d) by ACL",
               pcb, dst_ip, port, src_ip, pcb->remote_port);
        pbuf_free (p);
        return 1; // Handled (blocked)
    }

    /* DNS Forwarder 劫持检查（优先级最高）*/
    ip_addr_t target_ip;
    u16_t target_port = 53;

    if (handle_dns_forward_hijack (addr, port, &target_ip, &target_port)) {
        char tip_str[INET6_ADDRSTRLEN];
        ipaddr_ntoa_r (&target_ip, tip_str, sizeof (tip_str));
        LOG_I ("%p router: UDP DNS Forwarder hijack: %s:%d -> %s:%d", pcb,
               dst_ip, port, tip_str, target_port);
        pbuf_ref (p);
        hev_session_manager_start_direct_udp (pcb, &target_ip, target_port,
                                              addr, port, p);
        return 1;
    }

    /* 国内IP直连检查（第二优先级） */
    if (hev_filter_is_domestic (addr)) {
        LOG_I (
            "%p router: UDP routing %s:%d -> %s:%d via DIRECT (domestic IP, packet_size=%d)",
            pcb, src_ip, pcb->remote_port, dst_ip, port, p ? p->tot_len : 0);
        pbuf_ref (p);
        hev_session_manager_start_direct_udp (pcb, addr, port, addr, port, p);
        return 1;
    }

    LOG_D (
        "%p router: UDP packet %s:%d -> %s:%d not handled by router (will use SOCKS5)",
        pcb, src_ip, pcb->remote_port, dst_ip, port);

    return 0;
}