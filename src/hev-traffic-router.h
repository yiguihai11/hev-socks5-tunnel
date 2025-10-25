/*
 ============================================================================
 Name        : hev-traffic-router.h
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2024 hev
 Description : Traffic Router
 ============================================================================
 */

#ifndef __HEV_TRAFFIC_ROUTER_H__
#define __HEV_TRAFFIC_ROUTER_H__

#include <lwip/ip_addr.h>
#include <lwip/udp.h>
#include <lwip/tcp.h>

/**
 * hev_traffic_router_init:
 *
 * Initialize the traffic router.
 *
 * Returns: 0 on success, -1 on failure.
 */
int hev_traffic_router_init (void);

/**
 * hev_traffic_router_fini:
 *
 * Finalize the traffic router.
 */
void hev_traffic_router_fini (void);

/**
 * hev_traffic_router_handle_udp:
 * @pcb: udp pcb
 * @p: pbuf
 * @addr: destination address
 * @port: destination port
 *
 * Handle UDP traffic.
 *
 * Returns: 1 if handled, 0 if not.
 */
int hev_traffic_router_handle_udp (struct udp_pcb *pcb, struct pbuf *p,
                                   const ip_addr_t *addr, u16_t port);

/**
 * hev_traffic_router_handle_tcp:
 * @pcb: tcp pcb
 *
 * Handle TCP traffic.
 *
 * Returns: 1 if handled, 0 if not.
 */
int hev_traffic_router_handle_tcp (struct tcp_pcb *pcb);

/**
 * hev_traffic_router_blacklist_add:
 * @addr: IP address to blacklist
 *
 * Add an IP address to the blacklist (delegated to filter module).
 * NOTE: This function is deprecated - use hev_filter_blacklist_add instead.
 */
void hev_traffic_router_blacklist_add (const ip_addr_t *addr);

/**
 * hev_traffic_router_blacklist_check:
 * @addr: IP address to check
 *
 * Check if an IP address is blacklisted (delegated to filter module).
 * NOTE: This function is deprecated - use hev_filter_blacklist_check instead.
 *
 * Returns: 1 if blacklisted, 0 if not.
 */
int hev_traffic_router_blacklist_check (const ip_addr_t *addr);

#endif /* __HEV_TRAFFIC_ROUTER_H__ */
