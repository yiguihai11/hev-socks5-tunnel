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
#include "hev-dns-cache.h"

/* Blacklist functionality moved to hev-filter.c for unified management */

static int
parse_target_ip_port (const char *target, int is_ipv6, ip_addr_t *ip,
                      u16_t *port)
{
    char buf[128];
    char *ip_str;
    char *port_str = NULL;
    int parsed_port;

    if (!target || !ip || !port) {
        LOG_E ("router: parse_target_ip_port: invalid parameters");
        return 0;
    }

    strncpy (buf, target, sizeof (buf) - 1);
    buf[sizeof (buf) - 1] = '\0';

    *port = 53; /* Default port */

    if (is_ipv6) {
        ip_str = buf;
        /* [IPv6]:port format */
        char *bracket_end = strrchr (buf, ']');
        if (bracket_end && bracket_end[1] == ':') {
            port_str = bracket_end + 2;
            *bracket_end = '\0';
            ip_str = buf + 1;
        }
        /* Validate IPv6 brackets */
        if (buf[0] != '[') {
            LOG_W ("router: Invalid IPv6 format (missing '['): %s", target);
            return 0;
        }
    } else {
        ip_str = buf;
        /* IPv4:port format */
        char *colon = strchr (buf, ':');
        if (colon) {
            port_str = colon + 1;
            *colon = '\0';
        }
    }

    /* Parse and validate port */
    if (port_str && port_str[0] != '\0') {
        parsed_port = atoi (port_str);
        if (parsed_port <= 0 || parsed_port > 65535) {
            LOG_W ("router: Invalid port number '%s' in target: %s", port_str,
                   target);
            return 0;
        }
        *port = (u16_t)parsed_port;
    }

    /* Parse IP address */
    if (!ipaddr_aton (ip_str, ip)) {
        LOG_W ("router: Invalid IP address '%s' in target: %s", ip_str, target);
        return 0;
    }

    LOG_D ("router: Parsed target: %s -> %s:%d", target, ipaddr_ntoa (ip),
           *port);
    return 1;
}

static int
check_and_hijack (const ip_addr_t *addr, const char *virtual_ip_str,
                  const char *target_str, ip_addr_t *target_ip,
                  u16_t *target_port, int is_ipv6, const char *log_ver)
{
    ip_addr_t virtual_ip;

    if (!addr || !virtual_ip_str || !target_str || !target_ip || !target_port) {
        LOG_E ("router: check_and_hijack: invalid parameters");
        return 0;
    }

    if (!ipaddr_aton (virtual_ip_str, &virtual_ip)) {
        LOG_W ("router: Invalid virtual IP '%s' for %s hijack", virtual_ip_str,
               log_ver);
        return 0;
    }

    if (!ip_addr_cmp (addr, &virtual_ip))
        return 0;

    if (!parse_target_ip_port (target_str, is_ipv6, target_ip, target_port)) {
        LOG_W ("router: Failed to parse target '%s' for %s hijack", target_str,
               log_ver);
        return 0;
    }

    LOG_I ("router: DNS forward %s hijack detected: %s -> %s:%d", log_ver,
           ipaddr_ntoa (addr), ipaddr_ntoa (target_ip), *target_port);
    return 1;
}

static int
handle_dns_forward_hijack (const ip_addr_t *addr, u16_t port,
                           ip_addr_t *target_ip, u16_t *target_port)
{
    const char *virtual_ip = NULL;
    const char *target = NULL;
    int is_ipv6;
    const char *log_ver;

    if (!addr || !target_ip || !target_port) {
        LOG_E ("router: handle_dns_forward_hijack: invalid parameters");
        return 0;
    }

    if (port != 53)
        return 0;

    if (IP_IS_V4 (addr)) {
        virtual_ip = hev_config_get_dns_forwarder_virtual_ip4 ();
        target = hev_config_get_dns_forwarder_target_ip4 ();
        is_ipv6 = 0;
        log_ver = "IPv4";
    } else if (IP_IS_V6 (addr)) {
        virtual_ip = hev_config_get_dns_forwarder_virtual_ip6 ();
        target = hev_config_get_dns_forwarder_target_ip6 ();
        is_ipv6 = 1;
        log_ver = "IPv6";
    } else {
        return 0;
    }

    if (virtual_ip && target) {
        return check_and_hijack (addr, virtual_ip, target, target_ip,
                                 target_port, is_ipv6, log_ver);
    }

    return 0;
}

int
hev_traffic_router_init (void)
{
    LOG_D ("router: Initializing traffic router");

    /* 初始化 DNS 缓存模块 */
    if (hev_dns_cache_init () < 0) {
        LOG_E ("router: Failed to initialize DNS cache module");
        return -1;
    }

    LOG_I ("router: Traffic router initialized successfully (with DNS cache)");
    return 0;
}

void
hev_traffic_router_fini (void)
{
    LOG_D ("router: Finalizing traffic router");

    /* 清理 DNS 缓存模块 */
    size_t total, poisoned, memory, max_memory;
    uint64_t hits;
    hev_dns_cache_get_stats (&total, &poisoned, &hits, &memory, &max_memory);
    LOG_I (
        "router: DNS cache stats - total:%zu, poisoned:%zu, hits:%llu, memory:%zu/%zuMB",
        total, poisoned, (unsigned long long)hits, memory / (1024 * 1024),
        max_memory / (1024 * 1024));

    hev_dns_cache_fini ();

    LOG_I ("router: Traffic router finalized");
}

int
hev_traffic_router_handle_tcp (struct tcp_pcb *pcb)
{
    const ip_addr_t *local_ip = &pcb->local_ip;
    char dst_ip[INET6_ADDRSTRLEN];
    char src_ip[INET6_ADDRSTRLEN];

    ipaddr_ntoa_r (local_ip, dst_ip, sizeof (dst_ip));
    ipaddr_ntoa_r (&pcb->remote_ip, src_ip, sizeof (src_ip));

    LOG_D ("%p router: TCP routing decision for %s:%d -> %s:%d", pcb, src_ip,
           pcb->remote_port, dst_ip, pcb->local_port);

    /*
     * All TCP connections are routed through domain-first for unified
     * handling of ACL (IP/Port/Domain), domestic check, and Smart Proxy.
     */
    hev_session_manager_start_task (pcb, NULL, HEV_SESSION_DOMAIN_FIRST);
    return 1;
}

int
hev_traffic_router_handle_udp (struct udp_pcb *pcb, struct pbuf *p,
                               const ip_addr_t *addr, u16_t port)
{
    char dst_ip[INET6_ADDRSTRLEN];
    char src_ip[INET6_ADDRSTRLEN];
    int is_domestic;

    ipaddr_ntoa_r (addr, dst_ip, sizeof (dst_ip));
    ipaddr_ntoa_r (&pcb->remote_ip, src_ip, sizeof (src_ip));

    LOG_D (
        "%p router: UDP routing decision for %s:%d -> %s:%d (packet_size=%d)",
        pcb, src_ip, pcb->remote_port, dst_ip, port, p ? p->tot_len : 0);

    // --- IP-based ACL check ---
    if (unlikely (hev_filter_is_blocked_ip (addr))) {
        LOG_W ("%p router: UDP packet blocked to IP: %s:%d (from %s:%d) by ACL",
               pcb, dst_ip, port, src_ip, pcb->remote_port);
        pbuf_free (p);
        return 1; // Handled (blocked)
    }

    /* 缓存国内IP判断结果，避免重复查询 */
    is_domestic = hev_filter_is_domestic (addr);

    /* ⭐ DNS 查询特殊处理 */
    if (unlikely (port == 53)) {
        /* 优先级1: 检查是否为 DNS Forwarder 劫持（不受 split-tunnel 影响） */
        ip_addr_t hijack_target_ip;
        u16_t hijack_target_port = 53;

        if (handle_dns_forward_hijack (addr, port, &hijack_target_ip,
                                       &hijack_target_port)) {
            /* DNS Forwarder 劫持优先级最高，直接转发 */
            char tip_str[INET6_ADDRSTRLEN];
            ipaddr_ntoa_r (&hijack_target_ip, tip_str, sizeof (tip_str));
            LOG_I ("%p router: UDP DNS Forwarder hijack: %s:%d -> %s:%d", pcb,
                   dst_ip, port, tip_str, hijack_target_port);
            hev_session_manager_start_direct_udp (
                pcb, &hijack_target_ip, hijack_target_port, addr, port, p);
            pbuf_ref (p);
            return 1;
        }

        /* 优先级2: 检查 DNS 分流是否启用 */
        if (!hev_config_get_dns_split_tunnel ()) {
            /* DNS 分流禁用，跳过特殊处理，继续普通 UDP 路由 */
            LOG_D (
                "%p router: DNS split-tunnel disabled, using normal UDP routing for %s:%d",
                pcb, dst_ip, port);
            goto normal_udp_routing;
        }

        /* 优先级3: DNS 分流逻辑（以下仅在 split-tunnel 启用时执行） */

        /* 检查 DNS 缓存（直接传递原始 pbuf，不克隆） */
        if (hev_dns_cache_check_only (pcb, p, addr, port)) {
            LOG_I ("%p router: DNS response from cache for %s:%d", pcb, dst_ip,
                   port);
            return 1; /* 缓存命中，已响应 */
        }

        /* 缓存未命中，根据目标DNS服务器类型决定路由 */
        if (is_domestic) {
            /* 国内DNS服务器 → DIRECT连接（响应中检测污染） */
            LOG_I (
                "%p router: DNS query to domestic %s:%d (cache miss), using DIRECT for pollution detection",
                pcb, dst_ip, port);
            hev_session_manager_start_direct_udp (pcb, addr, port, addr, port,
                                                  p);
            pbuf_ref (p);
            return 1;
        } else {
            /* 国外DNS服务器 → 直接走SOCKS5代理（不检测污染） */
            LOG_I (
                "%p router: DNS query to foreign %s:%d (cache miss), using SOCKS5 proxy",
                pcb, dst_ip, port);
            return 0; /* 让主流程使用SOCKS5代理 */
        }
    }

normal_udp_routing:
    /* 国内IP直连检查（使用缓存的判断结果） */
    if (is_domestic) {
        LOG_I (
            "%p router: UDP routing %s:%d -> %s:%d via DIRECT (domestic IP, packet_size=%d)",
            pcb, src_ip, pcb->remote_port, dst_ip, port, p ? p->tot_len : 0);
        hev_session_manager_start_direct_udp (pcb, addr, port, addr, port, p);
        pbuf_ref (p);
        return 1;
    }

    LOG_D (
        "%p router: UDP packet %s:%d -> %s:%d not handled by router (will use SOCKS5)",
        pcb, src_ip, pcb->remote_port, dst_ip, port);

    return 0;
}