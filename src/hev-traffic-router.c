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

typedef struct _HevBlacklistedIP {
    HevListNode node;
    ip_addr_t addr;
    time_t expiry;
    time_t added_time;  /* 新增：记录加入黑名单的时间 */
} HevBlacklistedIP;

static HevList blacklist;
static HevTaskMutex blacklist_mutex;


static void
terminate_pcb_task (void *data)
{
    struct tcp_pcb *pcb = data;
    LOG_D ("router: Terminating PCB %p in deferred task", pcb);
    tcp_arg(pcb, NULL);
    tcp_recv(pcb, NULL);
    tcp_sent(pcb, NULL);
    tcp_err(pcb, NULL);
    tcp_abort (pcb);
    LOG_D ("router: PCB %p terminated.", pcb);
}

void
hev_traffic_router_blacklist_add (const ip_addr_t *addr) {
    HevBlacklistedIP *bip;
    int expiry_minutes;
    char ip_str[INET6_ADDRSTRLEN];
    
    expiry_minutes = hev_config_get_smart_proxy_blocked_ip_expiry_minutes ();
    if (expiry_minutes <= 0)
        return;
    
    bip = hev_malloc (sizeof (HevBlacklistedIP));
    if (!bip) {
        LOG_E ("router: Failed to allocate blacklist entry");
        return;
    }
    
    ip_addr_copy (bip->addr, *addr);
    bip->added_time = time (NULL);
    bip->expiry = bip->added_time + expiry_minutes * 60;
    
    ipaddr_ntoa_r (addr, ip_str, sizeof (ip_str));
    
    hev_task_mutex_lock (&blacklist_mutex);
    hev_list_add_tail (&blacklist, &bip->node);
    hev_task_mutex_unlock (&blacklist_mutex);
    
    LOG_I ("router: Added %s to blacklist (expires in %d minutes)",
           ip_str, expiry_minutes);
}

int
hev_traffic_router_blacklist_check (const ip_addr_t *addr) {
    HevListNode *node, *next;
    time_t now = time (NULL);
    int found = 0;
    int expired_count = 0;
    char ip_str[INET6_ADDRSTRLEN];
    
    hev_task_mutex_lock (&blacklist_mutex);
    
    for (node = hev_list_first (&blacklist); node; node = next) {
        HevBlacklistedIP *bip = container_of (node, HevBlacklistedIP, node);
        next = hev_list_node_next (node);
        
        if (now > bip->expiry) {
            char expired_ip[INET6_ADDRSTRLEN];
            ipaddr_ntoa_r (&bip->addr, expired_ip, sizeof (expired_ip));
            
            time_t blacklisted_duration = now - bip->added_time;
            LOG_D ("router: Removing expired blacklist entry %s (was blacklisted for %ld seconds)",
                   expired_ip, blacklisted_duration);
            
            hev_list_del (&blacklist, node);
            hev_free (bip);
            expired_count++;
            continue;
        }
        
        if (ip_addr_cmp (&bip->addr, addr)) {
            found = 1;
            ipaddr_ntoa_r (addr, ip_str, sizeof (ip_str));
            time_t time_remaining = bip->expiry - now;
            LOG_D ("router: IP %s found in blacklist (expires in %ld seconds)",
                   ip_str, time_remaining);
        }
    }
    
    hev_task_mutex_unlock (&blacklist_mutex);
    
    if (expired_count > 0) {
        LOG_D ("router: Cleaned up %d expired blacklist entries", expired_count);
    }
    
    return found;
}

int
hev_traffic_router_init (void) {
    LOG_D ("router: Initializing traffic router");
    
    hev_task_mutex_init (&blacklist_mutex);
    
    LOG_I ("router: Traffic router initialized successfully");
    return 0;
}

void
hev_traffic_router_fini (void) {
    HevListNode *node;
    int blacklist_count = 0;
    
    LOG_D ("router: Finalizing traffic router");
    
    hev_task_mutex_lock (&blacklist_mutex);
    for (node = hev_list_first (&blacklist); node; node = hev_list_first (&blacklist)) {
        HevBlacklistedIP *bip = container_of (node, HevBlacklistedIP, node);
        char ip_str[INET6_ADDRSTRLEN];
        ipaddr_ntoa_r (&bip->addr, ip_str, sizeof (ip_str));
        
        LOG_D ("router: Removing blacklist entry %s", ip_str);
        
        hev_list_del (&blacklist, node);
        hev_free (bip);
        blacklist_count++;
    }
    hev_task_mutex_unlock (&blacklist_mutex);
    
    if (blacklist_count > 0) {
        LOG_I ("router: Cleaned up %d blacklist entries", blacklist_count);
    }
    
    LOG_I ("router: Traffic router finalized");
}

int
hev_traffic_router_handle_tcp (struct tcp_pcb *pcb) {
    const ip_addr_t *local_ip = &pcb->local_ip;
    char dst_ip[INET6_ADDRSTRLEN];
    char src_ip[INET6_ADDRSTRLEN];
    
    ipaddr_ntoa_r (local_ip, dst_ip, sizeof (dst_ip));
    ipaddr_ntoa_r (&pcb->remote_ip, src_ip, sizeof (src_ip));
    
    LOG_D ("%p router: TCP routing decision for %s:%d -> %s:%d",
           pcb, src_ip, pcb->remote_port, dst_ip, pcb->local_port);
    
    // --- IP-based ACL check ---
    if (hev_filter_is_blocked_ip (local_ip)) {
        LOG_W ("%p router: TCP connection blocked to IP: %s:%d (from %s:%d) by ACL. Deferring termination.",
               pcb, dst_ip, pcb->local_port, src_ip, pcb->remote_port);
        int stack_size = hev_config_get_misc_task_stack_size();
        hev_task_run (hev_task_new (stack_size), terminate_pcb_task, pcb); // Create a new task to terminate the PCB
        return 1;
    }

    /* 1. Domestic IPs are connected directly. */
    if (hev_filter_is_domestic (local_ip)) {
        LOG_I ("%p router: TCP routing %s:%d -> %s:%d via DIRECT (domestic IP)",
               pcb, src_ip, pcb->remote_port, dst_ip, pcb->local_port);
        hev_session_manager_start_direct_tcp (pcb);
        return 1;
    }
    
    /* 2. For non-domestic IPs, attempt smart proxy if enabled and not blacklisted. */
    if (hev_config_get_smart_proxy_timeout_ms () > 0 &&
        hev_config_get_smart_proxy_blocked_ip_expiry_minutes () > 0 &&
        !hev_traffic_router_blacklist_check (local_ip)) {
        LOG_I ("%p router: TCP routing %s:%d -> %s:%d via SMART_PROXY (trying direct first)",
               pcb, src_ip, pcb->remote_port, dst_ip, pcb->local_port);
        hev_session_manager_start_smart_proxy (pcb);
        return 1;
    }
    
    /* 3. Fallback to SOCKS5 for all other cases (blacklisted, smart proxy disabled). */
    if (hev_traffic_router_blacklist_check (local_ip)) {
        LOG_I ("%p router: TCP routing %s:%d -> %s:%d via SOCKS5 (IP is blacklisted)",
               pcb, src_ip, pcb->remote_port, dst_ip, pcb->local_port);
    } else {
        LOG_I ("%p router: TCP routing %s:%d -> %s:%d via SOCKS5 (smart proxy disabled)",
               pcb, src_ip, pcb->remote_port, dst_ip, pcb->local_port);
    }
    hev_session_manager_start_socks5_tcp (pcb);
    return 1;
}

int
hev_traffic_router_handle_udp (struct udp_pcb *pcb, struct pbuf *p,
                               const ip_addr_t *addr, u16_t port) {
    char dst_ip[INET6_ADDRSTRLEN];
    char src_ip[INET6_ADDRSTRLEN];
    
    ipaddr_ntoa_r (addr, dst_ip, sizeof (dst_ip));
    ipaddr_ntoa_r (&pcb->remote_ip, src_ip, sizeof (src_ip));
    
    LOG_D ("%p router: UDP routing decision for %s:%d -> %s:%d (packet_size=%d)",
           pcb, src_ip, pcb->remote_port, dst_ip, port, p ? p->tot_len : 0);
    
    // --- IP-based ACL check ---
    if (hev_filter_is_blocked_ip (addr)) {
        LOG_W ("%p router: UDP packet blocked to IP: %s:%d (from %s:%d) by ACL",
               pcb, dst_ip, port, src_ip, pcb->remote_port);
        pbuf_free(p);
        return 1; // Handled (blocked)
    }

    /* DNS Forwarder 劫持检查（优先级最高）*/
    if (port == 53) {
        const char *dns_fwd_virtual_ip4 = hev_config_get_dns_forwarder_virtual_ip4();
        const char *dns_fwd_virtual_ip6 = hev_config_get_dns_forwarder_virtual_ip6();
        const char *dns_fwd_target_ip4 = hev_config_get_dns_forwarder_target_ip4();
        const char *dns_fwd_target_ip6 = hev_config_get_dns_forwarder_target_ip6();
        int is_hijacked = 0;
        ip_addr_t target_ip;
        u16_t target_port = 53;
        
        /* 检查IPv4劫持 */
        if (dns_fwd_virtual_ip4 && dns_fwd_target_ip4 && IP_IS_V4(addr)) {
            ip_addr_t virtual_ip4;
            if (ipaddr_aton(dns_fwd_virtual_ip4, &virtual_ip4)) {
                if (ip_addr_cmp(addr, &virtual_ip4)) {
                    char target_buf[128];
                    strncpy(target_buf, dns_fwd_target_ip4, sizeof(target_buf) - 1);
                    char *colon = strchr(target_buf, ':');
                    if (colon) {
                        *colon = '\0';
                        target_port = atoi(colon + 1);
                    }
                    if (ipaddr_aton(target_buf, &target_ip)) {
                        is_hijacked = 1;
                        char vip_str[INET6_ADDRSTRLEN];
                        char tip_str[INET6_ADDRSTRLEN];
                        ipaddr_ntoa_r(&virtual_ip4, vip_str, sizeof(vip_str));
                        ipaddr_ntoa_r(&target_ip, tip_str, sizeof(tip_str));
                        LOG_I ("%p router: UDP DNS Forwarder hijack: %s:53 -> %s:%d", 
                               pcb, vip_str, tip_str, target_port);
                    }
                }
            }
        }
        
        /* 检查IPv6劫持 */
        if (!is_hijacked && dns_fwd_virtual_ip6 && dns_fwd_target_ip6 && IP_IS_V6(addr)) {
            ip_addr_t virtual_ip6;
            if (ipaddr_aton(dns_fwd_virtual_ip6, &virtual_ip6)) {
                if (ip_addr_cmp(addr, &virtual_ip6)) {
                    char target_buf[128];
                    strncpy(target_buf, dns_fwd_target_ip6, sizeof(target_buf) - 1);
                    char *bracket_end = strrchr(target_buf, ']');
                    if (bracket_end && *(bracket_end + 1) == ':') {
                        target_port = atoi(bracket_end + 2);
                        *bracket_end = '\0';
                        if (ipaddr_aton(target_buf + 1, &target_ip)) {
                            is_hijacked = 1;
                        }
                    } else {
                        if (ipaddr_aton(target_buf, &target_ip)) {
                            is_hijacked = 1;
                        }
                    }
                    if (is_hijacked) {
                        char vip_str[INET6_ADDRSTRLEN];
                        char tip_str[INET6_ADDRSTRLEN];
                        ipaddr_ntoa_r(&virtual_ip6, vip_str, sizeof(vip_str));
                        ipaddr_ntoa_r(&target_ip, tip_str, sizeof(tip_str));
                        LOG_I ("%p router: UDP DNS Forwarder hijack (IPv6): %s:53 -> %s:%d", 
                               pcb, vip_str, tip_str, target_port);
                    }
                }
            }
        }
        
        /* 如果被劫持，使用目标地址进行UDP直连 */
        if (is_hijacked) {
            LOG_I ("%p router: UDP routing %s:%d -> %s:%d via DNS_FORWARD (hijacked DNS query)",
                   pcb, src_ip, pcb->remote_port, dst_ip, target_port);
            pbuf_ref(p);
            hev_session_manager_start_direct_udp (pcb, &target_ip, target_port, addr, port, p);
            return 1;
        }
    }
    
    /* 国内IP直连检查（第二优先级） */
    if (hev_filter_is_domestic (addr)) {
        LOG_I ("%p router: UDP routing %s:%d -> %s:%d via DIRECT (domestic IP, packet_size=%d)",
               pcb, src_ip, pcb->remote_port, dst_ip, port, p ? p->tot_len : 0);
        pbuf_ref(p);
        hev_session_manager_start_direct_udp (pcb, addr, port, addr, port, p);
        return 1;
    }
    
    LOG_D ("%p router: UDP packet %s:%d -> %s:%d not handled by router (will use SOCKS5)",
           pcb, src_ip, pcb->remote_port, dst_ip, port);
    
    return 0;
}