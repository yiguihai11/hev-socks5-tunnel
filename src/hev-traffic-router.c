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

typedef struct _HevIPAddressRange4 {
    u32_t start;
    u32_t end;
} HevIPAddressRange4;

typedef struct _HevIPAddressRange6 {
    u8_t start[16];
    u8_t end[16];
} HevIPAddressRange6;

typedef struct _HevBlacklistedIP {
    HevListNode node;
    ip_addr_t addr;
    time_t expiry;
    time_t added_time;  /* 新增：记录加入黑名单的时间 */
} HevBlacklistedIP;

static HevList blacklist;
static HevTaskMutex blacklist_mutex;
static HevIPAddressRange4 *chnroutes_ip4;
static unsigned int chnroutes_ip4_count;
static HevIPAddressRange6 *chnroutes_ip6;
static unsigned int chnroutes_ip6_count;

static int
compare_ip4_range (const void *a, const void *b) {
    const HevIPAddressRange4 *ra = a;
    const HevIPAddressRange4 *rb = b;
    if (ra->start < rb->start) return -1;
    if (ra->start > rb->start) return 1;
    return 0;
}

static int
compare_ip6_range (const void *a, const void *b) {
    const HevIPAddressRange6 *ra = a;
    const HevIPAddressRange6 *rb = b;
    return memcmp(ra->start, rb->start, 16);
}

static int
chnroutes_init (const char *path) {
    FILE *fp;
    char line[128];
    char ip_str[128];
    int prefix_len;
    
    if (!path) {
        LOG_D ("router: chnroutes file not configured.");
        return 0;
    }
    
    fp = fopen (path, "r");
    if (!fp) {
        LOG_E ("router: Failed to open chnroutes file: %s", path);
        return -1;
    }
    
    LOG_I ("router: Loading chnroutes file: %s", path);
    
    while (fgets (line, sizeof (line), fp)) {
        if (sscanf (line, "%[^/]/%d", ip_str, &prefix_len) != 2)
            continue;
        
        if (strchr(ip_str, ':')) {
            // IPv6
            chnroutes_ip6_count++;
            chnroutes_ip6 = realloc (chnroutes_ip6, sizeof(HevIPAddressRange6) * chnroutes_ip6_count);
            struct in6_addr addr_struct;
            inet_pton(AF_INET6, ip_str, &addr_struct);
            HevIPAddressRange6 *range = &chnroutes_ip6[chnroutes_ip6_count - 1];
            memcpy(range->start, &addr_struct, 16);
            memcpy(range->end, &addr_struct, 16);
            int bits_to_mask = 128 - prefix_len;
            int i = 15;
            while (bits_to_mask > 0 && i >= 0) {
                int bits_in_byte = (bits_to_mask > 8) ? 8 : bits_to_mask;
                u8_t mask = (0xFF >> bits_in_byte);
                range->start[i] &= mask;
                range->end[i] |= ~mask;
                bits_to_mask -= bits_in_byte;
                i--;
            }
        } else {
            // IPv4
            chnroutes_ip4_count++;
            chnroutes_ip4 = realloc (chnroutes_ip4, sizeof(HevIPAddressRange4) * chnroutes_ip4_count);
            struct in_addr addr_struct;
            inet_aton(ip_str, &addr_struct);
            u32_t addr_host = ntohl(addr_struct.s_addr);
            u32_t mask_host = (prefix_len == 0) ? 0 : (0xFFFFFFFF << (32 - prefix_len));
            u32_t start_host = addr_host & mask_host;
            u32_t end_host = start_host | (~mask_host);
            chnroutes_ip4[chnroutes_ip4_count - 1].start = start_host;
            chnroutes_ip4[chnroutes_ip4_count - 1].end = end_host;
        }
    }
    
    fclose (fp);
    
    if (chnroutes_ip4)
        qsort (chnroutes_ip4, chnroutes_ip4_count, sizeof (HevIPAddressRange4),
               compare_ip4_range);
    if (chnroutes_ip6)
        qsort (chnroutes_ip6, chnroutes_ip6_count, sizeof (HevIPAddressRange6),
               compare_ip6_range);
    
    LOG_I ("router: Loaded %u IPv4 and %u IPv6 chnroutes.", chnroutes_ip4_count, chnroutes_ip6_count);
    return 0;
}

static void
chnroutes_fini (void) {
    if (chnroutes_ip4) {
        LOG_D ("router: Freeing %u IPv4 chnroutes", chnroutes_ip4_count);
        free (chnroutes_ip4);
        chnroutes_ip4 = NULL;
        chnroutes_ip4_count = 0;
    }
    if (chnroutes_ip6) {
        LOG_D ("router: Freeing %u IPv6 chnroutes", chnroutes_ip6_count);
        free (chnroutes_ip6);
        chnroutes_ip6 = NULL;
        chnroutes_ip6_count = 0;
    }
}

static int
is_domestic (const ip_addr_t *addr) {
    if (IP_IS_V4 (addr)) {
        if (!chnroutes_ip4)
            return 0;
        
        u32_t addr_host = ntohl(ip_2_ip4(addr)->addr);
        int l = 0, r = chnroutes_ip4_count - 1;
        
        while (l <= r) {
            int mid = l + (r - l) / 2;
            if (addr_host >= chnroutes_ip4[mid].start && addr_host <= chnroutes_ip4[mid].end) {
                return 1;
            }
            if (addr_host < chnroutes_ip4[mid].start) {
                r = mid - 1;
            } else {
                l = mid + 1;
            }
        }
    } else if (IP_IS_V6 (addr)) {
        if (!chnroutes_ip6)
            return 0;
        
        int l = 0, r = chnroutes_ip6_count - 1;
        
        while (l <= r) {
            int mid = l + (r - l) / 2;
            if (memcmp(ip_2_ip6(addr)->addr, chnroutes_ip6[mid].start, 16) >= 0 &&
                memcmp(ip_2_ip6(addr)->addr, chnroutes_ip6[mid].end, 16) <= 0) {
                return 1;
            }
            if (memcmp(ip_2_ip6(addr)->addr, chnroutes_ip6[mid].start, 16) < 0) {
                r = mid - 1;
            } else {
                l = mid + 1;
            }
        }
    }
    return 0;
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
    const char *chnroutes_path = hev_config_get_chnroutes_file_path ();
    
    LOG_D ("router: Initializing traffic router");
    
    hev_task_mutex_init (&blacklist_mutex);
    
    if (chnroutes_init (chnroutes_path) < 0) {
        LOG_E ("router: Failed to initialize chnroutes!");
        return -1;
    }
    
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
    
    chnroutes_fini ();
    
    LOG_I ("router: Traffic router finalized");
}

int
hev_traffic_router_handle_tcp (struct tcp_pcb *pcb) {
    const ip_addr_t *local_ip = &pcb->local_ip;
    char dst_ip[INET6_ADDRSTRLEN];
    char src_ip[INET6_ADDRSTRLEN];
    
    ipaddr_ntoa_r (local_ip, dst_ip, sizeof (dst_ip));
    ipaddr_ntoa_r (&pcb->remote_ip, src_ip, sizeof (src_ip));
    
    LOG_D ("router: TCP routing decision for %s:%d -> %s:%d",
           src_ip, pcb->remote_port, dst_ip, pcb->local_port);
    
    /* 1. Domestic IPs are connected directly. */
    if (is_domestic (local_ip)) {
        LOG_I ("router: TCP routing %s:%d -> %s:%d via DIRECT (domestic IP)",
               src_ip, pcb->remote_port, dst_ip, pcb->local_port);
        hev_session_manager_start_direct_tcp (pcb);
        return 1;
    }
    
    /* 2. For non-domestic IPs, attempt smart proxy if enabled and not blacklisted. */
    if (hev_config_get_smart_proxy_timeout_ms () > 0 &&
        hev_config_get_smart_proxy_blocked_ip_expiry_minutes () > 0 &&
        !hev_traffic_router_blacklist_check (local_ip)) {
        LOG_I ("router: TCP routing %s:%d -> %s:%d via SMART_PROXY (trying direct first)",
               src_ip, pcb->remote_port, dst_ip, pcb->local_port);
        hev_session_manager_start_smart_proxy (pcb);
        return 1;
    }
    
    /* 3. Fallback to SOCKS5 for all other cases (blacklisted, smart proxy disabled). */
    if (hev_traffic_router_blacklist_check (local_ip)) {
        LOG_I ("router: TCP routing %s:%d -> %s:%d via SOCKS5 (IP is blacklisted)",
               src_ip, pcb->remote_port, dst_ip, pcb->local_port);
    } else {
        LOG_I ("router: TCP routing %s:%d -> %s:%d via SOCKS5 (smart proxy disabled)",
               src_ip, pcb->remote_port, dst_ip, pcb->local_port);
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
    
    LOG_D ("router: UDP routing decision for %s:%d -> %s:%d (packet_size=%d)",
           src_ip, pcb->remote_port, dst_ip, port, p ? p->tot_len : 0);
    
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
                        LOG_I ("router: UDP DNS Forwarder hijack: %s:53 -> %s:%d", 
                               vip_str, tip_str, target_port);
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
                        LOG_I ("router: UDP DNS Forwarder hijack (IPv6): %s:53 -> %s:%d", 
                               vip_str, tip_str, target_port);
                    }
                }
            }
        }
        
        /* 如果被劫持，使用目标地址进行UDP直连 */
        if (is_hijacked) {
            LOG_I ("router: UDP routing %s:%d -> %s:%d via DNS_FORWARD (hijacked DNS query)",
                   src_ip, pcb->remote_port, dst_ip, target_port);
            pbuf_ref(p);
            hev_session_manager_start_direct_udp (pcb, &target_ip, target_port, p);
            return 1;
        }
    }
    
    /* 国内IP直连检查（第二优先级） */
    if (is_domestic (addr)) {
        LOG_I ("router: UDP routing %s:%d -> %s:%d via DIRECT (domestic IP, packet_size=%d)",
               src_ip, pcb->remote_port, dst_ip, port, p ? p->tot_len : 0);
        pbuf_ref(p);
        hev_session_manager_start_direct_udp (pcb, addr, port, p);
        return 1;
    }
    
    LOG_D ("router: UDP packet %s:%d -> %s:%d not handled by router (will use SOCKS5)",
           src_ip, pcb->remote_port, dst_ip, port);
    
    return 0;
}