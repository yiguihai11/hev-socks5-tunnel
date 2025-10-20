/*
 ============================================================================
 Name        : hev-traffic-router.c
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2024 hev
 Description : Traffic Router
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
}
HevIPAddressRange4;
typedef struct _HevIPAddressRange6 {
	u8_t start[16];
	u8_t end[16];
}
HevIPAddressRange6;
typedef struct _HevBlacklistedIP {
	HevListNode node;
	ip_addr_t addr;
	time_t expiry;
}
HevBlacklistedIP;
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
	LOG_D ("router: Loading chnroutes file: %s", path);
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
	free (chnroutes_ip4);
	free (chnroutes_ip6);
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
	expiry_minutes = hev_config_get_smart_proxy_blocked_ip_expiry_minutes ();
	if (expiry_minutes <= 0)
	        return;
	bip = hev_malloc (sizeof (HevBlacklistedIP));
	if (!bip)
	        return;
	ip_addr_copy (bip->addr, *addr);
	bip->expiry = time (NULL) + expiry_minutes * 60;
	hev_task_mutex_lock (&blacklist_mutex);
	hev_list_add_tail (&blacklist, &bip->node);
	hev_task_mutex_unlock (&blacklist_mutex);
}
int
hev_traffic_router_blacklist_check (const ip_addr_t *addr) {
	HevListNode *node, *next;
	time_t now = time (NULL);
	int found = 0;
	hev_task_mutex_lock (&blacklist_mutex);
	for (node = hev_list_first (&blacklist); node; node = next) {
		HevBlacklistedIP *bip = container_of (node, HevBlacklistedIP, node);
		next = hev_list_node_next (node);
		if (now > bip->expiry) {
			hev_list_del (&blacklist, node);
			hev_free (bip);
			continue;
		}
		if (ip_addr_cmp (&bip->addr, addr)) {
			found = 1;
		}
	}
	hev_task_mutex_unlock (&blacklist_mutex);
	return found;
}
int
hev_traffic_router_init (void) {
	const char *chnroutes_path = hev_config_get_chnroutes_file_path ();
	hev_task_mutex_init (&blacklist_mutex);
	if (chnroutes_init (chnroutes_path) < 0) {
		LOG_E ("router: Failed to initialize chnroutes!");
		return -1;
	}
	return 0;
}
void
hev_traffic_router_fini (void) {
	HevListNode *node;
	hev_task_mutex_lock (&blacklist_mutex);
	for (node = hev_list_first (&blacklist); node; node = hev_list_first (&blacklist)) {
		HevBlacklistedIP *bip = container_of (node, HevBlacklistedIP, node);
		hev_list_del (&blacklist, node);
		hev_free (bip);
	}
	hev_task_mutex_unlock (&blacklist_mutex);
	chnroutes_fini ();
}
int
hev_traffic_router_handle_tcp (struct tcp_pcb *pcb) {
	const ip_addr_t *local_ip = &pcb->local_ip;
	/* 1. Domestic IPs are connected directly. */
	if (is_domestic (local_ip)) {
		hev_session_manager_start_direct_tcp (pcb);
		return 1;
	}
	/* 2. For non-domestic IPs, attempt smart proxy if enabled and not blacklisted. */
	if (hev_config_get_smart_proxy_timeout_ms () > 0 &&
	        hev_config_get_smart_proxy_blocked_ip_expiry_minutes () > 0 &&
	        !hev_traffic_router_blacklist_check (local_ip)) {
		hev_session_manager_start_smart_proxy (pcb);
		return 1;
	}
	/* 3. Fallback to SOCKS5 for all other cases (blacklisted, smart proxy disabled). */
	hev_session_manager_start_socks5_tcp (pcb);
	return 1;
}
int
hev_traffic_router_handle_udp (struct udp_pcb *pcb, struct pbuf *p,
                               const ip_addr_t *addr, u16_t port) {
	/* DNS Forwarder 劫持检查（优先级最高）
     * 
     * 功能：劫持发往特定虚拟DNS地址的查询，转发到真实DNS服务器
     * 配置示例：
     *   virtual-ip4: 8.8.8.8     -> target-ip4: 1.1.1.1:53
     *   virtual-ip6: 2001:4860:4860::8844 -> target-ip6: 2606:4700:4700::1111:53
     * 
     * 应用场景：
     *   1. 统一DNS出口，方便管理
     *   2. 劫持特定DNS地址到本地/指定服务器
     *   3. 实现DNS分流（国内DNS用直连，国外DNS用代理）
     */
	if (port == 53) {
		const char *dns_fwd_virtual_ip4 = hev_config_get_dns_forwarder_virtual_ip4();
		const char *dns_fwd_virtual_ip6 = hev_config_get_dns_forwarder_virtual_ip6();
		const char *dns_fwd_target_ip4 = hev_config_get_dns_forwarder_target_ip4();
		const char *dns_fwd_target_ip6 = hev_config_get_dns_forwarder_target_ip6();
		int is_hijacked = 0;
		ip_addr_t target_ip;
		u16_t target_port = 53;
		// 默认端口53
		/* 检查IPv4劫持 */
		if (dns_fwd_virtual_ip4 && dns_fwd_target_ip4 && IP_IS_V4(addr)) {
			ip_addr_t virtual_ip4;
			if (ipaddr_aton(dns_fwd_virtual_ip4, &virtual_ip4)) {
				if (ip_addr_cmp(addr, &virtual_ip4)) {
					/* 解析目标地址（可能包含端口） */
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
						LOG_I ("router: DNS Forwarder hijack: %s:53 -> %s:%d", 
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
					/* 解析目标地址（格式：[ipv6]:port 或 ipv6） */
					char target_buf[128];
					strncpy(target_buf, dns_fwd_target_ip6, sizeof(target_buf) - 1);
					char *bracket_end = strrchr(target_buf, ']');
					if (bracket_end && *(bracket_end + 1) == ':') {
						target_port = atoi(bracket_end + 2);
						*bracket_end = '\0';
						if (ipaddr_aton(target_buf + 1, &target_ip)) {
							// 跳过 '['
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
						LOG_I ("router: DNS Forwarder hijack (IPv6): %s:53 -> %s:%d", 
						                               vip_str, tip_str, target_port);
					}
				}
			}
		}
		/* 如果被劫持，使用目标地址进行UDP直连 */
		if (is_hijacked) {
			char dest_ip_str[INET6_ADDRSTRLEN];
			char src_ip_str[INET6_ADDRSTRLEN];
			ipaddr_ntoa_r (&target_ip, dest_ip_str, sizeof (dest_ip_str));
			ipaddr_ntoa_r (&pcb->remote_ip, src_ip_str, sizeof (src_ip_str));
			LOG_I ("router: UDP DNS forward (hijacked): %s:%d -> %s:%d", 
			           src_ip_str, pcb->remote_port, dest_ip_str, target_port);
			pbuf_ref(p);
			hev_session_manager_start_direct_udp (pcb, &target_ip, target_port, p);
			return 1;
		}
	}
	/* 国内IP直连检查（第二优先级） */
	if (is_domestic (addr)) {
		char dest_ip_str[INET6_ADDRSTRLEN];
		char src_ip_str[INET6_ADDRSTRLEN];
		ipaddr_ntoa_r (addr, dest_ip_str, sizeof (dest_ip_str));
		ipaddr_ntoa_r (&pcb->remote_ip, src_ip_str, sizeof (src_ip_str));
		LOG_I ("router: UDP direct connect: %s:%d -> %s:%d (domestic)", 
		           src_ip_str, pcb->remote_port, dest_ip_str, port);
		pbuf_ref(p);
		hev_session_manager_start_direct_udp (pcb, addr, port, p);
		return 1;
	}
	return 0;
}