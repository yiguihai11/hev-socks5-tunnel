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

#include "hev-compiler.h"
#include <hev-task.h>
#include <hev-memory-allocator.h>

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

static HevIPAddressRange4 *chnroutes_ip4;
static unsigned int chnroutes_ip4_count;
static HevIPAddressRange6 *chnroutes_ip6;
static unsigned int chnroutes_ip6_count;

static int
compare_ip4_range (const void *a, const void *b)
{
    const HevIPAddressRange4 *ra = a;
    const HevIPAddressRange4 *rb = b;
    if (ra->start < rb->start) return -1;
    if (ra->start > rb->start) return 1;
    return 0;
}

static int
compare_ip6_range (const void *a, const void *b)
{
    const HevIPAddressRange6 *ra = a;
    const HevIPAddressRange6 *rb = b;
    return memcmp(ra->start, rb->start, 16);
}

static int
chnroutes_init (const char *path)
{
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

        if (strchr(ip_str, ':')) { // IPv6
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
        } else { // IPv4
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
chnroutes_fini (void)
{
    free (chnroutes_ip4);
    free (chnroutes_ip6);
}

static int
is_domestic (const ip_addr_t *addr)
{
    char ip_str[INET6_ADDRSTRLEN];
    ipaddr_ntoa_r(addr, ip_str, sizeof(ip_str));
    LOG_D("router: Checking if %s is domestic.", ip_str);

    if (IP_IS_V4 (addr)) {
        if (!chnroutes_ip4)
            return 0;

        u32_t addr_host = ntohl(ip_2_ip4(addr)->addr);
        int l = 0, r = chnroutes_ip4_count - 1;
        while (l <= r) {
            int mid = l + (r - l) / 2;
            if (addr_host >= chnroutes_ip4[mid].start && addr_host <= chnroutes_ip4[mid].end) {
                LOG_D("router: %s is domestic (IPv4).", ip_str);
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
                LOG_D("router: %s is domestic (IPv6).", ip_str);
                return 1;
            }
            if (memcmp(ip_2_ip6(addr)->addr, chnroutes_ip6[mid].start, 16) < 0) {
                r = mid - 1;
            } else {
                l = mid + 1;
            }
        }
    }

    LOG_D("router: %s is not domestic.", ip_str);
    return 0;
}

int
hev_traffic_router_init (void)
{
    const char *chnroutes_path = hev_config_get_chnroutes_file_path ();
    if (chnroutes_init (chnroutes_path) < 0) {
        LOG_E ("router: Failed to initialize chnroutes!");
        return -1;
    }
    return 0;
}

void
hev_traffic_router_fini (void)
{
    chnroutes_fini ();
}

int
hev_traffic_router_handle_tcp (struct tcp_pcb *pcb)
{
    if (is_domestic (&pcb->local_ip)) {
        hev_session_manager_start_direct_tcp (pcb);
        return 1;
    }

    /* Fallback to SOCKS5 for non-domestic traffic */
    return 0;
}

int
hev_traffic_router_handle_udp (struct udp_pcb *pcb, struct pbuf *p,
                               const ip_addr_t *addr, u16_t port)
{
    /* TODO: Implement DNS forwarder and direct UDP */
    return 0; /* Not handled */
}