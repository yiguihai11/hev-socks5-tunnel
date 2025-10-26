/*
 ============================================================================
 Name        : hev-socks5-misc.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2021 - 2025 hev
 Description : Socks5 Misc
 ============================================================================
 */

#ifndef __HEV_SOCKS5_MISC_H__
#define __HEV_SOCKS5_MISC_H__

#include <netinet/in.h>

#include <hev-task.h>

#include "hev-socks5-proto.h"

#ifdef __cplusplus
extern "C" {
#endif

int hev_socks5_task_io_yielder (HevTaskYieldType type, void *data);

void hev_socks5_set_task_stack_size (int stack_size);
void hev_socks5_set_udp_recv_buffer_size (int buffer_size);

/* 智能缓冲区管理 */
void hev_socks5_init_smart_buffer (void);
void hev_socks5_update_buffer_stats (unsigned long rx_bytes, double latency_ms);
void hev_socks5_adjust_buffer_size (void);
void hev_socks5_get_buffer_stats (int *current_size, double *avg_latency,
                                  int *congestion_level);

int hev_socks5_addr_len (const HevSocks5Addr *addr);
int hev_socks5_addr_from_name (HevSocks5Addr *addr, const char *name, int port);
int hev_socks5_addr_from_ipv4 (HevSocks5Addr *addr, const void *ipv4, int port);
int hev_socks5_addr_from_ipv6 (HevSocks5Addr *addr, const void *ipv6, int port);
int hev_socks5_addr_from_sockaddr6 (HevSocks5Addr *addr,
                                    struct sockaddr_in6 *saddr);
int hev_socks5_addr_into_sockaddr6 (const HevSocks5Addr *addr,
                                    struct sockaddr_in6 *saddr, int *family);
int hev_socks5_name_into_sockaddr6 (const char *host, int port,
                                    struct sockaddr_in6 *saddr, int *family);

#ifdef __cplusplus
}
#endif

#endif /* __HEV_SOCKS5_MISC_H__ */
