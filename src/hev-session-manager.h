/*
 ============================================================================
 Name        : hev-session-manager.h
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2024 hev
 Description : Session Manager
 ============================================================================
 */

#ifndef __HEV_SESSION_MANAGER_H__
#define __HEV_SESSION_MANAGER_H__

#include <lwip/tcp.h>
#include <lwip/udp.h>
#include <lwip/pbuf.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum _HevSessionType
{
    HEV_SESSION_SOCKS5,
    HEV_SESSION_DIRECT,
    HEV_SESSION_SMART_PROXY,
    HEV_SESSION_DOMAIN_FIRST,
} HevSessionType;

void hev_session_manager_start_task (struct tcp_pcb *pcb, struct pbuf *queue,
                                     HevSessionType session_type,
                                     const char *hostname);
void hev_session_manager_start_direct_udp (struct udp_pcb *pcb,
                                           const ip_addr_t *addr, u16_t port,
                                           const ip_addr_t *orig_addr,
                                           u16_t orig_port, struct pbuf *p);

#ifdef __cplusplus
}
#endif

#endif /* __HEV_SESSION_MANAGER_H__ */
