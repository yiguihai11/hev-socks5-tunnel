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
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void hev_session_manager_init (void);
void hev_session_manager_fini (void);

void hev_session_manager_start_socks5_tcp (struct tcp_pcb *pcb);
void hev_session_manager_start_direct_tcp (struct tcp_pcb *pcb);
void hev_session_manager_start_smart_proxy (struct tcp_pcb *pcb);
void hev_session_manager_start_direct_udp (struct udp_pcb *pcb,
                                           const ip_addr_t *addr, u16_t port,
                                           const ip_addr_t *orig_addr,
                                           u16_t orig_port, struct pbuf *p);

/* Protocol parsing zero-copy optimization functions */
int hev_session_manager_enable_protocol_zerocopy (void);
void hev_session_manager_disable_protocol_zerocopy (void);
int hev_session_manager_is_protocol_zerocopy_enabled (void);

/* Zero-copy protocol parsing utility functions */
int hev_extract_string_from_offset (const struct pbuf *p, size_t start_offset,
                                    const char *end_marker, char *buffer,
                                    size_t buffer_len);

#ifdef __cplusplus
}
#endif

#endif /* __HEV_SESSION_MANAGER_H__ */
