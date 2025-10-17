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

void hev_session_manager_init (void);
void hev_session_manager_fini (void);

void hev_session_manager_start_socks5_tcp (struct tcp_pcb *pcb);
void hev_session_manager_start_direct_tcp (struct tcp_pcb *pcb);
void hev_session_manager_start_smart_proxy (struct tcp_pcb *pcb);


#endif /* __HEV_SESSION_MANAGER_H__ */
