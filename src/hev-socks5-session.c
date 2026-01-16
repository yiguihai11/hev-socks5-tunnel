/*
 ============================================================================
 Name        : hev-socks5-session.c
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2023 hev
 Description : Socks5 Session
 ============================================================================
 */

#include <string.h>

#include "hev-logger.h"
#include "hev-config.h"
#include "hev-socks5-client.h"

#include "hev-socks5-session.h"

void
hev_socks5_session_run (HevSocks5Session *self)
{
    HevSocks5SessionIface *iface;
    HevConfigSocks5Server *srv;
    int read_write_timeout;
    int connect_timeout;
    int res;
    time_t start_time, connect_time, handshake_time, splice_time;

    start_time = get_current_time_ms ();
    LOG_D ("%p socks5 session run", self);

    srv = hev_config_get_socks5_tcp_server ();
    connect_timeout = hev_config_get_misc_connect_timeout ();
    read_write_timeout = hev_config_get_misc_tcp_read_write_timeout ();

    hev_socks5_set_timeout (HEV_SOCKS5 (self), connect_timeout);

    res = hev_socks5_client_connect (HEV_SOCKS5_CLIENT (self), srv->addr,
                                     srv->port);
    connect_time = get_current_time_ms ();
    if (res < 0) {
        LOG_E ("%p socks5 session connect (connect_time=%ldms)", self,
               connect_time - start_time);
        return;
    }
    LOG_I ("%p socks5 session connected (connect_time=%ldms)", self,
           connect_time - start_time);

    hev_socks5_set_timeout (HEV_SOCKS5 (self), read_write_timeout);

    if (srv->user && srv->pass) {
        hev_socks5_client_set_auth (HEV_SOCKS5_CLIENT (self), srv->user,
                                    srv->pass);
        LOG_D ("%p socks5 client auth %s:%s", self, srv->user, srv->pass);
    }

    res = hev_socks5_client_handshake (HEV_SOCKS5_CLIENT (self), srv->pipeline);
    handshake_time = get_current_time_ms ();
    if (res < 0) {
        LOG_E ("%p socks5 session handshake (handshake_time=%ldms)", self,
               handshake_time - connect_time);
        return;
    }
    LOG_I ("%p socks5 session handshake done (handshake_time=%ldms)", self,
           handshake_time - connect_time);

    iface = HEV_OBJECT_GET_IFACE (self, HEV_SOCKS5_SESSION_TYPE);
    iface->splicer (self);

    splice_time = get_current_time_ms ();
    LOG_I (
        "%p socks5 session ended (total_time=%ldms, connect=%ldms, handshake=%ldms, data=%ldms)",
        self, splice_time - start_time, connect_time - start_time,
        handshake_time - connect_time, splice_time - handshake_time);
}

void
hev_socks5_session_terminate (HevSocks5Session *self)
{
    HevSocks5SessionIface *iface;

    LOG_D ("%p socks5 session terminate", self);

    /* 添加空指针检查，防止段错误 */
    if (!self) {
        LOG_D ("socks5 session terminate: self is NULL, skipping termination");
        return;
    }

    iface = HEV_OBJECT_GET_IFACE (self, HEV_SOCKS5_SESSION_TYPE);
    hev_socks5_set_timeout (HEV_SOCKS5 (self), 0);
    hev_task_wakeup (iface->get_task (self));
}

void
hev_socks5_session_set_task (HevSocks5Session *self, HevTask *task)
{
    HevSocks5SessionIface *iface;

    iface = HEV_OBJECT_GET_IFACE (self, HEV_SOCKS5_SESSION_TYPE);
    iface->set_task (self, task);
}

HevListNode *
hev_socks5_session_get_node (HevSocks5Session *self)
{
    HevSocks5SessionIface *iface;

    iface = HEV_OBJECT_GET_IFACE (self, HEV_SOCKS5_SESSION_TYPE);
    return iface->get_node (self);
}

void *
hev_socks5_session_iface (void)
{
    static char type;

    return &type;
}
