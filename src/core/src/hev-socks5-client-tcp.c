/*
 ============================================================================
 Name        : hev-socks5-client-tcp.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2021 - 2025 hev
 Description : Socks5 Client TCP
 ============================================================================
 */

#include <string.h>

#include <hev-memory-allocator.h>

#include "hev-socks5-misc-priv.h"
#include "hev-socks5-logger-priv.h"
#include "hev-connection-pool.h"

#include "hev-socks5-client-tcp.h"

HevSocks5ClientTCP *
hev_socks5_client_tcp_new_name (const char *name, int port)
{
    HevSocks5ClientTCP *self;
    HevSocks5Addr addr;
    int res;

    self = hev_malloc0 (sizeof (HevSocks5ClientTCP));
    if (!self)
        return NULL;

    hev_socks5_addr_from_name (&addr, name, port);
    res = hev_socks5_client_tcp_construct (self, &addr);
    if (res < 0) {
        hev_free (self);
        return NULL;
    }

    LOG_D ("%p socks5 client tcp new name", self);

    return self;
}

HevSocks5ClientTCP *
hev_socks5_client_tcp_new_ipv4 (const void *ipv4, int port)
{
    HevSocks5ClientTCP *self;
    HevSocks5Addr addr;
    int res;

    self = hev_malloc0 (sizeof (HevSocks5ClientTCP));
    if (!self)
        return NULL;

    hev_socks5_addr_from_ipv4 (&addr, ipv4, port);
    res = hev_socks5_client_tcp_construct (self, &addr);
    if (res < 0) {
        hev_free (self);
        return NULL;
    }

    LOG_D ("%p socks5 client tcp new ipv4", self);

    return self;
}

HevSocks5ClientTCP *
hev_socks5_client_tcp_new_ipv6 (const void *ipv6, int port)
{
    HevSocks5ClientTCP *self;
    HevSocks5Addr addr;
    int res;

    self = hev_malloc0 (sizeof (HevSocks5ClientTCP));
    if (!self)
        return NULL;

    hev_socks5_addr_from_ipv6 (&addr, ipv6, port);
    res = hev_socks5_client_tcp_construct (self, &addr);
    if (res < 0) {
        hev_free (self);
        return NULL;
    }

    LOG_D ("%p socks5 client tcp new ipv6", self);

    return self;
}

static HevSocks5Addr *
hev_socks5_client_tcp_get_upstream_addr (HevSocks5Client *base)
{
    HevSocks5ClientTCP *self = HEV_SOCKS5_CLIENT_TCP (base);
    HevSocks5Addr *addr;

    addr = self->addr;
    self->addr = NULL;

    return addr;
}

static int
hev_socks5_client_tcp_set_upstream_addr (HevSocks5Client *base,
                                         HevSocks5Addr *addr)
{
    return 0;
}

int
hev_socks5_client_tcp_construct (HevSocks5ClientTCP *self,
                                 const HevSocks5Addr *addr)
{
    int res;

    res = hev_socks5_client_construct (&self->base, HEV_SOCKS5_TYPE_TCP);
    if (res < 0)
        return res;

    LOG_D ("%p socks5 client tcp construct", self);

    HEV_OBJECT (self)->klass = HEV_SOCKS5_CLIENT_TCP_TYPE;

    res = hev_socks5_addr_len (addr);
    self->addr = hev_malloc (res);
    if (!self->addr)
        return -1;
    memcpy (self->addr, addr, res);

    if (LOG_ON ()) {
        const char *str;
        char buf[272];

        str = hev_socks5_addr_into_str (self->addr, buf, sizeof (buf));
        LOG_I ("%p socks5 client tcp -> %s", self, str);
    }

    return 0;
}

static void
hev_socks5_client_tcp_destruct (HevObject *base)
{
    HevSocks5ClientTCP *self = HEV_SOCKS5_CLIENT_TCP (base);

    LOG_D ("%p socks5 client tcp destruct", self);

    if (self->addr)
        hev_free (self->addr);

    HEV_SOCKS5_CLIENT_TYPE->destruct (base);
}

static void *
hev_socks5_client_tcp_iface (HevObject *base, void *type)
{
    HevSocks5ClientTCPClass *klass = HEV_OBJECT_GET_CLASS (base);

    return &klass->tcp;
}

HevObjectClass *
hev_socks5_client_tcp_class (void)
{
    static HevSocks5ClientTCPClass klass;
    HevSocks5ClientTCPClass *kptr = &klass;
    HevObjectClass *okptr = HEV_OBJECT_CLASS (kptr);

    if (!okptr->name) {
        HevSocks5ClientClass *ckptr;
        HevSocks5TCPIface *tiptr;

        memcpy (kptr, HEV_SOCKS5_CLIENT_TYPE, sizeof (HevSocks5ClientClass));

        okptr->name = "HevSocks5ClientTCP";
        okptr->destruct = hev_socks5_client_tcp_destruct;
        okptr->iface = hev_socks5_client_tcp_iface;

        ckptr = HEV_SOCKS5_CLIENT_CLASS (kptr);
        ckptr->get_upstream_addr = hev_socks5_client_tcp_get_upstream_addr;
        ckptr->set_upstream_addr = hev_socks5_client_tcp_set_upstream_addr;

        tiptr = &kptr->tcp;
        memcpy (tiptr, HEV_SOCKS5_TCP_TYPE, sizeof (HevSocks5TCPIface));
    }

    return okptr;
}

/* 连接池版本：从连接池获取或创建连接 */
HevSocks5ClientTCP *
hev_socks5_client_tcp_new_pooled (const char *name, int port)
{
    HevSocks5ClientTCP *self;
    HevSocks5Addr addr;
    HevConnectionPoolEntry *pool_entry;
    int res;

    /* 首先尝试从连接池获取连接 */
    pool_entry = hev_connection_pool_get (name, port, HEV_SOCKS5_TYPE_TCP);
    if (pool_entry && pool_entry->fd >= 0) {
        /* 使用池中的连接 */
        self = hev_malloc0 (sizeof (HevSocks5ClientTCP));
        if (!self) {
            LOG_E (
                "socks5 client tcp: failed to allocate client for pooled connection");
            return NULL;
        }

        self->pool_entry = pool_entry;
        self->from_pool = 1;

        /* 设置fd，避免创建新连接 */
        HEV_SOCKS5 (self)->fd = pool_entry->fd;

        /* 构造客户端，但不建立新连接 */
        hev_socks5_addr_from_name (&addr, name, port);
        res = hev_socks5_client_tcp_construct (self, &addr);
        if (res < 0) {
            LOG_E ("socks5 client tcp: failed to construct pooled client");
            hev_free (self);
            hev_connection_pool_remove (pool_entry);
            return NULL;
        }

        LOG_D ("%p socks5 client tcp new pooled (fd=%d)", self, pool_entry->fd);
        return self;
    }

    /* 池中没有可用连接，创建新连接 */
    LOG_D ("socks5 client tcp: no pooled connection available, creating new");
    return hev_socks5_client_tcp_new_name (name, port);
}

/* 将连接返回到连接池 */
void
hev_socks5_client_tcp_return_to_pool (HevSocks5ClientTCP *self)
{
    if (!self || !self->from_pool) {
        /* 不是来自连接池的连接，直接销毁 */
        if (self) {
            hev_socks5_client_tcp_destruct (HEV_OBJECT (self));
            hev_free (self);
        }
        return;
    }

    /* 将连接返回池中 */
    if (self->pool_entry) {
        hev_connection_pool_put (self->pool_entry);
        LOG_D ("%p socks5 client tcp: returned to pool (fd=%d)", self,
               self->pool_entry->fd);
    }

    /* 清理客户端结构，但保留连接池条目 */
    self->pool_entry = NULL;
    hev_free (self);
}
