/*
 ============================================================================
 Name        : hev-socks5-session-udp.c
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2023 hev
 Description : Socks5 Session UDP (增强日志版本)
 ============================================================================
 */

#include <errno.h>
#include <string.h>

#include <lwip/udp.h>

#include <hev-task.h>
#include <hev-task-io.h>
#include <hev-task-io-socket.h>
#include <hev-task-mutex.h>
#include <hev-memory-allocator.h>
#include <hev-socks5-udp.h>
#include <hev-socks5-misc.h>

#include "hev-utils.h"
#include "hev-config.h"
#include "hev-logger.h"
#include "hev-compiler.h"
#include "hev-config-const.h"
#include "hev-memory-pool.h"
#include "hev-socks5-tunnel.h"

#include "hev-socks5-session-udp.h"

typedef struct _HevSocks5UDPFrame HevSocks5UDPFrame;

struct _HevSocks5UDPFrame
{
    HevListNode node;
    HevSocks5Addr addr;
    struct pbuf *data;
};

static int
task_io_yielder (HevTaskYieldType type, void *data)
{
    HevSocks5 *self = data;
    HevListNode *node;
    int res;

    if (self->type == HEV_SOCKS5_TYPE_UDP_IN_UDP) {
        ssize_t res;
        char buf;

        res = recv (self->fd, &buf, sizeof (buf), 0);
        if ((res == 0) || ((res < 0) && (errno != EAGAIN))) {
            LOG_W ("%p socks5 session udp: UDP-in-UDP connection check failed", self);
            hev_socks5_set_timeout (self, 0);
            return -1;
        }
    }

    res = hev_socks5_task_io_yielder (type, data);
    node = hev_socks5_session_get_node (HEV_SOCKS5_SESSION (self));
    hev_socks5_tunnel_update_session (node);

    return res;
}

static int
hev_socks5_session_udp_fwd_f (HevSocks5SessionUDP *self)
{
    HevSocks5UDPFrame *frame;
    HevListNode *node;
    HevSocks5UDP *udp;
    struct pbuf *buf;
    int res;

    for (;;) {
        node = hev_list_first (&self->frame_list);
        if (node)
            break;

        res = task_io_yielder (HEV_TASK_WAITIO, self);
        if (res < 0) {
            self->alive &= ~HEV_SOCKS5_SESSION_UDP_ALIVE_F;
            if (self->alive && hev_socks5_get_timeout (HEV_SOCKS5 (self))) {
                LOG_D ("%p socks5 session udp fwd f: timeout but still alive", self);
                return 0;
            }
            LOG_D ("%p socks5 session udp fwd f: yielder error, closing", self);
            return -1;
        }
    }

    frame = container_of (node, HevSocks5UDPFrame, node);
    buf = frame->data;

    LOG_D ("%p socks5 session udp fwd f: sending %d bytes", self, buf->len);

    udp = HEV_SOCKS5_UDP (self);
    res = hev_socks5_udp_sendto (udp, buf->payload, buf->len, &frame->addr);
    hev_list_del (&self->frame_list, node);
    hev_free (frame);
    pbuf_free (buf);
    self->frames--;
    
    if (res <= 0) {
        if (res < -1) {
            self->alive &= ~HEV_SOCKS5_SESSION_UDP_ALIVE_F;
            if (self->alive && hev_socks5_get_timeout (HEV_SOCKS5 (self))) {
                LOG_W ("%p socks5 session udp fwd f: send error but still alive", self);
                return 0;
            }
        }
        if (HEV_SOCKS5 (self)->type == HEV_SOCKS5_TYPE_UDP_IN_TCP)
            hev_socks5_set_timeout (HEV_SOCKS5 (self), 0);
        LOG_E ("%p socks5 session udp fwd f: send failed (res=%d)", self, res);
        res = -1;
    } else {
        LOG_D ("%p socks5 session udp fwd f: sent %d bytes successfully", self, res);
    }

    self->alive |= HEV_SOCKS5_SESSION_UDP_ALIVE_F;

    return 0;
}

static int
hev_socks5_session_udp_fwd_b (HevSocks5SessionUDP *self)
{
    HevSocks5UDP *udp = HEV_SOCKS5_UDP (self);
    HevSocks5Addr addr;
    err_t err = ERR_OK;
    struct pbuf *buf;
    ip_addr_t saddr;
    uint16_t port;
    char dst_ip[INET6_ADDRSTRLEN];
    int res;

    buf = pbuf_alloc (PBUF_TRANSPORT, UDP_BUF_SIZE, PBUF_RAM);
    if (!buf) {
        LOG_E ("%p socks5 session udp fwd b: failed to allocate pbuf", self);
        return -1;
    }

    res = hev_socks5_udp_recvfrom (udp, buf->payload, buf->len, &addr);
    if (res <= 0) {
        if (res < -1) {
            self->alive &= ~HEV_SOCKS5_SESSION_UDP_ALIVE_B;
            if (self->alive && hev_socks5_get_timeout (HEV_SOCKS5 (self))) {
                LOG_D ("%p socks5 session udp fwd b: recv error but still alive", self);
                pbuf_free (buf);
                return 0;
            }
        }
        if (HEV_SOCKS5 (self)->type == HEV_SOCKS5_TYPE_UDP_IN_TCP)
            hev_socks5_set_timeout (HEV_SOCKS5 (self), 0);
        LOG_E ("%p socks5 session udp fwd b: recv failed (res=%d)", self, res);
        pbuf_free (buf);
        return -1;
    }

    buf->len = res;
    buf->tot_len = res;

    LOG_D ("%p socks5 session udp fwd b: received %d bytes", self, res);

    if (self->addr && self->port) {
        ip_2_ip4 (&saddr)->addr = self->addr;
        port = self->port;
    } else {
        res = hev_socks5_addr_into_lwip (&addr, &saddr, &port);
        if (res < 0) {
            LOG_E ("%p socks5 session udp fwd b: failed to convert address", self);
            pbuf_free (buf);
            return -1;
        }
    }

    ipaddr_ntoa_r (&saddr, dst_ip, sizeof (dst_ip));
    LOG_D ("%p socks5 session udp fwd b: forwarding to %s:%d", self, dst_ip, port);

    hev_task_mutex_lock (self->mutex);
    if (self->pcb) {
        err = udp_sendfrom (self->pcb, buf, &saddr, port);
    } else {
        LOG_W ("%p socks5 session udp fwd b: pcb is NULL", self);
        err = ERR_CONN;
    }
    hev_task_mutex_unlock (self->mutex);
    pbuf_free (buf);

    if (err != ERR_OK) {
        LOG_E ("%p socks5 session udp fwd b: udp_sendfrom failed (err=%d)", self, err);
        return -1;
    }

    self->alive |= HEV_SOCKS5_SESSION_UDP_ALIVE_B;

    return 0;
}

static void
udp_recv_handler (void *arg, struct udp_pcb *pcb, struct pbuf *p,
                  const ip_addr_t *addr, u16_t port)
{
    HevSocks5SessionUDP *self = arg;
    HevSocks5UDPFrame *frame;
    char src_ip[INET6_ADDRSTRLEN];

    if (!p) {
        LOG_D ("%p socks5 session udp: recv_handler got NULL pbuf, terminating", self);
        hev_socks5_session_terminate (HEV_SOCKS5_SESSION (self));
        return;
    }

    ipaddr_ntoa_r (addr, src_ip, sizeof (src_ip));
    LOG_D ("%p socks5 session udp: received %d bytes from %s:%d",
           self, p->tot_len, src_ip, port);

    /* 使用动态UDP池大小，并在接近满载时尝试调整 */
    int current_pool_size = hev_memory_pool_get_udp_size ();
    if (self->frames >= current_pool_size) {
        LOG_W ("%p socks5 session udp: frame pool full (%d/%d frames), dropping packet",
               self, self->frames, current_pool_size);

        /* 尝试动态调整池大小 */
        int new_size = hev_memory_pool_adjust_udp_size (self->frames, current_pool_size);
        if (new_size > current_pool_size) {
            LOG_I ("%p socks5 session udp: pool expanded to %d, retrying", self, new_size);
        } else {
            LOG_D ("%p socks5 session udp: pool cannot expand further", self);
        }

        pbuf_free (p);
        return;
    }

    frame = hev_malloc (sizeof (HevSocks5UDPFrame));
    if (!frame) {
        LOG_E ("%p socks5 session udp: failed to allocate frame", self);
        pbuf_free (p);
        return;
    }

    frame->data = p;
    memset (&frame->node, 0, sizeof (frame->node));
    hev_socks5_addr_from_lwip (&frame->addr, &pcb->local_ip, pcb->local_port);

    if (frame->addr.atype == HEV_SOCKS5_ADDR_TYPE_NAME) {
        self->addr = ip_2_ip4 (&pcb->local_ip)->addr;
        self->port = pcb->local_port;
        LOG_D ("%p socks5 session udp: using domain name address, caching IP", self);
    }

    self->frames++;
    hev_list_add_tail (&self->frame_list, &frame->node);
    
    LOG_D ("%p socks5 session udp: queued frame (%d frames total)", self, self->frames);
    
    hev_task_wakeup (self->data.task);
}

HevSocks5SessionUDP *
hev_socks5_session_udp_new (struct udp_pcb *pcb, HevTaskMutex *mutex)
{
    HevSocks5SessionUDP *self;
    int res;

    self = hev_malloc0 (sizeof (HevSocks5SessionUDP));
    if (!self) {
        LOG_E ("%p socks5 session udp: failed to allocate memory", self);
        return NULL;
    }

    res = hev_socks5_session_udp_construct (self, pcb, mutex);
    if (res < 0) {
        LOG_E ("%p socks5 session udp: failed to construct", self);
        hev_free (self);
        return NULL;
    }

    LOG_D ("%p socks5 session udp new", self);

    return self;
}

static int
hev_socks5_session_udp_bind (HevSocks5 *self, int fd,
                             const struct sockaddr *dest)
{
    HevConfigSocks5Server *srv;
    unsigned int mark;

    LOG_D ("%p socks5 session udp bind", self);

    srv = hev_config_get_socks5_udp_server ();
    mark = srv->mark;

    if (mark) {
        int res;

        res = set_sock_mark (fd, mark);
        if (res < 0) {
            LOG_E ("%p socks5 session udp: failed to set socket mark", self);
            return -1;
        }
        LOG_D ("%p socks5 session udp: socket mark set to %u", self, mark);
    }

    return 0;
}

static uint16_t
hev_socks5_addr_get_port (const HevSocks5Addr *addr)
{
    uint16_t port = 0;

    switch (addr->atype) {
    case HEV_SOCKS5_ADDR_TYPE_IPV4:
        port = addr->ipv4.port;
        break;
    case HEV_SOCKS5_ADDR_TYPE_IPV6:
        port = addr->ipv6.port;
        break;
    case HEV_SOCKS5_ADDR_TYPE_NAME:
        memcpy (&port, addr->domain.addr + addr->domain.len, 2);
    }

    return port;
}

static int
hev_socks5_session_udp_set_upstream_addr (HevSocks5Client *base,
                                          HevSocks5Addr *addr)
{
    HevConfigSocks5Server *srv = hev_config_get_socks5_udp_server ();
    HevSocks5ClientClass *ckptr;

    if (srv->udp_relay && srv->addr[0]) {
        uint16_t port = hev_socks5_addr_get_port (addr);
        LOG_D ("%p socks5 session udp: using UDP relay address %s:%d",
               base, srv->addr, port);
        hev_socks5_addr_from_name (addr, srv->addr, port);
    }

    ckptr = HEV_SOCKS5_CLIENT_CLASS (HEV_SOCKS5_CLIENT_UDP_TYPE);
    return ckptr->set_upstream_addr (base, addr);
}

static void
splice_task_entry (void *data)
{
    HevTask *task = hev_task_self ();
    HevSocks5SessionUDP *self = data;
    int fd;
    size_t total_received = 0;

    LOG_D ("%p socks5 session udp: backward splice task start", self);

    fd = hev_task_io_dup (hev_socks5_udp_get_fd (HEV_SOCKS5_UDP (self)));
    if (fd < 0) {
        LOG_E ("%p socks5 session udp: failed to dup fd for backward task", self);
        return;
    }

    if (hev_task_add_fd (task, fd, POLLIN) < 0)
        hev_task_mod_fd (task, fd, POLLIN);

    for (;;) {
        if (hev_socks5_session_udp_fwd_b (self) < 0)
            break;
        total_received++;
    }

    self->alive &= ~HEV_SOCKS5_SESSION_UDP_ALIVE_B;
    hev_task_del_fd (task, fd);
    close (fd);

    LOG_D ("%p socks5 session udp: backward splice task end (received %zu packets)",
           self, total_received);
}

static int
hev_socks5_session_udp_splice (HevSocks5Session *base)
{
    HevSocks5SessionUDP *self = HEV_SOCKS5_SESSION_UDP (base);
    HevTask *task = hev_task_self ();
    int stack_size;
    int fd;
    size_t total_sent = 0;

    LOG_D ("%p socks5 session udp splice", self);

    self->alive = HEV_SOCKS5_SESSION_UDP_ALIVE_F |
                  HEV_SOCKS5_SESSION_UDP_ALIVE_B;
    
    fd = hev_socks5_udp_get_fd (HEV_SOCKS5_UDP (self));
    if (hev_task_mod_fd (task, fd, POLLOUT) < 0)
        hev_task_add_fd (task, fd, POLLOUT);

    stack_size = hev_config_get_misc_task_stack_size ();
    task = hev_task_new (stack_size);
    if (!task) {
        LOG_E ("%p socks5 session udp splice: failed to create backward task", self);
        return -1;
    }
    
    hev_task_ref (task);
    hev_task_run (task, splice_task_entry, self);

    LOG_D ("%p socks5 session udp splice: starting forward loop", self);

    for (;;) {
        if (hev_socks5_session_udp_fwd_f (self) < 0)
            break;
        total_sent++;
    }

    self->alive &= ~HEV_SOCKS5_SESSION_UDP_ALIVE_F;
    
    LOG_D ("%p socks5 session udp splice: waiting for backward task (sent %zu packets)",
           self, total_sent);
    
    hev_task_join (task);
    hev_task_unref (task);

    LOG_D ("%p socks5 session udp splice: completed", self);

    return 0;
}

static HevTask *
hev_socks5_session_udp_get_task (HevSocks5Session *base)
{
    HevSocks5SessionUDP *self = HEV_SOCKS5_SESSION_UDP (base);

    return self->data.task;
}

static void
hev_socks5_session_udp_set_task (HevSocks5Session *base, HevTask *task)
{
    HevSocks5SessionUDP *self = HEV_SOCKS5_SESSION_UDP (base);

    LOG_D ("%p socks5 session udp set task %p", self, task);
    self->data.task = task;
}

static HevListNode *
hev_socks5_session_udp_get_node (HevSocks5Session *base)
{
    HevSocks5SessionUDP *self = HEV_SOCKS5_SESSION_UDP (base);

    return &self->data.node;
}

int
hev_socks5_session_udp_construct (HevSocks5SessionUDP *self,
                                  struct udp_pcb *pcb, HevTaskMutex *mutex)
{
    HevConfigSocks5Server *srv = hev_config_get_socks5_udp_server ();
    char dst_ip[INET6_ADDRSTRLEN];
    int type;
    int res;

    if (srv->udp_relay) {
        type = HEV_SOCKS5_TYPE_UDP_IN_UDP;
        LOG_D ("%p socks5 session udp construct: using UDP-in-UDP mode", self);
    } else {
        type = HEV_SOCKS5_TYPE_UDP_IN_TCP;
        LOG_D ("%p socks5 session udp construct: using UDP-in-TCP mode", self);
    }

    res = hev_socks5_client_udp_construct (&self->base, type);
    if (res < 0) {
        LOG_E ("socks5 session udp construct: failed to construct client");
        return -1;
    }

    ipaddr_ntoa_r (&pcb->local_ip, dst_ip, sizeof (dst_ip));
    LOG_D ("%p socks5 session udp construct for %s:%d", self, dst_ip, pcb->local_port);

    HEV_OBJECT (self)->klass = HEV_SOCKS5_SESSION_UDP_TYPE;

    udp_recv (pcb, udp_recv_handler, self);

    self->pcb = pcb;
    self->mutex = mutex;
    self->data.self = self;

    return 0;
}

void
hev_socks5_session_udp_destruct (HevObject *base)
{
    HevSocks5SessionUDP *self = HEV_SOCKS5_SESSION_UDP (base);
    HevListNode *node;
    int dropped_frames = 0;

    LOG_D ("%p socks5 session udp destruct", self);

    node = hev_list_first (&self->frame_list);
    while (node) {
        HevSocks5UDPFrame *frame;

        frame = container_of (node, HevSocks5UDPFrame, node);
        node = hev_list_node_next (node);
        pbuf_free (frame->data);
        hev_free (frame);
        dropped_frames++;
    }

    if (dropped_frames > 0) {
        LOG_W ("%p socks5 session udp destruct: dropped %d pending frames",
               self, dropped_frames);
    }

    hev_task_mutex_lock (self->mutex);
    if (self->pcb) {
        LOG_D ("%p socks5 session udp destruct: removing pcb", self);
        udp_recv (self->pcb, NULL, NULL);
        udp_remove (self->pcb);
    }
    hev_task_mutex_unlock (self->mutex);

    HEV_SOCKS5_CLIENT_UDP_TYPE->destruct (base);
}

static void *
hev_socks5_session_udp_iface (HevObject *base, void *type)
{
    if (type == HEV_SOCKS5_SESSION_TYPE) {
        HevSocks5SessionUDPClass *klass = HEV_OBJECT_GET_CLASS (base);
        return &klass->session;
    }

    return HEV_SOCKS5_CLIENT_UDP_TYPE->iface (base, type);
}

HevObjectClass *
hev_socks5_session_udp_class (void)
{
    static HevSocks5SessionUDPClass klass;
    HevSocks5SessionUDPClass *kptr = &klass;
    HevObjectClass *okptr = HEV_OBJECT_CLASS (kptr);

    if (!okptr->name) {
        HevSocks5Class *skptr;
        HevSocks5ClientClass *ckptr;
        HevSocks5SessionIface *siptr;
        void *ptr;

        ptr = HEV_SOCKS5_CLIENT_UDP_TYPE;
        memcpy (kptr, ptr, sizeof (HevSocks5ClientUDPClass));

        okptr->name = "HevSocks5SessionUDP";
        okptr->destruct = hev_socks5_session_udp_destruct;
        okptr->iface = hev_socks5_session_udp_iface;

        skptr = HEV_SOCKS5_CLASS (kptr);
        skptr->binder = hev_socks5_session_udp_bind;

        ckptr = HEV_SOCKS5_CLIENT_CLASS (kptr);
        ckptr->set_upstream_addr = hev_socks5_session_udp_set_upstream_addr;

        siptr = &kptr->session;
        siptr->splicer = hev_socks5_session_udp_splice;
        siptr->get_task = hev_socks5_session_udp_get_task;
        siptr->set_task = hev_socks5_session_udp_set_task;
        siptr->get_node = hev_socks5_session_udp_get_node;
    }

    return okptr;
}