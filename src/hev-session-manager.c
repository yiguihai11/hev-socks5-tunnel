/*
 ============================================================================
 Name        : hev-session-manager.c
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2024 hev
 Description : Session Manager
 ============================================================================
 */

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include <hev-task.h>
#include <hev-task-system.h>
#include <hev-task-io-socket.h>
#include <hev-memory-allocator.h>
#include <hev-object.h>
#include <hev-socks5.h>
#include <hev-socks5-misc.h>

#include "hev-config.h"
#include "hev-logger.h"
#include "hev-socks5-session.h"
#include "hev-socks5-session-tcp.h"
#include "hev-socks5-tunnel.h"
#include "hev-traffic-router.h"

#include "hev-session-manager.h"

/* Forward declarations */
static void run_direct_connect_task (void *data);
static void run_smart_proxy_task (void *data);

void
hev_session_manager_init (void)
{
    /* Nothing to do */
}

void
hev_session_manager_fini (void)
{
    /* Nothing to do */
}

static void
hev_socks5_session_task_entry (void *data)
{
    HevSocks5Session *s = data;

    hev_socks5_session_run (s);

    hev_socks5_tunnel_delete_session (hev_socks5_session_get_node (s));
    hev_object_unref (HEV_OBJECT (s));
}

void
hev_session_manager_start_socks5_tcp (struct tcp_pcb *pcb)
{
    HevSocks5SessionTCP *tcp;
    HevListNode *node;
    int stack_size;
    HevTask *task;

    tcp = hev_socks5_session_tcp_new (pcb, &mutex);
    if (!tcp) {
        tcp_abort (pcb);
        return;
    }

    stack_size = hev_config_get_misc_task_stack_size ();
    task = hev_task_new (stack_size);
    if (!task) {
        hev_object_unref (HEV_OBJECT (tcp));
        return;
    }

    hev_socks5_session_set_task (HEV_SOCKS5_SESSION (tcp), task);
    node = hev_socks5_session_get_node (HEV_SOCKS5_SESSION (tcp));
    hev_socks5_tunnel_insert_session (node);
    hev_task_run (task, hev_socks5_session_task_entry, tcp);
}

void
hev_session_manager_start_direct_tcp (struct tcp_pcb *pcb)
{
    HevSocks5SessionTCP *tcp;
    HevListNode *node;
    int stack_size;
    HevTask *task;

    tcp = hev_socks5_session_tcp_new (pcb, &mutex);
    if (!tcp) {
        tcp_abort (pcb);
        return;
    }

    stack_size = hev_config_get_misc_task_stack_size ();
    task = hev_task_new (stack_size);
    if (!task) {
        hev_object_unref (HEV_OBJECT (tcp));
        return;
    }

    hev_socks5_session_set_task (HEV_SOCKS5_SESSION (tcp), task);
    node = hev_socks5_session_get_node (HEV_SOCKS5_SESSION (tcp));
    hev_socks5_tunnel_insert_session (node);
    hev_task_run (task, run_direct_connect_task, tcp);
}

void
hev_session_manager_start_smart_proxy (struct tcp_pcb *pcb)
{
    HevSocks5SessionTCP *tcp;
    HevListNode *node;
    int stack_size;
    HevTask *task;

    tcp = hev_socks5_session_tcp_new (pcb, &mutex);
    if (!tcp) {
        tcp_abort (pcb);
        return;
    }

    stack_size = hev_config_get_misc_task_stack_size ();
    task = hev_task_new (stack_size);
    if (!task) {
        hev_object_unref (HEV_OBJECT (tcp));
        return;
    }

    hev_socks5_session_set_task (HEV_SOCKS5_SESSION (tcp), task);
    node = hev_socks5_session_get_node (HEV_SOCKS5_SESSION (tcp));
    hev_socks5_tunnel_insert_session (node);
    hev_task_run (task, run_smart_proxy_task, tcp);
}

static void
run_direct_connect_task (void *data)
{
    HevSocks5SessionTCP *self = data;
    HevSocks5Session *s = HEV_SOCKS5_SESSION (self);
    HevObjectClass *klass = HEV_OBJECT_GET_CLASS (s);
    HevSocks5SessionIface *iface = klass->iface (HEV_OBJECT (s), HEV_SOCKS5_SESSION_TYPE);
    struct tcp_pcb *pcb = self->pcb;
    HevTask *task = iface->get_task (s);
    HevListNode *node = iface->get_node (s);
    struct sockaddr_storage saddr;
    socklen_t saddr_len;
    char ip_str[INET6_ADDRSTRLEN];
    int fd = -1;

    LOG_D ("router: direct connect task run");

    /* Build address structure for dual-stack socket */
    struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&saddr;
    saddr_len = sizeof (struct sockaddr_in6);
    memset (sa6, 0, saddr_len);
    sa6->sin6_family = AF_INET6;

    /* pcb->local_port is in host byte order in this environment;
       sockaddr expects network byte order, so convert with htons(). */
    sa6->sin6_port = htons(pcb->local_port);

    if (IP_IS_V6 (&pcb->local_ip)) {
        memcpy (&sa6->sin6_addr, ip_2_ip6 (&pcb->local_ip), 16);
    } else {
        u8_t *addr_bytes = (u8_t *)&sa6->sin6_addr;
        addr_bytes[10] = 0xff;
        addr_bytes[11] = 0xff;
        memcpy (&addr_bytes[12], ip_2_ip4 (&pcb->local_ip), 4);
    }

    /* Create a dual-stack socket, mimicking hev_socks5_socket */
    fd = hev_task_io_socket_socket (AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        goto exit_cleanup;
    }

    int zero = 0;
    setsockopt (fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof (zero));

    /* Register fd robustly for read/write events */
    if (hev_task_add_fd (task, fd, POLLIN | POLLOUT) < 0)
        hev_task_mod_fd (task, fd, POLLIN | POLLOUT);

    if (hev_task_io_socket_connect (fd, (struct sockaddr *)&saddr, saddr_len,
                                    NULL, NULL) < 0) {
        LOG_E ("router: direct connect failed: %s", strerror (errno));
        close (fd);
        goto exit_cleanup;
    }

    ipaddr_ntoa_r (&pcb->local_ip, ip_str, sizeof (ip_str));
    /* pcb->local_port is host order; print it directly (不要在这里再做 ntohs) */
    LOG_I ("router: Direct connect established to %s:%d", ip_str,
           pcb->local_port);

    /* Splice with GFW detection */
    self->is_smart_proxy_probe = 1;
    self->initial_data_received = 0;

    HEV_SOCKS5 (s)->fd = fd;

    if (iface->splicer (s) < 0) {
        LOG_W ("router: smart proxy splice timed out (GFW?), fallback to SOCKS5");
        hev_traffic_router_blacklist_add (&pcb->local_ip);
        HEV_SOCKS5 (s)->fd = -1;
        close (fd);
        hev_socks5_session_run (s);
        hev_socks5_tunnel_delete_session (node);
        hev_object_unref (HEV_OBJECT (self));
        return;
    }

    /* Cleanup */
    HEV_SOCKS5 (s)->fd = -1;
    close (fd);

exit_cleanup:
    hev_socks5_session_terminate (s);
    hev_socks5_tunnel_delete_session (node);
    hev_object_unref (HEV_OBJECT (self));
}

static void
run_smart_proxy_task (void *data)
{
    HevSocks5SessionTCP *self = data;
    HevSocks5Session *s = HEV_SOCKS5_SESSION (self);
    HevObjectClass *klass = HEV_OBJECT_GET_CLASS (s);
    HevSocks5SessionIface *iface = klass->iface (HEV_OBJECT (s), HEV_SOCKS5_SESSION_TYPE);
    struct tcp_pcb *pcb = self->pcb;
    HevTask *task = iface->get_task (s);
    HevListNode *node = iface->get_node (s);
    struct sockaddr_storage saddr;
    socklen_t saddr_len;
    char ip_str[INET6_ADDRSTRLEN];
    int fd = -1;
    int timeout;

    LOG_D ("router: smart proxy task run");

    /* Build address structure */
    struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&saddr;
    saddr_len = sizeof (struct sockaddr_in6);
    memset (sa6, 0, saddr_len);
    sa6->sin6_family = AF_INET6;
    sa6->sin6_port = htons (pcb->local_port);
    if (IP_IS_V6 (&pcb->local_ip)) {
        memcpy (&sa6->sin6_addr, ip_2_ip6 (&pcb->local_ip), 16);
    } else {
        u8_t *addr_bytes = (u8_t *)&sa6->sin6_addr;
        addr_bytes[10] = 0xff;
        addr_bytes[11] = 0xff;
        memcpy (&addr_bytes[12], ip_2_ip4 (&pcb->local_ip), 4);
    }

    /* Create socket */
    fd = hev_task_io_socket_socket (AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        goto fallback_socks5;
    }

    int zero = 0;
    setsockopt (fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof (zero));
    if (hev_task_add_fd (task, fd, POLLIN | POLLOUT) < 0)
        hev_task_mod_fd (task, fd, POLLIN | POLLOUT);

    /* Connect with timeout */
    timeout = hev_config_get_smart_proxy_timeout_ms ();
    hev_socks5_set_timeout (s, timeout);
    if (hev_task_io_socket_connect (fd, (struct sockaddr *)&saddr, saddr_len,
                                    hev_socks5_task_io_yielder, s) < 0) {
        LOG_W ("router: smart proxy direct connect failed, fallback to SOCKS5");
        hev_traffic_router_blacklist_add (&pcb->local_ip);
        close (fd);
        goto fallback_socks5;
    }

    ipaddr_ntoa_r (&pcb->local_ip, ip_str, sizeof (ip_str));
    LOG_I ("router: Smart proxy direct connect established to %s:%d", ip_str,
           pcb->local_port);

    /* Splice */
    HEV_SOCKS5 (s)->fd = fd;
    iface->splicer (s);

    /* Cleanup */
    HEV_SOCKS5 (s)->fd = -1;
    close (fd);
    hev_socks5_session_terminate (s);
    hev_socks5_tunnel_delete_session (node);
    hev_object_unref (HEV_OBJECT (self));
    return;

fallback_socks5:
    hev_socks5_session_run (s);
    hev_socks5_tunnel_delete_session (node);
    hev_object_unref (HEV_OBJECT (self));
}

/* ============================================================================
   UDP Direct Connect Session 实现
   用于国内 IP 的 UDP 直连,避免通过 SOCKS5 代理
   ============================================================================ */

/* UDP Direct Session Structure */
typedef struct _HevDirectUDPSession {
    struct udp_pcb *pcb;
    HevTaskMutex *mutex;
    HevTask *task;
    HevListNode node;
    int fd;
    int alive;
    struct pbuf *first_packet;
    /* 保存真实的目标地址和源地址 */
    ip_addr_t dest_ip;     /* 真实目标地址,如 114.114.114.114 */
    u16_t dest_port;       /* 真实目标端口,如 53 */
    ip_addr_t src_ip;      /* 真实源地址,如 198.18.0.1 */
    u16_t src_port;        /* 真实源端口,如 1234 */
} HevDirectUDPSession;

static void
direct_udp_cleanup (HevDirectUDPSession *session)
{
    if (session->fd >= 0) {
        hev_task_del_fd (session->task, session->fd);
        close (session->fd);
        session->fd = -1;
    }

    hev_task_mutex_lock (session->mutex);
    if (session->pcb) {
        udp_recv (session->pcb, NULL, NULL);
        udp_remove (session->pcb);
        session->pcb = NULL;
    }
    hev_task_mutex_unlock (session->mutex);

    if (session->first_packet) {
        pbuf_free (session->first_packet);
        session->first_packet = NULL;
    }

    hev_socks5_tunnel_delete_session (&session->node);
    hev_free (session);
}

static void
direct_udp_recv_handler (void *arg, struct udp_pcb *pcb, struct pbuf *p,
                        const ip_addr_t *addr, u16_t port)
{
    HevDirectUDPSession *session = arg;

    if (!p) {
        session->alive = 0;
        hev_task_wakeup (session->task);
        return;
    }

    /* 构建真实的目标地址(服务器地址) */
    struct sockaddr_storage dest_addr;
    socklen_t addr_len;

    if (IP_IS_V6 (&session->dest_ip)) {
        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&dest_addr;
        addr_len = sizeof (struct sockaddr_in6);
        memset (sa6, 0, addr_len);
        sa6->sin6_family = AF_INET6;
        sa6->sin6_port = htons (session->dest_port);
        memcpy (&sa6->sin6_addr, ip_2_ip6 (&session->dest_ip), 16);
    } else {
        struct sockaddr_in *sa4 = (struct sockaddr_in *)&dest_addr;
        addr_len = sizeof (struct sockaddr_in);
        memset (sa4, 0, addr_len);
        sa4->sin_family = AF_INET;
        sa4->sin_port = htons (session->dest_port);
        sa4->sin_addr.s_addr = ip_2_ip4 (&session->dest_ip)->addr;
    }

    /* 发送 UDP 数据包到真实目标(如 114.114.114.114:53) */
    ssize_t sent = sendto (session->fd, p->payload, p->len, 0,
                          (struct sockaddr *)&dest_addr, addr_len);
    
    if (sent < 0) {
        LOG_W ("router: direct UDP send failed: %s", strerror (errno));
    } else {
        LOG_D ("router: Direct UDP sent %zd bytes to server", sent);
    }

    pbuf_free (p);  // 在使用完 p 之后立即释放
    hev_task_wakeup (session->task);
}

static void
run_direct_udp_task (void *data)
{
    HevDirectUDPSession *session = data;
    unsigned char buffer[2048];
    struct sockaddr_storage remote_addr;
    socklen_t addr_len;

    LOG_D ("router: direct UDP task run");

    // 创建 socket
    session->fd = hev_task_io_socket_socket (AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (session->fd < 0) {
        LOG_E ("router: failed to create UDP socket: %s", strerror (errno));
        goto cleanup;
    }

    int zero = 0;
    setsockopt (session->fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof (zero));

    // 【删除绑定代码 - 让系统自动分配源端口】
    // 不需要 bind()，直接使用 sendto() 会自动绑定一个临时端口

    if (hev_task_add_fd (session->task, session->fd, POLLIN) < 0) {
        LOG_E ("router: failed to add fd to task");
        goto cleanup;
    }

    // 设置 UDP 接收处理器
    hev_task_mutex_lock (session->mutex);
    if (session->pcb) {
        udp_recv (session->pcb, direct_udp_recv_handler, session);
    }
    hev_task_mutex_unlock (session->mutex);

// 处理第一个数据包
if (session->first_packet) {
    struct sockaddr_storage dest_addr;
    socklen_t addr_len;

    LOG_I ("router: ===== UDP Direct Connect Debug Info =====");
    LOG_I ("router: Packet length: %u, total length: %u", 
           session->first_packet->len, 
           session->first_packet->tot_len);

    /* 
     * 重要：检测并移除 UDP header
     * 
     * 原因：lwIP 在使用 NETIF_FLAG_PRETEND_UDP 标志时，传递给 udp_recv_handler
     * 的 pbuf 可能包含完整的 UDP header（8字节）：
     *   [0-1]: 源端口 (Source Port)
     *   [2-3]: 目标端口 (Destination Port)  
     *   [4-5]: 长度 (Length)
     *   [6-7]: 校验和 (Checksum)
     * 
     * 我们需要发送的是纯 DNS 数据（应用层），所以需要移除 UDP header。
     * 检测方法：检查字节[2-3]是否等于目标端口（如53），如果是则说明包含UDP header。
     */
    unsigned char *data = (unsigned char *)session->first_packet->payload;
    if (session->first_packet->len > 8) {
        uint16_t check_port = (data[2] << 8) | data[3];
        if (check_port == session->dest_port) {
            LOG_W ("router: ⚠️  Detected UDP header in pbuf, removing 8 bytes");
            /* 使用 lwIP API 移除前8字节的 UDP header */
            if (pbuf_remove_header(session->first_packet, 8) != 0) {
                LOG_E ("router: Failed to remove UDP header from pbuf");
                goto cleanup;
            }
            LOG_D ("router: UDP header removed, new length: %u", session->first_packet->len);
        }
    }

    /* 现在 first_packet->payload 指向纯 DNS 数据 */
    unsigned char *dns_data = (unsigned char *)session->first_packet->payload;
    int dns_len = session->first_packet->len;

    // 打印完整的数据包内容（hex dump）
    {
        char hex_line[128];
        char ascii_line[64];
        
        LOG_I ("router: ----- Raw DNS Packet Data -----");
        for (int i = 0; i < dns_len; i += 16) {
            memset(hex_line, 0, sizeof(hex_line));
            memset(ascii_line, 0, sizeof(ascii_line));
            
            int line_len = (dns_len - i) > 16 ? 16 : (dns_len - i);
            
            for (int j = 0; j < line_len; j++) {
                sprintf(hex_line + strlen(hex_line), "%02x ", dns_data[i + j]);
                ascii_line[j] = (dns_data[i + j] >= 32 && dns_data[i + j] <= 126) ? dns_data[i + j] : '.';
            }
            
            LOG_I ("router: %04x: %-48s |%s|", i, hex_line, ascii_line);
        }
        LOG_I ("router: ----- End of Packet -----");
    }

    // 解析DNS查询（如果是DNS）
    if (session->dest_port == 53 && dns_len >= 12) {
        unsigned char *dns = dns_data;
        LOG_I ("router: DNS Query Analysis:");
        LOG_I ("router:   Transaction ID: 0x%02x%02x", dns[0], dns[1]);
        LOG_I ("router:   Flags: 0x%02x%02x", dns[2], dns[3]);
        LOG_I ("router:   Questions: %d", (dns[4] << 8) | dns[5]);
        LOG_I ("router:   Answer RRs: %d", (dns[6] << 8) | dns[7]);
        LOG_I ("router:   Authority RRs: %d", (dns[8] << 8) | dns[9]);
        LOG_I ("router:   Additional RRs: %d", (dns[10] << 8) | dns[11]);
        
        // 解析域名
        if (dns_len > 12) {
            char domain[256] = {0};
            int pos = 12;
            int domain_pos = 0;
            while (pos < dns_len && dns[pos] != 0) {
                int label_len = dns[pos];
                if (label_len == 0 || label_len > 63 || pos + label_len >= dns_len)
                    break;
                if (domain_pos > 0)
                    domain[domain_pos++] = '.';
                memcpy(domain + domain_pos, dns + pos + 1, label_len);
                domain_pos += label_len;
                pos += label_len + 1;
            }
            LOG_I ("router:   Domain: %s", domain);
        }
    }

    char dest_str[INET6_ADDRSTRLEN];
    char src_str[INET6_ADDRSTRLEN];
    ipaddr_ntoa_r (&session->dest_ip, dest_str, sizeof (dest_str));
    ipaddr_ntoa_r (&session->src_ip, src_str, sizeof (src_str));
    LOG_I ("router: Source: %s:%d -> Dest: %s:%d", 
           src_str, session->src_port, dest_str, session->dest_port);

    if (IP_IS_V6 (&session->dest_ip)) {
        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&dest_addr;
        addr_len = sizeof (struct sockaddr_in6);
        memset (sa6, 0, addr_len);
        sa6->sin6_family = AF_INET6;
        sa6->sin6_port = htons (session->dest_port);
        memcpy (&sa6->sin6_addr, ip_2_ip6 (&session->dest_ip), 16);
    } else {
        struct sockaddr_in *sa4 = (struct sockaddr_in *)&dest_addr;
        addr_len = sizeof (struct sockaddr_in);
        memset (sa4, 0, addr_len);
        sa4->sin_family = AF_INET;
        sa4->sin_port = htons (session->dest_port);
        sa4->sin_addr.s_addr = ip_2_ip4 (&session->dest_ip)->addr;
    }

    // 发送DNS数据到真实目标
    LOG_I ("router: Attempting to send %d bytes via sendto()...", dns_len);
    ssize_t sent = sendto (session->fd, dns_data, dns_len, 0,
                          (struct sockaddr *)&dest_addr, addr_len);
    
    if (sent < 0) {
        LOG_E ("router: ❌ sendto() FAILED: %s (errno=%d)", 
               strerror (errno), errno);
        goto cleanup;
    } else {
        LOG_I ("router: ✅ sendto() SUCCESS: sent %zd bytes", sent);
        
        // 打印实际使用的源地址（系统自动分配的）
        struct sockaddr_storage local_addr;
        socklen_t local_len = sizeof(local_addr);
        if (getsockname(session->fd, (struct sockaddr *)&local_addr, &local_len) == 0) {
            char local_str[INET6_ADDRSTRLEN];
            int local_port;
            if (local_addr.ss_family == AF_INET6) {
                struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&local_addr;
                inet_ntop(AF_INET6, &sa6->sin6_addr, local_str, sizeof(local_str));
                local_port = ntohs(sa6->sin6_port);
            } else {
                struct sockaddr_in *sa4 = (struct sockaddr_in *)&local_addr;
                inet_ntop(AF_INET, &sa4->sin_addr, local_str, sizeof(local_str));
                local_port = ntohs(sa4->sin_port);
            }
            LOG_I ("router: Actual socket bound to: %s:%d", local_str, local_port);
        }
    }
    LOG_I ("router: ==========================================");

    pbuf_free (session->first_packet);
    session->first_packet = NULL;
}

    session->alive = 1;

    char dest_ip_str[INET6_ADDRSTRLEN];
    char src_ip_str[INET6_ADDRSTRLEN];
    ipaddr_ntoa_r (&session->dest_ip, dest_ip_str, sizeof (dest_ip_str));
    ipaddr_ntoa_r (&session->src_ip, src_ip_str, sizeof (src_ip_str));
    LOG_I ("router: Direct UDP session started: %s:%d <-> %s:%d",
           src_ip_str, session->src_port, dest_ip_str, session->dest_port);
    LOG_I ("router: Waiting for response from server (socket fd=%d)...", session->fd);

    // 接收循环 - 等待服务器响应
    int recv_attempts = 0;
    while (session->alive && recv_attempts < 100) {
        addr_len = sizeof (remote_addr);
        
        LOG_D ("router: recvfrom() attempt #%d...", ++recv_attempts);
        ssize_t received = recvfrom (session->fd, buffer, sizeof (buffer), 0,
                                    (struct sockaddr *)&remote_addr, &addr_len);

        if (received < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                LOG_D ("router: recvfrom() returned EAGAIN/EWOULDBLOCK, yielding...");
                hev_task_yield (HEV_TASK_WAITIO);
                continue;
            }
            LOG_E ("router: ❌ recvfrom() failed: %s (errno=%d)", strerror (errno), errno);
            break;
        }

        if (received == 0) {
            LOG_W ("router: recvfrom() returned 0 bytes");
            break;
        }

        LOG_I ("router: ✅ Received %zd bytes from server!", received);
        
        // 打印接收到的数据
        {
            char hex_line[128];
            char ascii_line[64];
            
            LOG_I ("router: ----- Received Response Data -----");
            for (int i = 0; i < received && i < 256; i += 16) {
                memset(hex_line, 0, sizeof(hex_line));
                memset(ascii_line, 0, sizeof(ascii_line));
                
                int line_len = (received - i) > 16 ? 16 : (received - i);
                
                for (int j = 0; j < line_len; j++) {
                    sprintf(hex_line + strlen(hex_line), "%02x ", buffer[i + j]);
                    ascii_line[j] = (buffer[i + j] >= 32 && buffer[i + j] <= 126) ? buffer[i + j] : '.';
                }
                
                LOG_I ("router: %04x: %-48s |%s|", i, hex_line, ascii_line);
            }
            LOG_I ("router: ----- End of Response -----");
        }

        // 分配 pbuf 并复制接收到的数据
        struct pbuf *p = pbuf_alloc (PBUF_TRANSPORT, received, PBUF_RAM);
        if (!p) {
            LOG_E ("router: failed to allocate pbuf for response");
            continue;
        }

        memcpy (p->payload, buffer, received);
        LOG_D ("router: Allocated pbuf: %u bytes", p->len);

        // 发送响应回客户端
hev_task_mutex_lock (session->mutex);
if (session->pcb) {
    LOG_I ("router: Forwarding response to client %s:%d (spoofing source as %s:%d)", 
           src_ip_str, session->src_port, dest_ip_str, session->dest_port);
    
    // 使用 udp_sendfrom 伪装源地址
    // pcb->remote_ip 和 pcb->remote_port 是客户端地址（198.18.0.1:xxxxx）
    // 我们要伪装源地址为 DNS 服务器地址（114.114.114.114:53）
    err_t err = udp_sendfrom (session->pcb, p, 
                             &session->dest_ip,     // 伪装源地址：DNS服务器
                             session->dest_port);   // 伪装源端口：53
    
    if (err != ERR_OK) {
        LOG_E ("router: ❌ udp_sendfrom() to client failed, error: %d", err);
    } else {
        LOG_I ("router: ✅ Successfully forwarded %zd bytes to client", received);
    }
} else {
    LOG_W ("router: pcb is NULL, cannot forward response");
}
hev_task_mutex_unlock (session->mutex);

pbuf_free (p);
    }

    if (recv_attempts >= 100) {
        LOG_W ("router: Exceeded maximum recv attempts (100), exiting");
    }

cleanup:
    LOG_I ("router: Direct UDP session ended");
    direct_udp_cleanup (session);
}

void
hev_session_manager_start_direct_udp (struct udp_pcb *pcb, 
                                     const ip_addr_t *dest_addr,
                                     u16_t dest_port,
                                     struct pbuf *first_packet)
{
    HevDirectUDPSession *session;
    int stack_size;
    HevTask *task;

    session = hev_malloc0 (sizeof (HevDirectUDPSession));
    if (!session) {
        pbuf_free (first_packet);
        udp_remove (pcb);
        return;
    }

    // 创建任务
    stack_size = hev_config_get_misc_task_stack_size ();
    task = hev_task_new (stack_size);
    if (!task) {
        hev_free (session);
        pbuf_free (first_packet);
        udp_remove (pcb);
        return;
    }

    session->pcb = pcb;
    session->mutex = &mutex;
    session->task = task;
    session->fd = -1;
    session->first_packet = first_packet;
    
    // 保存地址信息
    ip_addr_copy (session->dest_ip, *dest_addr);
    session->dest_port = dest_port;
    ip_addr_copy (session->src_ip, pcb->remote_ip);
    session->src_port = pcb->remote_port;

    hev_socks5_tunnel_insert_session (&session->node);
    hev_task_run (task, run_direct_udp_task, session);
}