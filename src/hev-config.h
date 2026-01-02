/*
 ============================================================================
 Name        : hev-config.h
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2019 - 2025 hev
 Description : Config (支持 TCP/UDP 分离的 SOCKS5 服务器)
 ============================================================================
 */

#ifndef __HEV_CONFIG_H__
#define __HEV_CONFIG_H__

typedef struct _HevConfigSocks5Server HevConfigSocks5Server;

struct _HevConfigSocks5Server
{
    const char *user;
    const char *pass;
    unsigned int mark;
    unsigned short port;
    unsigned char pipeline;
    unsigned char udp_relay; /* 0=tcp, 1=udp */
    char addr[256];
};

typedef struct _HevConfigSocks5 HevConfigSocks5;

struct _HevConfigSocks5
{
    HevConfigSocks5Server tcp; /* TCP 专用 SOCKS5 服务器 */
    HevConfigSocks5Server udp; /* UDP 专用 SOCKS5 服务器 */
};

int hev_config_init_from_file (const char *config_path);
int hev_config_init_from_str (const unsigned char *config_str,
                              unsigned int config_len);
void hev_config_fini (void);

const char *hev_config_get_tunnel_name (void);
unsigned int hev_config_get_tunnel_mtu (void);
int hev_config_get_tunnel_multi_queue (void);

const char *hev_config_get_tunnel_ipv4_address (void);
const char *hev_config_get_tunnel_ipv6_address (void);

const char *hev_config_get_tunnel_post_up_script (void);
const char *hev_config_get_tunnel_pre_down_script (void);

/* TCP SOCKS5 Server */
HevConfigSocks5Server *hev_config_get_socks5_tcp_server (void);

/* UDP SOCKS5 Server */
HevConfigSocks5Server *hev_config_get_socks5_udp_server (void);

int hev_config_get_mapdns_address (void);
const unsigned char *hev_config_get_mapdns_address6 (void);
int hev_config_get_mapdns_port (void);
int hev_config_get_mapdns_network (void);
int hev_config_get_mapdns_netmask (void);
const unsigned char *hev_config_get_mapdns_network6 (void);
int hev_config_get_mapdns_prefixlen (void);
int hev_config_get_mapdns_cache_size (void);

int hev_config_get_misc_task_stack_size (void);
int hev_config_get_misc_tcp_buffer_size (void);
int hev_config_get_misc_udp_copy_buffer_nums (void);
int hev_config_get_misc_max_session_count (void);
int hev_config_get_misc_connect_timeout (void);
int hev_config_get_misc_read_write_timeout (void);
int hev_config_get_misc_limit_nofile (void);
const char *hev_config_get_misc_pid_file (void);
const char *hev_config_get_misc_log_file (void);
int hev_config_get_misc_log_level (void);

/* dns-forwarder */
const char *hev_config_get_dns_forwarder_virtual_ip4 (void);
const char *hev_config_get_dns_forwarder_virtual_ip6 (void);
const char *hev_config_get_dns_forwarder_target_ip4 (void);
const char *hev_config_get_dns_forwarder_target_ip6 (void);

/* chnroutes */
const char *hev_config_get_chnroutes_file_path (void);

/* smart-proxy */
int hev_config_get_smart_proxy_timeout_ms (void);
int hev_config_get_smart_proxy_blocked_ip_expiry_minutes (void);
int hev_config_get_smart_proxy_probe_ports (int **ports);
int hev_config_is_smart_proxy_probe_port (int port);

/* acl */
const char *hev_config_get_acl_file_path (void);

/* dns-split-tunnel */
int hev_config_get_dns_split_tunnel (void);
const char **
hev_config_get_foreign_dns_v4 (int *count); /* 返回自动分类的IPv4 DNS列表 */
const char **
hev_config_get_foreign_dns_v6 (int *count); /* 返回自动分类的IPv6 DNS列表 */
const char **
hev_config_get_foreign_dns (int *count); /* 向后兼容，默认返回IPv4列表 */

/* dns-latency-optimize */
int hev_config_get_dns_latency_optimize (void);
int hev_config_get_dns_latency_timeout_ms (void);

#endif /* __HEV_CONFIG_H__ */