/*
 ============================================================================
 Name        : hev-config.c
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2019 - 2024 hev
 Description : Config
 ============================================================================
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <yaml.h>

#include "hev-logger.h"
#include "hev-config.h"
#include "hev-config-const.h"

/* YAML 辅助宏 */
#define CHECK_YAML_MAPPING(base) \
    do { \
        if (!(base) || YAML_MAPPING_NODE != (base)->type) \
            return -1; \
    } while (0)

static char tun_name[64];
static unsigned int tun_mtu = 8500;
static int multi_queue;

static char tun_ipv4_address[16];
static char tun_ipv6_address[64];

static char tun_post_up_script[1024];
static char tun_pre_down_script[1024];

static HevConfigSocks5 socks5_config;

static int
yaml_parse_bool (const char *val)
{
    if (strcmp (val, "true") == 0)
        return 1;
    return 0;
}

static int
hev_config_parse_socks5_tcp (yaml_document_t *doc, yaml_node_t *base)
{
    yaml_node_pair_t *pair;

    CHECK_YAML_MAPPING (base);
    for (pair = base->data.mapping.pairs.start;
         pair < base->data.mapping.pairs.top; pair++) {
        yaml_node_t *node_key = yaml_document_get_node (doc, pair->key);
        yaml_node_t *node_val = yaml_document_get_node (doc, pair->value);

        if (!node_key || !node_val)
            continue;

        const char *key = (const char *)node_key->data.scalar.value;
        const char *val = (const char *)node_val->data.scalar.value;

        if (strcmp (key, "port") == 0) {
            socks5_config.tcp.port = strtoul (val, NULL, 10);
        } else if (strcmp (key, "address") == 0) {
            strncpy (socks5_config.tcp.addr, val,
                     sizeof (socks5_config.tcp.addr) - 1);
        } else if (strcmp (key, "username") == 0) {
            socks5_config.tcp.user = strdup (val);
        } else if (strcmp (key, "password") == 0) {
            socks5_config.tcp.pass = strdup (val);
        } else if (strcmp (key, "mark") == 0) {
            socks5_config.tcp.mark = strtoul (val, NULL, 10);
        } else if (strcmp (key, "pipeline") == 0) {
            socks5_config.tcp.pipeline = yaml_parse_bool (val);
        }
    }

    return 0;
}

static int
hev_config_parse_socks5_udp (yaml_document_t *doc, yaml_node_t *base)
{
    yaml_node_pair_t *pair;

    CHECK_YAML_MAPPING (base);
    for (pair = base->data.mapping.pairs.start;
         pair < base->data.mapping.pairs.top; pair++) {
        yaml_node_t *node_key = yaml_document_get_node (doc, pair->key);
        yaml_node_t *node_val = yaml_document_get_node (doc, pair->value);

        if (!node_key || !node_val)
            continue;

        const char *key = (const char *)node_key->data.scalar.value;
        const char *val = (const char *)node_val->data.scalar.value;

        if (strcmp (key, "port") == 0) {
            socks5_config.udp.port = strtoul (val, NULL, 10);
        } else if (strcmp (key, "address") == 0) {
            strncpy (socks5_config.udp.addr, val,
                     sizeof (socks5_config.udp.addr) - 1);
        } else if (strcmp (key, "username") == 0) {
            socks5_config.udp.user = strdup (val);
        } else if (strcmp (key, "password") == 0) {
            socks5_config.udp.pass = strdup (val);
        } else if (strcmp (key, "mark") == 0) {
            socks5_config.udp.mark = strtoul (val, NULL, 10);
        } else if (strcmp (key, "udp-relay") == 0) {
            socks5_config.udp.udp_relay = (strcmp (val, "udp") == 0) ? 1 : 0;
        }
    }

    return 0;
}

static int
hev_config_parse_socks5 (yaml_document_t *doc, yaml_node_t *base)
{
    yaml_node_pair_t *pair;

    CHECK_YAML_MAPPING (base);
    for (pair = base->data.mapping.pairs.start;
         pair < base->data.mapping.pairs.top; pair++) {
        yaml_node_t *node_key = yaml_document_get_node (doc, pair->key);
        yaml_node_t *node_val = yaml_document_get_node (doc, pair->value);

        if (!node_key || !node_val)
            continue;

        const char *key = (const char *)node_key->data.scalar.value;

        if (strcmp (key, "tcp") == 0) {
            if (hev_config_parse_socks5_tcp (doc, node_val) < 0)
                return -1;
        } else if (strcmp (key, "udp") == 0) {
            if (hev_config_parse_socks5_udp (doc, node_val) < 0)
                return -1;
        }
    }

    return 0;
}

static int mapdns_address;
static int mapdns_port;
static int mapdns_network;
static int mapdns_netmask;
static int mapdns_cache_size;

static char log_file[1024];
static char pid_file[1024];
static int max_session_count;
static int task_stack_size = 86016;
static int tcp_buffer_size = 65536;
static int udp_copy_buffer_nums = 10;
static int connect_timeout = 10000;
static int read_write_timeout = 300000;
static int limit_nofile = 65535;
static int log_level = HEV_LOGGER_WARN;

/* dns-forwarder */
static char dns_fwd_virtual_ip4[64];
static char dns_fwd_virtual_ip6[64];
static char dns_fwd_target_ip4[64];
static char dns_fwd_target_ip6[64];

/* chnroutes */
static char chnroutes_file_path[1024];

/* smart-proxy */
static int smart_proxy_timeout_ms;
static int smart_proxy_blocked_ip_expiry_minutes;
static int *smart_proxy_probe_ports = NULL;
static int smart_proxy_probe_ports_count = 0;

/* acl */
static char acl_file_path[1024];

HevConfigSocks5Server *
hev_config_get_socks5_tcp_server (void)
{
    return &socks5_config.tcp;
}

HevConfigSocks5Server *
hev_config_get_socks5_udp_server (void)
{
    return &socks5_config.udp;
}

HevConfigSocks5Server *
hev_config_get_socks5_server (void)
{
    return &socks5_config.tcp;
}

static int
hev_config_parse_tunnel_ipv4 (yaml_document_t *doc, yaml_node_t *base)
{
    yaml_node_pair_t *pair;

    CHECK_YAML_MAPPING (base);
    for (pair = base->data.mapping.pairs.start;
         pair < base->data.mapping.pairs.top; pair++) {
        yaml_node_t *node;
        const char *key, *value;

        if (!pair->key || !pair->value)
            break;

        node = yaml_document_get_node (doc, pair->key);
        if (!node || YAML_SCALAR_NODE != node->type)
            break;
        key = (const char *)node->data.scalar.value;

        node = yaml_document_get_node (doc, pair->value);
        if (!node || YAML_SCALAR_NODE != node->type)
            break;
        value = (const char *)node->data.scalar.value;

        if (0 == strcmp (key, "address"))
            strncpy (tun_ipv4_address, value, 16 - 1);
    }

    return 0;
}

static int
hev_config_parse_tunnel_ipv6 (yaml_document_t *doc, yaml_node_t *base)
{
    yaml_node_pair_t *pair;

    CHECK_YAML_MAPPING (base);
    for (pair = base->data.mapping.pairs.start;
         pair < base->data.mapping.pairs.top; pair++) {
        yaml_node_t *node;
        const char *key, *value;

        if (!pair->key || !pair->value)
            break;

        node = yaml_document_get_node (doc, pair->key);
        if (!node || YAML_SCALAR_NODE != node->type)
            break;
        key = (const char *)node->data.scalar.value;

        node = yaml_document_get_node (doc, pair->value);
        if (!node || YAML_SCALAR_NODE != node->type)
            break;
        value = (const char *)node->data.scalar.value;

        if (0 == strcmp (key, "address"))
            strncpy (tun_ipv6_address, value, 64 - 1);
    }

    return 0;
}

static int
hev_config_parse_tunnel (yaml_document_t *doc, yaml_node_t *base)
{
    yaml_node_pair_t *pair;

    CHECK_YAML_MAPPING (base);
    for (pair = base->data.mapping.pairs.start;
         pair < base->data.mapping.pairs.top; pair++) {
        yaml_node_t *node;
        const char *key;

        if (!pair->key || !pair->value)
            break;

        node = yaml_document_get_node (doc, pair->key);
        if (!node || YAML_SCALAR_NODE != node->type)
            break;
        key = (const char *)node->data.scalar.value;

        node = yaml_document_get_node (doc, pair->value);
        if (!node)
            break;

        if (YAML_SCALAR_NODE == node->type) {
            const char *value = (const char *)node->data.scalar.value;

            if (0 == strcmp (key, "name"))
                strncpy (tun_name, value, 64 - 1);
            else if (0 == strcmp (key, "mtu"))
                tun_mtu = strtoul (value, NULL, 10);
            else if (0 == strcmp (key, "multi-queue"))
                multi_queue = strcasecmp (value, "false");
            else if (0 == strcmp (key, "ipv4"))
                strncpy (tun_ipv4_address, value, 16 - 1);
            else if (0 == strcmp (key, "ipv6"))
                strncpy (tun_ipv6_address, value, 64 - 1);
            else if (0 == strcmp (key, "post-up-script"))
                strncpy (tun_post_up_script, value, 64 - 1);
            else if (0 == strcmp (key, "pre-down-script"))
                strncpy (tun_pre_down_script, value, 64 - 1);
        } else {
            if (0 == strcmp (key, "ipv4"))
                hev_config_parse_tunnel_ipv4 (doc, node);
            else if (0 == strcmp (key, "ipv6"))
                hev_config_parse_tunnel_ipv6 (doc, node);
        }
    }

    return 0;
}

static int
hev_config_parse_mapdns (yaml_document_t *doc, yaml_node_t *base)
{
    yaml_node_pair_t *pair;

    CHECK_YAML_MAPPING (base);
    for (pair = base->data.mapping.pairs.start;
         pair < base->data.mapping.pairs.top; pair++) {
        yaml_node_t *node;
        const char *key, *value;

        if (!pair->key || !pair->value)
            break;

        node = yaml_document_get_node (doc, pair->key);
        if (!node || YAML_SCALAR_NODE != node->type)
            break;
        key = (const char *)node->data.scalar.value;

        node = yaml_document_get_node (doc, pair->value);
        if (!node || YAML_SCALAR_NODE != node->type)
            break;
        value = (const char *)node->data.scalar.value;

        if (0 == strcmp (key, "address"))
            inet_pton (AF_INET, value, &mapdns_address);
        else if (0 == strcmp (key, "port"))
            mapdns_port = strtoul (value, NULL, 10);
        else if (0 == strcmp (key, "network"))
            inet_pton (AF_INET, value, &mapdns_network);
        else if (0 == strcmp (key, "netmask"))
            inet_pton (AF_INET, value, &mapdns_netmask);
        else if (0 == strcmp (key, "cache-size"))
            mapdns_cache_size = strtoul (value, NULL, 10);
    }

    mapdns_network = ntohl (mapdns_network);
    mapdns_netmask = ntohl (mapdns_netmask);

    return 0;
}

static int
hev_config_parse_log_level (const char *value)
{
    if (0 == strcmp (value, "debug"))
        return HEV_LOGGER_DEBUG;
    else if (0 == strcmp (value, "info"))
        return HEV_LOGGER_INFO;
    else if (0 == strcmp (value, "error"))
        return HEV_LOGGER_ERROR;

    return HEV_LOGGER_WARN;
}

static int
hev_config_parse_dns_forwarder (yaml_document_t *doc, yaml_node_t *base)
{
    yaml_node_pair_t *pair;

    CHECK_YAML_MAPPING (base);
    for (pair = base->data.mapping.pairs.start;
         pair < base->data.mapping.pairs.top; pair++) {
        yaml_node_t *node;
        const char *key, *value;

        if (!pair->key || !pair->value)
            break;

        node = yaml_document_get_node (doc, pair->key);
        if (!node || YAML_SCALAR_NODE != node->type)
            break;
        key = (const char *)node->data.scalar.value;

        node = yaml_document_get_node (doc, pair->value);
        if (!node || YAML_SCALAR_NODE != node->type)
            break;
        value = (const char *)node->data.scalar.value;

        if (0 == strcmp (key, "virtual-ip4"))
            strncpy (dns_fwd_virtual_ip4, value,
                     sizeof (dns_fwd_virtual_ip4) - 1);
        else if (0 == strcmp (key, "virtual-ip6"))
            strncpy (dns_fwd_virtual_ip6, value,
                     sizeof (dns_fwd_virtual_ip6) - 1);
        else if (0 == strcmp (key, "target-ip4"))
            strncpy (dns_fwd_target_ip4, value,
                     sizeof (dns_fwd_target_ip4) - 1);
        else if (0 == strcmp (key, "target-ip6"))
            strncpy (dns_fwd_target_ip6, value,
                     sizeof (dns_fwd_target_ip6) - 1);
    }

    return 0;
}

static int
hev_config_parse_chnroutes (yaml_document_t *doc, yaml_node_t *base)
{
    yaml_node_pair_t *pair;

    CHECK_YAML_MAPPING (base);
    for (pair = base->data.mapping.pairs.start;
         pair < base->data.mapping.pairs.top; pair++) {
        yaml_node_t *node;
        const char *key, *value;

        if (!pair->key || !pair->value)
            break;

        node = yaml_document_get_node (doc, pair->key);
        if (!node || YAML_SCALAR_NODE != node->type)
            break;
        key = (const char *)node->data.scalar.value;

        node = yaml_document_get_node (doc, pair->value);
        if (!node || YAML_SCALAR_NODE != node->type)
            break;
        value = (const char *)node->data.scalar.value;

        if (0 == strcmp (key, "file-path"))
            strncpy (chnroutes_file_path, value,
                     sizeof (chnroutes_file_path) - 1);
    }

    return 0;
}

static int
hev_config_parse_smart_proxy (yaml_document_t *doc, yaml_node_t *base)
{
    yaml_node_pair_t *pair;

    CHECK_YAML_MAPPING (base);
    for (pair = base->data.mapping.pairs.start;
         pair < base->data.mapping.pairs.top; pair++) {
        yaml_node_t *node;
        const char *key;

        if (!pair->key || !pair->value)
            break;

        node = yaml_document_get_node (doc, pair->key);
        if (!node || YAML_SCALAR_NODE != node->type)
            break;
        key = (const char *)node->data.scalar.value;

        node = yaml_document_get_node (doc, pair->value);

        if (0 == strcmp (key, "timeout-ms")) {
            if (node && YAML_SCALAR_NODE == node->type) {
                const char *value = (const char *)node->data.scalar.value;
                smart_proxy_timeout_ms = strtoul (value, NULL, 10);
            }
        } else if (0 == strcmp (key, "blocked-ip-expiry-minutes")) {
            if (node && YAML_SCALAR_NODE == node->type) {
                const char *value = (const char *)node->data.scalar.value;
                smart_proxy_blocked_ip_expiry_minutes =
                    strtoul (value, NULL, 10);
            }
        } else if (0 == strcmp (key, "probe-ports")) {
            /* Parse port list (YAML sequence) */
            if (node && YAML_SEQUENCE_NODE == node->type) {
                yaml_node_item_t *item;
                int count = 0;

                /* Count ports first */
                for (item = node->data.sequence.items.start;
                     item < node->data.sequence.items.top; item++) {
                    count++;
                }

                /* Allocate array */
                if (smart_proxy_probe_ports) {
                    free (smart_proxy_probe_ports);
                }
                smart_proxy_probe_ports = malloc (sizeof (int) * count);
                if (!smart_proxy_probe_ports)
                    return -1;

                /* Fill array */
                int idx = 0;
                for (item = node->data.sequence.items.start;
                     item < node->data.sequence.items.top; item++) {
                    yaml_node_t *port_node =
                        yaml_document_get_node (doc, *item);
                    if (port_node && YAML_SCALAR_NODE == port_node->type) {
                        smart_proxy_probe_ports[idx++] =
                            strtoul ((const char *)port_node->data.scalar.value,
                                     NULL, 10);
                    }
                }
                smart_proxy_probe_ports_count = count;

                LOG_I ("config: Loaded %d smart-proxy probe ports", count);
            }
        }
    }

    return 0;
}

static int
hev_config_parse_acl (yaml_document_t *doc, yaml_node_t *base)
{
    yaml_node_pair_t *pair;

    CHECK_YAML_MAPPING (base);
    for (pair = base->data.mapping.pairs.start;
         pair < base->data.mapping.pairs.top; pair++) {
        yaml_node_t *node;
        const char *key, *value;

        if (!pair->key || !pair->value)
            break;

        node = yaml_document_get_node (doc, pair->key);
        if (!node || YAML_SCALAR_NODE != node->type)
            break;
        key = (const char *)node->data.scalar.value;

        node = yaml_document_get_node (doc, pair->value);
        if (!node || YAML_SCALAR_NODE != node->type)
            break;
        value = (const char *)node->data.scalar.value;

        if (0 == strcmp (key, "file-path"))
            strncpy (acl_file_path, value, sizeof (acl_file_path) - 1);
    }

    return 0;
}

static int
hev_config_parse_misc (yaml_document_t *doc, yaml_node_t *base)
{
    yaml_node_pair_t *pair;

    CHECK_YAML_MAPPING (base);
    for (pair = base->data.mapping.pairs.start;
         pair < base->data.mapping.pairs.top; pair++) {
        yaml_node_t *node;
        const char *key, *value;

        if (!pair->key || !pair->value)
            break;

        node = yaml_document_get_node (doc, pair->key);
        if (!node || YAML_SCALAR_NODE != node->type)
            break;
        key = (const char *)node->data.scalar.value;

        node = yaml_document_get_node (doc, pair->value);
        if (!node || YAML_SCALAR_NODE != node->type)
            break;
        value = (const char *)node->data.scalar.value;

        if (0 == strcmp (key, "task-stack-size"))
            task_stack_size = strtoul (value, NULL, 10);
        else if (0 == strcmp (key, "tcp-buffer-size"))
            tcp_buffer_size = strtoul (value, NULL, 10);
        else if (0 == strcmp (key, "max-session-count"))
            max_session_count = strtoul (value, NULL, 10);
        else if (0 == strcmp (key, "connect-timeout"))
            connect_timeout = strtoul (value, NULL, 10);
        else if (0 == strcmp (key, "read-write-timeout"))
            read_write_timeout = strtoul (value, NULL, 10);
        else if (0 == strcmp (key, "pid-file"))
            strncpy (pid_file, value, 1024 - 1);
        else if (0 == strcmp (key, "log-file"))
            strncpy (log_file, value, 1024 - 1);
        else if (0 == strcmp (key, "log-level"))
            log_level = hev_config_parse_log_level (value);
        else if (0 == strcmp (key, "limit-nofile"))
            limit_nofile = strtol (value, NULL, 10);
    }

    return 0;
}

static int
hev_config_parse_doc (yaml_document_t *doc)
{
    yaml_node_t *root;
    yaml_node_pair_t *pair;
    int min_task_stack_size;

    root = yaml_document_get_root_node (doc);
    if (!root || YAML_MAPPING_NODE != root->type)
        return -1;

    for (pair = root->data.mapping.pairs.start;
         pair < root->data.mapping.pairs.top; pair++) {
        yaml_node_t *node;
        const char *key;
        int res = 0;

        if (!pair->key || !pair->value)
            break;

        node = yaml_document_get_node (doc, pair->key);
        if (!node || YAML_SCALAR_NODE != node->type)
            break;

        key = (const char *)node->data.scalar.value;
        node = yaml_document_get_node (doc, pair->value);

        if (0 == strcmp (key, "tunnel"))
            res = hev_config_parse_tunnel (doc, node);
        else if (0 == strcmp (key, "socks5"))
            res = hev_config_parse_socks5 (doc, node);
        else if (0 == strcmp (key, "mapdns"))
            res = hev_config_parse_mapdns (doc, node);
        else if (0 == strcmp (key, "misc"))
            res = hev_config_parse_misc (doc, node);
        else if (0 == strcmp (key, "dns-forwarder"))
            res = hev_config_parse_dns_forwarder (doc, node);
        else if (0 == strcmp (key, "chnroutes"))
            res = hev_config_parse_chnroutes (doc, node);
        else if (0 == strcmp (key, "smart-proxy"))
            res = hev_config_parse_smart_proxy (doc, node);
        else if (0 == strcmp (key, "acl"))
            res = hev_config_parse_acl (doc, node);

        if (res < 0)
            return -1;
    }

    min_task_stack_size = TASK_STACK_SIZE + tcp_buffer_size;
    if (task_stack_size < min_task_stack_size)
        task_stack_size = min_task_stack_size;

    return 0;
}

/* Common initialization logic */
static int
hev_config_init_with_parser (yaml_parser_t *parser, const char *error_msg)
{
    yaml_document_t doc;
    int res = -1;

    if (!yaml_parser_load (parser, &doc)) {
        fprintf (stderr, "%s", error_msg);
        goto exit;
    }

    res = hev_config_parse_doc (&doc);
    yaml_document_delete (&doc);

exit:
    return res;
}

int
hev_config_init_from_file (const char *config_path)
{
    yaml_parser_t parser;
    FILE *fp;
    int res = -1;
    char error_msg[256];

    if (!yaml_parser_initialize (&parser))
        goto exit;

    fp = fopen (config_path, "r");
    if (!fp) {
        snprintf (error_msg, sizeof (error_msg), "Open %s failed!\n",
                  config_path);
        goto exit_free_parser;
    }

    yaml_parser_set_input_file (&parser, fp);
    res = hev_config_init_with_parser (&parser, error_msg);

    fclose (fp);
exit_free_parser:
    yaml_parser_delete (&parser);
exit:
    return res;
}

int
hev_config_init_from_str (const unsigned char *config_str,
                          unsigned int config_len)
{
    yaml_parser_t parser;
    int res = -1;

    if (!yaml_parser_initialize (&parser))
        goto exit;

    yaml_parser_set_input_string (&parser, config_str, config_len);
    res = hev_config_init_with_parser (&parser, "Failed to parse config.\n");

    yaml_parser_delete (&parser);
exit:
    return res;
}

void
hev_config_fini (void)
{
}

const char *
hev_config_get_tunnel_name (void)
{
    if (!tun_name[0])
        return NULL;

    return tun_name;
}

unsigned int
hev_config_get_tunnel_mtu (void)
{
    return tun_mtu;
}

int
hev_config_get_tunnel_multi_queue (void)
{
    return multi_queue;
}

const char *
hev_config_get_tunnel_ipv4_address (void)
{
    if (!tun_ipv4_address[0])
        return NULL;

    return tun_ipv4_address;
}

const char *
hev_config_get_tunnel_ipv6_address (void)
{
    if (!tun_ipv6_address[0])
        return NULL;

    return tun_ipv6_address;
}

const char *
hev_config_get_tunnel_post_up_script (void)
{
    if (!tun_post_up_script[0])
        return NULL;

    return tun_post_up_script;
}

const char *
hev_config_get_tunnel_pre_down_script (void)
{
    if (!tun_pre_down_script[0])
        return NULL;

    return tun_pre_down_script;
}

int
hev_config_get_mapdns_address (void)
{
    return mapdns_address;
}

int
hev_config_get_mapdns_port (void)
{
    return mapdns_port;
}

int
hev_config_get_mapdns_network (void)
{
    return mapdns_network;
}

int
hev_config_get_mapdns_netmask (void)
{
    return mapdns_netmask;
}

int
hev_config_get_mapdns_cache_size (void)
{
    return mapdns_cache_size;
}

int
hev_config_get_misc_task_stack_size (void)
{
    return task_stack_size;
}

int
hev_config_get_misc_tcp_buffer_size (void)
{
    return tcp_buffer_size;
}

int
hev_config_get_misc_udp_copy_buffer_nums (void)
{
    return udp_copy_buffer_nums;
}

int
hev_config_get_misc_max_session_count (void)
{
    return max_session_count;
}

int
hev_config_get_misc_connect_timeout (void)
{
    return connect_timeout;
}

int
hev_config_get_misc_read_write_timeout (void)
{
    return read_write_timeout;
}

int
hev_config_get_misc_limit_nofile (void)
{
    return limit_nofile;
}

const char *
hev_config_get_misc_pid_file (void)
{
    if (!pid_file[0])
        return NULL;

    return pid_file;
}

const char *
hev_config_get_misc_log_file (void)
{
    if (!log_file[0])
        return "stderr";

    return log_file;
}

int
hev_config_get_misc_log_level (void)
{
    return log_level;
}

/* dns-forwarder */
const char *
hev_config_get_dns_forwarder_virtual_ip4 (void)
{
    if (!dns_fwd_virtual_ip4[0])
        return NULL;
    return dns_fwd_virtual_ip4;
}

const char *
hev_config_get_dns_forwarder_virtual_ip6 (void)
{
    if (!dns_fwd_virtual_ip6[0])
        return NULL;
    return dns_fwd_virtual_ip6;
}

const char *
hev_config_get_dns_forwarder_target_ip4 (void)
{
    if (!dns_fwd_target_ip4[0])
        return NULL;
    return dns_fwd_target_ip4;
}

const char *
hev_config_get_dns_forwarder_target_ip6 (void)
{
    if (!dns_fwd_target_ip6[0])
        return NULL;
    return dns_fwd_target_ip6;
}

/* chnroutes */
const char *
hev_config_get_chnroutes_file_path (void)
{
    if (!chnroutes_file_path[0])
        return NULL;
    return chnroutes_file_path;
}

/* smart-proxy */
int
hev_config_get_smart_proxy_timeout_ms (void)
{
    return smart_proxy_timeout_ms;
}

int
hev_config_get_smart_proxy_blocked_ip_expiry_minutes (void)
{
    return smart_proxy_blocked_ip_expiry_minutes;
}

int
hev_config_get_smart_proxy_probe_ports (int **ports)
{
    if (ports)
        *ports = smart_proxy_probe_ports;
    return smart_proxy_probe_ports_count;
}

int
hev_config_is_smart_proxy_probe_port (int port)
{
    int i;

    for (i = 0; i < smart_proxy_probe_ports_count; i++) {
        if (smart_proxy_probe_ports[i] == port)
            return 1;
    }
    return 0;
}

/* acl */
const char *
hev_config_get_acl_file_path (void)
{
    if (!acl_file_path[0])
        return NULL;
    return acl_file_path;
}
