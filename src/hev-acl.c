/*
 ============================================================================
 Name        : hev-acl.c
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2024 hev
 Description : ACL (Access Control List)
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stddef.h> /* For offsetof */

#include <lwip/sockets.h>

#include "hev-logger.h"
#include "hev-memory-allocator.h"
#include "hev-list.h"
#include "hev-compiler.h" /* For container_of */
#include "hev-acl.h"

static HevList acl_entries;

static int
hev_acl_add_entry (HevAclEntryType type, const char *value)
{
    HevAclEntry *entry = hev_malloc0 (sizeof (HevAclEntry));
    if (!entry) {
        LOG_E ("Failed to allocate ACL entry.");
        return -1;
    }

    entry->type = type;
    if (type == HEV_ACL_TYPE_IP) {
        if (ipaddr_aton (value, &entry->data.ip) == 0) {
            LOG_W ("Invalid IP address in ACL: %s", value);
            hev_free (entry);
            return -1;
        }
    } else if (type == HEV_ACL_TYPE_HOSTNAME) {
        strncpy (entry->data.hostname, value, sizeof (entry->data.hostname) - 1);
        entry->data.hostname[sizeof (entry->data.hostname) - 1] = '\0';
    }

    hev_list_add_tail (&acl_entries, &entry->node);
    return 0;
}

int
hev_acl_init (void)
{
    acl_entries.head = NULL;
    acl_entries.tail = NULL;
    return 0;
}

void
hev_acl_fini (void)
{
    HevListNode *node = acl_entries.head;
    while (node) {
        HevListNode *next_node = node->next;
        HevAclEntry *entry = container_of (node, HevAclEntry, node);
        hev_free (entry);
        node = next_node;
    }
    acl_entries.head = NULL;
    acl_entries.tail = NULL;
}

int
hev_acl_load_from_file (const char *file_path)
{
    FILE *fp;
    char line[1024];
    int count = 0;
    int ipv4_count = 0;
    int ipv6_count = 0;
    int hostname_count = 0;

    if (!file_path || strlen (file_path) == 0) {
        LOG_D ("ACL file path is not set.");
        return 0;
    }

    fp = fopen (file_path, "r");
    if (!fp) {
        LOG_W ("Failed to open ACL file %s: %s", file_path, strerror (errno));
        return -1;
    }

    LOG_I ("Loading ACL from file: %s", file_path);

    while (fgets (line, sizeof (line), fp) != NULL) {
        char *trim_line = line;
        char *comment_pos;

        // Trim leading whitespace
        while (isspace ((unsigned char)*trim_line)) {
            trim_line++;
        }

        // Remove trailing whitespace and newline
        char *end = trim_line + strlen(trim_line) - 1;
        while (end >= trim_line && isspace ((unsigned char)*end)) {
            *end = '\0';
            end--;
        }

        // Remove comments
        comment_pos = strchr (trim_line, '#');
        if (comment_pos) {
            *comment_pos = '\0';
        }

        if (strlen (trim_line) == 0) {
            continue; // Empty line or only comment
        }

        // Try to parse as IP address first
        ip_addr_t ip_test;
        if (ipaddr_aton (trim_line, &ip_test) != 0) {
            if (hev_acl_add_entry (HEV_ACL_TYPE_IP, trim_line) == 0) {
                count++;
                if (IP_IS_V4(&ip_test)) {
                    ipv4_count++;
                } else if (IP_IS_V6(&ip_test)) {
                    ipv6_count++;
                }
            }
        } else { // Otherwise, treat as hostname
            if (hev_acl_add_entry (HEV_ACL_TYPE_HOSTNAME, trim_line) == 0) {
                hostname_count++;
                count++;
            }
        }
    }

    fclose (fp);
    LOG_I ("Loaded %d ACL entries from %s (IPv4: %d, IPv6: %d, Hostname: %d).",
           count, file_path, ipv4_count, ipv6_count, hostname_count);
    return 0;
}

int
hev_acl_is_blocked_ip (const ip_addr_t *ip)
{
    HevListNode *node;
    for (node = acl_entries.head; node; node = node->next) {
        HevAclEntry *entry = container_of (node, HevAclEntry, node);
        if (entry->type == HEV_ACL_TYPE_IP) {
            if (ip_addr_cmp (ip, &entry->data.ip)) {
                return 1; // Blocked
            }
        }
    }
    return 0; // Not blocked
}

int
hev_acl_is_blocked_hostname (const char *hostname)
{
    HevListNode *node;
    if (!hostname || strlen(hostname) == 0) return 0;

    for (node = acl_entries.head; node; node = node->next) {
        HevAclEntry *entry = container_of (node, HevAclEntry, node);
        if (entry->type == HEV_ACL_TYPE_HOSTNAME) {
            // Case-insensitive comparison for hostnames
            if (strcasecmp (hostname, entry->data.hostname) == 0) {
                return 1; // Blocked
            }
        }
    }
    return 0; // Not blocked
}
