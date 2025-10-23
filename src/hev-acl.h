/*
 ============================================================================
 Name        : hev-acl.h
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2024 hev
 Description : ACL (Access Control List)
 ============================================================================
 */

#ifndef __HEV_ACL_H__
#define __HEV_ACL_H__

#include <lwip/ip_addr.h>
#include <hev-list.h>

typedef enum _HevAclEntryType {
    HEV_ACL_TYPE_NONE,
    HEV_ACL_TYPE_IP,
    HEV_ACL_TYPE_HOSTNAME,
} HevAclEntryType;

typedef struct _HevAclEntry {
    HevListNode node;
    HevAclEntryType type;
    union {
        ip_addr_t ip;
        char hostname[256];
    } data;
} HevAclEntry;

int hev_acl_init (void);
void hev_acl_fini (void);
int hev_acl_load_from_file (const char *file_path);
int hev_acl_is_blocked_ip (const ip_addr_t *ip);
int hev_acl_is_blocked_hostname (const char *hostname);

#endif /* __HEV_ACL_H__ */
