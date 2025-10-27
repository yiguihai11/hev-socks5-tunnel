/*
 ============================================================================
 Name        : test-enhanced-blacklist.c
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2025 hev
 Description : Enhanced Blacklist Test Program
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <lwip/ip_addr.h>

#include "hev-filter.h"
#include "hev-logger.h"
#include "hev-config.h"

static void
test_ip_blacklist (void)
{
    ip_addr_t test_ip;
    const char *entry_id;

    printf ("\n=== Testing IP Blacklist ===\n");

    /* 测试IPv4 */
    ip4addr_aton ("192.168.1.100", &test_ip);
    entry_id = hev_filter_blacklist_add_ip (&test_ip, "Test IPv4 blocking",
                                           HEV_BLACKLIST_SOURCE_MANUAL, 3600);
    if (entry_id) {
        printf ("✓ Added IPv4 entry: %s\n", entry_id);

        /* 测试检查 */
        if (hev_filter_blacklist_check_ip (&test_ip)) {
            printf ("✓ IPv4 check passed\n");
        } else {
            printf ("✗ IPv4 check failed\n");
        }

        /* 测试统计更新 */
        if (hev_filter_blacklist_update_hit (entry_id, 1024) == 0) {
            printf ("✓ Statistics updated\n");
        } else {
            printf ("✗ Statistics update failed\n");
        }

        /* 获取条目详情 */
        HevBlacklistEntry *entry = hev_filter_blacklist_get_entry (entry_id);
        if (entry) {
            printf ("✓ Entry found: hits=%lu, bytes=%lu\n",
                   entry->hit_count, entry->bytes_blocked);
        } else {
            printf ("✗ Entry not found\n");
        }
    }

    /* 测试IPv6 */
    ip6addr_aton ("2001:db8::1", &test_ip);
    entry_id = hev_filter_blacklist_add_ip (&test_ip, "Test IPv6 blocking",
                                           HEV_BLACKLIST_SOURCE_API, 7200);
    if (entry_id) {
        printf ("✓ Added IPv6 entry: %s\n", entry_id);

        if (hev_filter_blacklist_check_ip (&test_ip)) {
            printf ("✓ IPv6 check passed\n");
        } else {
            printf ("✗ IPv6 check failed\n");
        }
    }
}

static void
test_port_blacklist (void)
{
    const char *entry_id;

    printf ("\n=== Testing Port Blacklist ===\n");

    entry_id = hev_filter_blacklist_add_entry (HEV_BLACKLIST_ENTRY_PORT,
                                              NULL, 8080, NULL,
                                              "Test port blocking",
                                              HEV_BLACKLIST_SOURCE_MANUAL, 7, 3600);
    if (entry_id) {
        printf ("✓ Added port entry: %s\n", entry_id);

        if (hev_filter_blacklist_check_entry (HEV_BLACKLIST_ENTRY_PORT,
                                             NULL, 8080, NULL)) {
            printf ("✓ Port check passed\n");
        } else {
            printf ("✗ Port check failed\n");
        }
    }
}

static void
test_hostname_blacklist (void)
{
    const char *entry_id;

    printf ("\n=== Testing Hostname Blacklist ===\n");

    /* 测试SNI */
    entry_id = hev_filter_blacklist_add_entry (HEV_BLACKLIST_ENTRY_SNI,
                                              NULL, 0, "malicious-site.com",
                                              "Test SNI blocking",
                                              HEV_BLACKLIST_SOURCE_AUTO, 8, 1800);
    if (entry_id) {
        printf ("✓ Added SNI entry: %s\n", entry_id);

        if (hev_filter_blacklist_check_entry (HEV_BLACKLIST_ENTRY_SNI,
                                             NULL, 0, "malicious-site.com")) {
            printf ("✓ SNI check passed\n");
        } else {
            printf ("✗ SNI check failed\n");
        }
    }

    /* 测试域名 */
    entry_id = hev_filter_blacklist_add_entry (HEV_BLACKLIST_ENTRY_DOMAIN,
                                              NULL, 0, "bad-domain.org",
                                              "Test domain blocking",
                                              HEV_BLACKLIST_SOURCE_ACL, 6, 7200);
    if (entry_id) {
        printf ("✓ Added domain entry: %s\n", entry_id);

        if (hev_filter_blacklist_check_entry (HEV_BLACKLIST_ENTRY_DOMAIN,
                                             NULL, 0, "bad-domain.org")) {
            printf ("✓ Domain check passed\n");
        } else {
            printf ("✗ Domain check failed\n");
        }
    }
}

static void
test_statistics (void)
{
    size_t total_entries, active_entries;
    uint64_t total_hits, total_blocked;

    printf ("\n=== Testing Statistics ===\n");

    hev_filter_blacklist_get_stats (&total_entries, &active_entries,
                                   &total_hits, &total_blocked);

    printf ("✓ Total entries: %zu\n", total_entries);
    printf ("✓ Active entries: %zu\n", active_entries);
    printf ("✓ Total hits: %lu\n", total_hits);
    printf ("✓ Total blocked bytes: %lu\n", total_blocked);
}

static void
test_export (void)
{
    char buffer[4096];
    int result;

    printf ("\n=== Testing JSON Export ===\n");

    result = hev_filter_blacklist_export (buffer, sizeof (buffer));
    if (result > 0) {
        printf ("✓ Export successful (%d bytes)\n", result);
        printf ("JSON preview (first 200 chars):\n%.200s...\n", buffer);
    } else {
        printf ("✗ Export failed\n");
    }
}

static void
test_removal (void)
{
    HevBlacklistEntry *entry;
    ip_addr_t test_ip;
    const char *entry_id;

    printf ("\n=== Testing Entry Removal ===\n");

    /* 添加一个条目然后删除 */
    ip4addr_aton ("10.0.0.1", &test_ip);
    entry_id = hev_filter_blacklist_add_ip (&test_ip, "Test removal",
                                           HEV_BLACKLIST_SOURCE_MANUAL, 3600);
    if (entry_id) {
        printf ("✓ Added entry for removal test: %s\n", entry_id);

        /* 确认条目存在 */
        entry = hev_filter_blacklist_get_entry (entry_id);
        if (entry) {
            printf ("✓ Entry confirmed before removal\n");

            /* 删除条目 */
            if (hev_filter_blacklist_remove_entry (entry_id) == 0) {
                printf ("✓ Entry removed successfully\n");

                /* 确认条目已删除 */
                entry = hev_filter_blacklist_get_entry (entry_id);
                if (!entry) {
                    printf ("✓ Entry confirmed removed\n");
                } else {
                    printf ("✗ Entry still exists after removal\n");
                }
            } else {
                printf ("✗ Entry removal failed\n");
            }
        } else {
            printf ("✗ Entry not found after addition\n");
        }
    }
}

static void
test_compatibility (void)
{
    ip_addr_t test_ip;

    printf ("\n=== Testing Backward Compatibility ===\n");

    /* 测试旧接口 */
    ip4addr_aton ("192.168.1.200", &test_ip);
    hev_filter_blacklist_add (&test_ip);
    printf ("✓ Legacy add interface called\n");

    if (hev_filter_blacklist_check (&test_ip)) {
        printf ("✓ Legacy check interface passed\n");
    } else {
        printf ("✗ Legacy check interface failed\n");
    }

    printf ("✓ Total entries: %zu\n", hev_filter_blacklist_get_count ());
}

int
main (void)
{
    printf ("Enhanced Blacklist Test Program\n");
    printf ("================================\n");

    /* 初始化 */
    if (hev_filter_init () < 0) {
        printf ("✗ Failed to initialize filter\n");
        return 1;
    }
    printf ("✓ Filter initialized\n");

    /* 运行测试 */
    test_ip_blacklist ();
    test_port_blacklist ();
    test_hostname_blacklist ();
    test_statistics ();
    test_export ();
    test_removal ();
    test_compatibility ();

    /* 清理 */
    hev_filter_blacklist_clear ();
    hev_filter_fini ();
    printf ("\n✓ Filter finalized\n");

    printf ("\n=== Test Complete ===\n");
    return 0;
}