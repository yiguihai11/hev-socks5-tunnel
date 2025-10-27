/*
 ============================================================================
 Name        : hev-test.c
 Author      : L Gemini
 Copyright   : Copyright (c) 2025 L Gemini
 Description : Test Runner
 ============================================================================
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "hev-main.h"
#include "hev-filter.h"
#include "hev-config.h"

#include "hev-test.h"

#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_RESET "\x1b[0m"

int g_is_test_mode = 0; // Global flag to indicate test mode

static int total_tests = 0;
static int passed_tests = 0;

#define TEST_ASSERT(expr)                                                 \
    do {                                                                  \
        total_tests++;                                                    \
        if (expr) {                                                       \
            passed_tests++;                                               \
            printf (ANSI_COLOR_GREEN "[  OK  ] " ANSI_COLOR_RESET "%s\n", \
                    #expr);                                               \
        } else {                                                          \
            printf (ANSI_COLOR_RED "[ FAIL ] " ANSI_COLOR_RESET "%s\n",   \
                    #expr);                                               \
        }                                                                 \
    } while (0)

static void
create_test_file (const char *path, const char *content)
{
    FILE *fp = fopen (path, "w");
    if (fp) {
        fputs (content, fp);
        fclose (fp);
    }
}

static void
run_parser_tests (void)
{
    printf ("--- Running tests for parsers ---\n");

    // Test: hev_filter_parse_http_host
    printf ("\nTesting HTTP Host parser...\n");
    const char *http_req =
        "GET /test HTTP/1.1\r\nHost: http.example.com\r\n\r\n";
    char http_host[256];
    int res = hev_filter_parse_http_host (NULL, (const unsigned char *)http_req,
                                          strlen (http_req), http_host,
                                          sizeof (http_host));
    TEST_ASSERT (res == 0);
    TEST_ASSERT (strcmp (http_host, "http.example.com") == 0);

    // Test: hev_filter_parse_tls (SNI)
    printf ("\nTesting TLS SNI parser...\n");
    // A minimal, structurally-valid TLS Client Hello for parsing SNI
    const unsigned char tls_req[] = {
        0x16, 0x03, 0x01, 0x00,
        0x4B, // Handshake, TLS 1.0, length (0x4B = 75 bytes)
        0x01, 0x00, 0x00, 0x47, // ClientHello, length (0x47 = 71 bytes)
        0x03, 0x03, // Version TLS 1.2
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, // Random (32 bytes)
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f,
        0x00, // Session ID length (1 byte)
        0x00, 0x02, 0x13,
        0x01, // Cipher Suites length (2 bytes) + dummy suite (2 bytes) = 4 bytes
        0x01,
        0x00, // Compression methods length (1 byte) + dummy method (1 byte) = 2 bytes
        0x00, 0x1C, // Extensions length (2 bytes) (0x1C = 28 bytes)
        // Extension: server_name (20 bytes total)
        0x00, 0x00, // Type: server_name (0x0000)
        0x00, 0x14, // Length: 20 bytes (0x0014)
        0x00, 0x12, // List length: 18 bytes (0x0012)
        0x00, // Type: host_name (0x00)
        0x00, 0x0f, // Host name length (0x000f = 15 bytes)
        't', 'l', 's', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o',
        'm', // 15 bytes
        // Dummy extension to pad out (6 bytes)
        0x00, 0x0b, 0x00, 0x02, 0x01, 0x00
    };
    HevTLSClientHello hello;
    res = hev_filter_parse_tls (NULL, tls_req, sizeof (tls_req), &hello);
    printf ("Extracted SNI: '%s'\n", hello.sni); // Debug print
    TEST_ASSERT (res == 0);
    TEST_ASSERT (hello.detected == 1);
    TEST_ASSERT (strcmp (hello.sni, "tls.example.com") == 0);
}

static void
run_blacklist_tests (void)
{
    printf ("--- Running tests for enhanced blacklist ---\n");

    // Initialize filter for blacklist tests
    hev_filter_init ();

    // Test: Enhanced IP blacklist with metadata
    printf ("\nTesting enhanced IP blacklist...\n");
    ip_addr_t test_ip;
    ipaddr_aton ("192.168.100.1", &test_ip);

    const char *entry_id = hev_filter_blacklist_add_ip (
        &test_ip,
        "Test malicious activity",
        HEV_BLACKLIST_SOURCE_MANUAL,
        3600
    );

    TEST_ASSERT (entry_id != NULL);
    TEST_ASSERT (strlen (entry_id) > 0);

    // Test: IP check
    int is_blacklisted = hev_filter_blacklist_check_ip (&test_ip);
    TEST_ASSERT (is_blacklisted == 1);

    // Test: Get entry details
    HevBlacklistEntry *entry = hev_filter_blacklist_get_entry (entry_id);
    TEST_ASSERT (entry != NULL);
    TEST_ASSERT (entry->type == HEV_BLACKLIST_ENTRY_IP);
    TEST_ASSERT (entry->source == HEV_BLACKLIST_SOURCE_MANUAL);
    TEST_ASSERT (strcmp (entry->reason, "Test malicious activity") == 0);
    TEST_ASSERT (entry->hit_count == 1); // Should be incremented by check

    // Test: Update hit statistics
    int update_res = hev_filter_blacklist_update_hit (entry_id, 1024);
    TEST_ASSERT (update_res == 0);

    // Verify statistics updated
    entry = hev_filter_blacklist_get_entry (entry_id);
    TEST_ASSERT (entry->hit_count == 2);
    TEST_ASSERT (entry->bytes_blocked == 1024);

    // Test: Port blacklist
    printf ("\nTesting port blacklist...\n");
    const char *port_entry_id = hev_filter_blacklist_add_entry (
        HEV_BLACKLIST_ENTRY_PORT,
        NULL, 8080, NULL,
        "Blocked proxy port",
        HEV_BLACKLIST_SOURCE_AUTO,
        7, 1800
    );

    TEST_ASSERT (port_entry_id != NULL);
    int port_blocked = hev_filter_blacklist_check_entry (
        HEV_BLACKLIST_ENTRY_PORT,
        NULL, 8080, NULL
    );
    TEST_ASSERT (port_blocked == 1);

    // Test: SNI blacklist
    printf ("\nTesting SNI blacklist...\n");
    const char *sni_entry_id = hev_filter_blacklist_add_entry (
        HEV_BLACKLIST_ENTRY_SNI,
        NULL, 0, "malicious.example.com",
        "Malware domain",
        HEV_BLACKLIST_SOURCE_AUTO,
        9, 7200
    );

    TEST_ASSERT (sni_entry_id != NULL);
    int sni_blocked = hev_filter_blacklist_check_entry (
        HEV_BLACKLIST_ENTRY_SNI,
        NULL, 0, "malicious.example.com"
    );
    TEST_ASSERT (sni_blocked == 1);

    // Test: Domain blacklist
    printf ("\nTesting domain blacklist...\n");
    const char *domain_entry_id = hev_filter_blacklist_add_entry (
        HEV_BLACKLIST_ENTRY_DOMAIN,
        NULL, 0, "bad-site.org",
        "Phishing domain",
        HEV_BLACKLIST_SOURCE_ACL,
        8, 3600
    );

    TEST_ASSERT (domain_entry_id != NULL);
    int domain_blocked = hev_filter_blacklist_check_entry (
        HEV_BLACKLIST_ENTRY_DOMAIN,
        NULL, 0, "bad-site.org"
    );
    TEST_ASSERT (domain_blocked == 1);

    // Test: Statistics
    printf ("\nTesting blacklist statistics...\n");
    size_t total_entries, active_entries;
    uint64_t total_hits, total_blocked;

    hev_filter_blacklist_get_stats (&total_entries, &active_entries,
                                   &total_hits, &total_blocked);

    TEST_ASSERT (total_entries >= 4);
    TEST_ASSERT (active_entries >= 4);
    TEST_ASSERT (total_hits >= 4);
    TEST_ASSERT (total_blocked >= 1024);

    // Test: JSON export
    printf ("\nTesting JSON export...\n");
    char json_buffer[2048];
    int export_result = hev_filter_blacklist_export (json_buffer, sizeof (json_buffer));
    TEST_ASSERT (export_result > 0);
    TEST_ASSERT (strstr (json_buffer, "\"blacklist\"") != NULL);
    TEST_ASSERT (strstr (json_buffer, "\"entries\"") != NULL);

    // Test: Entry removal
    printf ("\nTesting entry removal...\n");
    int remove_result = hev_filter_blacklist_remove_entry (entry_id);
    TEST_ASSERT (remove_result == 0);

    // Verify entry removed
    HevBlacklistEntry *removed_entry = hev_filter_blacklist_get_entry (entry_id);
    TEST_ASSERT (removed_entry == NULL);

    // Test: Check removed IP is no longer blacklisted
    int still_blacklisted = hev_filter_blacklist_check_ip (&test_ip);
    TEST_ASSERT (still_blacklisted == 0);

    // Test: Backward compatibility
    printf ("\nTesting backward compatibility...\n");
    ip_addr_t compat_ip;
    ipaddr_aton ("10.0.0.50", &compat_ip);

    hev_filter_blacklist_add (&compat_ip);
    int compat_check = hev_filter_blacklist_check (&compat_ip);
    TEST_ASSERT (compat_check == 1);

    // Cleanup
    hev_filter_blacklist_clear ();
    hev_filter_fini ();
}

static void
run_filter_tests (void)
{
    printf ("--- Running tests for hev-filter ---\n");

    const char *acl_file = "test_acl.txt";
    const char *chn_file = "test_chnroutes.txt";

    create_test_file (acl_file, "8.8.8.8\n2001:db8::1\nblocked.example.com\n");
    create_test_file (chn_file, "1.0.1.0/24\n2001:db8:1::/48\n");

    // Manually call load functions, skipping init/fini to avoid task system
    TEST_ASSERT (hev_filter_load_acl (acl_file) == 0);
    TEST_ASSERT (hev_filter_load_chnroutes (chn_file) == 0);

    // Test: hev_filter_is_blocked_hostname
    printf ("\nTesting hostname blocking...\n");
    TEST_ASSERT (hev_filter_is_blocked_hostname ("blocked.example.com") == 1);
    TEST_ASSERT (hev_filter_is_blocked_hostname ("allowed.example.com") == 0);

    // Test: hev_filter_is_blocked_ip (IPv4)
    printf ("\nTesting IPv4 blocking...\n");
    ip_addr_t blocked_ip4, allowed_ip4;
    ipaddr_aton ("8.8.8.8", &blocked_ip4);
    ipaddr_aton ("1.1.1.1", &allowed_ip4);
    TEST_ASSERT (hev_filter_is_blocked_ip (&blocked_ip4) == 1);
    TEST_ASSERT (hev_filter_is_blocked_ip (&allowed_ip4) == 0);

    // Test: hev_filter_is_blocked_ip (IPv6)
    printf ("\nTesting IPv6 blocking...\n");
    ip_addr_t blocked_ip6, allowed_ip6;
    ipaddr_aton ("2001:db8::1", &blocked_ip6);
    ipaddr_aton ("2001:db8::2", &allowed_ip6);
    TEST_ASSERT (hev_filter_is_blocked_ip (&blocked_ip6) == 1);
    TEST_ASSERT (hev_filter_is_blocked_ip (&allowed_ip6) == 0);

    // Test: hev_filter_is_domestic (IPv4)
    printf ("\nTesting IPv4 domestic IP rule...\n");
    ip_addr_t domestic_ip4, foreign_ip4;
    ipaddr_aton ("1.0.1.1", &domestic_ip4);
    ipaddr_aton ("8.8.4.4", &foreign_ip4);
    TEST_ASSERT (hev_filter_is_domestic (&domestic_ip4) == 1);
    TEST_ASSERT (hev_filter_is_domestic (&foreign_ip4) == 0);

    // Test: hev_filter_is_domestic (IPv6)
    printf ("\nTesting IPv6 domestic IP rule...\n");
    ip_addr_t domestic_ip6, foreign_ip6;
    ipaddr_aton ("2001:db8:1::1", &domestic_ip6);
    ipaddr_aton ("2001:db8:2::1", &foreign_ip6);
    TEST_ASSERT (hev_filter_is_domestic (&domestic_ip6) == 1);
    TEST_ASSERT (hev_filter_is_domestic (&foreign_ip6) == 0);

    // NOTE: We are not calling init/fini to avoid the complexities
    // of the task system in this simple test runner.

    remove (acl_file);
    remove (chn_file);
}

int
hev_test_run (void)
{
    g_is_test_mode = 1; // Set test mode flag

    const char *test_config = "smart_proxy:\n  blocked_ip_expiry_minutes: 1\n";
    hev_config_init_from_str ((const unsigned char *)test_config,
                              strlen (test_config));
    printf ("======== Running Built-in Tests =========\n");

    run_filter_tests ();
    run_parser_tests ();
    run_blacklist_tests ();

    printf ("=========================================\n");
    printf ("Test Summary: %d/%d passed.\n", passed_tests, total_tests);
    printf ("=========================================\n");

    return (passed_tests == total_tests) ? 0 : -1;
}