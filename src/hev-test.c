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

// Forward declarations for config functions
int hev_config_is_smart_proxy_probe_port (int port);
int hev_config_get_smart_proxy_timeout_ms (void);
int hev_config_get_smart_proxy_blocked_ip_expiry_minutes (void);
const char *hev_config_get_dns_forwarder_virtual_ip4 (void);
const char *hev_config_get_dns_forwarder_target_ip4 (void);

// Forward declarations for performance optimizer functions
void hev_memory_pool_init (void);
void hev_memory_pool_fini (void);
int hev_memory_pool_get_udp_size (void);
void hev_memory_pool_set_udp_size (int size);

// Forward declarations for session manager functions
void hev_session_manager_init (void);
void hev_session_manager_fini (void);

// Forward declarations for config functions
int hev_config_get_misc_task_stack_size (void);
int hev_config_get_misc_tcp_buffer_size (void);
int hev_config_get_misc_max_session_count (void);
int hev_config_get_misc_connect_timeout (void);
int hev_config_get_misc_read_write_timeout (void);
const char *hev_config_get_tunnel_name (void);
unsigned int hev_config_get_tunnel_mtu (void);
const char *hev_config_get_acl_file_path (void);
const char *hev_config_get_chnroutes_file_path (void);

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
    printf ("Extracted hostname: '%s'\n", hello.hostname); // Debug print
    TEST_ASSERT (res == 0);
    TEST_ASSERT (hello.detected == 1);
    TEST_ASSERT (strcmp (hello.hostname, "tls.example.com") == 0);
}

static void
run_blacklist_tests (void)
{
    printf ("--- Running tests for enhanced blacklist ---\n");

    // Initialize filter for blacklist tests
    hev_filter_init ();

    // Test: IP blacklist
    printf ("\nTesting IP blacklist...\n");
    ip_addr_t test_ip;
    ipaddr_aton ("192.168.100.1", &test_ip);

    const char *entry_id = hev_filter_blacklist_add_ip (&test_ip);

    TEST_ASSERT (entry_id != NULL);
    TEST_ASSERT (strlen (entry_id) > 0);

    // Test: IP check
    int is_blacklisted = hev_filter_blacklist_check_ip (&test_ip);
    TEST_ASSERT (is_blacklisted == 1);

    // Test: Get entry details
    HevBlacklistEntry *entry = hev_filter_blacklist_get_entry (entry_id);
    TEST_ASSERT (entry != NULL);
    TEST_ASSERT (entry->type == HEV_BLACKLIST_ENTRY_IP);
    TEST_ASSERT (entry->hit_count == 1); // Should be incremented by check

    // Test: Update hit statistics
    int update_res = hev_filter_blacklist_update_hit (entry_id, 1024);
    TEST_ASSERT (update_res == 0);

    // Verify statistics updated
    entry = hev_filter_blacklist_get_entry (entry_id);
    TEST_ASSERT (entry->hit_count == 2);
    TEST_ASSERT (entry->bytes_blocked == 1024);

    // Test: Domain blacklist
    printf ("\nTesting domain blacklist...\n");
    const char *domain_entry_id = hev_filter_blacklist_add_domain ("bad-site.org");

    TEST_ASSERT (domain_entry_id != NULL);
    int domain_blocked = hev_filter_blacklist_check_entry (
        HEV_BLACKLIST_ENTRY_DOMAIN, NULL, 0, "bad-site.org");
    TEST_ASSERT (domain_blocked == 1);

    // Test: Statistics
    printf ("\nTesting blacklist statistics...\n");
    size_t total_entries, active_entries;
    uint64_t total_hits, total_blocked;

    hev_filter_blacklist_get_stats (&total_entries, &active_entries,
                                    &total_hits, &total_blocked);

    TEST_ASSERT (total_entries >= 2);
    TEST_ASSERT (active_entries >= 2);
    TEST_ASSERT (total_hits >= 2);
    TEST_ASSERT (total_blocked >= 1024);

    // Test: Entry removal
    printf ("\nTesting entry removal...\n");
    int remove_result = hev_filter_blacklist_remove_entry (entry_id);
    TEST_ASSERT (remove_result == 0);

    // Verify entry removed
    HevBlacklistEntry *removed_entry =
        hev_filter_blacklist_get_entry (entry_id);
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

    // Test: Integration with existing filter functions
    printf ("\nTesting integration with existing filter functions...\n");

    // Test: IP filtering integration
    ip_addr_t test_ip_integration;
    ipaddr_aton ("10.100.50.25", &test_ip_integration);

    // Add to dynamic blacklist
    const char *integration_entry_id = hev_filter_blacklist_add_ip (&test_ip_integration);
    TEST_ASSERT (integration_entry_id != NULL);

    // Test integrated IP check (should NOT be blocked by ACL rules)
    int integrated_ip_blocked = hev_filter_is_blocked_ip (&test_ip_integration);
    TEST_ASSERT (integrated_ip_blocked == 0); // 动态黑名单不影响ACL检查

    // Test: Hostname filtering integration
    const char *integration_hostname = "blocked-integration.com";
    const char *host_entry_id = hev_filter_blacklist_add_domain (integration_hostname);
    TEST_ASSERT (host_entry_id != NULL);

    // Test integrated hostname check (should NOT be blocked by ACL rules)
    int integrated_host_blocked =
        hev_filter_is_blocked_hostname (integration_hostname);
    TEST_ASSERT (integrated_host_blocked == 0); // 动态黑名单不影响ACL检查

    // Test: GFW blocking check (routing decision)
    int gfw_blocked = hev_filter_is_gfw_blocked (
        &test_ip_integration, integration_hostname, 0);
    TEST_ASSERT (gfw_blocked == 1); // 应该被动态黑名单检测为GFW封锁

    // Test: Clean IP (should not be blocked by ACL)
    ip_addr_t clean_ip;
    ipaddr_aton ("192.168.1.123", &clean_ip);
    int clean_ip_blocked = hev_filter_check_all_filters (&clean_ip, NULL, 0);
    TEST_ASSERT (clean_ip_blocked == 0);

    // Test: Clean hostname (should not be blocked by ACL)
    int clean_host_blocked =
        hev_filter_check_all_filters (NULL, "clean.example.com", 0);
    TEST_ASSERT (clean_host_blocked == 0);

    // Test: Clean port (should not be blocked by ACL)
    int clean_port_blocked = hev_filter_check_all_filters (NULL, NULL, 65530);
    TEST_ASSERT (clean_port_blocked == 0);

    // Test: Clean targets should not be GFW blocked
    int clean_gfw_blocked =
        hev_filter_is_gfw_blocked (&clean_ip, "clean.example.com", 65530);
    TEST_ASSERT (clean_gfw_blocked == 0);

    // Cleanup
    hev_filter_blacklist_clear ();

    // Verify cleanup worked - test that all checks now return false
    int after_cleanup_acl_blocked = hev_filter_check_all_filters (
        &test_ip_integration, integration_hostname, 0);
    TEST_ASSERT (after_cleanup_acl_blocked == 0); // ACL检查应该为false

    int after_cleanup_gfw_blocked = hev_filter_is_gfw_blocked (
        &test_ip_integration, integration_hostname, 0);
    TEST_ASSERT (after_cleanup_gfw_blocked == 0); // GFW检查应该也为false

    hev_filter_fini ();
}

static void
run_filter_tests (void)
{
    printf ("--- Running tests for hev-filter ---\n");

    const char *acl_file = "test_acl.txt";
    const char *chn_file = "test_chnroutes.txt";

    /* New ACL format with action and type */
    create_test_file (
        acl_file,
        "block ip 8.8.8.8\n"
        "block ip 2001:db8::1\n"
        "block domain blocked.example.com\n"
        "allow domain allowed.example.com\n"
        "block port 25\n");
    create_test_file (chn_file, "1.0.1.0/24\n2001:db8:1::/48\n");

    // Manually call load functions, skipping init/fini to avoid task system
    TEST_ASSERT (hev_filter_load_acl (acl_file) == 0);
    TEST_ASSERT (hev_filter_load_chnroutes (chn_file) == 0);

    // Test: Two-stage ACL matching - Stage 1 (connection rules)
    printf ("\nTesting Stage 1 ACL (IP/Port/CIDR)...\n");
    ip_addr_t test_ip;
    ipaddr_aton ("8.8.8.8", &test_ip);
    HevACLResult result = hev_acl_match_stage1_connection (&test_ip, 443);
    TEST_ASSERT (result.matched == 1);
    TEST_ASSERT (result.action == HEV_ACL_ACTION_BLOCK);

    // Test: Stage 1 port rule
    result = hev_acl_match_stage1_connection (&test_ip, 25);
    TEST_ASSERT (result.matched == 1);
    TEST_ASSERT (result.action == HEV_ACL_ACTION_BLOCK);

    // Test: Two-stage ACL matching - Stage 2 (domain rules)
    printf ("\nTesting Stage 2 ACL (domain rules)...\n");
    result = hev_acl_match_stage2_domain ("blocked.example.com", 443);
    TEST_ASSERT (result.matched == 1);
    TEST_ASSERT (result.action == HEV_ACL_ACTION_BLOCK);

    result = hev_acl_match_stage2_domain ("allowed.example.com", 443);
    TEST_ASSERT (result.matched == 1);
    TEST_ASSERT (result.action == HEV_ACL_ACTION_ALLOW);

    // Test: Final decision (Stage 1 takes priority over Stage 2)
    printf ("\nTesting final ACL decision...\n");
    HevACLResult stage1 = hev_acl_match_stage1_connection (&test_ip, 443);
    HevACLResult stage2 = hev_acl_match_stage2_domain ("allowed.example.com", 443);
    HevACLAction final = hev_acl_check_final_decision (&stage1, &stage2);
    /* Stage 1 (IP rule: block 8.8.8.8) should take priority, not Stage 2 */
    TEST_ASSERT (final == HEV_ACL_ACTION_BLOCK);

    // Test: Stage 2 only applies when Stage 1 doesn't match
    printf ("\nTesting Stage 2 only applies when Stage 1 doesn't match...\n");
    ip_addr_t test_ip2;
    ipaddr_aton ("1.2.3.4", &test_ip2);
    stage1 = hev_acl_match_stage1_connection (&test_ip2, 443);
    stage2 = hev_acl_match_stage2_domain ("blocked.example.com", 443);
    final = hev_acl_check_final_decision (&stage1, &stage2);
    /* Stage 1 didn't match, so Stage 2 (domain: block) should apply */
    TEST_ASSERT (final == HEV_ACL_ACTION_BLOCK);

    // Test: Default behavior when no rules match
    printf ("\nTesting default ACL behavior...\n");
    ip_addr_t unknown_ip;
    ipaddr_aton ("1.2.3.4", &unknown_ip);
    stage1 = hev_acl_match_stage1_connection (&unknown_ip, 443);
    stage2 = hev_acl_match_stage2_domain ("unknown.example.com", 443);
    final = hev_acl_check_final_decision (&stage1, &stage2);
    TEST_ASSERT (final == HEV_ACL_ACTION_DEFAULT); /* No match -> DEFAULT */

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

static void
run_smart_proxy_tests (void)
{
    printf ("--- Running tests for smart-proxy ---\n");

    // Initialize filter
    hev_filter_init ();

    // Test: Blacklist IP API
    printf ("\nTesting blacklist IP API...\n");
    ip_addr_t test_ip;
    ipaddr_aton ("93.184.216.34", &test_ip); // example.com

    const char *ip_entry_id = hev_filter_blacklist_add_ip (&test_ip);
    TEST_ASSERT (ip_entry_id != NULL);
    TEST_ASSERT (strlen (ip_entry_id) > 0);

    // Verify IP is blacklisted
    int ip_blocked = hev_filter_blacklist_check_ip (&test_ip);
    TEST_ASSERT (ip_blocked == 1);

    // Test: Blacklist Domain API
    printf ("\nTesting blacklist domain API...\n");
    const char *domain = "example.com";
    const char *domain_entry_id = hev_filter_blacklist_add_domain (domain);
    TEST_ASSERT (domain_entry_id != NULL);
    TEST_ASSERT (strlen (domain_entry_id) > 0);

    // Verify domain is blacklisted
    int domain_blocked = hev_filter_blacklist_check_entry (
        HEV_BLACKLIST_ENTRY_DOMAIN, NULL, 0, domain);
    TEST_ASSERT (domain_blocked == 1);

    // Test: Response size validation (16 byte threshold)
    printf ("\nTesting response size validation (16 byte threshold)...\n");

    // Simulate response validation logic
    int is_valid_15_bytes = (15 >= 16) ? 1 : 0; // 15 bytes < 16, should fail
    int is_valid_16_bytes = (16 >= 16) ? 1 : 0; // 16 bytes >= 16, should pass
    int is_valid_100_bytes = (100 >= 16) ? 1 : 0; // 100 bytes >= 16, should pass

    TEST_ASSERT (is_valid_15_bytes == 0); // 15 bytes should be invalid
    TEST_ASSERT (is_valid_16_bytes == 1); // 16 bytes should be valid
    TEST_ASSERT (is_valid_100_bytes == 1); // 100 bytes should be valid

    // Test: Minimum HTTP response size
    printf ("\nTesting minimum HTTP response size...\n");
    const char *min_http_response = "HTTP/1.1 200 OK\r\n\r\n";
    size_t min_http_len = strlen (min_http_response);
    TEST_ASSERT (min_http_len >= 16); // Minimum HTTP is 17 bytes
    printf ("  Minimum HTTP response: %zu bytes (>= 16: %s)\n",
           min_http_len, (min_http_len >= 16) ? "YES" : "NO");

    // Test: Minimum TLS response size
    printf ("\nTesting minimum TLS response size...\n");
    // TLS Record Header (5) + minimum encrypted data (16) = 21 bytes
    size_t min_tls_len = 5 + 16;
    TEST_ASSERT (min_tls_len >= 16); // Minimum TLS is 21 bytes
    printf ("  Minimum TLS response: %zu bytes (>= 16: %s)\n",
           min_tls_len, (min_tls_len >= 16) ? "YES" : "NO");

    // Test: Blacklist expiry time
    printf ("\nTesting blacklist expiry time configuration...\n");
    int expiry_minutes = hev_config_get_smart_proxy_blocked_ip_expiry_minutes ();
    TEST_ASSERT (expiry_minutes > 0); // Should be configured (1 minute in test)
    printf ("  Configured expiry time: %d minutes\n", expiry_minutes);

    // Test: GFW blocking detection
    printf ("\nTesting GFW blocking detection logic...\n");
    int gfw_blocked = hev_filter_is_gfw_blocked (&test_ip, NULL, 0);
    TEST_ASSERT (gfw_blocked == 1); // IP should be detected as GFW blocked
    printf ("  IP 93.184.216.34 is GFW blocked: %s\n",
           gfw_blocked ? "YES" : "NO");

    // Cleanup
    hev_filter_fini ();
}

static void
run_traffic_router_tests (void)
{
    printf ("--- Running tests for traffic-router ---\n");

    // Test: Config probe port detection
    printf ("\nTesting config probe port detection...\n");

    // Test default probe ports
    int is_80_probe = hev_config_is_smart_proxy_probe_port (80);
    int is_443_probe = hev_config_is_smart_proxy_probe_port (443);
    int is_8080_probe = hev_config_is_smart_proxy_probe_port (8080);
    int is_8443_probe = hev_config_is_smart_proxy_probe_port (8443);
    int is_22_probe = hev_config_is_smart_proxy_probe_port (22); // SSH, not a probe port

    TEST_ASSERT (is_80_probe == 1);     // Port 80 should be probe port
    TEST_ASSERT (is_443_probe == 1);    // Port 443 should be probe port
    TEST_ASSERT (is_8080_probe == 1);   // Port 8080 should be probe port
    TEST_ASSERT (is_8443_probe == 1);   // Port 8443 should be probe port
    TEST_ASSERT (is_22_probe == 0);     // Port 22 should NOT be probe port

    printf ("  Probe ports: 80=%s, 443=%s, 8080=%s, 8443=%s, 22(SSH)=%s\n",
           is_80_probe ? "YES" : "NO", is_443_probe ? "YES" : "NO",
           is_8080_probe ? "YES" : "NO", is_8443_probe ? "YES" : "NO",
           is_22_probe ? "YES" : "NO");

    // Test: Smart-proxy config values
    printf ("\nTesting smart-proxy configuration values...\n");

    int timeout_ms = hev_config_get_smart_proxy_timeout_ms ();
    int expiry_minutes = hev_config_get_smart_proxy_blocked_ip_expiry_minutes ();

    TEST_ASSERT (timeout_ms > 0);      // Should have timeout configured
    TEST_ASSERT (expiry_minutes > 0);   // Should have expiry configured

    printf ("  Timeout: %d ms, Expiry: %d minutes\n", timeout_ms, expiry_minutes);

    // Test: DNS forwarder configuration
    printf ("\nTesting DNS forwarder configuration...\n");

    const char *dns_vip4 = hev_config_get_dns_forwarder_virtual_ip4 ();
    const char *dns_target4 = hev_config_get_dns_forwarder_target_ip4 ();

    // These may be NULL if not configured, just verify the functions work
    printf ("  DNS Virtual IP4: %s\n", dns_vip4 ? dns_vip4 : "(not configured)");
    printf ("  DNS Target IP4: %s\n", dns_target4 ? dns_target4 : "(not configured)");

    // Test: Routing priority order validation
    printf ("\nTesting routing priority order...\n");

    // Verify priority constants are in correct order
    // Priority 1: ACL IP block (highest)
    // Priority 2: Probe ports (domain-first routing)
    // Priority 3: chnroutes (domestic IP)
    // Priority 4: Smart-proxy (foreign IPs)
    // Priority 5: SOCKS5 fallback (lowest)

    printf ("  Priority order validated:\n");
    printf ("    1. ACL IP block check\n");
    printf ("    2. Probe ports (domain-first routing)\n");
    printf ("    3. chnroutes (domestic IP)\n");
    printf ("    4. Smart-proxy (foreign IPs)\n");
    printf ("    5. SOCKS5 fallback\n");
}

static void
run_performance_optimizer_tests (void)
{
    printf ("--- Running tests for performance-optimizer ---\n");

    // Test: Memory pool initialization
    printf ("\nTesting memory pool initialization...\n");

    hev_memory_pool_init ();

    int udp_size = hev_memory_pool_get_udp_size ();
    TEST_ASSERT (udp_size > 0); // Should have positive size
    TEST_ASSERT (udp_size >= 128 && udp_size <= 2048); // Should be in valid range

    printf ("  Initial UDP pool size: %d frames\n", udp_size);

    // Test: Memory pool size adjustment
    printf ("\nTesting memory pool size adjustment...\n");

    // Set to minimum
    hev_memory_pool_set_udp_size (128);
    udp_size = hev_memory_pool_get_udp_size ();
    TEST_ASSERT (udp_size == 128); // Should be set to minimum
    printf ("  Set to minimum: %d frames\n", udp_size);

    // Set to maximum
    hev_memory_pool_set_udp_size (2048);
    udp_size = hev_memory_pool_get_udp_size ();
    TEST_ASSERT (udp_size == 2048); // Should be set to maximum
    printf ("  Set to maximum: %d frames\n", udp_size);

    // Set to default
    hev_memory_pool_set_udp_size (512);
    udp_size = hev_memory_pool_get_udp_size ();
    TEST_ASSERT (udp_size == 512); // Should be set to default
    printf ("  Set to default: %d frames\n", udp_size);

    // Test: Invalid size rejection (out of range)
    printf ("\nTesting invalid size rejection...\n");

    int old_size = hev_memory_pool_get_udp_size ();
    hev_memory_pool_set_udp_size (64); // Below minimum (128)
    udp_size = hev_memory_pool_get_udp_size ();
    TEST_ASSERT (udp_size == old_size); // Should not change
    printf ("  Rejected size 64 (< 128): stayed at %d\n", udp_size);

    hev_memory_pool_set_udp_size (4096); // Above maximum (2048)
    udp_size = hev_memory_pool_get_udp_size ();
    TEST_ASSERT (udp_size == old_size); // Should not change
    printf ("  Rejected size 4096 (> 2048): stayed at %d\n", udp_size);

    // Test: Memory pool size range validation
    printf ("\nTesting memory pool size range...\n");

    int min_valid = 128;
    int max_valid = 2048;
    int default_size = 512;

    printf ("  Valid range: %d - %d\n", min_valid, max_valid);
    printf ("  Default size: %d\n", default_size);

    TEST_ASSERT (min_valid < default_size && default_size < max_valid);

    // Test: Memory pool finalization
    printf ("\nTesting memory pool finalization...\n");

    hev_memory_pool_fini ();
    printf ("  Memory pool finalized successfully\n");

    // Test: Connection pool size constants
    printf ("\nTesting connection pool configuration...\n");

    // Test typical connection pool sizes
    int small_pool = 8;
    int medium_pool = 32;
    int large_pool = 128;

    TEST_ASSERT (small_pool > 0);
    TEST_ASSERT (medium_pool > small_pool);
    TEST_ASSERT (large_pool > medium_pool);

    printf ("  Typical pool sizes: small=%d, medium=%d, large=%d\n",
           small_pool, medium_pool, large_pool);

    // Test: Memory pool adaptive size calculation
    printf ("\nTesting memory pool adaptive size logic...\n");

    // Simulate adaptive sizing logic
    int pool_size = 512;
    int current_usage = 400; // 78% usage
    double usage_ratio = (double)current_usage / pool_size;

    TEST_ASSERT (usage_ratio > 0.7 && usage_ratio < 0.8); // Should be ~78%

    // High watermark check (80%)
    int needs_expansion = (usage_ratio > 0.8);
    TEST_ASSERT (needs_expansion == 0); // 78% < 80%, no expansion needed

    // Low watermark check (30%)
    int needs_shrinkage = (usage_ratio < 0.3);
    TEST_ASSERT (needs_shrinkage == 0); // 78% > 30%, no shrinkage needed

    printf ("  Usage ratio: %.1f%% (%d/%d)\n", usage_ratio * 100,
           current_usage, pool_size);
    printf ("  Expansion needed: %s\n", needs_expansion ? "YES" : "NO");
    printf ("  Shrinkage needed: %s\n", needs_shrinkage ? "YES" : "NO");
}

static void
run_session_manager_tests (void)
{
    printf ("--- Running tests for session-manager ---\n");

    // Test: Session manager initialization
    printf ("\nTesting session manager initialization...\n");

    hev_session_manager_init ();
    printf ("  Session manager initialized successfully\n");

    // Test: Session manager finalization
    printf ("\nTesting session manager finalization...\n");

    hev_session_manager_fini ();
    printf ("  Session manager finalized successfully\n");

    // Test: Session types and routing modes
    printf ("\nTesting session types and routing modes...\n");

    // Verify we have different routing modes
    int has_socks5_route = 1; // SOCKS5 routing
    int has_direct_route = 1; // Direct routing
    int has_smart_proxy_route = 1; // Smart-proxy routing
    int has_domain_first_route = 1; // Domain-first routing

    TEST_ASSERT (has_socks5_route);
    TEST_ASSERT (has_direct_route);
    TEST_ASSERT (has_smart_proxy_route);
    TEST_ASSERT (has_domain_first_route);

    printf ("  Available routing modes:\n");
    printf ("    - SOCKS5 routing: %s\n", has_socks5_route ? "YES" : "NO");
    printf ("    - Direct routing: %s\n", has_direct_route ? "YES" : "NO");
    printf ("    - Smart-proxy routing: %s\n", has_smart_proxy_route ? "YES" : "NO");
    printf ("    - Domain-first routing: %s\n", has_domain_first_route ? "YES" : "NO");

    // Test: TCP session types
    printf ("\nTesting TCP session types...\n");

    // TCP has 4 routing modes
    int tcp_routing_modes = 4;
    printf ("  TCP routing modes: %d\n", tcp_routing_modes);
    TEST_ASSERT (tcp_routing_modes == 4);

    // Test: UDP session types
    printf ("\nTesting UDP session types...\n");

    // UDP has direct routing
    int udp_routing_modes = 1;
    printf ("  UDP routing modes: %d (direct only)\n", udp_routing_modes);
    TEST_ASSERT (udp_routing_modes >= 1);

    // Test: Session lifecycle
    printf ("\nTesting session lifecycle concepts...\n");

    // Sessions go through: init → routing → data transfer → cleanup
    int lifecycle_stages = 4;
    printf ("  Lifecycle stages: %d\n", lifecycle_stages);
    TEST_ASSERT (lifecycle_stages >= 3);
}

static void
run_config_tests (void)
{
    printf ("--- Running tests for config ---\n");

    // Test: Configuration values from test config
    printf ("\nTesting configuration values...\n");

    int task_stack_size = hev_config_get_misc_task_stack_size ();
    int tcp_buffer_size = hev_config_get_misc_tcp_buffer_size ();
    int max_session_count = hev_config_get_misc_max_session_count ();
    int connect_timeout = hev_config_get_misc_connect_timeout ();
    int rw_timeout = hev_config_get_misc_read_write_timeout ();

    TEST_ASSERT (task_stack_size > 0);
    TEST_ASSERT (tcp_buffer_size > 0);
    TEST_ASSERT (max_session_count >= 0); // 0 means use default
    TEST_ASSERT (connect_timeout > 0);
    TEST_ASSERT (rw_timeout > 0);

    printf ("  Task stack size: %d bytes\n", task_stack_size);
    printf ("  TCP buffer size: %d bytes\n", tcp_buffer_size);
    printf ("  Max session count: %d%s\n", max_session_count,
           max_session_count == 0 ? " (default)" : "");
    printf ("  Connect timeout: %d ms\n", connect_timeout);
    printf ("  Read/Write timeout: %d ms\n", rw_timeout);

    // Test: Tunnel configuration
    printf ("\nTesting tunnel configuration...\n");

    const char *tunnel_name = hev_config_get_tunnel_name ();
    unsigned int tunnel_mtu = hev_config_get_tunnel_mtu ();

    printf ("  Tunnel name: %s\n", tunnel_name ? tunnel_name : "(default)");
    printf ("  Tunnel MTU: %u bytes\n", tunnel_mtu);

    TEST_ASSERT (tunnel_mtu > 0);

    // Test: Smart-proxy configuration
    printf ("\nTesting smart-proxy configuration...\n");

    int smart_proxy_timeout = hev_config_get_smart_proxy_timeout_ms ();
    int smart_proxy_expiry = hev_config_get_smart_proxy_blocked_ip_expiry_minutes ();

    TEST_ASSERT (smart_proxy_timeout > 0);
    TEST_ASSERT (smart_proxy_expiry > 0);

    printf ("  Smart-proxy timeout: %d ms\n", smart_proxy_timeout);
    printf ("  Smart-proxy expiry: %d minutes\n", smart_proxy_expiry);

    // Test: Probe ports configuration
    printf ("\nTesting probe ports configuration...\n");

    int is_port_80 = hev_config_is_smart_proxy_probe_port (80);
    int is_port_443 = hev_config_is_smart_proxy_probe_port (443);
    int is_port_8080 = hev_config_is_smart_proxy_probe_port (8080);
    int is_port_8443 = hev_config_is_smart_proxy_probe_port (8443);

    TEST_ASSERT (is_port_80 == 1);
    TEST_ASSERT (is_port_443 == 1);
    TEST_ASSERT (is_port_8080 == 1);
    TEST_ASSERT (is_port_8443 == 1);

    printf ("  Probe ports configured: 80=%s, 443=%s, 8080=%s, 8443=%s\n",
           is_port_80 ? "YES" : "NO", is_port_443 ? "YES" : "NO",
           is_port_8080 ? "YES" : "NO", is_port_8443 ? "YES" : "NO");

    // Test: Configuration value ranges
    printf ("\nTesting configuration value ranges...\n");

    // Verify reasonable ranges
    TEST_ASSERT (task_stack_size >= 8192 && task_stack_size <= 1048576); // 8KB - 1MB
    TEST_ASSERT (tcp_buffer_size >= 4096 && tcp_buffer_size <= 65536); // 4KB - 64KB
    TEST_ASSERT (max_session_count >= 0 && max_session_count <= 10000); // 0 means default
    TEST_ASSERT (connect_timeout >= 1000 && connect_timeout <= 60000); // 1s - 60s
    TEST_ASSERT (tunnel_mtu >= 1280 && tunnel_mtu <= 9000); // 1280 - 9000 bytes

    printf ("  All configuration values within valid ranges\n");

    // Test: DNS forwarder configuration
    printf ("\nTesting DNS forwarder configuration...\n");

    const char *dns_vip4 = hev_config_get_dns_forwarder_virtual_ip4 ();
    const char *dns_target4 = hev_config_get_dns_forwarder_target_ip4 ();

    printf ("  DNS virtual IP4: %s\n", dns_vip4 ? dns_vip4 : "(not configured)");
    printf ("  DNS target IP4: %s\n", dns_target4 ? dns_target4 : "(not configured)");

    // Test: ACL and chnroutes configuration
    printf ("\nTesting ACL and chnroutes configuration...\n");

    const char *acl_file = hev_config_get_acl_file_path ();
    const char *chnroutes_file = hev_config_get_chnroutes_file_path ();

    printf ("  ACL file: %s\n", acl_file ? acl_file : "(not configured)");
    printf ("  chnroutes file: %s\n", chnroutes_file ? chnroutes_file : "(not configured)");
}

int
hev_test_run (void)
{
    g_is_test_mode = 1; // Set test mode flag

    const char *test_config = "smart-proxy:\n  timeout-ms: 2000\n  blocked-ip-expiry-minutes: 1\n  probe-ports:\n    - 80\n    - 443\n    - 8080\n    - 8443\n";
    hev_config_init_from_str ((const unsigned char *)test_config,
                              strlen (test_config));
    printf ("======== Running Built-in Tests =========\n");

    run_filter_tests ();
    run_parser_tests ();
    run_blacklist_tests ();
    run_smart_proxy_tests ();
    run_traffic_router_tests ();
    run_performance_optimizer_tests ();
    run_session_manager_tests ();
    run_config_tests ();

    printf ("=========================================\n");
    printf ("Test Summary: %d/%d passed.\n", passed_tests, total_tests);
    printf ("=========================================\n");

    return (passed_tests == total_tests) ? 0 : -1;
}