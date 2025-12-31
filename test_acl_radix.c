/*
 ============================================================================
 ACL Radix Tree Optimization Unit Test
 ============================================================================
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <arpa/inet.h>

/* Mock types */
typedef enum {
    HEV_ACL_ACTION_ALLOW,
    HEV_ACL_ACTION_BLOCK,
    HEV_ACL_ACTION_DEFAULT
} HevACLAction;

typedef struct _RadixNode {
    struct _RadixNode *left;
    struct _RadixNode *right;
    uint8_t is_leaf;
    uint8_t blocked;
    HevACLAction action;
} RadixNode;

static RadixNode *acl_ipv4_tree = NULL;

/* Radix Tree Functions (from hev-filter.c) */
static RadixNode *
radix_node_create (void)
{
    RadixNode *node = calloc (1, sizeof (RadixNode));
    return node;
}

static void
radix_tree_free (RadixNode *node)
{
    RadixNode *left, *right;

    if (!node)
        return;

    left = node->left;
    right = node->right;
    free (node);
    radix_tree_free (left);
    radix_tree_free (right);
}

static void
radix_tree_insert_ipv4 (uint32_t ip, uint8_t prefix, HevACLAction action)
{
    RadixNode **current = &acl_ipv4_tree;

    if (!*current)
        *current = radix_node_create ();

    for (int i = 0; i < prefix; i++) {
        uint8_t bit = (ip >> (31 - i)) & 1;
        RadixNode **next = bit ? &(*current)->right : &(*current)->left;

        if (!*next)
            *next = radix_node_create ();

        current = next;
    }

    (*current)->is_leaf = 1;
    (*current)->blocked = (action == HEV_ACL_ACTION_BLOCK);
    (*current)->action = action;
}

static HevACLAction
radix_tree_lookup_ipv4 (uint32_t ip)
{
    RadixNode *current = acl_ipv4_tree;
    HevACLAction found_action = HEV_ACL_ACTION_DEFAULT;

    for (int i = 0; i < 32 && current; i++) {
        if (current->is_leaf && current->action != HEV_ACL_ACTION_DEFAULT) {
            found_action = current->action;
        }

        uint8_t bit = (ip >> (31 - i)) & 1;
        current = bit ? current->right : current->left;
    }

    if (current && current->is_leaf && current->action != HEV_ACL_ACTION_DEFAULT) {
        found_action = current->action;
    }

    return found_action;
}

/* Helper to convert string IP to uint32_t */
static uint32_t
ip_to_uint32 (const char *ip_str)
{
    struct in_addr addr;
    inet_pton (AF_INET, ip_str, &addr);
    return ntohl (addr.s_addr);
}

/* Performance benchmark */
static double
benchmark_lookup (uint32_t *ips, size_t count, int iterations)
{
    struct timespec start, end;
    clock_gettime (CLOCK_MONOTONIC, &start);

    for (int i = 0; i < iterations; i++) {
        for (size_t j = 0; j < count; j++) {
            radix_tree_lookup_ipv4 (ips[j]);
        }
    }

    clock_gettime (CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec)
                     + (end.tv_nsec - start.tv_nsec) / 1e9;
    return elapsed;
}

/* Test Cases */
int
main (void)
{
    int tests_passed = 0;
    int tests_failed = 0;

    printf ("=== ACL Radix Tree Optimization Unit Test ===\n\n");

    /* Test 1: Exact IP Match */
    printf ("Test 1: Exact IP Match (192.168.1.1 -> BLOCK)... ");
    radix_tree_insert_ipv4 (ip_to_uint32 ("192.168.1.1"), 32,
                            HEV_ACL_ACTION_BLOCK);
    HevACLAction result =
        radix_tree_lookup_ipv4 (ip_to_uint32 ("192.168.1.1"));
    if (result == HEV_ACL_ACTION_BLOCK) {
        printf ("✓ PASS\n");
        tests_passed++;
    } else {
        printf ("✗ FAIL (expected BLOCK, got %d)\n", result);
        tests_failed++;
    }

    /* Test 2: CIDR Range Match */
    printf ("Test 2: CIDR Range Match (10.0.0.0/8 -> ALLOW)... ");
    radix_tree_insert_ipv4 (ip_to_uint32 ("10.0.0.0"), 8, HEV_ACL_ACTION_ALLOW);
    result = radix_tree_lookup_ipv4 (ip_to_uint32 ("10.1.2.3"));
    if (result == HEV_ACL_ACTION_ALLOW) {
        printf ("✓ PASS\n");
        tests_passed++;
    } else {
        printf ("✗ FAIL (expected ALLOW, got %d)\n", result);
        tests_failed++;
    }

    /* Test 3: No Match */
    printf ("Test 3: No Match (8.8.8.8 -> DEFAULT)... ");
    result = radix_tree_lookup_ipv4 (ip_to_uint32 ("8.8.8.8"));
    if (result == HEV_ACL_ACTION_DEFAULT) {
        printf ("✓ PASS\n");
        tests_passed++;
    } else {
        printf ("✗ FAIL (expected DEFAULT, got %d)\n", result);
        tests_failed++;
    }

    /* Test 4: More Specific Prefix Override */
    printf ("Test 4: Specific Override (192.168.0.0/16 BLOCK, "
            "192.168.100.0/24 ALLOW)... ");
    radix_tree_insert_ipv4 (ip_to_uint32 ("192.168.0.0"), 16,
                            HEV_ACL_ACTION_BLOCK);
    radix_tree_insert_ipv4 (ip_to_uint32 ("192.168.100.0"), 24,
                            HEV_ACL_ACTION_ALLOW);

    result = radix_tree_lookup_ipv4 (ip_to_uint32 ("192.168.50.1"));
    HevACLAction result2 = radix_tree_lookup_ipv4 (ip_to_uint32 ("192.168.100.5"));

    if (result == HEV_ACL_ACTION_BLOCK && result2 == HEV_ACL_ACTION_ALLOW) {
        printf ("✓ PASS\n");
        tests_passed++;
    } else {
        printf ("✗ FAIL (expected BLOCK/ALLOW, got %d/%d)\n", result, result2);
        tests_failed++;
    }

    /* Test 5: Performance Benchmark */
    printf ("\nTest 5: Performance Benchmark...\n");

    /* Insert 1000 CIDR rules */
    for (int i = 0; i < 1000; i++) {
        uint32_t base = (i << 8); /* /24 networks */
        HevACLAction action = (i % 2 == 0) ? HEV_ACL_ACTION_BLOCK
                                          : HEV_ACL_ACTION_ALLOW;
        radix_tree_insert_ipv4 (base, 24, action);
    }

    /* Benchmark lookup */
    uint32_t test_ips[10000];
    for (int i = 0; i < 10000; i++) {
        test_ips[i] = rand ();
    }

    double elapsed = benchmark_lookup (test_ips, 10000, 100);
    double ops_per_sec = (10000 * 100) / elapsed;

    printf ("  1000 rules, 10000 lookups x 100 iterations\n");
    printf ("  Time: %.3f seconds\n", elapsed);
    printf ("  Throughput: %.0f ops/sec\n", ops_per_sec);

    if (ops_per_sec > 1000000) { /* Expect > 1M ops/sec */
        printf ("  ✓ PASS (performance excellent)\n");
        tests_passed++;
    } else {
        printf ("  ✗ FAIL (performance below expected)\n");
        tests_failed++;
    }

    /* Cleanup */
    radix_tree_free (acl_ipv4_tree);

    /* Summary */
    printf ("\n=== Test Summary ===\n");
    printf ("Passed: %d\n", tests_passed);
    printf ("Failed: %d\n", tests_failed);
    printf ("Total:  %d\n", tests_passed + tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
