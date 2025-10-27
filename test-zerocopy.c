/*
 * Test program for zero-copy protocol parsing optimization
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "src/hev-session-manager.h"
#include "lwip/pbuf.h"

static void
test_http_host_parsing(void)
{
    printf("Testing HTTP Host parsing...\n");

    /* Enable zero-copy optimization */
    int result = hev_session_manager_enable_protocol_zerocopy();
    assert(result == 0);
    assert(hev_session_manager_is_protocol_zerocopy_enabled() == 1);

    printf("✓ Zero-copy optimization enabled\n");

    /* Test with sample HTTP request */
    const char *http_request =
        "GET /path HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "User-Agent: test/1.0\r\n"
        "\r\n";

    /* Create a simulated pbuf chain */
    struct pbuf *p1 = pbuf_alloc(PBUF_TRANSPORT, strlen(http_request), PBUF_RAM);
    assert(p1 != NULL);
    memcpy(p1->payload, http_request, strlen(http_request));

    char hostname[256];
    result = hev_extract_string_from_offset(p1, 0, "\r\n", hostname, sizeof(hostname));

    if (result == 0) {
        printf("✓ Extracted hostname: %s\n", hostname);
    } else {
        printf("✗ Failed to extract hostname\n");
    }

    pbuf_free(p1);

    /* Disable zero-copy optimization */
    hev_session_manager_disable_protocol_zerocopy();
    assert(hev_session_manager_is_protocol_zerocopy_enabled() == 0);

    printf("✓ Zero-copy optimization disabled\n");
}

static void
test_pbuf_chain_search(void)
{
    printf("\nTesting pbuf chain search...\n");

    const char *test_data = "GET http://test.example.com/path HTTP/1.1\r\nHost: test.example.com\r\n\r\n";

    /* Create pbuf chain */
    struct pbuf *p1 = pbuf_alloc(PBUF_TRANSPORT, 20, PBUF_RAM);
    struct pbuf *p2 = pbuf_alloc(PBUF_TRANSPORT, 30, PBUF_RAM);
    struct pbuf *p3 = pbuf_alloc(PBUF_TRANSPORT, strlen(test_data) - 50, PBUF_RAM);

    assert(p1 && p2 && p3);

    memcpy(p1->payload, test_data, 20);
    memcpy(p2->payload, test_data + 20, 30);
    memcpy(p3->payload, test_data + 50, strlen(test_data) - 50);

    p1->next = p2;
    p2->next = p3;

    printf("✓ Created pbuf chain with %d total bytes\n", p1->tot_len);

    /* Enable zero-copy and test search */
    hev_session_manager_enable_protocol_zerocopy();

    char hostname[256];
    result = hev_extract_string_from_offset(p1, 11, "/", hostname, sizeof(hostname));

    if (result == 0) {
        printf("✓ Found hostname in chain: %s\n", hostname);
    } else {
        printf("✗ Failed to find hostname in chain\n");
    }

    p1->next = NULL;
    p2->next = NULL;
    pbuf_free(p1);
    pbuf_free(p2);
    pbuf_free(p3);

    hev_session_manager_disable_protocol_zerocopy();
}

int
main(void)
{
    printf("=== hev-socks5-tunnel Zero-Copy Test ===\n");

    test_http_host_parsing();
    test_pbuf_chain_search();

    printf("\n=== All tests completed ===\n");
    return 0;
}