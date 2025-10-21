/*
 ============================================================================
 Name        : hev-tls-parser.c
 Author      : hev <r@hev.cc>
 Description : TLS ClientHello Parser
 ============================================================================
 */

#include <string.h>
#include <arpa/inet.h>

#include "hev-logger.h"
#include "hev-tls-parser.h"

/* 从缓冲区读取 uint16_t (Big Endian) */
static uint16_t
read_uint16 (const unsigned char *buf)
{
    return (buf[0] << 8) | buf[1];
}

/* 从缓冲区读取 uint24_t (Big Endian) */
static uint32_t
read_uint24 (const unsigned char *buf)
{
    return (buf[0] << 16) | (buf[1] << 8) | buf[2];
}

/* 解析 SNI 扩展 */
static int
parse_sni_extension (const unsigned char *data, size_t len, char *sni_out, size_t sni_max)
{
    size_t pos = 0;

    if (len < 2)
        return -1;

    /* Server Name List Length */
    uint16_t list_len = read_uint16 (data + pos);
    pos += 2;

    if (list_len + 2 > len)
        return -1;

    while (pos < len) {
        if (pos + 3 > len)
            break;

        /* Name Type (0 = host_name) */
        uint8_t name_type = data[pos++];

        /* Name Length */
        uint16_t name_len = read_uint16 (data + pos);
        pos += 2;

        if (pos + name_len > len)
            break;

        if (name_type == 0) {  /* host_name */
            size_t copy_len = (name_len < sni_max) ? name_len : sni_max;
            memcpy (sni_out, data + pos, copy_len);
            sni_out[copy_len] = '\0';
            return 0;
        }

        pos += name_len;
    }

    return -1;
}

/* 解析 ALPN 扩展 */
static int
parse_alpn_extension (const unsigned char *data, size_t len, char *alpn_out, size_t alpn_max)
{
    size_t pos = 0;

    if (len < 2)
        return -1;

    /* ALPN Extension Length */
    uint16_t alpn_len = read_uint16 (data + pos);
    pos += 2;

    if (alpn_len + 2 > len)
        return -1;

    /* 只读取第一个协议 */
    if (pos < len) {
        uint8_t proto_len = data[pos++];
        if (pos + proto_len <= len) {
            size_t copy_len = (proto_len < alpn_max - 1) ? proto_len : alpn_max - 1;
            memcpy (alpn_out, data + pos, copy_len);
            alpn_out[copy_len] = '\0';
            return 0;
        }
    }

    return -1;
}

int
hev_tls_parse_client_hello (const unsigned char *data, size_t len,
                             HevTLSClientHello *hello)
{
    size_t pos = 0;

    memset (hello, 0, sizeof (HevTLSClientHello));

    /* 至少需要 TLS Record Header (5 bytes) */
    if (len < 5)
        return -1;

    /* TLS Record Header */
    uint8_t content_type = data[pos++];
    if (content_type != TLS_CONTENT_TYPE_HANDSHAKE) {
        LOG_D ("tls parser: Not a TLS handshake (content_type=0x%02x)", content_type);
        return -1;
    }

    /* TLS Version */
    uint16_t tls_version = read_uint16 (data + pos);
    pos += 2;
    hello->tls_version = tls_version;

    /* Record Length */
    uint16_t record_len = read_uint16 (data + pos);
    pos += 2;

    if (pos + record_len > len) {
        LOG_D ("tls parser: Incomplete TLS record (need %u, have %zu)",
               record_len, len - pos);
        return -1;
    }

    /* Handshake Type */
    if (pos >= len)
        return -1;
    uint8_t handshake_type = data[pos++];
    if (handshake_type != TLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
        LOG_D ("tls parser: Not ClientHello (handshake_type=0x%02x)", handshake_type);
        return -1;
    }

    /* Handshake Length */
    if (pos + 3 > len)
        return -1;
    uint32_t handshake_len = read_uint24 (data + pos);
    pos += 3;

    LOG_D ("tls parser: Found ClientHello (version=0x%04x, length=%u)",
           tls_version, handshake_len);

    /* Client Version */
    if (pos + 2 > len)
        return -1;
    pos += 2;

    /* Random (32 bytes) */
    if (pos + 32 > len)
        return -1;
    pos += 32;

    /* Session ID */
    if (pos >= len)
        return -1;
    uint8_t session_id_len = data[pos++];
    if (pos + session_id_len > len)
        return -1;
    pos += session_id_len;

    /* Cipher Suites */
    if (pos + 2 > len)
        return -1;
    uint16_t cipher_suites_len = read_uint16 (data + pos);
    pos += 2;
    if (pos + cipher_suites_len > len)
        return -1;
    pos += cipher_suites_len;

    /* Compression Methods */
    if (pos >= len)
        return -1;
    uint8_t compression_len = data[pos++];
    if (pos + compression_len > len)
        return -1;
    pos += compression_len;

    /* Extensions */
    if (pos + 2 > len) {
        LOG_D ("tls parser: No extensions found");
        hello->detected = 1;
        return 0;  /* 没有扩展也是合法的 ClientHello */
    }

    uint16_t extensions_len = read_uint16 (data + pos);
    pos += 2;

    if (pos + extensions_len > len)
        return -1;

    LOG_D ("tls parser: Parsing extensions (length=%u)", extensions_len);

    size_t extensions_end = pos + extensions_len;
    while (pos + 4 <= extensions_end) {
        uint16_t ext_type = read_uint16 (data + pos);
        pos += 2;

        uint16_t ext_len = read_uint16 (data + pos);
        pos += 2;

        if (pos + ext_len > extensions_end)
            break;

        switch (ext_type) {
        case TLS_EXT_SERVER_NAME:
            LOG_D ("tls parser: Found SNI extension (length=%u)", ext_len);
            parse_sni_extension (data + pos, ext_len, hello->sni, MAX_SNI_LENGTH);
            break;

        case TLS_EXT_ALPN:
            LOG_D ("tls parser: Found ALPN extension (length=%u)", ext_len);
            parse_alpn_extension (data + pos, ext_len, hello->alpn, sizeof (hello->alpn));
            break;

        default:
            /* 忽略其他扩展 */
            break;
        }

        pos += ext_len;
    }

    hello->detected = 1;

    if (hello->sni[0]) {
        LOG_I ("tls parser: Detected SNI: %s", hello->sni);
    }
    if (hello->alpn[0]) {
        LOG_I ("tls parser: Detected ALPN: %s", hello->alpn);
    }

    return 0;
}