/*
 ============================================================================
 Name        : hev-tls-parser.h
 Author      : hev <r@hev.cc>
 Description : TLS ClientHello Parser
 ============================================================================
 */

#ifndef __HEV_TLS_PARSER_H__
#define __HEV_TLS_PARSER_H__

#include <stdint.h>
#include <stddef.h>

/* TLS Content Type */
#define TLS_CONTENT_TYPE_HANDSHAKE  0x16

/* TLS Handshake Type */
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO  0x01

/* TLS Extension Types */
#define TLS_EXT_SERVER_NAME     0x0000
#define TLS_EXT_ALPN            0x0010

/* 最大 SNI 长度 */
#define MAX_SNI_LENGTH 255

typedef struct _HevTLSClientHello {
    uint8_t  detected;          /* 是否检测到 TLS */
    uint16_t tls_version;       /* TLS 版本 */
    char     sni[MAX_SNI_LENGTH + 1];  /* Server Name Indication */
    char     alpn[64];          /* Application-Layer Protocol Negotiation */
} HevTLSClientHello;

/**
 * hev_tls_parse_client_hello:
 * @data: 数据包内容
 * @len: 数据包长度
 * @hello: 输出结构体
 *
 * 解析 TLS ClientHello 消息
 *
 * Returns: 0 成功, -1 失败或不是 TLS
 */
int hev_tls_parse_client_hello (const unsigned char *data, size_t len,
                                 HevTLSClientHello *hello);

#endif /* __HEV_TLS_PARSER_H__ */