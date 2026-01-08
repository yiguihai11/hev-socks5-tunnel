/* 验证DNS响应修改后的数据完整性 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((packed)) DNSHeader;

void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s (%zu bytes):\n  ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0 && i + 1 < len) printf("\n  ");
    }
    printf("\n");
}

// 解析DNS名称
int parse_dns_name(const uint8_t *data, size_t len, size_t *offset, char *name, size_t name_max) {
    size_t pos = *offset;
    size_t name_len = 0;
    int jumped = 0;
    size_t jump_pos = 0;

    while (pos < len) {
        uint8_t l = data[pos];

        if ((l & 0xC0) == 0xC0) {
            if (pos + 1 >= len) return -1;
            if (!jumped) {
                jump_pos = pos + 2;
                jumped = 1;
            }
            pos = ((l & 0x3F) << 8) | data[pos + 1];
            continue;
        }

        if (l == 0) {
            if (!jumped) *offset = pos + 1;
            else *offset = jump_pos;
            name[name_len] = '\0';
            return 0;
        }

        if (pos + 1 + l >= len) return -1;
        if (name_len + l + 1 >= name_max) return -1;

        if (name_len > 0) name[name_len++] = '.';
        memcpy(name + name_len, data + pos + 1, l);
        name_len += l;
        pos += l + 1;
    }
    return -1;
}

// 验证DNS响应格式
int validate_dns_response(const uint8_t *data, size_t len, const char *label) {
    printf("\n=== %s ===\n", label);

    if (len < 12) {
        printf("❌ 太短: %zu bytes\n", len);
        return -1;
    }

    DNSHeader *hdr = (DNSHeader *)data;
    printf("Header:\n");
    printf("  ID: 0x%04x\n", ntohs(hdr->id));
    printf("  Flags: 0x%04x\n", ntohs(hdr->flags));
    printf("  QDCOUNT: %d\n", ntohs(hdr->qdcount));
    printf("  ANCOUNT: %d\n", ntohs(hdr->ancount));
    printf("  NSCOUNT: %d\n", ntohs(hdr->nscount));
    printf("  ARCOUNT: %d\n", ntohs(hdr->arcount));

    // 检查标志位
    uint16_t flags = ntohs(hdr->flags);
    int qr = (flags >> 15) & 1;
    int rcode = flags & 0xF;

    printf("  Flags解析: QR=%d, RCODE=%d\n", qr, rcode);

    if (qr != 1) {
        printf("❌ 不是响应 (QR=0)\n");
        return -1;
    }
    if (rcode != 0) {
        printf("❌ 错误响应码: %d\n", rcode);
        return -1;
    }

    // 解析查询
    size_t pos = sizeof(DNSHeader);
    printf("\n查询部分:\n");
    for (int i = 0; i < ntohs(hdr->qdcount); i++) {
        char domain[256];
        size_t start = pos;
        if (parse_dns_name(data, len, &pos, domain, sizeof(domain)) < 0) {
            printf("❌ 查询[%d]解析失败\n", i);
            return -1;
        }
        printf("  [%d] %s (位置: %zu-%zu)\n", i, domain, start, pos);

        if (pos + 4 > len) {
            printf("❌ 查询[%d]缺少类型/类别\n", i);
            return -1;
        }
        uint16_t qtype = (data[pos] << 8) | data[pos + 1];
        uint16_t qclass = (data[pos + 2] << 8) | data[pos + 3];
        printf("      Type: %d, Class: %d\n", qtype, qclass);
        pos += 4;
    }

    // 解析回答
    printf("\n回答部分:\n");
    for (int i = 0; i < ntohs(hdr->ancount); i++) {
        char domain[256];
        size_t start = pos;
        if (parse_dns_name(data, len, &pos, domain, sizeof(domain)) < 0) {
            printf("❌ 回答[%d]名称解析失败\n", i);
            return -1;
        }
        printf("  [%d] %s (位置: %zu)\n", i, domain, start);

        if (pos + 10 > len) {
            printf("❌ 回答[%d]缺少头部\n", i);
            return -1;
        }

        uint16_t rtype = (data[pos] << 8) | data[pos + 1];
        uint16_t rclass = (data[pos + 2] << 8) | data[pos + 3];
        uint32_t ttl = (data[pos + 4] << 24) | (data[pos + 5] << 16) | (data[pos + 6] << 8) | data[pos + 7];
        uint16_t rdlen = (data[pos + 8] << 8) | data[pos + 9];
        pos += 10;

        printf("      Type: %d, Class: %d, TTL: %u, RDLEN: %d\n", rtype, rclass, ttl, rdlen);

        if (pos + rdlen > len) {
            printf("❌ 回答[%d]数据长度不足\n", i);
            return -1;
        }

        if (rtype == 1 && rdlen == 4) {
            printf("      IPv4: %d.%d.%d.%d\n", data[pos], data[pos+1], data[pos+2], data[pos+3]);
        } else if (rtype == 28 && rdlen == 16) {
            printf("      IPv6: ");
            for (int j = 0; j < 16; j++) {
                printf("%02x", data[pos + j]);
                if (j < 15) printf(":");
            }
            printf("\n");
        } else if (rtype == 5) {
            char cname[256];
            size_t cpos = pos;
            if (parse_dns_name(data, len, &cpos, cname, sizeof(cname)) == 0) {
                printf("      CNAME: %s\n", cname);
            }
        }

        pos += rdlen;
    }

    printf("\n长度验证: pos=%zu, len=%zu, %s\n", pos, len, pos == len ? "✓ 正常" : "❌ 有多余数据");

    return pos == len ? 0 : -1;
}

int main() {
    printf("DNS响应数据完整性验证\n");
    printf("====================\n");

    // 原始响应数据（来自trace_modify.c）
    uint8_t original[] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x77, 0x77, 0x77, 0x05, 0x63, 0x6e, 0x6e, 0x03, 0x63, 0x6f, 0x6d, 0x02, 0x63, 0x6e, 0x00,
        0x00, 0x01, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0x2a, 0x53, 0x90, 0x0d,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0xb6, 0x83, 0x1a, 0xe7,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0x05, 0x06, 0x07, 0x08,
    };

    // 修改后的响应（保留Answer 2: 182.131.26.231）
    uint8_t modified[] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x77, 0x77, 0x77, 0x05, 0x63, 0x6e, 0x6e, 0x03, 0x63, 0x6f, 0x6d, 0x02, 0x63, 0x6e, 0x00,
        0x00, 0x01, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0xb6, 0x83, 0x1a, 0xe7,
    };

    print_hex("原始响应", original, sizeof(original));
    validate_dns_response(original, sizeof(original), "原始响应验证");

    print_hex("\n修改后响应", modified, sizeof(modified));
    int result = validate_dns_response(modified, sizeof(modified), "修改后响应验证");

    printf("\n\n=== 结论 ===\n");
    if (result == 0) {
        printf("✓ 修改后的DNS响应数据完全合法！\n");
        printf("  - 符合RFC 1035标准\n");
        printf("  - 压缩指针正确\n");
        printf("  - 数据完整性良好\n");
        printf("  - 可以被DNS客户端正常解析\n");
    } else {
        printf("❌ 修改后的响应存在问题\n");
    }

    return result;
}
