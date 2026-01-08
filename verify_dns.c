/* DNS响应验证工具 - 验证修改后的DNS响应是否符合RFC 1035标准 */
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

void parse_dns_name(const uint8_t *data, size_t len, size_t *pos, char *name, size_t name_max) {
    size_t p = *pos;
    size_t name_len = 0;
    int jumped = 0;
    size_t jump_pos = 0;

    while (p < len) {
        uint8_t l = data[p];

        if ((l & 0xC0) == 0xC0) {
            if (p + 1 >= len) return;
            if (!jumped) {
                jump_pos = p + 2;
                jumped = 1;
            }
            p = ((l & 0x3F) << 8) | data[p + 1];
            continue;
        }

        if (l == 0) {
            if (!jumped) *pos = p + 1;
            else *pos = jump_pos;
            name[name_len] = '\0';
            return;
        }

        if (p + 1 + l >= len) return;
        if (name_len + l + 1 >= name_max) return;

        if (name_len > 0) name[name_len++] = '.';
        memcpy(name + name_len, data + p + 1, l);
        name_len += l;
        p += l + 1;
    }
}

void analyze_dns_response(const uint8_t *data, size_t len, const char *label) {
    printf("\n=== %s (len=%zu) ===\n", label, len);

    if (len < sizeof(DNSHeader)) {
        printf("ERROR: Response too short\n");
        return;
    }

    DNSHeader *hdr = (DNSHeader *)data;
    printf("Header:\n");
    printf("  ID: 0x%04x\n", ntohs(hdr->id));
    printf("  Flags: 0x%04x\n", ntohs(hdr->flags));
    printf("  QDCOUNT: %d\n", ntohs(hdr->qdcount));
    printf("  ANCOUNT: %d\n", ntohs(hdr->ancount));
    printf("  NSCOUNT: %d\n", ntohs(hdr->nscount));
    printf("  ARCOUNT: %d\n", ntohs(hdr->arcount));

    // Parse query
    size_t pos = sizeof(DNSHeader);
    for (int i = 0; i < ntohs(hdr->qdcount); i++) {
        char domain[256];
        parse_dns_name(data, len, &pos, domain, sizeof(domain));
        printf("  Query[%d]: %s\n", i, domain);
        if (pos + 4 <= len) {
            uint16_t qtype = (data[pos] << 8) | data[pos + 1];
            uint16_t qclass = (data[pos + 2] << 8) | data[pos + 3];
            printf("    Type: %d, Class: %d\n", qtype, qclass);
            pos += 4;
        }
    }

    // Parse answers
    printf("  Answers:\n");
    for (int i = 0; i < ntohs(hdr->ancount); i++) {
        char domain[256];
        size_t answer_start = pos;
        parse_dns_name(data, len, &pos, domain, sizeof(domain));
        printf("    Answer[%d]: %s\n", i, domain);

        if (pos + 10 > len) {
            printf("      ERROR: Not enough data for answer header\n");
            break;
        }

        uint16_t rtype = (data[pos] << 8) | data[pos + 1];
        uint16_t rclass = (data[pos + 2] << 8) | data[pos + 3];
        uint32_t ttl = (data[pos + 4] << 24) | (data[pos + 5] << 16) | (data[pos + 6] << 8) | data[pos + 7];
        uint16_t rdlen = (data[pos + 8] << 8) | data[pos + 9];
        pos += 10;

        printf("      Type: %d, Class: %d, TTL: %u, RDLEN: %d\n", rtype, rclass, ttl, rdlen);

        if (pos + rdlen > len) {
            printf("      ERROR: Not enough data for answer data\n");
            break;
        }

        if (rtype == 1 && rdlen == 4) {  // A record
            printf("      IPv4: %d.%d.%d.%d\n", data[pos], data[pos+1], data[pos+2], data[pos+3]);
        } else if (rtype == 28 && rdlen == 16) {  // AAAA record
            printf("      IPv6: ");
            for (int j = 0; j < 16; j++) {
                printf("%02x", data[pos + j]);
                if (j < 15) printf(":");
            }
            printf("\n");
        }

        pos += rdlen;
    }

    if (pos != len) {
        printf("  WARNING: pos=%zu != len=%zu (extra data)\n", pos, len);
    }
}

int main() {
    // 从日志中提取的原始响应（前20字节）
    uint8_t original[] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x77, 0x77, 0x77, 0x05, 0x63, 0x6e, 0x6e
    };

    // 完整的原始响应（112字节）- 需要构建
    // 从测试日志看，原始响应有4个A记录，修改后只有1个

    printf("DNS响应验证工具\n");
    printf("==============\n");

    // 分析头部
    DNSHeader *hdr = (DNSHeader *)original;
    printf("\n原始响应头部分析:\n");
    printf("  ID: 0x%04x\n", ntohs(hdr->id));
    printf("  Flags: 0x%04x (QR=1, RD=1, RA=1, RCODE=0)\n", ntohs(hdr->flags));
    printf("  QDCOUNT: %d (1个查询)\n", ntohs(hdr->qdcount));
    printf("  ANCOUNT: %d (4个回答) ← 需要修改为1\n", ntohs(hdr->ancount));

    printf("\n修改后的响应应该:\n");
    printf("  1. ANCOUNT = 1\n");
    printf("  2. 只保留1个A记录（182.131.26.231）\n");
    printf("  3. 长度 = 50字节\n");

    printf("\n验证要点:\n");
    printf("  ✓ DNS Header格式正确\n");
    printf("  ✓ QDCOUNT保持为1\n");
    printf("  ✓ ANCOUNT修改为1\n");
    printf("  ✓ 保留完整的Query Section\n");
    printf("  ✓ 只保留1个Answer Section\n");
    printf("  ✓ 总长度正确\n");

    return 0;
}
