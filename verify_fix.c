/* 验证DNS响应修改修复的正确性 */
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

#define DNS_TYPE_A      1
#define DNS_TYPE_CNAME  5

void print_bytes(const char *label, const uint8_t *data, size_t len) {
    printf("%s:\n  ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0 && i + 1 < len) printf("\n  ");
    }
    printf("\n\n");
}

/* 简化版解析 - 只用于验证 */
int parse_name_simple(const uint8_t *data, size_t len, size_t *offset) {
    size_t pos = *offset;
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
            if (!jumped)
                *offset = pos + 1;
            else
                *offset = jump_pos;
            return 0;
        }
        pos += 1 + l;
    }
    return -1;
}

/* 解析DNS名称到字符串 */
int parse_dns_name(const uint8_t *data, size_t len, size_t *offset, char *name_out, size_t name_max) {
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
            if (!jumped)
                *offset = pos + 1;
            else
                *offset = jump_pos;
            name_out[name_len] = '\0';
            return 0;
        }

        if (pos + 1 + l >= len) return -1;
        if (name_len + l + 1 >= name_max) return -1;

        if (name_len > 0)
            name_out[name_len++] = '.';
        memcpy(name_out + name_len, data + pos + 1, l);
        name_len += l;
        pos += l + 1;
    }
    return -1;
}

/* 验证修复后的数据 */
int verify_modified_response(const uint8_t *modified, size_t len) {
    printf("=== 验证修改后的DNS响应 ===\n\n");

    if (len < 12) {
        printf("❌ 太短\n");
        return -1;
    }

    DNSHeader *hdr = (DNSHeader *)modified;
    printf("Header:\n");
    printf("  ANCOUNT: %d\n", ntohs(hdr->ancount));
    printf("  QDCOUNT: %d\n", ntohs(hdr->qdcount));

    /* 检查压缩指针 */
    size_t pos = 12;
    parse_name_simple(modified, len, &pos);  // 跳过Query
    printf("\nQuery结束位置: %zu\n", pos);

    if (pos + 4 <= len) {
        pos += 4;  // 跳过QTYPE+QCLASS
    }

    printf("\nAnswer Section:\n");
    for (int i = 0; i < ntohs(hdr->ancount); i++) {
        if (pos >= len) {
            printf("  Answer[%d]: 数据不足\n", i);
            return -1;
        }

        size_t answer_start = pos;
        uint8_t first = modified[pos];
        uint16_t comp_target = 0;
        int is_compressed = 0;

        printf("  Answer[%d]: ", i);

        if ((first & 0xC0) == 0xC0) {
            is_compressed = 1;
            comp_target = ((first & 0x3F) << 8) | modified[pos + 1];
            printf("压缩指针 0x%02x%02x -> 位置 %d", first, modified[pos+1], comp_target);
            pos += 2;
        } else {
            printf("完整域名");
        }

        /* 解析域名（处理压缩指针） */
        size_t name_end = pos;
        if (parse_name_simple(modified, len, &name_end) < 0) {
            printf(" [域名解析失败]\n");
            return -1;
        }
        pos = name_end;

        /* 验证压缩指针目标 */
        if (is_compressed) {
            /* 压缩指针可以指向Query Section或Answer Section内部 */
            if (comp_target < 12) {
                printf(" [无效! 指向Header之前]");
            } else if (comp_target < answer_start) {
                printf(" [有效 指向Query]");
            } else if (comp_target < pos) {
                printf(" [有效 指向Answer内部]");
            } else {
                printf(" [无效! 指向未来位置]");
            }
        }

        if (pos + 10 > len) {
            printf(" - 数据不足\n");
            return -1;
        }

        uint16_t rtype = (modified[pos] << 8) | modified[pos+1];
        uint16_t rdlen = (modified[pos+8] << 8) | modified[pos+9];
        pos += 10;

        printf(", Type=%d, RDLEN=%d", rtype, rdlen);

        if (pos + rdlen > len) {
            printf(" - 数据不足\n");
            return -1;
        }

        if (rtype == DNS_TYPE_A && rdlen == 4) {
            printf(", IPv4: %d.%d.%d.%d", modified[pos], modified[pos+1], modified[pos+2], modified[pos+3]);
        } else if (rtype == DNS_TYPE_CNAME) {
            printf(", CNAME");
            /* 解析CNAME目标 */
            size_t cname_pos = pos;
            char cname[256];
            if (parse_dns_name(modified, len, &cname_pos, cname, sizeof(cname)) == 0) {
                printf(" -> %s", cname);
            }
        }

        printf("\n");
        pos += rdlen;
    }

    if (pos == len) {
        printf("\n✓ 数据完整，长度匹配\n");
        return 0;
    } else {
        printf("\n❌ 长度不匹配: pos=%zu, len=%zu\n", pos, len);
        return -1;
    }
}

int main() {
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  DNS响应修改修复验证                                           ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n\n");

    /* 测试1: 无CNAME场景 - 4个A记录 */
    printf("【测试1: 4个A记录，无CNAME】\n");
    printf("原始: Header + Query + A(1) + A(目标) + A(3) + A(4)\n");
    printf("修改: Header + Query + A(目标)\n\n");

    uint8_t test1_orig[] = {
        0x12,0x34,0x81,0x80, 0x00,0x01,0x00,0x04, 0x00,0x00,0x00,0x00,  // Header
        0x03,0x77,0x77,0x77, 0x05,0x63,0x6e,0x6e, 0x03,0x63,0x6f,0x6d, 0x02,0x63,0x6e,0x00,  // Query
        0x00,0x01,0x00,0x01,  // QTYPE+QCLASS
        0xc0,0x0c,0x00,0x01,0x00,0x01,0x00,0x00,0x01,0x2c,0x00,0x04,0x2a,0x53,0x90,0x0d,  // A1
        0xc0,0x0c,0x00,0x01,0x00,0x01,0x00,0x00,0x01,0x2c,0x00,0x04,0xb6,0x83,0x1a,0xe7,  // A2(目标)
        0xc0,0x0c,0x00,0x01,0x00,0x01,0x00,0x00,0x01,0x2c,0x00,0x04,0x01,0x02,0x03,0x04,  // A3
        0xc0,0x0c,0x00,0x01,0x00,0x01,0x00,0x00,0x01,0x2c,0x00,0x04,0x05,0x06,0x07,0x08,  // A4
    };

    /* 模拟修复后的结果: 只保留到目标Answer */
    uint8_t test1_fixed[] = {
        0x12,0x34,0x81,0x80, 0x00,0x01,0x00,0x01, 0x00,0x00,0x00,0x00,  // Header(ANCOUNT=1)
        0x03,0x77,0x77,0x77, 0x05,0x63,0x6e,0x6e, 0x03,0x63,0x6f,0x6d, 0x02,0x63,0x6e,0x00,  // Query
        0x00,0x01,0x00,0x01,  // QTYPE+QCLASS
        0xc0,0x0c,0x00,0x01,0x00,0x01,0x00,0x00,0x01,0x2c,0x00,0x04,0xb6,0x83,0x1a,0xe7,  // A2(目标)
    };

    print_bytes("原始响应", test1_orig, sizeof(test1_orig));
    print_bytes("修复后响应", test1_fixed, sizeof(test1_fixed));
    int r1 = verify_modified_response(test1_fixed, sizeof(test1_fixed));

    /* 测试2: CNAME场景 */
    printf("\n\n【测试2: CNAME + A记录】\n");
    printf("原始: Header + Query + CNAME + A(目标) + A(其他)\n");
    printf("修改: Header + Query + CNAME + A(目标)\n\n");

    uint8_t test2_orig[] = {
        0x12,0x34,0x81,0x80, 0x00,0x01,0x00,0x03, 0x00,0x00,0x00,0x00,  // Header
        0x03,0x77,0x77,0x77, 0x07,0x65,0x78,0x61, 0x6d,0x70,0x6c,0x65, 0x03,0x63,0x6f,0x6d, 0x00,  // Query
        0x00,0x01,0x00,0x01,  // QTYPE+QCLASS
        0xc0,0x0c,0x00,0x05,0x00,0x01,0x00,0x00,0x01,0x2c,0x00,0x0e,  // CNAME header
        0x04,0x63,0x6e,0x61,0x6d,0x65, 0x07,0x65,0x78,0x61,0x6d,0x70,0x6c,0x65, 0x03,0x63,0x6f,0x6d, 0x00,  // CNAME data
        0xc0,0x2a,0x00,0x01,0x00,0x01,0x00,0x00,0x01,0x2c,0x00,0x04,0xb6,0x83,0x1a,0xe7,  // A(目标)
        0xc0,0x2a,0x00,0x01,0x00,0x01,0x00,0x00,0x01,0x2c,0x00,0x04,0x05,0x06,0x07,0x08,  // A(其他)
    };

    /* 修复后: 保留CNAME + 目标A */
    uint8_t test2_fixed[] = {
        0x12,0x34,0x81,0x80, 0x00,0x01,0x00,0x02, 0x00,0x00,0x00,0x00,  // Header(ANCOUNT=2)
        0x03,0x77,0x77,0x77, 0x07,0x65,0x78,0x61, 0x6d,0x70,0x6c,0x65, 0x03,0x63,0x6f,0x6d, 0x00,  // Query
        0x00,0x01,0x00,0x01,  // QTYPE+QCLASS
        0xc0,0x0c,0x00,0x05,0x00,0x01,0x00,0x00,0x01,0x2c,0x00,0x0e,  // CNAME header
        0x04,0x63,0x6e,0x61,0x6d,0x65, 0x07,0x65,0x78,0x61,0x6d,0x70,0x6c,0x65, 0x03,0x63,0x6f,0x6d, 0x00,  // CNAME data
        0xc0,0x2a,0x00,0x01,0x00,0x01,0x00,0x00,0x01,0x2c,0x00,0x04,0xb6,0x83,0x1a,0xe7,  // A(目标)
    };

    print_bytes("原始响应", test2_orig, sizeof(test2_orig));
    print_bytes("修复后响应", test2_fixed, sizeof(test2_fixed));
    int r2 = verify_modified_response(test2_fixed, sizeof(test2_fixed));

    /* 测试3: 错误逻辑（只保留目标A，删除CNAME） */
    printf("\n\n【测试3: 错误逻辑 - 删除CNAME】\n");
    printf("错误: Header + Query + A(目标)  [CNAME被删除，压缩指针失效!]\n\n");

    uint8_t test3_wrong[] = {
        0x12,0x34,0x81,0x80, 0x00,0x01,0x00,0x01, 0x00,0x00,0x00,0x00,  // Header
        0x03,0x77,0x77,0x77, 0x07,0x65,0x78,0x61, 0x6d,0x70,0x6c,0x65, 0x03,0x63,0x6f,0x6d, 0x00,  // Query
        0x00,0x01,0x00,0x01,  // QTYPE+QCLASS
        0xc0,0x2a,0x00,0x01,0x00,0x01,0x00,0x00,0x01,0x2c,0x00,0x04,0xb6,0x83,0x1a,0xe7,  // A(目标) - 压缩指针0xc02a失效!
    };

    print_bytes("错误响应", test3_wrong, sizeof(test3_wrong));
    int r3 = verify_modified_response(test3_wrong, sizeof(test3_wrong));

    /* 结论 */
    printf("\n\n╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  验证结论                                                     ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n\n");

    printf("测试1 (无CNAME): %s\n", r1 == 0 ? "✓ 通过" : "❌ 失败");
    printf("测试2 (有CNAME): %s\n", r2 == 0 ? "✓ 通过" : "❌ 失败");
    printf("测试3 (错误逻辑): %s\n", r3 != 0 ? "✓ 正确检测到错误" : "❌ 未检测到错误");

    printf("\n");
    printf("修复方案: 保留CNAME链 + 目标Answer\n");
    printf("结果: %s\n", (r1 == 0 && r2 == 0 && r3 != 0) ? "✓ 验证通过" : "❌ 验证失败");

    return (r1 == 0 && r2 == 0 && r3 != 0) ? 0 : 1;
}
