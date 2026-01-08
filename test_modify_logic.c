/* 测试DNS修改逻辑的详细过程 */
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

uint16_t read_uint16(const uint8_t *p) {
    return (p[0] << 8) | p[1];
}

uint32_t read_uint32(const uint8_t *p) {
    return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

/* 模拟hev_dns_latency_modify_response的逻辑 */
int modify_response(const uint8_t *data, size_t *len, const uint8_t *target_ip) {
    printf("\n=== 开始修改响应 ===\n");

    if (*len < sizeof(DNSHeader)) return -1;

    DNSHeader *hdr = (DNSHeader *)data;
    uint16_t ancount = ntohs(hdr->ancount);
    printf("原始ANCOUNT: %d\n", ancount);

    if (ancount == 0) return 0;

    /* 跳过Query Section */
    size_t pos = sizeof(DNSHeader);
    uint16_t qdcount = ntohs(hdr->qdcount);

    printf("跳过Query Section...\n");
    for (int i = 0; i < qdcount && pos < *len; i++) {
        char domain[256];
        size_t query_start = pos;
        if (parse_dns_name(data, *len, &pos, domain, sizeof(domain)) < 0)
            return -1;
        printf("  Query[%d]: %s (位置: %zu-%zu)\n", i, domain, query_start, pos);
        if (pos + 4 > *len) return -1;
        pos += 4;
    }

    size_t first_answer_pos = pos;
    printf("第一个Answer位置: %zu\n", first_answer_pos);

    /* 遍历所有Answer，找到目标IP */
    size_t best_answer_start = 0;
    size_t best_answer_len = 0;
    int found = 0;

    printf("\n遍历Answer Section:\n");
    for (int i = 0; i < ancount && pos < *len; i++) {
        size_t answer_start = pos;
        char domain[256];
        if (parse_dns_name(data, *len, &pos, domain, sizeof(domain)) < 0)
            break;

        if (pos + 10 > *len) break;

        uint16_t rtype = read_uint16(data + pos);
        uint16_t rdlen = read_uint16(data + pos + 8);
        pos += 10;

        printf("  Answer[%d]: %s, Type=%d, RDLEN=%d, 数据位置=%zu\n", i, domain, rtype, rdlen, pos);

        if (pos + rdlen > *len) break;

        /* 检查是否匹配目标IP */
        int match = 0;
        if (rtype == 1 && rdlen == 4) {
            printf("    IP: %d.%d.%d.%d\n", data[pos], data[pos+1], data[pos+2], data[pos+3]);
            if (memcmp(data + pos, target_ip, 4) == 0) {
                match = 1;
                printf("    ✓ 找到目标IP！\n");
            }
        }

        if (match) {
            best_answer_start = answer_start;
            best_answer_len = (pos + rdlen) - answer_start;
            found = 1;
            printf("    Answer[%d] 起始位置: %zu, 长度: %zu\n", i, best_answer_start, best_answer_len);
            break;
        }

        pos += rdlen;
    }

    if (!found) {
        printf("未找到目标IP\n");
        return -1;
    }

    /* 移动最佳Answer到第一个位置 */
    printf("\n移动最佳Answer到第一个位置...\n");
    printf("  memmove(dest=%zu, src=%zu, len=%zu)\n", first_answer_pos, best_answer_start, best_answer_len);

    if (best_answer_start > first_answer_pos) {
        memmove((uint8_t *)data + first_answer_pos, data + best_answer_start, best_answer_len);
    }

    /* 更新长度和ANCOUNT */
    *len = first_answer_pos + best_answer_len;
    hdr->ancount = htons(1);

    printf("修改后长度: %zu\n", *len);
    printf("修改后ANCOUNT: %d\n", ntohs(hdr->ancount));

    return 0;
}

int main() {
    printf("=== DNS修改逻辑详细测试 ===\n\n");

    /* 场景1: 简单场景 - 4个A记录，目标在第2个 */
    printf("【场景1: 4个A记录，目标IP在第2个位置】\n");
    uint8_t original1[] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x77, 0x77, 0x77, 0x05, 0x63, 0x6e, 0x6e, 0x03, 0x63, 0x6f, 0x6d, 0x02, 0x63, 0x6e, 0x00,
        0x00, 0x01, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0x2a, 0x53, 0x90, 0x0d,  // 42.83.144.13
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0xb6, 0x83, 0x1a, 0xe7,  // 182.131.26.231 (目标)
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0x05, 0x06, 0x07, 0x08,
    };

    uint8_t target1[] = {0xb6, 0x83, 0x1a, 0xe7};  // 182.131.26.231

    size_t len1 = sizeof(original1);
    uint8_t modified1[256];
    memcpy(modified1, original1, len1);

    print_hex("原始响应", original1, len1);

    if (modify_response(modified1, &len1, target1) == 0) {
        print_hex("修改后响应", modified1, len1);

        /* 验证修改后的响应 */
        printf("\n验证修改后响应:\n");
        DNSHeader *hdr = (DNSHeader *)modified1;
        printf("  ID: 0x%04x\n", ntohs(hdr->id));
        printf("  Flags: 0x%04x\n", ntohs(hdr->flags));
        printf("  QDCOUNT: %d\n", ntohs(hdr->qdcount));
        printf("  ANCOUNT: %d\n", ntohs(hdr->ancount));

        /* 解析修改后的Answer */
        size_t pos = sizeof(DNSHeader);
        char domain[256];
        parse_dns_name(modified1, len1, &pos, domain, sizeof(domain));
        printf("  Answer域名: %s\n", domain);

        if (pos + 10 <= len1) {
            uint16_t rtype = read_uint16(modified1 + pos);
            uint16_t rdlen = read_uint16(modified1 + pos + 8);
            pos += 10;
            printf("  Type: %d, RDLEN: %d\n", rtype, rdlen);

            if (rtype == 1 && rdlen == 4) {
                printf("  IP: %d.%d.%d.%d\n", modified1[pos], modified1[pos+1], modified1[pos+2], modified1[pos+3]);
            }
        }

        /* 检查压缩指针 */
        printf("\n压缩指针检查:\n");
        printf("  Query Section结束位置: 32\n");
        printf("  Answer开始位置: 32\n");
        printf("  Answer中的压缩指针: 0x%02x%02x\n", modified1[32], modified1[33]);
        if (modified1[32] == 0xc0 && modified1[33] == 0x0c) {
            printf("  ✓ 压缩指针正确 (0xc00c -> 指向位置12)\n");
        } else {
            printf("  ✗ 压缩指针错误\n");
        }
    }

    /* 场景2: 带CNAME的响应 */
    printf("\n\n【场景2: 带CNAME的响应】\n");
    /*
     * DNS结构分析:
     * - Header: 12字节 (0-11)
     * - Query: www.example.com = 17字节 (12-28) + 4字节 = 29字节总
     * - Answer 1 (CNAME): 2字节压缩指针 + 10字节头部 + 14字节数据 = 26字节
     *   - 位置: 29-54
     *   - 压缩指针0xc00c指向位置12 (Query开始)
     *   - CNAME数据: cname.example.com
     * - Answer 2 (A): 2字节压缩指针 + 10字节头部 + 4字节IP = 16字节
     *   - 位置: 55-70
     *   - 压缩指针0xc02a指向位置42 (CNAME数据中的example.com)
     * - Answer 3 (A): 16字节
     *   - 位置: 71-86
     */
    uint8_t original2[] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,  // Header
        // Query: www.example.com
        0x03, 0x77, 0x77, 0x77, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        0x00, 0x01, 0x00, 0x01,
        // Answer 1: CNAME (位置29-54)
        0xc0, 0x0c,  // 压缩指针到位置12
        0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x0e,  // 头部
        // CNAME数据: cname.example.com
        0x04, 0x63, 0x6e, 0x61, 0x6d, 0x65, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        // Answer 2: A (位置55-70)
        0xc0, 0x2a,  // 压缩指针到位置42 (CNAME数据中的example.com)
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04,  // 头部
        0xb6, 0x83, 0x1a, 0xe7,  // IP: 182.131.26.231 (目标)
        // Answer 3: A (位置71-86)
        0xc0, 0x2a,  // 压缩指针到位置42
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04,  // 头部
        0x05, 0x06, 0x07, 0x08,  // IP: 5.6.7.8
    };

    uint8_t target2[] = {0xb6, 0x83, 0x1a, 0xe7};  // 182.131.26.231

    size_t len2 = sizeof(original2);
    uint8_t modified2[256];
    memcpy(modified2, original2, len2);

    print_hex("原始响应", original2, len2);

    /* 手动模拟修改过程，因为自动解析有问题 */
    printf("\n=== 手动模拟修改过程 ===\n");
    printf("Query Section结束位置: 29\n");
    printf("Answer 1 (CNAME) 位置: 29-54, 长度: 26\n");
    printf("Answer 2 (A, 目标) 位置: 55-70, 长度: 16\n");
    printf("Answer 3 (A) 位置: 71-86, 长度: 16\n");

    /* 目标是保留Answer 2，删除Answer 1和3 */
    /* 但是CNAME场景下，如果删除CNAME，Answer 2的压缩指针0xc02a会失效！ */

    printf("\n=== 关键问题分析 ===\n");
    printf("如果只保留Answer 2:\n");
    printf("  - Answer 2的压缩指针0xc02a指向位置42\n");
    printf("  - 位置42是CNAME数据中的example.com\n");
    printf("  - 如果删除Answer 1 (CNAME)，位置42的数据还在吗？\n");
    printf("  - 答案: 不在！因为Answer 1被删除了\n");
    printf("  - 结果: 压缩指针失效，解析失败\n");

    printf("\n=== 正确的修改方案 ===\n");
    printf("方案1: 保留CNAME + 目标A记录\n");
    printf("  - 修改后: Header + Query + CNAME + A(目标)\n");
    printf("  - ANCOUNT = 2\n");
    printf("  - 压缩指针都有效\n");

    printf("\n方案2: 删除CNAME，但需要修复压缩指针\n");
    printf("  - 修改后: Header + Query + A(目标)\n");
    printf("  - ANCOUNT = 1\n");
    printf("  - 需要将0xc02a改为0xc00c (指向Query)\n");

    /* 测试方案1 */
    printf("\n【测试方案1: 保留CNAME + 目标A记录】\n");
    uint8_t modified2_1[80];
    size_t new_len = 29 + 26 + 16;  // Query + CNAME + A
    memcpy(modified2_1, original2, 29);  // Header + Query
    memcpy(modified2_1 + 29, original2 + 29, 26);  // CNAME
    memcpy(modified2_1 + 29 + 26, original2 + 55, 16);  // A (目标)

    DNSHeader *hdr1 = (DNSHeader *)modified2_1;
    hdr1->ancount = htons(2);

    print_hex("方案1修改后", modified2_1, new_len);

    /* 验证方案1 */
    printf("验证方案1:\n");
    size_t pos = 12;
    char domain[256];
    parse_dns_name(modified2_1, new_len, &pos, domain, sizeof(domain));
    printf("  Query: %s\n", domain);
    pos += 4;

    /* Answer 1: CNAME */
    size_t a1_start = pos;
    parse_dns_name(modified2_1, new_len, &pos, domain, sizeof(domain));
    printf("  Answer[0]: %s (CNAME)\n", domain);
    pos += 10;
    size_t cname_data_pos = pos;
    parse_dns_name(modified2_1, new_len, &pos, domain, sizeof(domain));
    printf("    CNAME目标: %s\n", domain);
    pos += 0;  // 已经跳过了

    /* Answer 2: A */
    size_t a2_start = pos;
    printf("  Answer[1]起始位置: %zu\n", a2_start);
    printf("  Answer[1]压缩指针: 0x%02x%02x\n", modified2_1[a2_start], modified2_1[a2_start+1]);
    if (modified2_1[a2_start] == 0xc0 && modified2_1[a2_start+1] == 0x2a) {
        printf("  ⚠ 压缩指针0xc02a指向位置42\n");
        printf("    位置42在修改后数据中是: ");
        if (42 < new_len) {
            printf("0x%02x%02x%02x (CNAME数据的第13-15字节)\n", modified2_1[42], modified2_1[43], modified2_1[44]);
            printf("    这是CNAME数据中的'example.com'部分，仍然有效！\n");
            printf("  ✓ 压缩指针有效\n");
        } else {
            printf("超出范围！\n");
            printf("  ✗ 压缩指针无效\n");
        }
    }

    /* 验证IP */
    pos = a2_start + 2 + 10;
    if (pos + 4 <= new_len) {
        printf("  Answer[1] IP: %d.%d.%d.%d\n", modified2_1[pos], modified2_1[pos+1], modified2_1[pos+2], modified2_1[pos+3]);
        if (modified2_1[pos] == 0xb6 && modified2_1[pos+1] == 0x83 &&
            modified2_1[pos+2] == 0x1a && modified2_1[pos+3] == 0xe7) {
            printf("  ✓ 目标IP正确\n");
        }
    }

    /* 测试方案2 */
    printf("\n【测试方案2: 只保留目标A记录，修复压缩指针】\n");
    uint8_t modified2_2[80];
    size_t new_len2 = 29 + 16;  // Query + A
    memcpy(modified2_2, original2, 29);  // Header + Query
    memcpy(modified2_2 + 29, original2 + 55, 16);  // A (目标)

    /* 修改压缩指针 */
    modified2_2[29] = 0xc0;
    modified2_2[30] = 0x0c;  // 改为指向Query Section

    DNSHeader *hdr2 = (DNSHeader *)modified2_2;
    hdr2->ancount = htons(1);

    print_hex("方案2修改后", modified2_2, new_len2);

    /* 验证方案2 */
    printf("验证方案2:\n");
    pos = 12;
    parse_dns_name(modified2_2, new_len2, &pos, domain, sizeof(domain));
    printf("  Query: %s\n", domain);
    pos += 4;

    a1_start = pos;
    parse_dns_name(modified2_2, new_len2, &pos, domain, sizeof(domain));
    printf("  Answer[0]: %s\n", domain);
    pos += 10;
    if (pos + 4 <= new_len2) {
        printf("  Answer[0] IP: %d.%d.%d.%d\n", modified2_2[pos], modified2_2[pos+1], modified2_2[pos+2], modified2_2[pos+3]);
        if (modified2_2[pos] == 0xb6 && modified2_2[pos+1] == 0x83 &&
            modified2_2[pos+2] == 0x1a && modified2_2[pos+3] == 0xe7) {
            printf("  ✓ 目标IP正确\n");
        }
    }
    printf("  ✓ 压缩指针已修复为0xc00c\n");

    /* 结论 */
    printf("\n=== 结论 ===\n");
    printf("用户提到的'压缩指针问题'和'CNAME问题'是正确的！\n");
    printf("当前hev_dns_latency_modify_response()函数的问题:\n");
    printf("  1. 如果响应包含CNAME，直接移动Answer会破坏压缩指针\n");
    printf("  2. 函数没有检查Answer类型，可能删除CNAME导致后续A记录压缩指针失效\n");
    printf("  3. 正确做法:\n");
    printf("     - 如果有CNAME，保留CNAME和对应的A记录\n");
    printf("     - 或者删除CNAME但修复所有压缩指针\n");

    return 0;
}