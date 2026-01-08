/* 直接验证实际代码中的hev_dns_latency_modify_response逻辑 */
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

void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s:\n", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
}

uint16_t read_uint16(const uint8_t *p) {
    return (p[0] << 8) | p[1];
}

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

/* 从实际代码复制的逻辑 */
int hev_dns_latency_modify_response(uint8_t *data, size_t *len, const uint8_t *target_ip, int is_ipv6) {
    if (!data || !len || *len < sizeof(DNSHeader))
        return -1;

    DNSHeader *hdr = (DNSHeader *)data;
    uint16_t ancount = ntohs(hdr->ancount);

    if (ancount == 0)
        return 0;

    /* Skip query section */
    size_t pos = sizeof(DNSHeader);
    uint16_t qdcount = ntohs(hdr->qdcount);

    for (int i = 0; i < qdcount && pos < *len; i++) {
        char domain[256];
        if (parse_dns_name(data, *len, &pos, domain, sizeof(domain)) < 0)
            return -1;
        if (pos + 4 > *len)
            return -1;
        pos += 4;
    }

    /* 遍历所有Answer，找到目标并记录需要保留的数量 */
    size_t keep_end_pos = pos;
    int keep_count = 0;
    int found = 0;

    for (int i = 0; i < ancount && pos < *len; i++) {
        char domain[256];

        if (parse_dns_name(data, *len, &pos, domain, sizeof(domain)) < 0)
            break;

        if (pos + 10 > *len)
            break;

        uint16_t rtype = read_uint16(data + pos);
        uint16_t rdlen = read_uint16(data + pos + 8);
        pos += 10;

        if (pos + rdlen > *len)
            break;

        /* Check if this answer matches best_ip */
        int match = 0;
        if (!is_ipv6 && rtype == DNS_TYPE_A && rdlen == 4) {
            if (memcmp(data + pos, target_ip, 4) == 0)
                match = 1;
        }

        if (match) {
            /* 找到目标，记录结束位置和保留数量 */
            keep_end_pos = pos + rdlen;
            keep_count = i + 1;
            found = 1;
            break;
        }

        /* 如果是CNAME，继续保留（可能指向目标IP） */
        if (rtype == DNS_TYPE_CNAME) {
            keep_end_pos = pos + rdlen;
            keep_count = i + 1;
        }

        pos += rdlen;
    }

    if (!found) {
        printf("  Best IP not found\n");
        return -1;
    }

    /* 更新长度和ANCOUNT - 保留CNAME链 */
    *len = keep_end_pos;
    hdr->ancount = htons(keep_count);

    printf("  Modified: kept %d answers, len %zu -> %zu\n", keep_count, *len, keep_end_pos);

    return 0;
}

/* 验证响应 */
int verify_response(const uint8_t *data, size_t len, const char *desc) {
    printf("\n--- 验证: %s ---\n", desc);
    
    if (len < 12) return -1;
    
    DNSHeader *hdr = (DNSHeader *)data;
    printf("ANCOUNT=%d, QDCOUNT=%d\n", ntohs(hdr->ancount), ntohs(hdr->qdcount));
    
    size_t pos = sizeof(DNSHeader);
    char domain[256];
    
    /* Query */
    if (parse_dns_name(data, len, &pos, domain, sizeof(domain)) < 0) return -1;
    printf("Query: %s\n", domain);
    pos += 4;
    
    /* Answers */
    int valid = 1;
    for (int i = 0; i < ntohs(hdr->ancount); i++) {
        if (pos >= len) {
            printf("Answer[%d]: 数据不足\n", i);
            valid = 0;
            break;
        }
        
        uint8_t first = data[pos];
        if ((first & 0xC0) == 0xC0) {
            uint16_t ptr = ((first & 0x3F) << 8) | data[pos+1];
            printf("Answer[%d]: 压缩指针0x%02x%02x->%d ", i, first, data[pos+1], ptr);
            pos += 2;
            
            /* 验证指针 */
            if (ptr < 12 || ptr >= pos) {
                printf("[无效!]\n");
                valid = 0;
                continue;
            }
            printf("[有效] ");
        } else {
            printf("Answer[%d]: 完整域名 ", i);
        }
        
        size_t name_end = pos;
        if (parse_dns_name(data, len, &name_end, domain, sizeof(domain)) < 0) {
            printf("[解析失败]\n");
            valid = 0;
            break;
        }
        pos = name_end;
        
        if (pos + 10 > len) {
            printf("[头部不足]\n");
            valid = 0;
            break;
        }
        
        uint16_t rtype = read_uint16(data + pos);
        uint16_t rdlen = read_uint16(data + pos + 8);
        pos += 10;
        
        if (pos + rdlen > len) {
            printf("[数据不足]\n");
            valid = 0;
            break;
        }
        
        if (rtype == DNS_TYPE_A && rdlen == 4) {
            printf("Type=A, IP=%d.%d.%d.%d\n", data[pos], data[pos+1], data[pos+2], data[pos+3]);
        } else if (rtype == DNS_TYPE_CNAME) {
            printf("Type=CNAME\n");
        } else {
            printf("Type=%d\n", rtype);
        }
        
        pos += rdlen;
    }
    
    if (pos != len) {
        printf("长度不匹配: pos=%zu, len=%zu\n", pos, len);
        valid = 0;
    }
    
    if (valid) printf("✓ 合法\n");
    else printf("❌ 非法\n");
    
    return valid ? 0 : -1;
}

int main() {
    printf("════════════════════════════════════════════════════════════════\n");
    printf("  实际代码逻辑验证 - hev_dns_latency_modify_response\n");
    printf("════════════════════════════════════════════════════════════════\n\n");

    int test1_pass = 0, test2_pass = 0, test3_pass = 0;

    /* 测试1: 无CNAME */
    printf("【测试1: 4个A记录，目标在第2个】\n");
    uint8_t orig1[] = {
        0x12,0x34,0x81,0x80, 0x00,0x01,0x00,0x04, 0x00,0x00,0x00,0x00,
        0x03,0x77,0x77,0x77, 0x05,0x63,0x6e,0x6e, 0x03,0x63,0x6f,0x6d, 0x02,0x63,0x6e,0x00,
        0x00,0x01,0x00,0x01,
        0xc0,0x0c,0x00,0x01,0x00,0x01,0x00,0x00,0x01,0x2c,0x00,0x04,0x2a,0x53,0x90,0x0d,
        0xc0,0x0c,0x00,0x01,0x00,0x01,0x00,0x00,0x01,0x2c,0x00,0x04,0xb6,0x83,0x1a,0xe7,
        0xc0,0x0c,0x00,0x01,0x00,0x01,0x00,0x00,0x01,0x2c,0x00,0x04,0x01,0x02,0x03,0x04,
        0xc0,0x0c,0x00,0x01,0x00,0x01,0x00,0x00,0x01,0x2c,0x00,0x04,0x05,0x06,0x07,0x08,
    };
    uint8_t target1[] = {0xb6, 0x83, 0x1a, 0xe7};
    uint8_t mod1[256];
    size_t len1 = sizeof(orig1);
    memcpy(mod1, orig1, len1);
    
    print_hex("原始", orig1, sizeof(orig1));
    if (hev_dns_latency_modify_response(mod1, &len1, target1, 0) == 0) {
        print_hex("修改后", mod1, len1);
        if (verify_response(mod1, len1, "测试1结果") == 0) {
            test1_pass = 1;
        }
    }

    /* 测试2: CNAME */
    printf("\n【测试2: CNAME + A记录】\n");
    uint8_t orig2[] = {
        0x12,0x34,0x81,0x80, 0x00,0x01,0x00,0x03, 0x00,0x00,0x00,0x00,
        0x03,0x77,0x77,0x77, 0x07,0x65,0x78,0x61, 0x6d,0x70,0x6c,0x65, 0x03,0x63,0x6f,0x6d, 0x00,
        0x00,0x01,0x00,0x01,
        0xc0,0x0c,0x00,0x05,0x00,0x01,0x00,0x00,0x01,0x2c,0x00,0x0e,
        0x04,0x63,0x6e,0x61,0x6d,0x65, 0x07,0x65,0x78,0x61,0x6d,0x70,0x6c,0x65, 0x03,0x63,0x6f,0x6d, 0x00,
        0xc0,0x2a,0x00,0x01,0x00,0x01,0x00,0x00,0x01,0x2c,0x00,0x04,0xb6,0x83,0x1a,0xe7,
        0xc0,0x2a,0x00,0x01,0x00,0x01,0x00,0x00,0x01,0x2c,0x00,0x04,0x05,0x06,0x07,0x08,
    };
    uint8_t mod2[256];
    size_t len2 = sizeof(orig2);
    memcpy(mod2, orig2, len2);
    
    print_hex("原始", orig2, sizeof(orig2));
    if (hev_dns_latency_modify_response(mod2, &len2, target1, 0) == 0) {
        print_hex("修改后", mod2, len2);
        if (verify_response(mod2, len2, "测试2结果") == 0) {
            test2_pass = 1;
        }
    }

    /* 测试3: 错误逻辑 */
    printf("\n【测试3: 错误逻辑 - 只保留目标A，删除CNAME】\n");
    uint8_t wrong[256];
    size_t wrong_len = 29 + 16;  // Header+Query + A(目标)
    memcpy(wrong, orig2, 29);
    memcpy(wrong + 29, orig2 + 55, 16);  // 只复制Answer 2
    DNSHeader *wh = (DNSHeader *)wrong;
    wh->ancount = htons(1);
    
    print_hex("错误数据", wrong, wrong_len);
    int r3 = verify_response(wrong, wrong_len, "测试3结果");
    test3_pass = (r3 != 0);  // 预期应该失败

    /* 结论 */
    printf("\n════════════════════════════════════════════════════════════════\n");
    printf("  验证结论\n");
    printf("════════════════════════════════════════════════════════════════\n\n");
    printf("测试1 (无CNAME): %s\n", test1_pass ? "✓ 通过" : "❌ 失败");
    printf("测试2 (有CNAME): %s\n", test2_pass ? "✓ 通过" : "❌ 失败");
    printf("测试3 (错误检测): %s\n", test3_pass ? "✓ 正确" : "❌ 错误");

    printf("\n");
    if (test1_pass && test2_pass && test3_pass) {
        printf("✓✓✓ 全部验证通过！\n");
        printf("\n修复方案总结:\n");
        printf("1. 遍历所有Answer，找到目标IP\n");
        printf("2. 记录目标Answer之前的所有Answer（包括CNAME）\n");
        printf("3. 保留这些Answer + 目标Answer\n");
        printf("4. 更新ANCOUNT\n");
        printf("5. 所有压缩指针保持有效\n");
        return 0;
    } else {
        printf("❌ 部分验证失败\n");
        return 1;
    }
}
