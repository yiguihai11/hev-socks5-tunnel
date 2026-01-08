/* 最终验证：直接测试hev_dns_latency_modify_response的逻辑 */
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
    printf("%s (%zu bytes):\n  ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0 && i + 1 < len) printf("\n  ");
    }
    printf("\n\n");
}

uint16_t read_uint16(const uint8_t *p) {
    return (p[0] << 8) | p[1];
}

/* 解析DNS名称 */
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

/* 模拟修复后的hev_dns_latency_modify_response逻辑 */
int modify_response_fixed(const uint8_t *original, size_t orig_len,
                          uint8_t *modified, size_t *mod_len,
                          const uint8_t *target_ip) {
    if (orig_len < sizeof(DNSHeader)) return -1;

    DNSHeader *hdr = (DNSHeader *)original;
    uint16_t ancount = ntohs(hdr->ancount);
    if (ancount == 0) return 0;

    /* 跳过Query Section */
    size_t pos = sizeof(DNSHeader);
    uint16_t qdcount = ntohs(hdr->qdcount);

    for (int i = 0; i < qdcount && pos < orig_len; i++) {
        char domain[256];
        if (parse_dns_name(original, orig_len, &pos, domain, sizeof(domain)) < 0)
            return -1;
        if (pos + 4 > orig_len) return -1;
        pos += 4;
    }

    size_t keep_end_pos = pos;
    int keep_count = 0;
    int found = 0;

    /* 遍历Answer，找到目标并记录需要保留的数量 */
    for (int i = 0; i < ancount && pos < orig_len; i++) {
        char domain[256];
        size_t answer_start = pos;

        if (parse_dns_name(original, orig_len, &pos, domain, sizeof(domain)) < 0)
            break;

        if (pos + 10 > orig_len) break;

        uint16_t rtype = read_uint16(original + pos);
        uint16_t rdlen = read_uint16(original + pos + 8);
        pos += 10;

        if (pos + rdlen > orig_len) break;

        /* 检查是否匹配目标IP */
        int match = 0;
        if (rtype == DNS_TYPE_A && rdlen == 4) {
            if (memcmp(original + pos, target_ip, 4) == 0) {
                match = 1;
                printf("  找到目标IP: %d.%d.%d.%d\n", target_ip[0], target_ip[1], target_ip[2], target_ip[3]);
            }
        }

        if (match) {
            keep_end_pos = pos + rdlen;
            keep_count = i + 1;
            found = 1;
            break;
        }

        /* 如果是CNAME，继续保留 */
        if (rtype == DNS_TYPE_CNAME) {
            keep_end_pos = pos + rdlen;
            keep_count = i + 1;
            printf("  保留CNAME: %s\n", domain);
        }

        pos += rdlen;
    }

    if (!found) {
        printf("  未找到目标IP\n");
        return -1;
    }

    /* 复制修改后的数据 */
    memcpy(modified, original, keep_end_pos);
    *mod_len = keep_end_pos;

    /* 更新ANCOUNT */
    DNSHeader *mod_hdr = (DNSHeader *)modified;
    mod_hdr->ancount = htons(keep_count);

    printf("  修改完成: 保留%d个Answer，长度%zu -> %zu\n", keep_count, orig_len, *mod_len);

    return 0;
}

/* 验证DNS响应格式 */
int validate_response(const uint8_t *data, size_t len, const char *label) {
    printf("\n========== 验证: %s ==========\n", label);
    
    if (len < 12) {
        printf("❌ 太短\n");
        return -1;
    }

    DNSHeader *hdr = (DNSHeader *)data;
    uint16_t ancount = ntohs(hdr->ancount);
    uint16_t qdcount = ntohs(hdr->qdcount);

    printf("Header: ANCOUNT=%d, QDCOUNT=%d\n", ancount, qdcount);

    /* 解析Query */
    size_t pos = sizeof(DNSHeader);
    for (int i = 0; i < qdcount; i++) {
        char domain[256];
        size_t start = pos;
        if (parse_dns_name(data, len, &pos, domain, sizeof(domain)) < 0) {
            printf("❌ Query解析失败\n");
            return -1;
        }
        printf("Query[%d]: %s (位置%zu-%zu)\n", i, domain, start, pos);
        if (pos + 4 > len) return -1;
        pos += 4;
    }

    /* 解析Answer */
    int has_cname = 0;
    int has_a = 0;
    int all_valid = 1;

    for (int i = 0; i < ancount; i++) {
        if (pos >= len) {
            printf("❌ Answer[%d]数据不足\n", i);
            all_valid = -1;
            break;
        }

        size_t answer_start = pos;
        uint8_t first = data[pos];
        int is_compressed = (first & 0xC0) == 0xC0;
        uint16_t comp_target = 0;

        if (is_compressed) {
            comp_target = ((first & 0x3F) << 8) | data[pos + 1];
            pos += 2;
        }

        char domain[256];
        if (parse_dns_name(data, len, &pos, domain, sizeof(domain)) < 0) {
            printf("❌ Answer[%d]域名解析失败\n", i);
            all_valid = -1;
            break;
        }

        if (pos + 10 > len) {
            printf("❌ Answer[%d]头部不足\n", i);
            all_valid = -1;
            break;
        }

        uint16_t rtype = read_uint16(data + pos);
        uint16_t rdlen = read_uint16(data + pos + 8);
        pos += 10;

        if (pos + rdlen > len) {
            printf("❌ Answer[%d]数据不足\n", i);
            all_valid = -1;
            break;
        }

        printf("Answer[%d]: ", i);
        if (is_compressed) {
            printf("压缩指针0x%02x%02x->%d ", first, data[answer_start+1], comp_target);
            /* 验证压缩指针 */
            if (comp_target < 12 || comp_target >= answer_start) {
                printf("[无效!]");
                all_valid = -1;
            } else {
                printf("[有效]");
            }
        } else {
            printf("域名=%s ", domain);
        }

        if (rtype == DNS_TYPE_A && rdlen == 4) {
            printf("Type=A, IP=%d.%d.%d.%d", data[pos], data[pos+1], data[pos+2], data[pos+3]);
            has_a = 1;
        } else if (rtype == DNS_TYPE_CNAME) {
            printf("Type=CNAME");
            has_cname = 1;
        } else {
            printf("Type=%d", rtype);
        }
        printf("\n");

        pos += rdlen;
    }

    if (pos != len) {
        printf("❌ 长度不匹配: pos=%zu, len=%zu\n", pos, len);
        all_valid = -1;
    }

    if (all_valid == 0) {
        printf("✓ 验证通过\n");
    }

    return all_valid;
}

int main() {
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  DNS响应修改修复最终验证                                       ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n\n");

    int pass1 = 0, pass2 = 0, pass3 = 0;

    /* 测试1: 无CNAME场景 */
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
    size_t mod_len1 = 0;

    if (modify_response_fixed(orig1, sizeof(orig1), mod1, &mod_len1, target1) == 0) {
        print_hex("修改后数据", mod1, mod_len1);
        if (validate_response(mod1, mod_len1, "测试1结果") == 0) {
            pass1 = 1;
        }
    }

    /* 测试2: CNAME场景 */
    printf("\n\n【测试2: CNAME + A记录】\n");
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
    size_t mod_len2 = 0;

    if (modify_response_fixed(orig2, sizeof(orig2), mod2, &mod_len2, target1) == 0) {
        print_hex("修改后数据", mod2, mod_len2);
        if (validate_response(mod2, mod_len2, "测试2结果") == 0) {
            pass2 = 1;
        }
    }

    /* 测试3: 错误逻辑 */
    printf("\n\n【测试3: 错误逻辑（只保留目标，删除CNAME）】\n");
    uint8_t wrong[256];
    size_t wrong_len = 29 + 16;  // Query + A(目标)
    memcpy(wrong, orig2, 29);
    memcpy(wrong + 29, orig2 + 55, 16);  // 只复制目标Answer
    DNSHeader *wh = (DNSHeader *)wrong;
    wh->ancount = htons(1);
    
    print_hex("错误数据", wrong, wrong_len);
    int r3 = validate_response(wrong, wrong_len, "测试3结果");
    if (r3 != 0) {
        pass3 = 1;  // 预期应该失败
    }

    /* 结论 */
    printf("\n\n╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  最终结论                                                     ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n\n");
    printf("测试1 (无CNAME): %s\n", pass1 ? "✓ 通过" : "❌ 失败");
    printf("测试2 (有CNAME): %s\n", pass2 ? "✓ 通过" : "❌ 失败");
    printf("测试3 (错误检测): %s\n", pass3 ? "✓ 正确检测到错误" : "❌ 未检测到错误");

    printf("\n");
    if (pass1 && pass2 && pass3) {
        printf("✓✓✓ 全部验证通过！修复方案正确！\n");
        printf("\n修复后的逻辑:\n");
        printf("- 保留目标Answer之前的所有Answer（包括CNAME）\n");
        printf("- 保留目标Answer\n");
        printf("- 更新ANCOUNT为保留的Answer数量\n");
        printf("- 所有压缩指针保持有效\n");
        return 0;
    } else {
        printf("❌ 验证失败\n");
        return 1;
    }
}
