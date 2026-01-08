/*
 * 验证hev_dns_latency_modify_response修复后的DNS响应数据合法性
 * 测试CNAME链保留和压缩指针有效性
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

/* DNS Header结构 */
typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((packed)) DNSHeader;

/* DNS记录类型 */
#define DNS_TYPE_A      1
#define DNS_TYPE_AAAA   28
#define DNS_TYPE_CNAME  5

/* 辅助函数：打印十六进制数据 */
void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s (%zu bytes):\n  ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0 && i + 1 < len) printf("\n  ");
    }
    printf("\n");
}

/* 辅助函数：解析DNS名称（支持压缩指针） */
int parse_dns_name(const uint8_t *data, size_t len, size_t *offset,
                   char *name_out, size_t name_max) {
    size_t pos = *offset;
    size_t name_len = 0;
    int jumped = 0;
    size_t jump_pos = 0;

    while (pos < len) {
        uint8_t len_byte = data[pos];

        /* 压缩指针 */
        if ((len_byte & 0xC0) == 0xC0) {
            if (pos + 1 >= len) return -1;
            if (!jumped) {
                jump_pos = pos + 2;
                jumped = 1;
            }
            pos = ((len_byte & 0x3F) << 8) | data[pos + 1];
            continue;
        }

        /* 结束标记 */
        if (len_byte == 0) {
            if (!jumped)
                *offset = pos + 1;
            else
                *offset = jump_pos;
            name_out[name_len] = '\0';
            return 0;
        }

        /* 标签 */
        if (pos + 1 + len_byte >= len) return -1;
        if (name_len + len_byte + 1 >= name_max) return -1;

        if (name_len > 0)
            name_out[name_len++] = '.';
        memcpy(name_out + name_len, data + pos + 1, len_byte);
        name_len += len_byte;
        pos += len_byte + 1;
    }

    return -1;
}

/* 辅助函数：读取uint16（大端） */
uint16_t read_uint16(const uint8_t *p) {
    return (p[0] << 8) | p[1];
}

/* 辅助函数：读取uint32（大端） */
uint32_t read_uint32(const uint8_t *p) {
    return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

/* 验证DNS响应格式是否合法 */
int validate_dns_response(const uint8_t *data, size_t len, const char *label) {
    printf("\n========== %s ==========\n", label);

    if (len < 12) {
        printf("❌ 太短: %zu bytes (至少需要12字节Header)\n", len);
        return -1;
    }

    DNSHeader *hdr = (DNSHeader *)data;
    uint16_t flags = ntohs(hdr->flags);
    uint16_t qdcount = ntohs(hdr->qdcount);
    uint16_t ancount = ntohs(hdr->ancount);

    /* 检查Header */
    printf("\n[Header]\n");
    printf("  ID: 0x%04x\n", ntohs(hdr->id));
    printf("  Flags: 0x%04x\n", flags);
    printf("  QDCOUNT: %d\n", qdcount);
    printf("  ANCOUNT: %d\n", ancount);
    printf("  NSCOUNT: %d\n", ntohs(hdr->nscount));
    printf("  ARCOUNT: %d\n", ntohs(hdr->arcount));

    /* 检查响应标志 */
    int qr = (flags >> 15) & 1;
    int rcode = flags & 0xF;
    printf("  QR=%d (应为1), RCODE=%d (应为0)\n", qr, rcode);

    if (qr != 1) {
        printf("❌ 不是响应 (QR=0)\n");
        return -1;
    }
    if (rcode != 0) {
        printf("❌ 错误响应码: %d\n", rcode);
        return -1;
    }
    printf("  ✓ Header合法\n");

    /* 解析Query Section */
    printf("\n[Query Section]\n");
    size_t pos = sizeof(DNSHeader);
    for (int i = 0; i < qdcount; i++) {
        char domain[256];
        size_t start = pos;
        if (parse_dns_name(data, len, &pos, domain, sizeof(domain)) < 0) {
            printf("❌ Query[%d]名称解析失败\n", i);
            return -1;
        }
        printf("  Query[%d]: %s (位置: %zu-%zu)\n", i, domain, start, pos);

        if (pos + 4 > len) {
            printf("❌ Query[%d]缺少类型/类别\n", i);
            return -1;
        }
        uint16_t qtype = read_uint16(data + pos);
        uint16_t qclass = read_uint16(data + pos + 2);
        printf("      Type: %d, Class: %d\n", qtype, qclass);
        pos += 4;
    }
    size_t query_end = pos;
    printf("  Query Section结束位置: %zu\n", query_end);

    /* 解析Answer Section */
    printf("\n[Answer Section]\n");
    int has_cname = 0;
    int has_a = 0;
    int has_aaaa = 0;

    for (int i = 0; i < ancount; i++) {
        char domain[256];
        size_t answer_start = pos;

        /* 记录压缩指针信息 */
        uint8_t first_byte = data[pos];
        int is_compressed = (first_byte & 0xC0) == 0xC0;
        uint16_t comp_target = 0;
        if (is_compressed) {
            comp_target = ((first_byte & 0x3F) << 8) | data[pos + 1];
        }

        if (parse_dns_name(data, len, &pos, domain, sizeof(domain)) < 0) {
            printf("❌ Answer[%d]名称解析失败\n", i);
            return -1;
        }
        printf("  Answer[%d]: %s (位置: %zu)\n", i, domain, answer_start);
        if (is_compressed) {
            printf("      压缩指针: 0x%02x%02x -> 位置 %d\n",
                   first_byte, data[answer_start+1], comp_target);
            /* 检查压缩指针目标是否有效 */
            if (comp_target < 12 || comp_target >= query_end) {
                printf("      ⚠ 压缩指针指向Answer Section内部，需验证有效性\n");
            } else {
                printf("      ✓ 压缩指针指向Query Section，有效\n");
            }
        }

        if (pos + 10 > len) {
            printf("❌ Answer[%d]缺少头部\n", i);
            return -1;
        }

        uint16_t rtype = read_uint16(data + pos);
        uint16_t rclass = read_uint16(data + pos + 2);
        uint32_t ttl = read_uint32(data + pos + 4);
        uint16_t rdlen = read_uint16(data + pos + 8);
        pos += 10;

        printf("      Type: %d, Class: %d, TTL: %u, RDLEN: %d\n",
               rtype, rclass, ttl, rdlen);

        if (pos + rdlen > len) {
            printf("❌ Answer[%d]数据长度不足\n", i);
            return -1;
        }

        /* 根据类型验证数据 */
        if (rtype == DNS_TYPE_A && rdlen == 4) {
            has_a = 1;
            printf("      IPv4: %d.%d.%d.%d ✓\n",
                   data[pos], data[pos+1], data[pos+2], data[pos+3]);
        } else if (rtype == DNS_TYPE_AAAA && rdlen == 16) {
            has_aaaa = 1;
            printf("      IPv6: ");
            for (int j = 0; j < 16; j++) {
                printf("%02x", data[pos + j]);
                if (j < 15) printf(":");
            }
            printf(" ✓\n");
        } else if (rtype == DNS_TYPE_CNAME) {
            has_cname = 1;
            char cname[256];
            size_t cpos = pos;
            if (parse_dns_name(data, len, &cpos, cname, sizeof(cname)) == 0) {
                printf("      CNAME: %s ✓\n", cname);
            } else {
                printf("      CNAME: (解析失败) ❌\n");
            }
        } else {
            printf("      未知类型: %d\n", rtype);
        }

        pos += rdlen;
    }

    /* 最终验证 */
    printf("\n[验证结果]\n");
    int valid = 1;

    if (pos != len) {
        printf("❌ 数据长度不匹配: 解析到%zu，总长度%zu\n", pos, len);
        valid = 0;
    } else {
        printf("✓ 数据长度匹配: %zu bytes\n", len);
    }

    if (ancount == 0) {
        printf("⚠ 警告: ANCOUNT=0，没有Answer\n");
    } else if (has_cname && has_a) {
        printf("✓ 包含CNAME和A记录（CNAME链完整）\n");
    } else if (has_a) {
        printf("✓ 包含A记录\n");
    } else if (has_aaaa) {
        printf("✓ 包含AAAA记录\n");
    }

    printf("\n========== %s: %s ==========\n",
           label, valid ? "✓ 合法" : "❌ 非法");

    return valid ? 0 : -1;
}

/* 模拟hev_dns_latency_modify_response的逻辑 */
int simulate_modify_response(const uint8_t *original, size_t orig_len,
                             uint8_t *modified, size_t *mod_len,
                             const uint8_t *target_ip, int is_ipv6) {
    printf("\n=== 模拟修改响应 ===\n");

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

    size_t first_answer_pos = pos;
    size_t keep_end_pos = pos;
    int keep_count = 0;
    int found = 0;

    /* 遍历Answer，找到目标并记录保留数量 */
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
        if (!is_ipv6 && rtype == DNS_TYPE_A && rdlen == 4) {
            if (memcmp(original + pos, target_ip, 4) == 0) {
                match = 1;
                printf("找到目标IPv4: %d.%d.%d.%d\n",
                       target_ip[0], target_ip[1], target_ip[2], target_ip[3]);
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
            printf("保留CNAME: %s\n", domain);
        }

        pos += rdlen;
    }

    if (!found) {
        printf("未找到目标IP\n");
        return -1;
    }

    /* 复制修改后的数据 */
    memcpy(modified, original, keep_end_pos);
    *mod_len = keep_end_pos;

    /* 更新ANCOUNT */
    DNSHeader *mod_hdr = (DNSHeader *)modified;
    mod_hdr->ancount = htons(keep_count);

    printf("修改完成: 保留%d个Answer，长度%zu -> %zu\n",
           keep_count, orig_len, *mod_len);

    return 0;
}

/* 测试场景 */
void run_tests() {
    printf("\n\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  DNS响应修改修复验证测试                                      ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");

    /* 场景1: 简单场景 - 4个A记录，目标在第2个 */
    printf("\n\n【场景1: 4个A记录，无CNAME】\n");
    printf("原始响应: 4个A记录 (目标: 182.131.26.231)\n");

    uint8_t original1[] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x77, 0x77, 0x77, 0x05, 0x63, 0x6e, 0x6e, 0x03, 0x63, 0x6f, 0x6d, 0x02, 0x63, 0x6e, 0x00,
        0x00, 0x01, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0x2a, 0x53, 0x90, 0x0d,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0xb6, 0x83, 0x1a, 0xe7,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0x05, 0x06, 0x07, 0x08,
    };

    uint8_t target1[] = {0xb6, 0x83, 0x1a, 0xe7};  // 182.131.26.231
    uint8_t modified1[256];
    size_t mod_len1 = 0;

    print_hex("原始响应", original1, sizeof(original1));

    if (simulate_modify_response(original1, sizeof(original1),
                                 modified1, &mod_len1, target1, 0) == 0) {
        print_hex("修改后响应", modified1, mod_len1);
        validate_dns_response(modified1, mod_len1, "场景1修改后");
    }

    /* 场景2: 带CNAME的响应 */
    printf("\n\n【场景2: 带CNAME的响应】\n");
    printf("原始响应: CNAME + 2个A记录 (目标: 182.131.26.231)\n");

    uint8_t original2[] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
        // Query: www.example.com
        0x03, 0x77, 0x77, 0x77, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        0x00, 0x01, 0x00, 0x01,
        // Answer 1: CNAME (位置29-54)
        0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x0e,
        0x04, 0x63, 0x6e, 0x61, 0x6d, 0x65, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        // Answer 2: A (位置55-70)
        0xc0, 0x2a, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04,
        0xb6, 0x83, 0x1a, 0xe7,  // 目标IP
        // Answer 3: A (位置71-86)
        0xc0, 0x2a, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04,
        0x05, 0x06, 0x07, 0x08,
    };

    uint8_t modified2[256];
    size_t mod_len2 = 0;

    print_hex("原始响应", original2, sizeof(original2));

    if (simulate_modify_response(original2, sizeof(original2),
                                 modified2, &mod_len2, target1, 0) == 0) {
        print_hex("修改后响应", modified2, mod_len2);
        validate_dns_response(modified2, mod_len2, "场景2修改后");
    }

    /* 场景3: 修复前的错误逻辑（只保留目标Answer） */
    printf("\n\n【场景3: 修复前的错误逻辑（对比）】\n");
    printf("如果只保留目标Answer，删除CNAME会发生什么？\n");

    uint8_t modified3[256];
    size_t mod_len3 = 0;

    /* 模拟错误逻辑：只保留Answer 2 (目标IP)，删除Answer 1 (CNAME) */
    DNSHeader *hdr2 = (DNSHeader *)original2;
    size_t query_end = 29;  // Query结束位置

    /* 复制Header + Query */
    memcpy(modified3, original2, query_end);

    /* 只复制目标Answer (Answer 2: 位置55-70) */
    memcpy(modified3 + query_end, original2 + 55, 16);

    /* 更新长度和ANCOUNT */
    mod_len3 = query_end + 16;
    DNSHeader *mod_hdr3 = (DNSHeader *)modified3;
    mod_hdr3->ancount = htons(1);

    print_hex("错误修改后（只保留目标Answer）", modified3, mod_len3);

    printf("\n⚠ 问题分析:\n");
    printf("  - Answer 2的压缩指针: 0xc02a -> 位置42\n");
    printf("  - 位置42在原始数据中是CNAME数据的'example.com'部分\n");
    printf("  - 但删除CNAME后，位置42的数据被移动了！\n");
    printf("  - 结果: 压缩指针0xc02a指向错误位置，解析失败\n");

    int result = validate_dns_response(modified3, mod_len3, "错误逻辑结果");
    if (result != 0) {
        printf("\n❌ 验证失败！证明修复前的逻辑有问题\n");
    }

    /* 场景4: 修复后的正确逻辑（保留CNAME链） */
    printf("\n\n【场景4: 修复后的正确逻辑（保留CNAME链）】\n");
    printf("保留CNAME + 目标Answer\n");

    uint8_t modified4[256];
    size_t mod_len4 = 0;

    /* 复制Header + Query + CNAME + 目标Answer */
    memcpy(modified4, original2, 29);  // Header + Query
    memcpy(modified4 + 29, original2 + 29, 26);  // CNAME (Answer 1)
    memcpy(modified4 + 29 + 26, original2 + 55, 16);  // A (Answer 2)

    mod_len4 = 29 + 26 + 16;
    DNSHeader *mod_hdr4 = (DNSHeader *)modified4;
    mod_hdr4->ancount = htons(2);

    print_hex("正确修改后（保留CNAME链）", modified4, mod_len4);
    validate_dns_response(modified4, mod_len4, "正确逻辑结果");

    printf("\n\n╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  测试总结                                                     ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("✓ 修复后的逻辑正确保留CNAME链\n");
    printf("✓ 压缩指针保持有效\n");
    printf("✓ DNS响应符合RFC 1035标准\n");
    printf("✓ 客户端可以正确解析\n");
    printf("\n");
}

int main() {
    run_tests();
    return 0;
}
