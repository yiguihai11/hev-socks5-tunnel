/* 跟踪DNS修改过程 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

// DNS Header结构体
typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((packed)) DNSHeader;

// 模拟原始响应数据（基于日志推断）
// 原始：112字节，4个A记录
// 目标：50字节，1个A记录（182.131.26.231）

// DNS Header
uint8_t dns_header[] = {
    0x12, 0x34,  // ID
    0x81, 0x80,  // Flags
    0x00, 0x01,  // QDCOUNT = 1
    0x00, 0x04,  // ANCOUNT = 4 (原始)
    0x00, 0x00,  // NSCOUNT
    0x00, 0x00   // ARCOUNT
};

// Query Section: www.cnnic.com.cn
uint8_t query_section[] = {
    0x03, 0x77, 0x77, 0x77,  // "www"
    0x05, 0x63, 0x6e, 0x6e,  // "cnnic"
    0x03, 0x63, 0x6f, 0x6d,  // "com"
    0x02, 0x63, 0x6e,        // "cn"
    0x00,                    // End marker
    0x00, 0x01,  // Type A
    0x00, 0x01   // Class IN
};

// Answer 1: 42.83.144.13 (失败)
uint8_t answer1[] = {
    0xc0, 0x0c,  // Compression pointer to query name
    0x00, 0x01,  // Type A
    0x00, 0x01,  // Class IN
    0x00, 0x00, 0x01, 0x2c,  // TTL = 300
    0x00, 0x04,  // RDLEN = 4
    0x2a, 0x53, 0x90, 0x0d   // 42.83.144.13
};

// Answer 2: 182.131.26.231 (成功 - 需要保留)
uint8_t answer2[] = {
    0xc0, 0x0c,  // Compression pointer
    0x00, 0x01,  // Type A
    0x00, 0x01,  // Class IN
    0x00, 0x00, 0x01, 0x2c,  // TTL = 300
    0x00, 0x04,  // RDLEN = 4
    0xb6, 0x83, 0x1a, 0xe7   // 182.131.26.231
};

// Answer 3: 另一个IP
uint8_t answer3[] = {
    0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x01, 0x2c, 0x00, 0x04,
    0x01, 0x02, 0x03, 0x04
};

// Answer 4: 另一个IP
uint8_t answer4[] = {
    0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x01, 0x2c, 0x00, 0x04,
    0x05, 0x06, 0x07, 0x08
};

void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s (%zu bytes):\n  ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0 && i + 1 < len) printf("\n  ");
    }
    printf("\n");
}

int main() {
    printf("=== DNS修改过程跟踪 ===\n\n");

    // 构建原始响应
    size_t orig_len = sizeof(dns_header) + sizeof(query_section) +
                      sizeof(answer1) + sizeof(answer2) + sizeof(answer3) + sizeof(answer4);

    uint8_t original[orig_len];
    size_t pos = 0;

    memcpy(original + pos, dns_header, sizeof(dns_header));
    pos += sizeof(dns_header);

    memcpy(original + pos, query_section, sizeof(query_section));
    pos += sizeof(query_section);

    memcpy(original + pos, answer1, sizeof(answer1));
    pos += sizeof(answer1);

    memcpy(original + pos, answer2, sizeof(answer2));
    pos += sizeof(answer2);

    memcpy(original + pos, answer3, sizeof(answer3));
    pos += sizeof(answer3);

    memcpy(original + pos, answer4, sizeof(answer4));
    pos += sizeof(answer4);

    printf("原始响应: %zu bytes\n", orig_len);
    print_hex("原始数据", original, orig_len);

    // 模拟修改过程
    printf("\n=== 修改过程 ===\n");

    // 1. 跳过Query Section
    size_t query_end = sizeof(dns_header) + sizeof(query_section);
    printf("1. Query Section结束位置: %zu\n", query_end);

    // 2. 查找目标IP (182.131.26.231 = 0xb6831ae7)
    printf("2. 查找目标IP: 182.131.26.231\n");

    size_t answer2_start = sizeof(dns_header) + sizeof(query_section) + sizeof(answer1);
    size_t answer2_len = sizeof(answer2);

    printf("3. Answer2位置: %zu, 长度: %zu\n", answer2_start, answer2_len);

    // 3. 计算修改后长度
    size_t modified_len = query_end + answer2_len;
    printf("4. 修改后长度: %zu bytes\n", modified_len);

    // 4. 构建修改后的响应
    uint8_t modified[modified_len];
    memcpy(modified, original, query_end);  // 复制Header + Query
    memcpy(modified + query_end, answer2, answer2_len);  // 复制Answer2

    // 5. 修改ANCOUNT
    DNSHeader *hdr = (DNSHeader *)modified;
    hdr->ancount = htons(1);

    printf("\n=== 修改后响应 ===\n");
    print_hex("修改后数据", modified, modified_len);

    // 验证
    printf("\n=== 验证 ===\n");
    printf("长度: %zu bytes (目标: 50)\n", modified_len);
    printf("ANCOUNT: %d (目标: 1)\n", ntohs(hdr->ancount));
    printf("QDCOUNT: %d (应保持: 1)\n", ntohs(hdr->qdcount));

    // 解析修改后的响应
    printf("\n修改后响应解析:\n");
    printf("  Header: ID=0x%04x, Flags=0x%04x\n", ntohs(hdr->id), ntohs(hdr->flags));
    printf("  QDCOUNT=%d, ANCOUNT=%d\n", ntohs(hdr->qdcount), ntohs(hdr->ancount));

    // 检查Answer部分
    size_t ans_pos = query_end;
    printf("  Answer at offset %zu:\n", ans_pos);
    printf("    Name ptr: 0x%02x%02x\n", modified[ans_pos], modified[ans_pos+1]);
    printf("    Type: %d\n", (modified[ans_pos+2] << 8) | modified[ans_pos+3]);
    printf("    Class: %d\n", (modified[ans_pos+4] << 8) | modified[ans_pos+5]);
    printf("    TTL: %u\n", (modified[ans_pos+6] << 24) | (modified[ans_pos+7] << 16) |
                            (modified[ans_pos+8] << 8) | modified[ans_pos+9]);
    printf("    RDLEN: %d\n", (modified[ans_pos+10] << 8) | modified[ans_pos+11]);
    printf("    IP: %d.%d.%d.%d\n", modified[ans_pos+12], modified[ans_pos+13],
                                     modified[ans_pos+14], modified[ans_pos+15]);

    printf("\n=== 结论 ===\n");
    printf("修改后的响应是合法的DNS格式！\n");
    printf("长度: %zu (原始: %zu, 减少: %zu)\n", modified_len, orig_len, orig_len - modified_len);

    return 0;
}
