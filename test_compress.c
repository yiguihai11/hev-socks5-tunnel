/* 测试DNS压缩指针和CNAME处理 */
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

// 解析DNS名称（支持压缩指针）
int parse_dns_name(const uint8_t *data, size_t len, size_t *offset, char *name, size_t name_max) {
    size_t pos = *offset;
    size_t name_len = 0;
    int jumped = 0;
    size_t jump_pos = 0;
    int jump_count = 0;  // 防止无限循环

    while (pos < len && jump_count < 10) {
        uint8_t l = data[pos];

        // 压缩指针 (最高2位为11)
        if ((l & 0xC0) == 0xC0) {
            if (pos + 1 >= len) return -1;

            uint16_t ptr = ((l & 0x3F) << 8) | data[pos + 1];
            printf("  [压缩指针] 位置=%zu, 值=0x%04x -> 跳转到 %d\n", pos, ((l & 0x3F) << 8) | data[pos + 1], ptr);

            if (!jumped) {
                jump_pos = pos + 2;
                jumped = 1;
            }
            pos = ptr;
            jump_count++;
            continue;
        }

        // 结束标记
        if (l == 0) {
            if (!jumped) *offset = pos + 1;
            else *offset = jump_pos;
            name[name_len] = '\0';
            printf("  [结束] 名称长度=%zu\n", name_len);
            return 0;
        }

        // 普通标签
        if (pos + 1 + l >= len) return -1;
        if (name_len + l + 1 >= name_max) return -1;

        if (name_len > 0) name[name_len++] = '.';
        memcpy(name + name_len, data + pos + 1, l);
        name_len += l;
        pos += l + 1;
        printf("  [标签] 长度=%d, 内容=%.*s\n", l, l, data + pos - l);
    }

    return -1;
}

// 检查DNS响应的压缩指针引用位置
void analyze_compression_pointers(const uint8_t *data, size_t len) {
    printf("\n=== 压缩指针分析 ===\n");

    DNSHeader *hdr = (DNSHeader *)data;
    size_t pos = sizeof(DNSHeader);

    // 跳过查询部分
    printf("\n[查询部分]\n");
    for (int i = 0; i < ntohs(hdr->qdcount); i++) {
        char domain[256];
        size_t start = pos;
        parse_dns_name(data, len, &pos, domain, sizeof(domain));
        printf("查询[%d]: %s (位置: %zu-%zu)\n", i, domain, start, pos);
        if (pos + 4 <= len) {
            pos += 4;
        }
    }

    // 分析回答部分
    printf("\n[回答部分]\n");
    for (int i = 0; i < ntohs(hdr->ancount); i++) {
        printf("\n回答[%d]:\n", i);
        size_t answer_start = pos;
        char domain[256];
        size_t name_start = pos;
        parse_dns_name(data, len, &pos, domain, sizeof(domain));
        printf("  名称位置: %zu-%zu\n", name_start, pos);

        if (pos + 10 > len) break;

        uint16_t rtype = (data[pos] << 8) | data[pos + 1];
        uint16_t rclass = (data[pos + 2] << 8) | data[pos + 3];
        uint32_t ttl = (data[pos + 4] << 24) | (data[pos + 5] << 16) | (data[pos + 6] << 8) | data[pos + 7];
        uint16_t rdlen = (data[pos + 8] << 8) | data[pos + 9];
        pos += 10;

        printf("  Type: %d, Class: %d, TTL: %u, RDLEN: %d\n", rtype, rclass, ttl, rdlen);
        printf("  数据位置: %zu\n", pos);

        if (rtype == 1 && rdlen == 4) {  // A记录
            printf("  IPv4: %d.%d.%d.%d\n", data[pos], data[pos+1], data[pos+2], data[pos+3]);
        } else if (rtype == 5) {  // CNAME
            printf("  CNAME: ");
            size_t cname_pos = pos;
            char cname[256];
            parse_dns_name(data, len, &cname_pos, cname, sizeof(cname));
            printf("%s\n", cname);
        }

        pos += rdlen;
        answer_start = answer_start;  // 避免未使用警告
    }
}

// 模拟真实场景：带CNAME的响应
void test_cname_scenario() {
    printf("\n\n=== 测试场景：带CNAME的DNS响应 ===\n");

    // 构建一个带CNAME的响应
    // www.example.com -> cname.example.com -> 1.2.3.4
    uint8_t response[] = {
        // Header
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
        // Query: www.example.com
        0x03, 0x77, 0x77, 0x77, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        0x00, 0x01, 0x00, 0x01,
        // Answer 1: CNAME (压缩指针指向查询)
        0xc0, 0x0c,  // 压缩指针到位置12 (查询名称开始)
        0x00, 0x05,  // Type CNAME
        0x00, 0x01,  // Class IN
        0x00, 0x00, 0x01, 0x2c,  // TTL 300
        0x00, 0x0e,  // RDLEN 14
        // CNAME数据: cname.example.com
        0x04, 0x63, 0x6e, 0x61, 0x6d, 0x65, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        // Answer 2: A record (压缩指针指向CNAME)
        0xc0, 0x2a,  // 压缩指针到位置42 (cname.example.com)
        0x00, 0x01,  // Type A
        0x00, 0x01,  // Class IN
        0x00, 0x00, 0x01, 0x2c,  // TTL 300
        0x00, 0x04,  // RDLEN 4
        0x01, 0x02, 0x03, 0x04,  // IP 1.2.3.4
        // Answer 3: A record (另一个IP，需要删除)
        0xc0, 0x2a,  // 压缩指针到位置42
        0x00, 0x01,  // Type A
        0x00, 0x01,  // Class IN
        0x00, 0x00, 0x01, 0x2c,  // TTL 300
        0x00, 0x04,  // RDLEN 4
        0x05, 0x06, 0x07, 0x08,  // IP 5.6.7.8
    };

    printf("原始响应长度: %zu bytes\n", sizeof(response));
    analyze_compression_pointers(response, sizeof(response));

    // 现在尝试删除Answer 3，只保留Answer 2
    printf("\n\n=== 删除Answer 3后的响应 ===\n");

    // 找到Answer 2的开始位置
    // Header(12) + Query(17) + Answer1(12+18=30) = 59字节到Answer 2
    size_t answer2_start = 59;
    size_t answer2_len = 16;  // 2字节指针 + 10字节头部 + 4字节IP

    // 新的响应
    uint8_t modified[59 + 16];
    memcpy(modified, response, 59);  // 复制到Answer 2之前
    memcpy(modified + 59, response + answer2_start, 16);  // 复制Answer 2

    // 修改ANCOUNT
    DNSHeader *mhdr = (DNSHeader *)modified;
    mhdr->ancount = htons(2);  // CNAME + A = 2个回答

    printf("修改后长度: %zu bytes\n", 59 + 16);
    analyze_compression_pointers(modified, 59 + 16);
}

int main() {
    printf("DNS压缩指针和CNAME测试工具\n");
    printf("=========================\n");

    // 测试1：简单场景（trace_modify.c中的场景）
    printf("\n\n=== 测试1：简单A记录场景 ===\n");
    uint8_t simple[] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x77, 0x77, 0x77, 0x05, 0x63, 0x6e, 0x6e, 0x03, 0x63, 0x6f, 0x6d, 0x02, 0x63, 0x6e, 0x00,
        0x00, 0x01, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0x2a, 0x53, 0x90, 0x0d,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0xb6, 0x83, 0x1a, 0xe7,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0x05, 0x06, 0x07, 0x08,
    };
    analyze_compression_pointers(simple, sizeof(simple));

    // 测试2：CNAME场景
    test_cname_scenario();

    return 0;
}
