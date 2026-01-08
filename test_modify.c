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

#define DNS_TYPE_A 1
#define DNS_TYPE_CNAME 5

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

/* 模拟修改函数 */
int modify_response(uint8_t *data, size_t *len, uint8_t *target_ip) {
    DNSHeader *hdr = (DNSHeader *)data;
    uint16_t ancount = ntohs(hdr->ancount);
    uint16_t qdcount = ntohs(hdr->qdcount);

    if (ancount == 0) return 0;

    size_t pos = sizeof(DNSHeader);

    /* 跳过Query */
    for (int i = 0; i < qdcount && pos < *len; i++) {
        char domain[256];
        if (parse_dns_name(data, *len, &pos, domain, sizeof(domain)) < 0)
            return -1;
        pos += 4;
    }

    /* 遍历Answer */
    int target_answer_count = 0;
    int found = 0;

    for (int i = 0; i < ancount && pos < *len; i++) {
        char domain[256];

        if (parse_dns_name(data, *len, &pos, domain, sizeof(domain)) < 0)
            break;

        if (pos + 10 > *len) break;

        uint16_t rtype = read_uint16(data + pos);
        uint16_t rdlen = read_uint16(data + pos + 8);
        pos += 10;

        if (pos + rdlen > *len) break;

        int is_target = 0;
        if (rtype == DNS_TYPE_A && rdlen == 4) {
            if (memcmp(data + pos, target_ip, 4) == 0) {
                is_target = 1;
                found = 1;
            }
        }

        if (rtype == DNS_TYPE_CNAME) {
            target_answer_count++;
        }

        if (is_target) {
            *len = pos + rdlen;
            hdr->ancount = htons(target_answer_count + 1);
            break;
        }

        pos += rdlen;
    }

    return found ? 0 : -1;
}

int main() {
    /* 测试数据: www.example.com -> cname.example.com -> 182.131.26.231 */
    uint8_t orig[] = {
        0x12,0x34,0x81,0x80, 0x00,0x01,0x00,0x04, 0x00,0x00,0x00,0x00,  // Header
        // Query: www.example.com
        0x03,'w','w','w', 0x07,'e','x','a','m','p','l','e', 0x03,'c','o','m', 0x00,
        0x00,0x01,0x00,0x01,
        // Answer 1: CNAME cname.example.com
        0xc0,0x0c, 0x00,0x05, 0x00,0x01, 0x00,0x00,0x01,0x2c, 0x00,0x13,
        0x04,'c','n','a','m','e', 0x07,'e','x','a','m','p','l','e', 0x03,'c','o','m', 0x00,
        // Answer 2: A 42.83.144.13 (坏IP)
        0xc0,0x2a, 0x00,0x01, 0x00,0x01, 0x00,0x00,0x01,0x2c, 0x00,0x04,
        0x2a,0x53,0x90,0x0d,
        // Answer 3: A 182.131.26.231 (好IP - 目标)
        0xc0,0x2a, 0x00,0x01, 0x00,0x01, 0x00,0x00,0x01,0x2c, 0x00,0x04,
        0xb6,0x83,0x1a,0xe7,
        // Answer 4: A 5.6.7.8 (其他)
        0xc0,0x2a, 0x00,0x01, 0x00,0x01, 0x00,0x00,0x01,0x2c, 0x00,0x04,
        0x05,0x06,0x07,0x08,
    };

    uint8_t target[] = {0xb6, 0x83, 0x1a, 0xe7};
    uint8_t modified[256];
    size_t len = sizeof(orig);
    memcpy(modified, orig, len);

    printf("原始数据: %zu bytes, ANCOUNT=%d\n", len, ntohs(((DNSHeader*)orig)->ancount));
    printf("目标IP: 182.131.26.231\n\n");

    int ret = modify_response(modified, &len, target);

    printf("修改结果: %s\n", ret == 0 ? "成功" : "失败");
    printf("新长度: %zu bytes\n", len);
    printf("新ANCOUNT: %d\n", ntohs(((DNSHeader*)modified)->ancount));

    printf("\n修改后数据:\n");
    for (int i = 0; i < len; i++) {
        printf("%02x ", modified[i]);
        if ((i+1) % 16 == 0) printf("\n");
    }
    printf("\n");

    /* 验证 */
    printf("\n=== 验证 ===\n");
    printf("预期: 保留Answer 1(CNAME) + Answer 3(目标IP)\n");
    printf("预期长度: Header(12) + Query(21) + Answer1(31) + Answer3(16) = 80\n");
    printf("预期ANCOUNT: 2\n");
    printf("实际长度: %zu\n", len);
    printf("实际ANCOUNT: %d\n", ntohs(((DNSHeader*)modified)->ancount));

    if (len == 80 && ntohs(((DNSHeader*)modified)->ancount) == 2) {
        printf("\n✅ 验证通过！\n");
        printf("删除了Answer 2和Answer 4，保留了CNAME和目标IP\n");
    } else {
        printf("\n❌ 验证失败\n");
    }

    return 0;
}
