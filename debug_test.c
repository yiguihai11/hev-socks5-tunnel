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

int main() {
    /* 测试2数据 */
    uint8_t orig2[] = {
        0x12,0x34,0x81,0x80, 0x00,0x01,0x00,0x03, 0x00,0x00,0x00,0x00,
        0x03,0x77,0x77,0x77, 0x07,0x65,0x78,0x61, 0x6d,0x70,0x6c,0x65, 0x03,0x63,0x6f,0x6d, 0x00,
        0x00,0x01,0x00,0x01,
        0xc0,0x0c,0x00,0x05,0x00,0x01,0x00,0x00,0x01,0x2c,0x00,0x0e,
        0x04,0x63,0x6e,0x61,0x6d,0x65, 0x07,0x65,0x78,0x61,0x6d,0x70,0x6c,0x65, 0x03,0x63,0x6f,0x6d, 0x00,
        0xc0,0x2a,0x00,0x01,0x00,0x01,0x00,0x00,0x01,0x2c,0x00,0x04,0xb6,0x83,0x1a,0xe7,
        0xc0,0x2a,0x00,0x01,0x00,0x01,0x00,0x00,0x01,0x2c,0x00,0x04,0x05,0x06,0x07,0x08,
    };
    
    printf("测试2数据长度: %zu\n", sizeof(orig2));
    printf("数据内容:\n");
    for (int i = 0; i < sizeof(orig2); i++) {
        printf("%02x ", orig2[i]);
        if ((i+1) % 16 == 0) printf("\n");
    }
    printf("\n\n");
    
    /* 手动解析 */
    DNSHeader *hdr = (DNSHeader *)orig2;
    printf("Header: ANCOUNT=%d\n", ntohs(hdr->ancount));
    
    size_t pos = 12;  // Header结束
    char domain[256];
    
    /* Query */
    parse_dns_name(orig2, sizeof(orig2), &pos, domain, sizeof(domain));
    printf("Query: %s (结束于位置%zu)\n", domain, pos);
    pos += 4;  // QTYPE+QCLASS
    printf("Query Section结束位置: %zu\n\n", pos);
    
    /* Answer 1: CNAME */
    printf("Answer 1 (CNAME):\n");
    printf("  起始位置: %zu\n", pos);
    printf("  前2字节: %02x %02x\n", orig2[pos], orig2[pos+1]);
    
    size_t a1_name_start = pos;
    parse_dns_name(orig2, sizeof(orig2), &pos, domain, sizeof(domain));
    printf("  域名解析后位置: %zu\n", pos);
    printf("  域名: %s\n", domain);
    
    uint16_t rtype1 = read_uint16(orig2 + pos);
    uint16_t rdlen1 = read_uint16(orig2 + pos + 8);
    printf("  Type: %d, RDLEN: %d\n", rtype1, rdlen1);
    
    pos += 10 + rdlen1;  // 跳过头部和数据
    printf("  结束位置: %zu\n\n", pos);
    
    /* Answer 2: A */
    printf("Answer 2 (A, 目标):\n");
    printf("  起始位置: %zu\n", pos);
    printf("  前2字节: %02x %02x\n", orig2[pos], orig2[pos+1]);
    
    size_t a2_name_start = pos;
    parse_dns_name(orig2, sizeof(orig2), &pos, domain, sizeof(domain));
    printf("  域名解析后位置: %zu\n", pos);
    printf("  域名: %s\n", domain);
    
    uint16_t rtype2 = read_uint16(orig2 + pos);
    uint16_t rdlen2 = read_uint16(orig2 + pos + 8);
    printf("  Type: %d, RDLEN: %d\n", rtype2, rdlen2);
    
    uint8_t *ip_ptr = orig2 + pos + 10;
    printf("  IP数据位置: %zu\n", pos + 10);
    printf("  IP: %d.%d.%d.%d\n", ip_ptr[0], ip_ptr[1], ip_ptr[2], ip_ptr[3]);
    printf("  目标IP: 182.131.26.231 (0xb6 0x83 0x1a 0xe7)\n");
    printf("  匹配: %s\n", (ip_ptr[0]==0xb6 && ip_ptr[1]==0x83 && ip_ptr[2]==0x1a && ip_ptr[3]==0xe7) ? "是" : "否");
    
    pos += 10 + rdlen2;
    printf("  结束位置: %zu\n\n", pos);
    
    /* Answer 3 */
    printf("Answer 3 (A, 其他):\n");
    printf("  起始位置: %zu\n", pos);
    printf("  前2字节: %02x %02x\n", orig2[pos], orig2[pos+1]);
    
    return 0;
}
