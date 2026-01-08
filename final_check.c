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

int main() {
    printf("=== 创建正确的测试数据 ===\n\n");
    
    /* 正确的测试2数据: www.example.com -> cname.example.com -> 182.131.26.231 */
    /* Header */
    uint8_t orig2[] = {
        0x12,0x34,0x81,0x80,  // ID, Flags
        0x00,0x01,  // QDCOUNT=1
        0x00,0x03,  // ANCOUNT=3
        0x00,0x00,  // NSCOUNT=0
        0x00,0x00,  // ARCOUNT=0
        
        // Query: www.example.com
        0x03, 'w','w','w',  // 3字节 + 'www'
        0x07, 'e','x','a','m','p','l','e',  // 7字节 + 'example'
        0x03, 'c','o','m',  // 3字节 + 'com'
        0x00,  // 结束符
        0x00,0x01,  // QTYPE=A
        0x00,0x01,  // QCLASS=IN
        
        // Answer 1: CNAME cname.example.com
        0xc0,0x0c,  // 压缩指针 -> 位置12 (www.example.com)
        0x00,0x05,  // Type=CNAME
        0x00,0x01,  // Class=IN
        0x00,0x00,0x01,0x2c,  // TTL=300
        0x00,0x11,  // RDLEN=17 (04 63 6e 61 6d 65 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 = 1+4+1+7+1+3+1 = 18? 等等)
        // cname.example.com = 4(cname) + 7(example) + 3(com) + 1(.) + 1(结束) = 16字节? 不对
        // 04 63 6e 61 6d 65 (cname) = 6字节
        // 07 65 78 61 6d 70 6c 65 (example) = 8字节
        // 03 63 6f 6d (com) = 4字节
        // 00 (结束) = 1字节
        // 总共: 19字节
    };
    
    /* 完整构建 */
    uint8_t full[256];
    int p = 0;
    
    // Header
    full[p++] = 0x12; full[p++] = 0x34; full[p++] = 0x81; full[p++] = 0x80;
    full[p++] = 0x00; full[p++] = 0x01;  // QDCOUNT
    full[p++] = 0x00; full[p++] = 0x03;  // ANCOUNT
    full[p++] = 0x00; full[p++] = 0x00;  // NSCOUNT
    full[p++] = 0x00; full[p++] = 0x00;  // ARCOUNT
    
    // Query: www.example.com
    int query_start = p;
    full[p++] = 0x03; memcpy(full+p, "www", 3); p += 3;
    full[p++] = 0x07; memcpy(full+p, "example", 7); p += 7;
    full[p++] = 0x03; memcpy(full+p, "com", 3); p += 3;
    full[p++] = 0x00;
    full[p++] = 0x00; full[p++] = 0x01;  // QTYPE
    full[p++] = 0x00; full[p++] = 0x01;  // QCLASS
    int query_end = p;
    
    // Answer 1: CNAME cname.example.com
    int ans1_start = p;
    full[p++] = 0xc0; full[p++] = 0x0c;  // 压缩指针 -> 位置12
    full[p++] = 0x00; full[p++] = 0x05;  // Type=CNAME
    full[p++] = 0x00; full[p++] = 0x01;  // Class=IN
    full[p++] = 0x00; full[p++] = 0x00; full[p++] = 0x01; full[p++] = 0x2c;  // TTL=300
    full[p++] = 0x00; full[p++] = 0x13;  // RDLEN=19
    // CNAME数据: cname.example.com
    full[p++] = 0x04; memcpy(full+p, "cname", 5); p += 5;  // 04 + cname = 6字节
    full[p++] = 0x07; memcpy(full+p, "example", 7); p += 7;  // 07 + example = 8字节
    full[p++] = 0x03; memcpy(full+p, "com", 3); p += 3;  // 03 + com = 4字节
    full[p++] = 0x00;  // 结束符 = 1字节
    int ans1_end = p;
    
    // Answer 2: A 182.131.26.231
    int ans2_start = p;
    full[p++] = 0xc0; full[p++] = 0x2a;  // 压缩指针 -> 位置42
    full[p++] = 0x00; full[p++] = 0x01;  // Type=A
    full[p++] = 0x00; full[p++] = 0x01;  // Class=IN
    full[p++] = 0x00; full[p++] = 0x00; full[p++] = 0x01; full[p++] = 0x2c;  // TTL=300
    full[p++] = 0x00; full[p++] = 0x04;  // RDLEN=4
    full[p++] = 0xb6; full[p++] = 0x83; full[p++] = 0x1a; full[p++] = 0xe7;  // IP
    int ans2_end = p;
    
    // Answer 3: A 5.6.7.8
    int ans3_start = p;
    full[p++] = 0xc0; full[p++] = 0x2a;  // 压缩指针 -> 位置42
    full[p++] = 0x00; full[p++] = 0x01;  // Type=A
    full[p++] = 0x00; full[p++] = 0x01;  // Class=IN
    full[p++] = 0x00; full[p++] = 0x00; full[p++] = 0x01; full[p++] = 0x2c;  // TTL=300
    full[p++] = 0x00; full[p++] = 0x04;  // RDLEN=4
    full[p++] = 0x05; full[p++] = 0x06; full[p++] = 0x07; full[p++] = 0x08;  // IP
    
    printf("构建的测试数据:\n");
    printf("Header: 0-11\n");
    printf("Query: %d-%d (长度%d)\n", query_start, query_end-1, query_end-query_start);
    printf("Answer1: %d-%d (长度%d)\n", ans1_start, ans1_end-1, ans1_end-ans1_start);
    printf("Answer2: %d-%d (长度%d)\n", ans2_start, ans2_end-1, ans2_end-ans2_start);
    printf("Answer3: %d-%d (长度%d)\n", ans3_start, p-1, p-ans3_start);
    
    printf("\n关键位置验证:\n");
    printf("位置42: 0x%02x (应该是Answer1头部的一部分)\n", full[42]);
    printf("位置%d (Answer2开始): 0x%02x 0x%02x\n", ans2_start, full[ans2_start], full[ans2_start+1]);
    
    printf("\n=== 修复方案 ===\n");
    printf("保留: Header + Query + Answer1 + Answer2\n");
    printf("新长度: %d\n", ans2_end);
    
    uint8_t fixed[256];
    memcpy(fixed, full, query_end);  // Header + Query
    memcpy(fixed + query_end, full + query_end, ans1_end - query_end);  // Answer1
    memcpy(fixed + ans1_end, full + ans2_start, ans2_end - ans2_start);  // Answer2
    
    DNSHeader *hdr = (DNSHeader *)fixed;
    hdr->ancount = htons(2);
    
    printf("\n修复后数据:\n");
    for (int i = 0; i < ans2_end; i++) {
        printf("%02x ", fixed[i]);
        if ((i+1) % 16 == 0) printf("\n");
    }
    printf("\n");
    
    printf("\n验证Answer2压缩指针:\n");
    printf("Answer2位置: %d\n", ans1_end);
    printf("Answer2前2字节: 0x%02x 0x%02x\n", fixed[ans1_end], fixed[ans1_end+1]);
    int ptr = ((fixed[ans1_end] & 0x3F) << 8) | fixed[ans1_end+1];
    printf("压缩指针 -> 位置%d\n", ptr);
    printf("位置%d内容: 0x%02x 0x%02x 0x%02x\n", ptr, fixed[ptr], fixed[ptr+1], fixed[ptr+2]);
    
    if (ptr >= 12 && ptr < ans1_end) {
        printf("✓ 有效\n");
    } else {
        printf("❌ 无效\n");
    }
    
    return 0;
}
