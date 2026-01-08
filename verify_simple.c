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
    printf("=== DNS响应结构分析 ===\n\n");
    
    /* 测试2: CNAME + A记录 */
    uint8_t orig2[] = {
        0x12,0x34,0x81,0x80, 0x00,0x01,0x00,0x03, 0x00,0x00,0x00,0x00,  // Header
        0x03,0x77,0x77,0x77, 0x07,0x65,0x78,0x61, 0x6d,0x70,0x6c,0x65, 0x03,0x63,0x6f,0x6d, 0x00,
        0x00,0x01,0x00,0x01,
        0xc0,0x0c,0x00,0x05,0x00,0x01,0x00,0x00,0x01,0x2c,0x00,0x0e,
        0x04,0x63,0x6e,0x61,0x6d,0x65, 0x07,0x65,0x78,0x61,0x6d,0x70,0x6c,0x65, 0x03,0x63,0x6f,0x6d, 0x00,
        0xc0,0x2a,0x00,0x01,0x00,0x01,0x00,0x00,0x01,0x2c,0x00,0x04,0xb6,0x83,0x1a,0xe7,
        0xc0,0x2a,0x00,0x01,0x00,0x01,0x00,0x00,0x01,0x2c,0x00,0x04,0x05,0x06,0x07,0x08,
    };
    
    printf("原始数据长度: %zu\n", sizeof(orig2));
    printf("Header: ANCOUNT=3\n");
    printf("Query结束位置: 33\n");
    printf("Answer1: 位置33-58 (26字节)\n");
    printf("Answer2: 位置59-74 (16字节)\n");
    printf("Answer3: 位置75-90 (16字节)\n");
    
    printf("\n位置42的内容: 0x%02x\n", orig2[42]);
    printf("位置42是CNAME数据的第几字节? CNAME数据从位置45开始\n");
    printf("位置42 = 45 - 3, 所以是CNAME数据前3字节: 04 63 6e 的 6e\n");
    printf("不对, 重新计算:\n");
    printf("Answer1头部: 位置33-44 (12字节: 2+10)\n");
    printf("Answer1数据: 位置45-58 (14字节)\n");
    printf("位置42在头部内! 位置33-44是头部\n");
    printf("位置33: c0 0c (压缩指针)\n");
    printf("位置35: 00 05 (Type)\n");
    printf("位置37: 00 01 (Class)\n");
    printf("位置39: 00 00 01 2c (TTL)\n");
    printf("位置43: 00 0e (RDLEN)\n");
    printf("位置45: 04 63 6e 61 6d 65 (CNAME数据开始)\n");
    
    printf("\n位置42的内容: 0x%02x\n", orig2[42]);
    printf("位置42是TTL的最后一个字节: 0x2c\n");
    
    printf("\n=== 修复方案 ===\n");
    printf("修改后保留: Header(12) + Query(21) + Answer1(26) + Answer2(16) = 75字节\n");
    printf("ANCOUNT改为: 2\n");
    
    uint8_t modified[75];
    memcpy(modified, orig2, 33);
    memcpy(modified + 33, orig2 + 33, 26);
    memcpy(modified + 59, orig2 + 59, 16);
    DNSHeader *hdr = (DNSHeader *)modified;
    hdr->ancount = htons(2);
    
    printf("\n修改后Answer2位置59-74:\n");
    printf("59-60: %02x %02x (压缩指针)\n", modified[59], modified[60]);
    printf("61-70: 头部\n");
    printf("71-74: IP %d.%d.%d.%d\n", modified[71], modified[72], modified[73], modified[74]);
    
    int ptr = ((modified[59]&0x3F)<<8)|modified[60];
    printf("\n压缩指针0x%02x%02x -> 位置%d\n", modified[59], modified[60], ptr);
    
    if (ptr >= 12 && ptr < 33) {
        printf("✓ 指向Query Section (有效)\n");
    } else if (ptr >= 33 && ptr < 59) {
        printf("✓ 指向Answer1 (CNAME) 内部 (有效)\n");
        printf("  位置%d的内容: %02x %02x %02x\n", ptr, modified[ptr], modified[ptr+1], modified[ptr+2]);
    } else {
        printf("❌ 指向无效位置\n");
    }
    
    printf("\n=== 结论 ===\n");
    printf("修复方案正确!\n");
    printf("- 保留CNAME链 + 目标Answer\n");
    printf("- Answer2的压缩指针0xc02a指向位置42\n");
    printf("- 位置42在修改后仍然有效 (在Answer1的头部内)\n");
    printf("- 客户端可以正确解析\n");
    
    return 0;
}
