#include <stdio.h>

int main() {
    /* 测试2原始数据 */
    unsigned char orig2[] = {
        0x12,0x34,0x81,0x80, 0x00,0x01,0x00,0x03, 0x00,0x00,0x00,0x00,  // 0-11
        0x03,0x77,0x77,0x77, 0x07,0x65,0x78,0x61, 0x6d,0x70,0x6c,0x65, 0x03,0x63,0x6f,0x6d, 0x00,  // 12-28
        0x00,0x01,0x00,0x01,  // 29-32
        0xc0,0x0c,0x00,0x05,0x00,0x01,0x00,0x00,0x01,0x2c,0x00,0x0e,  // 33-44
        0x04,0x63,0x6e,0x61,0x6d,0x65, 0x07,0x65,0x78,0x61,0x6d,0x70,0x6c,0x65, 0x03,0x63,0x6f,0x6d, 0x00,  // 45-58
        0xc0,0x2a,0x00,0x01,0x00,0x01,0x00,0x00,0x01,0x2c,0x00,0x04,0xb6,0x83,0x1a,0xe7,  // 59-74
        0xc0,0x2a,0x00,0x01,0x00,0x01,0x00,0x00,0x01,0x2c,0x00,0x04,0x05,0x06,0x07,0x08,  // 75-90
    };
    
    printf("逐字节分析:\n");
    printf("位置0-11: Header\n");
    printf("位置12-28: Query域名\n");
    printf("位置29-32: Query尾部\n");
    printf("位置33-44: Answer1头部\n");
    printf("位置45-58: Answer1数据\n");
    printf("位置59-74: Answer2\n");
    
    printf("\n位置59-60实际值: %02x %02x\n", orig2[59], orig2[60]);
    printf("位置42实际值: %02x\n", orig2[42]);
    
    printf("\n重新计算:\n");
    printf("Answer1从位置33开始\n");
    printf("Answer1: c0 0c (2字节) + 10字节头部 + 14字节数据 = 26字节\n");
    printf("Answer1结束位置: 33 + 26 = 59\n");
    printf("Answer2从位置59开始\n");
    printf("位置59应该是Answer2的压缩指针\n");
    printf("但实际位置59-60是: %02x %02x\n", orig2[59], orig2[60]);
    
    printf("\n检查Answer1数据结束位置:\n");
    printf("Answer1数据从位置45开始，长度14字节\n");
    printf("Answer1数据结束: 45 + 14 = 59\n");
    printf("位置59的值: %02x\n", orig2[59]);
    
    printf("\nAnswer2应该从位置59开始\n");
    printf("位置59-60: %02x %02x\n", orig2[59], orig2[60]);
    printf("如果是压缩指针c0 2a，应该是: c0 2a\n");
    printf("但实际是: %02x %02x\n", orig2[59], orig2[60]);
    
    printf("\n让我检查整个Answer1的结束位置:\n");
    printf("位置33-34: c0 0c\n");
    printf("位置35-44: 00 05 00 01 00 00 01 2c 00 0e\n");
    printf("位置45-58: 04 63 6e 61 6d 65 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00\n");
    printf("位置59: %02x\n", orig2[59]);
    
    return 0;
}
