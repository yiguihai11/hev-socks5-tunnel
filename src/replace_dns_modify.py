#!/usr/bin/env python3
import re

# 读取原文件
with open('hev-dns-latency.c', 'r', encoding='utf-8') as f:
    content = f.read()

# 定义新函数
new_function = '''int
hev_dns_latency_modify_response (uint8_t *data, size_t *len,
                                 const ip_addr_t *best_ip)
{
    if (!data || !len || !best_ip || *len < sizeof (DNSHeader))
        return -1;

    DNSHeader *hdr = (DNSHeader *)data;
    uint16_t ancount = ntohs (hdr->ancount);

    if (ancount == 0)
        return 0;

    /* Skip query section */
    size_t pos = sizeof (DNSHeader);
    uint16_t qdcount = ntohs (hdr->qdcount);

    for (int i = 0; i < qdcount && pos < *len; i++) {
        char domain[256];
        if (parse_dns_name (data, *len, &pos, domain, sizeof (domain)) < 0)
            return -1;
        if (pos + 4 > *len)
            return -1;
        pos += 4;
    }

    /* 遍历所有Answer，找到目标并记录需要保留的数量 */
    size_t first_answer_pos = pos;
    size_t keep_end_pos = pos;
    int keep_count = 0;
    int found = 0;

    for (int i = 0; i < ancount && pos < *len; i++) {
        size_t answer_start = pos;
        char domain[256];

        if (parse_dns_name (data, *len, &pos, domain, sizeof (domain)) < 0)
            break;

        if (pos + 10 > *len)
            break;

        uint16_t rtype = read_uint16 (data + pos);
        uint16_t rdlen = read_uint16 (data + pos + 8);
        pos += 10;

        if (pos + rdlen > *len)
            break;

        /* Check if this answer matches best_ip */
        int match = 0;
        if (IP_IS_V4 (best_ip) && rtype == DNS_TYPE_A && rdlen == 4) {
            ip_addr_t ip;
            IP_ADDR4 (&ip, data[pos], data[pos + 1], data[pos + 2],
                      data[pos + 3]);
            if (ip_addr_cmp (&ip, best_ip))
                match = 1;
        } else if (IP_IS_V6 (best_ip) && rtype == DNS_TYPE_AAAA &&
                   rdlen == 16) {
            ip_addr_t ip;
            memset (&ip, 0, sizeof (ip));
            memcpy (ip_2_ip6 (&ip)->addr, data + pos, 16);
            ip.type = IPADDR_TYPE_V6;
            if (ip_addr_cmp (&ip, best_ip))
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
        LOG_W ("dns-latency: Best IP not found in DNS response");
        return -1;
    }

    /* 更新长度和ANCOUNT - 保留CNAME链 */
    *len = keep_end_pos;
    hdr->ancount = htons (keep_count);

    LOG_I ("dns-latency: Modified DNS response, kept %d answers (len=%zu)",
           keep_count, *len);

    return 0;
}
'''

# 查找并替换函数
pattern = r'int\nhev_dns_latency_modify_response \(uint8_t \*data, size_t \*len,\n                                 const ip_addr_t \*best_ip\)\n\{[^}]+\n    return 0;\n\}'
match = re.search(pattern, content, re.DOTALL)

if match:
    print(f"找到原函数，位置: {match.start()}-{match.end()}")
    print(f"原函数长度: {len(match.group())} 字符")
    
    # 替换
    new_content = content[:match.start()] + new_function + content[match.end():]
    
    # 写回
    with open('hev-dns-latency.c', 'w', encoding='utf-8') as f:
        f.write(new_content)
    
    print("✓ 函数已成功替换")
else:
    print("✗ 未找到原函数")
