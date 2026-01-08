#!/usr/bin/env python3
"""
调试DNS查询 - 验证缓存响应是否能正确返回
"""
import socket
import struct
import time

def build_dns_query(domain, tid=0x1234):
    """构建DNS查询"""
    flags = 0x0100  # 递归查询
    header = struct.pack(">HHHHHH", tid, flags, 1, 0, 0, 0)

    qname = b""
    for part in domain.split("."):
        qname += struct.pack("B", len(part)) + part.encode()
    qname += b"\x00"

    question = qname + struct.pack(">HH", 0x0001, 0x0001)
    return header + question

def parse_dns_response(data):
    """简单解析DNS响应"""
    if len(data) < 12:
        return None

    tid, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])

    print(f"  DNS响应 - ID: {tid}, Flags: {flags:04x}, Answers: {ancount}")

    if ancount > 0:
        return f"包含 {ancount} 个回答记录"
    else:
        return "无回答记录"

def test_dns_query(dns_ip, dns_port, domain, iface="tun0"):
    """测试单个DNS查询"""
    print(f"\n测试 {dns_ip}:{dns_port}...")

    try:
        # 创建UDP套接字
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # 绑定网卡
        if iface:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode())

        sock.settimeout(6)

        # 构建查询
        query = build_dns_query(domain)

        # 发送
        print(f"  发送查询到 {dns_ip}:{dns_port} (大小: {len(query)} bytes)")
        sock.sendto(query, (dns_ip, dns_port))

        # 接收
        start = time.time()
        response, addr = sock.recvfrom(1024)
        elapsed = (time.time() - start) * 1000

        print(f"  ✅ 收到响应 from {addr} (大小: {len(response)} bytes, 耗时: {elapsed:.1f}ms)")

        # 解析
        result = parse_dns_response(response)
        print(f"  {result}")

        # 检查是否包含优化后的IP
        hex_response = response.hex()
        if "182.131.26.231" in hex_response or "42.83.144.13" in hex_response:
            print("  ⚠️  响应包含优化IP（可能是缓存/优化响应）")

        sock.close()
        return True

    except socket.timeout:
        print(f"  ❌ 超时（6秒未收到响应）")
        return False
    except Exception as e:
        print(f"  ❌ 错误: {e}")
        return False

if __name__ == "__main__":
    domain = "www.cnnic.com.cn"
    dns_servers = [
        ("119.29.29.29", 53),      # 国内
        ("114.114.114.114", 53),   # 国内
        ("8.8.8.8", 53),           # 国外
        ("8.8.4.4", 53),           # 国外
        ("1.1.1.1", 53),           # 国外
    ]

    print("=" * 60)
    print("DNS查询调试测试")
    print(f"目标域名: {domain}")
    print(f"网卡: tun0")
    print("=" * 60)

    # 第一轮 - 建立缓存
    print("\n【第一轮】建立DNS缓存")
    for dns_ip, dns_port in dns_servers:
        test_dns_query(dns_ip, dns_port, domain)

    print("\n" + "=" * 60)
    print("等待2秒...")
    time.sleep(2)

    # 第二轮 - 测试缓存
    print("\n【第二轮】测试DNS缓存")
    for dns_ip, dns_port in dns_servers:
        test_dns_query(dns_ip, dns_port, domain)