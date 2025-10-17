import socket
import struct
import ssl
import ipaddress
import subprocess
import time
import os
import signal

# ---------------------- 基础功能函数（完整保留，确保无遗漏） ----------------------
def build_dns_query(domain):
    tid = 0x1234
    flags = 0x0100
    header = struct.pack(">HHHHHH", tid, flags, 1, 0, 0, 0)
    qname = b""
    for part in domain.split("."):
        qname += struct.pack("B", len(part)) + part.encode("utf-8")
    qname += b"\x00"
    question = qname + struct.pack(">HH", 0x0001, 0x0001)
    return header + question

def _test_single_dns(dns_ip, dns_port, query, iface, timeout):
    try:
        ip = ipaddress.ip_address(dns_ip)
        family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        if iface:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode())
        sock.settimeout(timeout)
        sent_bytes = sock.sendto(query, (dns_ip, dns_port))
        if sent_bytes != len(query):
            return f"发送不完整：预期{len(query)}字节，实际{sent_bytes}字节"
        response, addr = sock.recvfrom(1024)
        return f"成功！收到响应（{len(response)}字节），Hex前32位：{response.hex()[:32]}..."
    except socket.timeout:
        return "超时：3秒内未收到响应"
    except PermissionError:
        return f"权限不足：绑定{iface}需root权限，请用sudo运行"
    except Exception as e:
        return f"测试失败：{str(e)}"
    finally:
        sock.close()

def test_dns_servers(dns_servers, domain, iface=None, timeout=3):
    query = build_dns_query(domain)
    print(f"=== 开始测试 DNS 服务器（目标域名：{domain}，绑定网卡：{iface}）===\n")
    for dns_ip, dns_port in dns_servers:
        print(f"测试 {dns_ip}:{dns_port}...")
        result = _test_single_dns(dns_ip, dns_port, query, iface, timeout)
        print(f"  {'✅' if '成功' in result else '❌'} {result}\n")

def _test_single_tcp(target_domain, target_ip, port, iface, timeout):
    try:
        ip = ipaddress.ip_address(target_ip)
        family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        if iface:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode())
        sock.settimeout(timeout)
        sock.connect((target_ip, port))
        if port == 443:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=target_domain)
        http_request = (
            f"GET /generate_204 HTTP/1.1\r\n"
            f"Host: {target_domain}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        sock.sendall(http_request)
        response_data = sock.recv(1024)
        if not response_data:
            return "无响应数据"
        response = response_data.decode('utf-8', errors='ignore')
        lines = response.splitlines()
        if not lines:
            return "响应解析失败：无行数据"
        status_line = lines[0].split()
        if len(status_line) < 2:
            return "响应解析失败：无效状态行"
        status_code = status_line[1]
        return f"成功！HTTP状态码：{status_code}"
    except socket.timeout:
        return f"超时：{timeout}秒内未完成连接/接收"
    except ssl.SSLError as e:
        return f"SSL错误：{str(e)}"
    except PermissionError:
        return f"权限不足：绑定{iface}需root权限，请用sudo运行"
    except Exception as e:
        return f"测试失败：{str(e)}"
    finally:
        sock.close()

def test_tcp_connect(target_domain, target_ip, ports, iface=None, timeout=3):
    print(f"\n=== 开始 TCP 连接测试（目标域名：{target_domain}）===")
    print(f"目标配置：{target_domain} → {target_ip}，端口{ports}，绑定网卡{iface}\n")
    for port in ports:
        print(f"测试 {target_ip}:{port}（映射域名：{target_domain}）...")
        result = _test_single_tcp(target_domain, target_ip, port, iface, timeout)
        print(f"  {'✅' if '成功' in result else '❌'} {result}\n")

# ---------------------- 核心逻辑（整合修复+新增隧道状态实时检测） ----------------------
def run_hev_tunnel_and_test(iface="tun0"):
    # 修复1：自动获取脚本所在绝对目录，不管在哪运行都能找到bin/conf
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # 拼接隧道程序和配置文件的绝对路径
    tunnel_exe = os.path.join(script_dir, "bin", "hev-socks5-tunnel")
    tunnel_conf = os.path.join(script_dir, "conf", "main.yml")
    tunnel_cmd = [tunnel_exe, tunnel_conf]

    # 启动隧道进程（执行目录设为脚本目录，确保依赖路径正确）
    tunnel_process = subprocess.Popen(
        tunnel_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        cwd=script_dir  # 关键：执行目录锁定为脚本所在目录
    )
    
    # 给进程启动留1秒准备时间
    time.sleep(1)
    print("=== hev-socks5-tunnel 启动完成，开始执行网络测试 ===\n")
    # 初始状态检测：明确启动后隧道是否存活
    print(f"当前隧道进程状态：{'存活' if tunnel_process.poll() is None else '已退出'}\n")

    try:
        # 1. 执行DNS服务器测试（前加状态检测，验证测试前隧道未关闭）
        print("=== 准备执行DNS测试：隧道进程状态 -> " + 
              f"{'存活' if tunnel_process.poll() is None else '已退出'} ===")
        DNS_SERVERS = [
            ("119.29.29.29", 53), ("114.114.114.114", 53), ("8.8.8.8", 53),
            ("8.8.4.4", 53), ("1.1.1.1", 53), ("2001:4860:4860::8844", 53),
            ("2606:4700:4700::1111", 53)
        ]
        TARGET_DOMAIN_DNS = "music.163.com"
        test_dns_servers(DNS_SERVERS, TARGET_DOMAIN_DNS, iface=iface)

        # 2. 执行Cloudflare TCP测试（前加状态检测，核心验证点）
        print("=== 准备执行Cloudflare TCP测试：隧道进程状态 -> " + 
              f"{'存活' if tunnel_process.poll() is None else '已退出'} ===")
        TCP_PARAMS_CF = {
            "target_domain": "cp.cloudflare.com",
            "target_ip": "104.16.133.229",
            "ports": [80, 443],
            "iface": iface,
            "timeout": 3
        }
        test_tcp_connect(**TCP_PARAMS_CF)

        # 3. 执行vivo TCP测试（前加状态检测，再次验证）
        print("=== 准备执行vivo TCP测试：隧道进程状态 -> " + 
              f"{'存活' if tunnel_process.poll() is None else '已退出'} ===")
        TCP_PARAMS_VIVO = {
            "target_domain": "wifi.vivo.com.cn",
            "target_ip": "39.136.191.59",
            "ports": [80, 443],
            "iface": iface,
            "timeout": 3
        }
        test_tcp_connect(**TCP_PARAMS_VIVO)

        # 修复2：先杀进程再读输出，彻底解决阻塞问题
        print("\n=== 测试完成，开始处理隧道进程 ===")
        # 先终止隧道进程
        if tunnel_process.poll() is None:
            os.kill(tunnel_process.pid, signal.SIGTERM)
            print(f"已发送终止信号到隧道进程（PID：{tunnel_process.pid}）")
        # 进程死后读取输出，不会阻塞
        tunnel_output = tunnel_process.stdout.read()
        print("\n=== hev-socks5-tunnel 运行期间输出 ===")
        print(tunnel_output if tunnel_output else "（进程无额外输出）")

    finally:
        # 双重保险：确保进程已退出
        if tunnel_process.poll() is None:
            os.kill(tunnel_process.pid, signal.SIGKILL)
            print(f"\n=== 强制终止残留隧道进程（PID：{tunnel_process.pid}）===")
        else:
            print(f"\n=== 隧道进程已正常退出（退出码：{tunnel_process.returncode}）===")

# ---------------------- 主程序入口 ----------------------
if __name__ == "__main__":
    # 配置绑定网卡（根据实际情况调整，先解决之前的"No such device"问题）
    IFACE = "tun0"  # 建议先通过`ip link show`确认存在的网卡名
    # 一键执行所有流程
    run_hev_tunnel_and_test(iface=IFACE)
