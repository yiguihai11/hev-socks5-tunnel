import socket
import struct
import ssl
import ipaddress
import subprocess
import time
import os
import signal
import argparse  # 新增：导入命令行参数解析模块

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
        if 'sock' in locals():  # 新增：避免未定义sock时调用close
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
            return "失败！无响应数据"
        response = response_data.decode('utf-8', errors='ignore')
        lines = response.splitlines()
        if not lines:
            return "失败！响应解析失败：无行数据"
        status_line = lines[0].split()
        if len(status_line) < 2:
            return "失败！响应解析失败：无效状态行"
        status_code = status_line[1]
        
        if status_code == '200' or status_code == '204':
            return f"成功！HTTP状态码：{status_code}"
        else:
            return f"失败！非预期HTTP状态码：{status_code}"
    except ConnectionResetError:
        return "失败！连接被重置（可能被ACL阻止）"
    except socket.timeout:
        return f"超时：{timeout}秒内未完成连接/接收"
    except ssl.SSLError as e:
        return f"SSL错误：{str(e)}"
    except PermissionError:
        return f"权限不足：绑定{iface}需root权限，请用sudo运行"
    except Exception as e:
        return f"测试失败：{str(e)}"
    finally:
        if 'sock' in locals():  # 新增：避免未定义sock时调用close
            sock.close()

def test_tcp_connect(target_domain, target_ip, ports, iface=None, timeout=3):
    print(f"\n=== 开始 TCP 连接测试（目标域名：{target_domain}）===")
    print(f"目标配置：{target_domain} → {target_ip}，端口{ports}，绑定网卡{iface}\n")
    for port in ports:
        print(f"测试 {target_ip}:{port}（映射域名：{target_domain}）...")
        result = _test_single_tcp(target_domain, target_ip, port, iface, timeout)
        print(f"  {'✅' if '成功' in result else '❌'} {result}\n")

# ---------------------- 核心逻辑（新增参数控制是否启动隧道） ----------------------
# 新增参数：start_tunnel（布尔值），True=启动隧道（默认），False=不启动隧道
def run_hev_tunnel_and_test(iface="tun0", start_tunnel=True):
    tunnel_process = None  # 初始化进程变量，避免后续引用错误
    script_dir = os.path.dirname(os.path.abspath(__file__))
    tunnel_exe = os.path.join(script_dir, "bin", "hev-socks5-tunnel")
    tunnel_conf = os.path.join(script_dir, "conf", "main.yml")

    # 仅当 start_tunnel 为 True 时，才启动隧道进程
    if start_tunnel:
        # 检查隧道程序是否存在（新增容错）
        if not os.path.exists(tunnel_exe):
            print(f"⚠️  警告：未找到隧道程序 {tunnel_exe}，跳过启动隧道")
            start_tunnel = False  # 标记为未启动，后续不处理进程
        else:
            tunnel_cmd = [tunnel_exe, tunnel_conf]
            tunnel_process = subprocess.Popen(
                tunnel_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=script_dir
            )
            time.sleep(1)
            print("=== hev-socks5-tunnel 启动完成（若未启动，检查程序路径）===\n")
            print(f"当前隧道进程状态：{'存活' if tunnel_process.poll() is None else '已退出'}\n")
    else:
        # 不启动隧道时，明确提示用户
        print("=== 已跳过启动 hev-socks5-tunnel（通过 --no-start-tunnel 参数控制）===\n")
        print(f"⚠️  注意：当前绑定网卡为 {iface}，请确保该网卡已存在（可通过 `ip link show` 确认）\n")

    try:
        # 1. DNS 服务器测试（无论是否启动隧道，都执行测试）
        print("=== 准备执行DNS测试：隧道进程状态 -> " + 
              (f"存活" if (start_tunnel and tunnel_process and tunnel_process.poll() is None) else "未启动") + " ===")
        DNS_SERVERS = [
            ("119.29.29.29", 53), ("114.114.114.114", 53), ("8.8.8.8", 53),
            ("8.8.4.4", 53), ("1.1.1.1", 53), ("2001:4860:4860::8844", 53),
            ("2606:4700:4700::1111", 53)
        ]
        TARGET_DOMAIN_DNS = "music.163.com"
        test_dns_servers(DNS_SERVERS, TARGET_DOMAIN_DNS, iface=iface)

        # 2. Cloudflare TCP 测试
        print("=== 准备执行Cloudflare TCP测试：隧道进程状态 -> " + 
              (f"存活" if (start_tunnel and tunnel_process and tunnel_process.poll() is None) else "未启动") + " ===")
        TCP_PARAMS_CF = {
            "target_domain": "cp.cloudflare.com",
            "target_ip": "104.16.133.229",
            "ports": [80, 443],
            "iface": iface,
            "timeout": 3
        }
        test_tcp_connect(**TCP_PARAMS_CF)

        # 3. vivo TCP 测试
        print("=== 准备执行vivo TCP测试：隧道进程状态 -> " + 
              (f"存活" if (start_tunnel and tunnel_process and tunnel_process.poll() is None) else "未启动") + " ===")
        TCP_PARAMS_VIVO = {
            "target_domain": "wifi.vivo.com.cn",
            "target_ip": "39.136.191.59",
            "ports": [80, 443],
            "iface": iface,
            "timeout": 3
        }
        test_tcp_connect(**TCP_PARAMS_VIVO)

        # 仅当启动了隧道进程时，才处理进程终止和输出读取
        if start_tunnel and tunnel_process:
            print("\n=== 测试完成，开始处理隧道进程 ===")
            if tunnel_process.poll() is None:
                os.kill(tunnel_process.pid, signal.SIGTERM)
                print(f"已发送终止信号到隧道进程（PID：{tunnel_process.pid}）")
            tunnel_output = tunnel_process.stdout.read()
            print("\n=== hev-socks5-tunnel 运行期间输出 ===")
            print(tunnel_output if tunnel_output else "（进程无额外输出）")

    finally:
        # 仅当启动了隧道进程时，才做强制终止保险
        if start_tunnel and tunnel_process and tunnel_process.poll() is None:
            os.kill(tunnel_process.pid, signal.SIGKILL)
            print(f"\n=== 强制终止残留隧道进程（PID：{tunnel_process.pid}）===")
        elif start_tunnel and tunnel_process:
            print(f"\n=== 隧道进程已正常退出（退出码：{tunnel_process.returncode}）===")
        else:
            print(f"\n=== 未启动隧道进程，无需终止 ===")

# ---------------------- 主程序入口（新增命令行参数解析） ----------------------
if __name__ == "__main__":
    # 1. 创建参数解析器
    parser = argparse.ArgumentParser(description="hev-socks5-tunnel 网络测试脚本")
    # 2. 添加参数：--no-start-tunnel（无需传值，加了就代表“不启动隧道”）
    parser.add_argument(
        "--no-start-tunnel",
        action="store_true",  # 布尔参数：加了该参数则为True，否则为False
        help="不启动 hev-socks5-tunnel，仅执行DNS和TCP测试（默认：启动隧道）"
    )
    # 3. 解析命令行参数
    args = parser.parse_args()

    # 4. 配置参数并执行核心逻辑
    IFACE = "tun0"  # 可通过 `ip link show` 确认实际网卡名
    # 控制是否启动隧道：args.no_start_tunnel 为 True → 不启动（start_tunnel=False）
    run_hev_tunnel_and_test(iface=IFACE, start_tunnel=not args.no_start_tunnel)
