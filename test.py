# 完整依赖模块导入（无需额外安装，Python标准库）
import socket
import struct
import ssl
import ipaddress
import subprocess
import time
import os
import signal
import argparse

# ---------------------- 全局配置（可根据实际环境调整） ----------------------
# 隧道进程全局变量：供终止函数访问
tunnel_process = None
# 核心配置项（根据实际路径/网卡修改）
TUNNEL_EXE_REL_PATH = "bin/hev-socks5-tunnel"  # 隧道程序相对脚本的路径
TUNNEL_CONF_REL_PATH = "conf/main.yml"          # 隧道配置文件相对路径
DEFAULT_IFACE = "tun0"                          # 默认绑定网卡（用`ip link show`确认）
TEST_DOMAIN_DNS = "music.163.com"               # DNS测试目标域名
DNS_SERVERS = [                                  # 待测试DNS服务器列表（可增删）
    ("119.29.29.29", 53),
    ("114.114.114.114", 53),
    ("8.8.8.8", 53),
    ("8.8.4.4", 53),
    ("1.1.1.1", 53),
    ("2001:4860:4860::8844", 53),
    ("2606:4700:4700::1111", 53)
]
TCP_TEST_CONFIGS = [                             # TCP测试配置（可增删目标）
    {
        "target_domain": "cp.cloudflare.com",
        "target_ip": "104.16.133.229",
        "ports": [80, 443],
        "timeout": 3
    },
    {
        "target_domain": "wifi.vivo.com.cn",
        "target_ip": "112.90.223.30",
        "ports": [80, 443],
        "timeout": 3
    }
]

# ---------------------- 核心：隧道三步终止函数（2→15→9，脚本自主调用） ----------------------
def auto_terminate_tunnel():
    """
    脚本自主终止隧道进程，按优先级发送信号：
    1. SIGINT(2)：模拟Ctrl+C，让隧道尝试优雅中断
    2. SIGTERM(15)：标准优雅终止信号（第一步失败后重试）
    3. SIGKILL(9)：强制终止兜底（前两步均失败）
    """
    global tunnel_process
    # 隧道不存在或已退出，直接返回
    if not tunnel_process or tunnel_process.poll() is not None:
        return

    pid = tunnel_process.pid
    print(f"\n=== 开始自动终止隧道进程（PID：{pid}），信号顺序：2→15→9 ===")

    # 第一步：发送SIGINT（信号2）
    print(f"1. 发送 SIGINT(2) → 隧道（模拟Ctrl+C中断）...")
    os.kill(pid, signal.SIGINT)
    time.sleep(3)  # 等待3秒，给隧道执行清理（会话终止、任务退出、资源释放）
    if tunnel_process.poll() is not None:
        print(f"✅ 成功：隧道被 SIGINT(2) 终止（退出码：{tunnel_process.returncode}）")
        return

    # 第二步：发送SIGTERM（信号15）（第一步失败后重试）
    print(f"2. SIGINT(2) 失败，发送 SIGTERM(15) → 隧道（优雅终止）...")
    os.kill(pid, signal.SIGTERM)
    time.sleep(1)
    if tunnel_process.poll() is not None:
        print(f"✅ 成功：隧道被 SIGTERM(15) 终止（退出码：{tunnel_process.returncode}）")
        return

    # 第三步：发送SIGKILL（信号9）（兜底强制终止，不可抗拒）
    print(f"3. SIGTERM(15) 失败，发送 SIGKILL(9) → 隧道（强制终止）...")
    os.kill(pid, signal.SIGKILL)
    time.sleep(0.5)
    if tunnel_process.poll() is not None:
        print(f"✅ 成功：隧道被 SIGKILL(9) 强制终止（退出码：{tunnel_process.returncode}）")
    else:
        print(f"❌ 异常：SIGKILL(9) 仍未终止，需手动执行 `kill -9 {pid}`")

# ---------------------- DNS测试核心函数 ----------------------
def build_dns_query(domain):
    """构建DNS查询包（A记录，递归查询）"""
    tid = 0x1234  # 事务ID（随机即可）
    flags = 0x0100  # 递归查询标记（RD=1）
    # 头部：事务ID(2B) + 标志(2B) + 问题数(2B) + 回答数(2B) + 权威数(2B) + 附加数(2B)
    header = struct.pack(">HHHHHH", tid, flags, 1, 0, 0, 0)
    # 问题部分：域名（按点分割，每个段前加长度字节）+ 终止符(0x00)
    qname = b""
    for part in domain.split("."):
        qname += struct.pack("B", len(part)) + part.encode("utf-8")
    qname += b"\x00"
    # 查询类型（A记录=0x0001）+ 查询类（IN=0x0001）
    question = qname + struct.pack(">HH", 0x0001, 0x0001)
    return header + question

def _parse_dns_name_labels(response, offset):
    """(辅助函数) 递归解析DNS名称，正确处理指针压缩。"""
    labels = []
    # 跟踪原始偏移量以处理指针跳转
    current_offset = offset
    while current_offset < len(response):
        length = response[current_offset]
        current_offset += 1
        # 检查是否为指针（前两位是11）
        if (length & 0xC0) == 0xC0:
            pointer = ((length & 0x3F) << 8) + response[current_offset]
            # 从指针位置递归解析，但主偏移量只前进2字节
            labels.extend(_parse_dns_name_labels(response, pointer)[0])
            current_offset += 1 # 指针本身占2字节
            return labels, current_offset
        # 名称段结束符
        if length == 0:
            return labels, current_offset
        # 读取标签内容
        labels.append(response[current_offset:current_offset + length])
        current_offset += length
    raise ValueError("解析DNS名称时超出响应边界")

def parse_dns_response(response):
    """(辅助函数) 解析完整的DNS响应，提取A、AAAA、CNAME记录。"""
    if len(response) < 12:
        raise ValueError("DNS响应头不完整")

    # 解析头部
    tid, flags, qdcount, ancount, _, _ = struct.unpack('>HHHHHH', response[:12])
    
    # 跳过问题区域
    offset = 12
    for _ in range(qdcount):
        _, offset = _parse_dns_name_labels(response, offset)
        offset += 4  # 跳过QTYPE (2B) 和 QCLASS (2B)

    # 解析回答区域
    records = []
    for _ in range(ancount):
        if offset >= len(response): break
        
        # 解析域名
        labels, offset = _parse_dns_name_labels(response, offset)
        name = b".".join(labels).decode("utf-8", errors="ignore")
        
        if offset + 10 > len(response): break
        
        # 解析RR头部：类型、类别、TTL、数据长度
        rr_type, _, _, rdlength = struct.unpack('>HHIH', response[offset:offset+10])
        offset += 10

        if offset + rdlength > len(response): break
        
        rdata_offset = offset
        
        record = {'name': name}
        # 根据记录类型解析数据
        if rr_type == 1 and rdlength == 4:  # A 记录
            record['type'] = 'A'
        elif rr_type == 28 and rdlength == 16:  # AAAA 记录
            record['type'] = 'AAAA'
        elif rr_type == 5:  # CNAME 记录
            record['type'] = 'CNAME'
        
        # 只有在是我们关心的类型时才添加到列表
        if 'type' in record:
            records.append(record)
            
        offset += rdlength # 移动到下一条记录

    return records

def _test_single_dns(dns_ip, dns_port, query, iface, timeout):
    """测试单个DNS服务器，并验证响应是否包含A、AAAA、CNAME记录中的至少一个。"""
    try:
        # 自动适配IPv4/IPv6
        ip = ipaddress.ip_address(dns_ip)
        family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
        # 创建UDP套接字
        sock = socket.socket(family, socket.SOCK_DGRAM)
        # 绑定指定网卡（需root权限）
        if iface:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode())
        sock.settimeout(timeout)

        # 发送DNS查询
        sock.sendto(query, (dns_ip, dns_port))
        
        # 接收响应
        response, _ = sock.recvfrom(1024)
        
        # 1. 检查响应大小
        if not response:
            return "失败：收到0字节的空响应"
        
        # 2. 检查响应是否合法
        # parse_dns_response 会在响应不合法时抛出异常，被外层的except捕获
        records = parse_dns_response(response)
        
        found_types = {r['type'] for r in records if 'type' in r}
        
        has_a = 'A' in found_types
        has_aaaa = 'AAAA' in found_types
        has_cname = 'CNAME' in found_types
        
        # 3. 根据记录完整性返回结果 (至少存在其中一个即可)
        if has_a or has_aaaa or has_cname:
            found_list = [t for t, h in [('A', has_a), ('AAAA', has_aaaa), ('CNAME', has_cname)] if h]
            return f"成功：收到{len(response)}字节响应，包含 {', '.join(found_list)} 记录"
        else:
            return f"失败：收到{len(response)}字节响应，但未找到 A、AAAA 或 CNAME 记录"

    except socket.timeout:
        return f"超时：{timeout}秒内未收到响应"
    except PermissionError:
        return f"权限不足：绑定网卡{iface}需用sudo运行脚本"
    except Exception as e: # This will catch ValueError from parse_dns_response
        return f"测试失败：响应不合法或解析失败 - {e}"
    finally:
        # 确保套接字关闭（避免资源泄漏）
        if 'sock' in locals():
            sock.close()

def test_dns_servers(iface=None, timeout=3):
    """批量测试所有配置的DNS服务器"""
    query = build_dns_query(TEST_DOMAIN_DNS)
    print(f"\n=== DNS测试开始（目标域名：{TEST_DOMAIN_DNS}，绑定网卡：{iface}）===")
    for dns_ip, dns_port in DNS_SERVERS:
        print(f"\n测试 {dns_ip}:{dns_port}...")
        result = _test_single_dns(dns_ip, dns_port, query, iface, timeout)
        print(f"  {'✅' if '成功' in result else '❌'} {result}")

# ---------------------- TCP（含HTTPS）测试核心函数 ----------------------
def _test_single_tcp(target_domain, target_ip, port, iface, timeout):
    """测试单个TCP端口的连接+请求能力（443端口自动走SSL）"""
    try:
        # 自动适配IPv4/IPv6
        ip = ipaddress.ip_address(target_ip)
        family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
        # 创建TCP套接字
        sock = socket.socket(family, socket.SOCK_STREAM)
        # 绑定指定网卡（需root权限）
        if iface:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode())
        sock.settimeout(timeout)

        # 连接目标IP:端口
        sock.connect((target_ip, port))
        # 443端口自动启用SSL/TLS（模拟HTTPS请求）
        if port == 443:
            context = ssl.create_default_context()  # 使用系统默认SSL配置
            sock = context.wrap_socket(sock, server_hostname=target_domain)  # 验证域名

        # 发送简单HTTP请求（用/generate_204端点，无返回体，适合测试）
        http_request = (
            f"GET /generate_204 HTTP/1.1\r\n"
            f"Host: {target_domain}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("utf-8")
        sock.sendall(http_request)

        # 接收响应并解析状态码
        response_data = sock.recv(1024)
        if not response_data:
            return "失败：连接成功但无响应数据"
        
        # 解析HTTP状态码（忽略编码错误，兼容非UTF-8响应）
        response = response_data.decode("utf-8", errors="ignore")
        status_line = response.splitlines()[0].strip()  # 第一行是状态行（如HTTP/1.1 204 No Content）
        if not status_line:
            return "失败：响应无状态行，格式异常"
        
        status_parts = status_line.split()
        if len(status_parts) < 2:
            return f"失败：状态行无效（内容：{status_line}）"
        
        status_code = status_parts[1]
        if status_code in ("200", "204"):
            return f"成功：HTTP状态码{status_code}（连接+请求正常）"
        else:
            return f"失败：HTTP状态码{status_code}（非预期响应）"

    except ConnectionRefusedError:
        return "失败：连接被拒绝（目标端口未开放）"
    except ConnectionResetError:
        return "失败：连接被重置（可能被防火墙/ACL拦截）"
    except socket.timeout:
        return f"超时：{timeout}秒内未完成连接/接收响应"
    except ssl.SSLError as e:
        return f"SSL错误：{str(e)}（如证书无效、协议不兼容）"
    except PermissionError:
        return f"权限不足：绑定网卡{iface}需用sudo运行脚本"
    except Exception as e:
        return f"测试失败：{str(e)}（如IP不可达、网络中断）"
    finally:
        # 确保套接字关闭（避免资源泄漏）
        if 'sock' in locals():
            sock.close()

def test_tcp_servers(iface=None):
    """批量测试所有配置的TCP目标"""
    print(f"\n=== TCP（含HTTPS）测试开始（绑定网卡：{iface}）===")
    for config in TCP_TEST_CONFIGS:
        target_domain = config["target_domain"]
        target_ip = config["target_ip"]
        ports = config["ports"]
        timeout = config["timeout"]
        
        print(f"\n测试目标：{target_domain}（{target_ip}）")
        for port in ports:
            print(f"\n  端口 {port}...")
            result = _test_single_tcp(target_domain, target_ip, port, iface, timeout)
            print(f"    {'✅' if '成功' in result else '❌'} {result}")

# ---------------------- 主逻辑（启动隧道→执行测试→终止隧道） ----------------------
def run_test_workflow(iface=DEFAULT_IFACE, start_tunnel=True):
    global tunnel_process
    # 获取脚本所在目录（确保隧道程序路径正确，不受运行目录影响）
    script_dir = os.path.dirname(os.path.abspath(__file__))
    tunnel_exe = os.path.join(script_dir, TUNNEL_EXE_REL_PATH)
    tunnel_conf = os.path.join(script_dir, TUNNEL_CONF_REL_PATH)
    tunnel_log_file = None

    try:
        # 第一步：启动隧道（仅当参数允许且程序存在）
        if start_tunnel:
            # 检查隧道程序是否存在
            if not os.path.exists(tunnel_exe):
                raise FileNotFoundError(f"隧道程序不存在：{tunnel_exe}（请检查TUNNEL_EXE_REL_PATH配置）")
            # 启动隧道进程（日志输出到文件避免PIPE阻塞）
            print(f"=== 启动 hev-socks5-tunnel（配置：{tunnel_conf}）===")
            log_file_path = os.path.join(script_dir, "tunnel.log")
            tunnel_log_file = open(log_file_path, "w")
            tunnel_process = subprocess.Popen(
                args=[tunnel_exe, tunnel_conf],
                stdout=tunnel_log_file,
                stderr=subprocess.STDOUT,  # 合并stderr到stdout
                text=True,
                cwd=script_dir
            )
            # 等待1秒，确保隧道进程启动完成（避免测试时隧道未就绪）
            time.sleep(1)
            # 检查隧道启动状态
            if tunnel_process.poll() is not None:
                raise RuntimeError(f"隧道启动失败（退出码：{tunnel_process.returncode}），请检查配置文件")
            print(f"✅ 隧道启动成功（PID：{tunnel_process.pid}，状态：存活）")

        # 第二步：执行网络测试（DNS + TCP）
        test_dns_servers(iface=iface)
        test_tcp_servers(iface=iface)

        # 第三步：测试完成后，主动终止隧道（核心逻辑）
        if start_tunnel:
            auto_terminate_tunnel()

    except Exception as e:
        # 测试/启动过程中出现异常，立即终止隧道（避免残留）
        print(f"\n⚠️  工作流异常中断：{str(e)}")
        if start_tunnel:
            print("立即终止隧道进程...")
            auto_terminate_tunnel()
        raise  # 保留异常抛出（便于用户排查问题，注释则不抛出）

    finally:
        # 双重兜底：确保隧道完全退出（极端情况三步终止失败时补充）
        if start_tunnel and tunnel_process:
            if tunnel_process.poll() is not None:
                print(f"\n=== 最终检查：隧道已退出（退出码：{tunnel_process.returncode}）===")
            else:
                print(f"\n=== 紧急兜底：隧道仍存活，强制发送 SIGKILL(9) ===")
                os.kill(tunnel_process.pid, signal.SIGKILL)
                print(f"✅ 兜底强制终止完成（PID：{tunnel_process.pid}）")
        else:
            print(f"\n=== 未启动隧道，无需终止 ===")

        # 关闭日志文件
        if tunnel_log_file:
            tunnel_log_file.close()

        # 读取并打印隧道运行日志（若有）
        if start_tunnel and tunnel_process:
            try:
                with open(log_file_path, "r") as f:
                    tunnel_log = f.read()
                if tunnel_log:
                    print(f"\n=== 隧道运行日志（最后100行）===")
                    lines = tunnel_log.splitlines()
                    for line in lines[-100:]:
                        print(line)
                else:
                    print(f"\n=== 隧道无运行日志 ===")
            except Exception as e:
                print(f"\n=== 读取日志文件失败：{e} ===")

# ---------------------- 命令行参数解析+程序入口 ----------------------
if __name__ == "__main__":
    # 创建参数解析器（支持--no-start-tunnel跳过隧道启动）
    parser = argparse.ArgumentParser(
        description="网络测试脚本（自动启动隧道+DNS/TCP测试，按2→15→9终止隧道）",
        formatter_class=argparse.RawTextHelpFormatter  # 保留帮助信息换行
    )
    # 添加参数：--no-start-tunnel（无需传值，添加则跳过隧道启动）
    parser.add_argument(
        "--no-start-tunnel",
        action="store_true",
        help="仅执行DNS和TCP测试，不启动hev-socks5-tunnel\n"
             "（示例：python3 script.py --no-start-tunnel）"
    )
    # 添加参数：--iface（指定绑定网卡，默认用配置的DEFAULT_IFACE）
    parser.add_argument(
        "--iface",
        type=str,
        default=DEFAULT_IFACE,
        help=f"指定测试/隧道绑定的网卡（默认：{DEFAULT_IFACE}）\n"
             "（示例：python3 script.py --iface eth0）"
    )
    # 解析命令行参数
    args = parser.parse_args()

    # 执行主工作流（根据参数控制是否启动隧道）
    run_test_workflow(
        iface=args.iface,
        start_tunnel=not args.no_start_tunnel  # --no-start-tunnel为True则不启动
    )
