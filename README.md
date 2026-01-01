# HevSocks5Tunnel

[![Build Status](https://github.com/yiguihai11/hev-socks5-tunnel/workflows/Build/badge.svg)](https://github.com/yiguihai11/hev-socks5-tunnel/actions)
[![License](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](LICENSE)

高性能 SOCKS5 隧道工具，支持 DNS 分流、智能路由、流量过滤和 GFW 规避。

## ✨ 核心特性

### 🌐 DNS 分流与污染检测（NEW）
- **DNS 智能分流**: 根据国内/国外 DNS 服务器选择不同路由策略
- **DNS 污染检测**: 自动检测 DNS 响应中的污染（包含国外 IP）
- **智能重查询**: 检测到污染时自动通过 SOCKS5 使用干净的国外 DNS 查询
- **协议匹配选择**: 根据原 DNS 服务器类型（IPv4/IPv6）选择对应协议的国外 DNS
- **DNS 缓存**: 自动缓存 DNS 响应，减少重复查询

```yaml
dns-split-tunnel:
  split-tunnel: true              # 启用 DNS 分流
  foreign-dns:                    # 国外 DNS 列表（自动分类 IPv4/IPv6）
    - "1.1.1.1"                  # Cloudflare DNS (IPv4)
    - "8.8.8.8"                  # Google DNS (IPv4)
    - "2606:4700:4700::1111"     # Cloudflare DNS (IPv6)
    - "2001:4860:4860::8888"     # Google DNS (IPv6)
```

### 🚀 高性能网络处理
- **零拷贝技术**: 最小化数据包复制开销
- **内存池优化**: 动态调整 UDP 帧池大小
- **异步 I/O**: 基于 hev-task-system 协程框架
- **批量处理**: 网络 I/O、包转发、会话管理批量化

### 🛡️ 智能规避功能
- **智能代理**: 直连超时自动切换到 SOCKS5 代理
- **动态黑名单**: 连接失败的 IP 被临时标记，下次直接走代理
- **ACL 过滤**: 支持 IP、CIDR、端口、域名（通配符）的访问控制
- **GFW RST 检测**: 自动识别网络重置攻击并切换代理

### 🌏 智能路由系统
- **国内外分流**: 基于 chnroutes 的精确路由判断
- **DNS 劫持转发**: 智能解析和透明代理
- **多协议支持**: TCP/UDP 双协议隧道

## 📊 性能特性

| 指标 | 性能 | 说明 |
|------|------|------|
| **黑名单查找速度** | 50-100 million ops/sec | O(1) 哈希表 |
| **ACL/CIDR 查找** | O(1) 或 O(prefix) | Radix Tree |
| **内存占用** | < 10MB | 优化内存管理 |
| **并发连接数** | 10,000+ | 协程异步处理 |
| **DNS 缓存分片** | 16 分片 | 减少锁竞争 |

## 🚀 快速开始

### 安装

```bash
# 克隆代码（包含子模块）
git clone --recursive https://github.com/yiguihai11/hev-socks5-tunnel.git
cd hev-socks5-tunnel

# 如果已经克隆但未初始化子模块，运行：
# git submodule update --init --recursive

# 编译
make
```

### 配置文件

编辑 `conf/main.yml`：

```yaml
# ============================================
# 隧道接口配置
# ============================================
tunnel:
  name: tun0
  mtu: 8500
  ipv4: 198.18.0.1
  ipv6: 'fc00::1'

# ============================================
# SOCKS5 代理配置
# ============================================
socks5:
  tcp:
    address: your-proxy.com
    port: 1080
    username: your-username
    password: your-password
  udp:
    address: your-proxy.com     # UDP 独立配置
    port: 1080
    username: your-username
    password: your-password
    udp-relay: tcp               # 转发模式: tcp/udp

# ============================================
# DNS 分流配置（NEW）
# ============================================
dns-split-tunnel:
  split-tunnel: true             # 启用 DNS 分流
  foreign-dns:                   # 国外 DNS 列表
    - "1.1.1.1"                 # Cloudflare DNS (IPv4)
    - "8.8.8.8"                 # Google DNS (IPv4)
    - "2606:4700:4700::1111"    # Cloudflare DNS (IPv6)
    - "2001:4860:4860::8888"    # Google DNS (IPv6)

# ============================================
# 智能代理（直连超时自动切换代理）
# ============================================
smart-proxy:
  timeout-ms: 2000               # 直连超时时间（毫秒）
  blocked-ip-expiry-minutes: 360 # 超时 IP 缓存时间（分钟）
  probe-ports:                   # 探测端口（用于域名优先路由）
    - 80                        # HTTP
    - 443                       # HTTPS

# ============================================
# ACL 访问控制
# ============================================
acl:
  file-path: "conf/acl.txt"

# ============================================
# 中国路由（国内外分流判断）
# ============================================
chnroutes:
  file-path: "conf/chnroutes.txt"

# ============================================
# 日志配置
# ============================================
misc:
  log-level: debug               # debug, info, warn, error
  log-file: stdout               # 或指定日志文件路径
```

### ACL 规则文件（可选）

创建 `conf/acl.txt`：

```bash
# 阻止特定 IP
block ip 1.2.3.4

# 阻止 IP 范围（CIDR）
block cidr 10.0.0.0/8

# 阻止端口
block port 23    # Telnet
block port 135   # Windows RPC

# 阻止域名（支持通配符）
block domain *.adnetwork.com
block domain tracker.example.com

# 允许特定端口（白名单模式）
allow port 22    # SSH
allow port 443   # HTTPS
```

### 启动

```bash
# 前台运行
sudo ./bin/hev-socks5-tunnel conf/main.yml

# 后台运行
sudo ./bin/hev-socks5-tunnel conf/main.yml &

# 使用守护进程模式
# 在配置文件中设置 pid-file 选项
```

## 🔧 核心功能详解

### DNS 分流与污染检测

详见 [docs/DNS_SPLIT_TUNNEL.md](docs/DNS_SPLIT_TUNNEL.md)

**工作流程**：
```
查询国内 DNS (如 119.29.29.29)
    │
    ├─→ DNS 缓存命中 → 直接返回 ✅
    │
    ├─→ DNS 缓存未命中 → DIRECT 连接
    │   │
    │   ├─→ 响应干净 → 返回结果 ✅
    │   │
    │   └─→ 响应被污染（包含国外 IP）
    │       │
    │       ├─→ 根据原 DNS 类型选择国外 DNS
    │       │   ├─→ IPv4 DNS → 使用 foreign-dns 中的 IPv4 服务器
    │       │   └─→ IPv6 DNS → 使用 foreign-dns 中的 IPv6 服务器
    │       │
    │       ├─→ 通过 SOCKS5 查询干净的国外 DNS
    │       ├─→ 缓存干净响应 ✅
    │       └─→ 返回正确结果
    │
查询国外 DNS (如 8.8.8.8)
    │
    └─→ 直接走 SOCKS5 代理（不检测污染）
```

**配置说明**：
- `split-tunnel: true` - 启用 DNS 分流
- `split-tunnel: false` - 禁用分流，所有 DNS 按普通 UDP 路由处理
- `foreign-dns` - 国外 DNS 列表，自动分类为 IPv4 和 IPv6

### 智能代理

详见 [docs/SMART_PROXY.md](docs/SMART_PROXY.md)

**工作原理**：
```
连接国外 IP
    │
    ├─→ 首次连接：尝试直连
    │   ├─→ 成功（< 2秒）→ 使用直连 ✅
    │   └─→ 超时（≥ 2秒）→ 记录到黑名单
    │       └─→ 切换到 SOCKS5 代理
    │
    └─→ 再次连接：直接走代理（跳过直连尝试）
```

**配置参数**：
- `timeout-ms` - 直连超时时间（毫秒）
- `blocked-ip-expiry-minutes` - 黑名单过期时间（分钟）
- `probe-ports` - 探测端口列表，用于域名优先路由

### ACL 访问控制

详见 [docs/ACL.md](docs/ACL.md)

**支持的规则类型**：
- **IP 地址** - 精确匹配单个 IP
- **CIDR 范围** - IP 地址段（如 192.168.0.0/24）
- **端口** - TCP/UDP 端口号
- **域名** - 支持通配符（*.example.com）和后缀（.example.com）

**规则格式**：
```bash
# 完整格式
block ip 1.2.3.4
allow port 443
block domain *.example.com

# 简化格式（自动检测类型）
block 1.2.3.4          # 自动识别为 IP
block 192.168.0.0/24   # 自动识别为 CIDR
block 8080             # 自动识别为端口
block ads.example.com # 自动识别为域名
```

### UDP 转发模式

**UDP-in-TCP 模式**（推荐，`udp-relay: tcp`）：
- 需要 [hev-socks5-server](https://github.com/heiher/hev-socks5-server) 服务端
- UDP 数据封装在 TCP 连接中传输
- 稳定可靠，能穿越 NAT 和防火墙

**UDP-in-UDP 模式**（`udp-relay: udp`）：
- 直接 UDP 转发，性能更高
- 可能受 NAT 影响

## 📁 项目结构

```
hev-socks5-tunnel/
├── src/                          # 源代码
│   ├── hev-config.{c,h}         # 配置解析
│   ├── hev-dns-cache.{c,h}      # DNS 缓存与污染检测
│   ├── hev-session-manager.{c,h} # 会话管理
│   ├── hev-traffic-router.{c,h}  # 流量路由
│   ├── hev-filter.{c,h}         # ACL 和过滤
│   └── ...
├── conf/                         # 配置文件
│   └── main.yml                 # 主配置文件
├── docs/                         # 文档
│   ├── DNS_SPLIT_TUNNEL.md       # DNS 分流文档
│   ├── SMART_PROXY.md            # 智能代理文档
│   └── ACL.md                    # ACL 文档
├── bin/                         # 编译产物
├── third-part/                   # 第三方依赖（子模块）
│   ├── hev-task-system          # 协程框架
│   ├── yaml                      # YAML 解析
│   └── lwip                      # TCP/IP 协议栈
└── test.py                      # 测试工具
```

## 🧪 测试

```bash
# 完整功能测试
python3 test.py

# 仅测试网络（不启动隧道）
python3 test.py --no-start-tunnel

# 性能基准测试
python3 test.py --test
```

## 🐛 故障排除

### 程序无法启动

**问题**: `socks5 tunnel open (Operation not permitted)`

**解决**: 使用 `sudo` 运行程序，创建 TUN 设备需要 root 权限

### DNS 解析异常

**问题**: 无法解析域名或解析结果错误

**解决**:
1. 检查 `dns-split-tunnel.split-tunnel` 配置
2. 检查 `foreign-dns` 列表是否配置正确
3. 查看日志中的 DNS 相关错误信息

### 智能代理不生效

**问题**: 所有流量都走代理

**解决**:
1. 检查 `smart-proxy` 配置是否设置且非零
2. 检查 `chnroutes.txt` 文件是否正确加载
3. 查看日志中的路由决策信息

### 连接被阻止

**问题**: 某些 IP 或域名无法访问

**解决**:
1. 检查 `conf/acl.txt` 规则
2. 查看日志中的 ACL 阻止信息
3. 确认规则格式是否正确

## 📄 文档

| 文档 | 描述 |
|------|------|
| [DNS_SPLIT_TUNNEL.md](docs/DNS_SPLIT_TUNNEL.md) | DNS 分流功能详解 |
| [SMART_PROXY.md](docs/SMART_PROXY.md) | 智能代理功能详解 |
| [ACL.md](docs/ACL.md) | ACL 访问控制详解 |
| [PERFORMANCE_OPTIMIZATION.md](docs/PERFORMANCE_OPTIMIZATION.md) | 性能优化说明 |

## 🔧 开发

```bash
# 调试版本
make DEBUG=1

# 静态链接
make STATIC=1
```

## 📄 许可证

GPLv3 - 详见 [LICENSE](LICENSE) 文件

## 🙏 致谢

- [hev-task-system](https://github.com/heiher/hev-task-system) - 协程框架
- [hev-socks5-server](https://github.com/heiher/hev-socks5-server) - UDP-in-TCP 服务端
- [lwIP](https://savannah.nongnu.org/projects/lwip/) - 轻量级 TCP/IP 协议栈

---

如果这个项目对您有帮助，请给个 ⭐
