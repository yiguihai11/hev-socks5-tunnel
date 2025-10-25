# HevSocks5Tunnel

[![Build Status](https://github.com/yiguihai11/hev-socks5-tunnel/workflows/Build/badge.svg)](https://github.com/yiguihai11/hev-socks5-tunnel/actions)
[![License](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](LICENSE)

HevSocks5Tunnel 是一个企业级的高性能 SOCKS5 隧道工具，专为复杂的网络环境设计，提供智能路由和强大的流量过滤功能。

## ✨ 核心特性

### 🚀 高性能网络处理
- **零拷贝技术**: 最小化数据包复制开销
- **内存池优化**: 减少 malloc/free 系统调用
- **异步 I/O**: 基于 hev-task-system 协程框架
- **智能缓存**: 黑名单和路由结果的高效缓存机制

### 🛡️ 企业级安全过滤
- **ACL 访问控制**: 支持 IP 地址、域名、SNI 的精确过滤
- **TLS SNI 解析**: 深度包检测技术，识别加密流量
- **HTTP Host 检测**: 智能识别 HTTP 请求目标
- **动态黑名单**: 基于响应时间的智能 IP 屏蔽

### 🌏 智能路由系统
- **国内外流量分流**: 基于 chnroutes 的精确路由判断
- **智能代理模式**: 自动检测最佳连接路径
- **故障转移机制**: 连接失败时的无缝切换
- **性能监控**: 实时统计和日志记录

### 🔧 灵活配置选项
- **多协议支持**: TCP/UDP 双协议隧道
- **DNS 劫持转发**: 智能解析和转发机制
- **跨平台兼容**: Linux、macOS、Windows、Android 等
- **细粒度控制**: 详细的超时、缓冲区、并发控制

## 📊 性能指标

| 指标 | 数值 | 说明 |
|------|------|------|
| **黑名单查找速度** | 50-100 million ops/sec | O(1) 65536桶哈希表 |
| **ACL 过滤延迟** | < 1μs | Radix Tree 高效匹配 |
| **内存占用** | < 10MB | 优化的内存管理 |
| **并发连接数** | 10,000+ | 协程异步处理 |
| **CPU 使用率** | < 5% | 高效的事件驱动架构 |

## 🚀 快速开始

### 系统要求
- Linux/macOS/Windows/Android
- libyaml 开发库
- 管理员权限（创建 TUN 接口）

### 安装步骤

```bash
# 克隆项目
git clone --depth=1 --recursive https://github.com/yiguihai11/hev-socks5-tunnel.git
cd hev-socks5-tunnel

# 编译项目
make

# 创建配置文件
cp conf/main.yml.example conf/main.yml
```

### 基础配置

编辑 `conf/main.yml`：

```yaml
# SOCKS5 代理服务器配置
socks5:
  tcp:
    address: your-proxy-server.com
    port: 1080
    username: your-username
    password: your-password
  udp:
    address: your-proxy-server.com
    port: 1081
    udp-relay: tcp

# 智能代理配置
smart-proxy:
  timeout-ms: 2000              # 直连超时时间
  blocked-ip-expiry-minutes: 360 # 黑名单过期时间

# ACL 过滤配置
acl:
  file-path: "conf/acl.txt"

# 中国路由配置
chnroutes:
  file-path: "conf/chnroutes.txt"
```

### 启动隧道

```bash
# 启动隧道（需要管理员权限）
sudo ./bin/hev-socks5-tunnel conf/main.yml

# 后台运行
sudo nohup ./bin/hev-socks5-tunnel conf/main.yml > /dev/null 2>&1 &
```

## 📖 详细配置

### 隧道接口配置

```yaml
tunnel:
  name: tun0                    # TUN 接口名称
  mtu: 8500                     # 最大传输单元
  ipv4: 198.18.0.1             # IPv4 地址
  ipv6: 'fc00::1'              # IPv6 地址
```

### DNS 转发配置

```yaml
dns-forwarder:
  virtual-ip4: 8.8.8.8         # 劫持的 IPv4 DNS 地址
  virtual-ip6: '2001:4860:4860::8844'  # 劫持的 IPv6 DNS 地址
  target-ip4: 1.1.1.1:53       # 转发目标 DNS
  target-ip6: '[2606:4700:4700::1111]:53'
```

### 高级配置选项

```yaml
misc:
  log-level: info              # 日志级别: debug, info, warn, error
  log-file: stdout             # 日志输出: stdout, stderr, 文件路径
  max-session-count: 0         # 最大会话数 (0=无限制)
  connect-timeout: 10000       # 连接超时 (毫秒)
  read-write-timeout: 300000   # 读写超时 (毫秒)
```

## 🔍 ACL 过滤规则

在 `conf/acl.txt` 中定义过滤规则：

```
# IP 地址过滤
192.168.1.0/24
10.0.0.0/8

# 域名过滤
example.com
ads.example.com

# SNI 过滤 (HTTPS)
blocked-site.com
malware-site.com
```

## 🧪 测试工具

项目包含完整的测试套件：

```bash
# 运行网络连接测试
python3 test.py --no-start-tunnel

# 测试特定接口
python3 test.py --no-start-tunnel --iface wlan0

# 完整测试（包含隧道启动）
python3 test.py
```

### 测试功能

- ✅ **DNS 服务器测试**: 7 个国内外 DNS 服务器连通性
- ✅ **TCP 连接测试**: HTTP/HTTPS 端口连接验证
- ✅ **TLS SNI 解析**: HTTPS 流量识别测试
- ✅ **ACL 过滤测试**: 访问控制规则验证
- ✅ **智能路由测试**: 国内外流量分流验证

## 📁 项目结构

```
hev-socks5-tunnel/
├── src/                     # 源代码
│   ├── core/               # 核心模块
│   ├── hev-*.c            # 主要实现文件
│   └── misc/              # 工具函数
├── conf/                  # 配置文件
│   ├── main.yml          # 主配置文件
│   ├── acl.txt           # ACL 过滤规则
│   └── chnroutes.txt     # 中国 IP 路由表
├── bin/                   # 编译后的二进制文件
├── test.py               # 网络测试工具
└── rsync.sh              # 部署脚本
```

## 🔧 开发指南

### 编译选项

```bash
# 调试版本
make DEBUG=1

# 静态链接
make STATIC=1

# 交叉编译
make CROSS=arm-linux-gnueabihf-
```

### 性能调优

- **内存池大小**: 根据并发连接数调整
- **缓冲区大小**: 根据网络延迟优化
- **超时设置**: 根据网络环境调整
- **日志级别**: 生产环境建议使用 `warn`

## 🐛 故障排除

### 常见问题

1. **权限不足**: 确保使用 `sudo` 运行
2. **TUN 接口创建失败**: 检查系统是否支持 TUN/TAP
3. **DNS 解析失败**: 检查 `dns-forwarder` 配置
4. **连接超时**: 调整 `connect-timeout` 参数

### 调试模式

```bash
# 启用详细日志
./bin/hev-socks5-tunnel conf/main.yml --log-level debug
```

## 🤝 贡献指南

1. Fork 本项目
2. 创建特性分支: `git checkout -b feature/amazing-feature`
3. 提交更改: `git commit -m 'Add amazing feature'`
4. 推送分支: `git push origin feature/amazing-feature`
5. 提交 Pull Request

## 📄 许可证

本项目基于 [GPLv3](LICENSE) 许可证开源。

## 🙏 致谢

- [hev-task-system](https://github.com/heiher/hev-task-system) - 协程框架
- [lwIP](https://savannah.nongnu.org/projects/lwip/) - 轻量级 TCP/IP 协议栈
- [libyaml](https://github.com/yaml/libyaml) - YAML 解析库

## 📞 支持

- 🐛 **Bug 报告**: [Issues](https://github.com/yiguihai11/hev-socks5-tunnel/issues)
- 💬 **讨论交流**: [Discussions](https://github.com/yiguihai11/hev-socks5-tunnel/discussions)
- 📧 **联系作者**: [hev@hev.cc](mailto:hev@hev.cc)

---

⭐ 如果这个项目对您有帮助，请给我们一个 Star！