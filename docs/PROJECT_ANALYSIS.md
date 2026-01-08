# hev-socks5-tunnel 项目代码分析

## 项目概述

**hev-socks5-tunnel** 是一个高性能的 SOCKS5 隧道工具，主要用于网络流量代理和智能分流。该项目采用模块化设计，结合了轻量级 TCP/IP 协议栈 (lwIP) 和协程框架 (hev-task-system)，实现了高效的网络代理功能。

## 1. 项目整体结构

```
hev-socks5-tunnel/
├── src/                          # 主要源代码
│   ├── core/                     # 核心SOCKS5实现
│   │   ├── src/                  # 核心模块实现
│   │   └── include/              # 核心头文件
│   ├── misc/                     # 辅助工具模块
│   ├── hev-*.c/h                 # 主要功能模块
├── conf/                         # 配置文件
│   └── main.yml                  # 主配置文件
├── docs/                         # 详细文档
├── bin/                          # 编译产物
├── third-part/                   # 第三方依赖（Git子模块）
│   ├── hev-task-system          # 协程框架
│   ├── lwip                      # 轻量级TCP/IP协议栈
│   └── yaml                      # YAML解析库
├── test.py                       # 测试脚本
├── Makefile                      # 主构建文件
├── Android.mk                    # Android NDK构建配置
└── Application.mk                # Android应用配置
```

## 2. 主要源文件和功能

### 2.1 核心功能模块

#### 主程序入口
- **hev-main.c/h**: 主程序入口，负责初始化各个子系统
  - 初始化配置系统
  - 启动隧道服务
  - 信号处理和生命周期管理

#### 隧道核心
- **hev-socks5-tunnel.c/h**: 隧道核心实现，处理TUN设备数据包
  - TUN设备数据包读取
  - 数据包解析和路由
  - 流量统计和管理

- **hev-config.c/h**: YAML配置文件解析
  - 配置文件加载
  - 参数验证
  - 配置热重载

#### 会话管理
- **hev-session-manager.c/h**: 会话管理器，管理所有网络会话
  - TCP/UDP会话生命周期管理
  - 会话超时处理
  - 资源回收

- **hev-socks5-session.c/h**: SOCKS5会话基类
  - 会话状态管理
  - 数据转发逻辑
  - 错误处理

- **hev-socks5-session-tcp.c/h**: TCP会话实现
  - TCP连接建立
  - 数据流转发
  - 连接保持

- **hev-socks5-session-udp.c/h**: UDP会话实现
  - UDP数据包转发
  - 会话关联
  - 超时管理

#### 路由和过滤
- **hev-traffic-router.c/h**: 智能路由决策，分流国内/国外流量
  - 基于IP的路由判断
  - 国内外流量分流
  - 直连/代理选择

- **hev-filter.c/h**: ACL过滤器和黑名单管理
  - IP/CIDR过滤
  - 端口过滤
  - 域名过滤
  - 白名单/黑名单模式

#### DNS功能
- **hev-dns-cache.c/h**: DNS缓存与污染检测
  - DNS查询缓存
  - 污染检测
  - TTL管理

- **hev-dns-latency.c/h**: DNS延迟优化，自动选择最佳IP
  - 并发DNS查询
  - 延迟测试
  - 最优IP选择

#### SOCKS5协议
- **hev-socks5-client.c/h**: SOCKS5客户端实现
  - 握手协议
  - 认证处理
  - 代理请求

- **hev-socks5-server.c/h**: SOCKS5服务器实现
  - 连接接受
  - 请求处理
  - 响应发送

### 2.2 平台适配模块

- **hev-tunnel-linux.c**: Linux TUN设备适配
- **hev-tunnel-freebsd.c**: FreeBSD适配
- **hev-tunnel-macos.c**: macOS适配
- **hev-tunnel-windows.c**: Windows适配
- **hev-tunnel-netbsd.c**: NetBSD适配

## 3. 项目依赖

### 3.1 Git子模块

1. **hev-task-system** (协程框架)
   - 提供基于协程的异步I/O
   - 用于高并发网络处理
   - 非抢占式调度

2. **lwip** (轻量级TCP/IP协议栈)
   - 精简的TCP/IP实现
   - 处理网络协议栈功能
   - 零拷贝优化

3. **yaml** (YAML解析库)
   - 解析YAML配置文件
   - 提供灵活的配置方式

4. **wintun** (Windows TUN驱动)
   - Windows平台的TUN设备支持

## 4. 核心功能特性

### 4.1 SOCKS5代理隧道

- 支持TCP/UDP双协议
- 支持用户名密码认证
- 支持UDP-in-TCP和UDP-in-UDP两种模式
- 完整的SOCKS5协议实现

### 4.2 智能DNS分流

- 自动检测DNS污染
- 智能选择干净DNS服务器重查询
- DNS缓存优化
- 并发DNS查询以选择最快响应

### 4.3 智能路由系统

- 基于chnroutes的国内外分流
- 直连超时自动切换代理
- 动态黑名单机制
- 白名单模式支持

### 4.4 ACL访问控制

- 支持IP、CIDR、端口、域名过滤
- 支持通配符匹配
- 白名单/黑名单模式
- 正则表达式支持

### 4.5 性能优化

- 零拷贝技术
- 内存池管理
- 批量处理
- 协程异步I/O

## 5. 核心工作流程

```
应用请求 → TUN设备 → 隧道处理 → 路由决策 → 代理/直连
                                           ├── 国内IP → 直连
                                           ├── 国外IP → 尝试直连
                                           └── 直连失败 → SOCKS5代理
```

### 详细流程

1. **数据包捕获**
   - TUN设备捕获网络流量
   - 解析IP数据包头部

2. **路由决策**
   - 检查目标IP是否在路由表
   - 判断是否需要代理
   - 检查ACL规则

3. **DNS处理**
   - 拦截DNS查询
   - 检测DNS污染
   - 选择干净的DNS服务器
   - 缓存DNS响应

4. **会话管理**
   - 创建对应的会话对象
   - 建立SOCKS5连接（如需要）
   - 转发数据

5. **数据转发**
   - TCP：双向数据流转发
   - UDP：数据包转发和会话关联

## 6. 构建系统

### 6.1 主构建系统 (Makefile)

- 支持动态库、静态库构建
- 支持交叉编译
- 支持调试/发布模式
- 自动源文件收集

### 6.2 Android构建 (Android.mk)

- 支持NDK编译
- 针对Android平台优化
- 应用级配置

### 6.3 构建配置

- **build.mk**: 自动源文件收集和版本信息
- **Android.mk**: Android NDK构建配置
- **Application.mk**: 应用级配置

## 7. 配置文件

配置文件采用YAML格式 (conf/main.yml)，主要配置项：

### 隧道接口配置
```yaml
tunnel:
  name: tun0
  mtu: 1500
  address: 10.0.0.1
  netmask: 255.255.255.0
```

### SOCKS5代理配置
```yaml
socks5:
  address: 127.0.0.1
  port: 1080
  username: user
  password: pass
  udp: udp-in-udp
```

### DNS分流配置
```yaml
dns:
  servers:
    - 8.8.8.8
    - 8.8.4.4
  cache_size: 1024
  timeout: 5
```

### 智能代理配置
```yaml
proxy:
  mode: smart
  direct_timeout: 3
  blacklist_enable: true
```

## 8. 架构层次

### 8.1 应用层
- hev-main: 程序入口和生命周期管理
- hev-config: 配置管理
- hev-test: 测试工具

### 8.2 业务逻辑层
- hev-traffic-router: 路由决策
- hev-filter: 访问控制
- hev-session-manager: 会话管理
- hev-dns-cache: DNS缓存
- hev-dns-latency: DNS延迟优化

### 8.3 协议层
- hev-socks5-session: SOCKS5会话
- hev-socks5-client: SOCKS5客户端
- hev-socks5-server: SOCKS5服务器

### 8.4 传输层
- hev-socks5-session-tcp: TCP传输
- hev-socks5-session-udp: UDP传输

### 8.5 平台层
- hev-tunnel-*: 各平台TUN设备适配
- lwip: TCP/IP协议栈

## 9. 关键数据结构

### 9.1 会话管理
- 使用链表管理活跃会话
- 每个会话独立的超时控制
- 引用计数管理生命周期

### 9.2 路由决策
- 基于IP表的快速路由判断
- 哈希表实现O(1)查找
- 动态更新路由表

### 9.3 DNS缓存
- 分片锁设计减少竞争
- 支持IPv4/IPv6双栈
- LRU缓存淘汰策略

## 10. 并发模型

- 基于hev-task-system的协程
- 每个会话独立协程
- 异步I/O避免阻塞
- 批量处理提高效率

## 11. 技术特点总结

### 11.1 架构优势

1. **模块化设计**: 各模块职责明确，耦合度低
2. **跨平台支持**: 支持 Linux/macOS/Windows/FreeBSD/NetBSD/Android
3. **高性能**: 协程异步+零拷贝+批量处理
4. **功能丰富**: DNS分流、智能路由、ACL控制等

### 11.2 适用场景

- 网络代理服务
- VPN实现
- 流量分流
- 网络加速
- 跨平台网络应用开发

### 11.3 设计理念

1. **简洁性**: 代码结构清晰，易于理解和维护
2. **高效性**: 专注于性能优化
3. **可扩展**: 模块化设计便于添加新功能
4. **稳定性**: 完善的错误处理和资源管理

## 12. 总结

hev-socks5-tunnel 是一个功能强大的高性能 SOCKS5 隧道工具，具有以下特点：

1. **架构清晰**: 分层设计，职责明确
2. **性能优异**: 协程异步+零拷贝+批量处理
3. **功能丰富**: DNS分流、智能路由、ACL控制等
4. **跨平台**: 支持主流操作系统
5. **可扩展**: 模块化设计，易于扩展

该项目实现了复杂的网络隧道功能，代码质量高，架构设计合理，是一个优秀的高性能网络代理工具实现。特别适合用于构建 VPN 或代理服务，以及需要智能路由和流量分流的场景。
