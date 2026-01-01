# DNS 分流判断逻辑流程

## 一、UDP 路由入口 (`hev_traffic_router_handle_udp`)

```
UDP 数据包到达
    │
    ├─→ ACL IP 封锁检查
    │   └─→ 在黑名单 → 阻止并返回
    │
    └─→ 端口 = 53？
        │
        ├─→ 【是 DNS 查询】
        │   │
        │   ├─→ 【优先级1】DNS Forwarder 劫持检查
        │   │   └─→ 匹配 → 直接转发（不受 split-tunnel 影响）
        │   │
        │   ├─→ 【优先级2】split-tunnel 检查
        │   │   │
        │   │   ├─→ split-tunnel: false
        │   │   │   └─→ 跳到普通 UDP 路由 ↓↓↓
        │   │   │
        │   │   └─→ split-tunnel: true
        │   │       └─→ 继续 ↓
        │   │
        │   └─→ 【优先级3】DNS 分流逻辑（仅 split-tunnel: true）
        │       │
        │       ├─→ DNS 缓存检查
        │       │   ├─→ 命中 → 直接返回缓存 ✅
        │       │   └─→ 未命中 ↓
        │       │
        │       ├─→ 判断 DNS 服务器类型
        │       │   │
        │       │   ├─→ hev_filter_is_domestic(addr) = true
        │       │   │   │
        │       │   │   └─→ 【国内 DNS 服务器】
        │       │   │       │
        │       │   │       └─→ DIRECT 连接
        │       │   │           └─→ direct_udp_recv_task 接收响应
        │       │   │               │
        │       │   │               ├─→ split-tunnel 检查
        │       │   │               │   │
        │       │   │               │   ├─→ false → 跳过污染检测，返回响应
        │       │   │               │   │
        │       │   │               │   └─→ true → 污染检测 ↓
        │       │   │               │
        │       │   │               └─→ hev_dns_detect_pollution()
        │       │   │                   │
        │       │   │                   ├─→ 检测到污染？
        │       │   │                   │   │
        │       │   │                   │   ├─→ 【是 → 污染！】
        │       │   │                   │   │   │
        │       │   │                   │   │   ├─→ 根据原 DNS 类型选择
        │       │   │                   │   │   │   └─→ IP_IS_V6(&session->dest_ip) ?
        │       │   │                   │   │   │
        │       │   │                   │   │   ├─→ hev_dns_query_via_socks5()
        │       │   │                   │   │   │   │
        │       │   │                   │   │   │   ├─→ prefer_ipv6 = 0 (IPv4)
        │       │   │                   │   │   │   │   └─→ 使用 IPv4 foreign-dns
        │       │   │                   │   │   │   │       └─→ 1.1.1.1, 8.8.8.8, ...
        │       │   │                   │   │   │   │
        │       │   │                   │   │   │   ├─→ prefer_ipv6 = 1 (IPv6)
        │       │   │                   │   │   │   │   └─→ 使用 IPv6 foreign-dns
        │       │   │                   │   │   │   │       └─→ 2606:4700:4700::1111, ...
        │       │   │                   │   │   │   │
        │       │   │                   │   │   │   ├─→ 轮询选择 DNS 服务器
        │       │   │                   │   │   │   │
        │       │   │                   │   │   │   ├─→ 连接 SOCKS5 服务器
        │       │   │                   │   │   │   │
        │       │   │                   │   │   │   ├─→ 发送 DNS 查询
        │       │   │                   │   │   │   │
        │       │   │                   │   │   │   └─→ 接收干净响应
        │       │   │                   │   │   │       │
        │       │   │                   │   │   │       ├─→ 成功 → 缓存并替换 ✅
        │       │   │                   │   │   │       └─→ 失败 → 返回污染响应
        │       │   │                   │   │   │
        │       │   │                   │   │   └─→ 【否 → 干净】
        │       │   │                   │   │       └─→ 返回干净响应
        │       │   │                   │   │
        │       │   │                   │   └─→ 发送响应给客户端
        │       │   │                   │
        │       │   │   └─→ hev_filter_is_domestic(addr) = false
        │       │   │       │
        │       │   │       └─→ 【国外 DNS 服务器】
        │       │   │           │
        │       │   │           └─→ SOCKS5 代理（不检测污染）
        │       │   │               └─→ 返回 0，让主流程使用 SOCKS5
        │       │   │
        │       │   └─→ 返回处理结果
        │   │
        │   └─→ 【非 DNS】继续 ↓
        │
        └─→ 【普通 UDP 路由】(normal_udp_routing)
            │
            ├─→ 国内 IP (chnroutes 匹配)
            │   └─→ DIRECT 连接
            │
            └─→ 国外 IP
                └─→ 返回 0（让主流程使用 SOCKS5）
```

## 二、配置文件 (`conf/main.yml`)

```yaml
dns-split-tunnel:
  # 启用/禁用 DNS 分流
  split-tunnel: true

  # 国外 DNS 服务器列表（自动分类 IPv4/IPv6）
  # 当查询国内 DNS (如 119.29.29.29) 检测到污染时，
  # 会根据原 DNS 服务器的协议类型选择对应协议的国外 DNS 重新查询
  foreign-dns:
    - "1.1.1.1"              # Cloudflare DNS (IPv4)
    - "8.8.8.8"              # Google DNS (IPv4)
    - "2606:4700:4700::1111" # Cloudflare DNS (IPv6)
    - "2001:4860:4860::8888" # Google DNS (IPv6)
```

### 配置说明

- **split-tunnel**: 启用/禁用 DNS 分流功能
  - `true`: 启用分流，国内 DNS 进行污染检测，国外 DNS 直接走 SOCKS5
  - `false`: 禁用分流，所有 DNS 查询按普通 UDP 路由处理

- **foreign-dns**: 国外 DNS 服务器列表
  - 自动分类：包含 `:` 的地址被识别为 IPv6
  - 轮询使用：自动在列表中轮询选择
  - 协议匹配：根据原 DNS 服务器的协议类型选择对应协议的 DNS

## 三、关键代码位置索引

| 功能 | 文件 | 行号 |
|------|------|------|
| **路由层判断** | | |
| DNS 查询入口 | `hev-traffic-router.c` | 302-360 |
| DNS Forwarder 劫持检查（优先级1） | `hev-traffic-router.c` | 304-319 |
| split-tunnel 检查（优先级2） | `hev-traffic-router.c` | 321-328 |
| DNS 缓存检查 | `hev-traffic-router.c` | 332-341 |
| 国内/国外 DNS 判断 | `hev-traffic-router.c` | 344-359 |
| **响应层判断** | | |
| DIRECT UDP 接收任务 | `hev-session-manager.c` | 1620-1760 |
| split-tunnel 检查（响应层） | `hev-session-manager.c` | 1664-1669 |
| 污染检测 | `hev-session-manager.c` | 1671-1734 |
| 根据原 DNS 类型选择 | `hev-session-manager.c` | 1694-1697 |
| **核心功能** | | |
| SOCKS5 重新查询 | `hev-dns-cache.c` | 905-1049 |
| 根据协议类型选择 DNS | `hev-dns-cache.c` | 932-979 |
| 污染检测函数 | `hev-dns-cache.c` | 180-256 |
| 配置解析 | `hev-config.c` | 435-514 |

## 四、行为对比表

| 场景 | split-tunnel: true | split-tunnel: false |
|------|-------------------|---------------------|
| **查询国内 DNS** | DIRECT + 污染检测 | DIRECT（无污染检测）|
| **查询国内 DNS + 污染** | SOCKS5 重查询 | 使用污染响应 |
| **查询国外 DNS** | SOCKS5 代理 | 普通路由 → SOCKS5 代理 |
| **DNS Forwarder 劫持** | 直接转发（不受影响） | 直接转发（不受影响）|
| **DNS 缓存** | 启用 | 禁用 |

## 五、数据流示例

### 示例 1: split-tunnel: true，查询国内 DNS 被污染

```
用户: dig github.com @119.29.29.29
    │
    ├─→ hev_traffic_router_handle_udp
    │   ├─→ 端口 53 ✓
    │   ├─→ Forwarder 劫持 ✗
    │   ├─→ split-tunnel: true ✓
    │   ├─→ 缓存未命中 ✗
    │   ├─→ 119.29.29.29 = 国内 ✓
    │   └─→ DIRECT 连接
    │
    ├─→ direct_udp_recv_task 收到响应
    │   ├─→ 端口 53 ✓
    │   ├─→ split-tunnel: true ✓
    │   ├─→ 检测污染 [IP: 1.2.3.4] → 污染！✓
    │   ├─→ dest_ip 是 IPv4 → prefer_ipv6 = 0
    │   ├─→ hev_dns_query_via_socks5()
    │   │   ├─→ 使用 IPv4 foreign-dns
    │   │   ├─→ 轮询选中: 1.1.1.1:53
    │   │   └─→ SOCKS5 → 1.1.1.1:53
    │   └─→ 收到干净响应 [IP: 140.82.112.4]
    │
    └─→ 返回干净响应给用户 ✅
```

### 示例 2: split-tunnel: false，查询国内 DNS

```
用户: dig github.com @119.29.29.29
    │
    ├─→ hev_traffic_router_handle_udp
    │   ├─→ 端口 53 ✓
    │   ├─→ Forwarder 劫持 ✗
    │   ├─→ split-tunnel: false → 跳到普通路由
    │   └─→ 119.29.29.29 = 国内 IP → DIRECT
    │
    ├─→ direct_udp_recv_task 收到响应
    │   ├─→ 端口 53 ✓
    │   └─→ split-tunnel: false → 跳过污染检测
    │
    └─→ 直接返回响应（可能是污染的）⚠️
```

### 示例 3: split-tunnel: true，查询国外 DNS

```
用户: dig example.com @8.8.8.8
    │
    ├─→ hev_traffic_router_handle_udp
    │   ├─→ 端口 53 ✓
    │   ├─→ Forwarder 劫持 ✗
    │   ├─→ split-tunnel: true ✓
    │   ├─→ 缓存未命中 ✗
    │   ├─→ 8.8.8.8 = 国外 ✗
    │   └─→ 返回 0 → SOCKS5 代理
    │
    └─→ SOCKS5 → 8.8.8.8:53 ✅
```

### 示例 4: split-tunnel: true，查询国内 IPv6 DNS 被污染

```
用户: dig twitter.com @2400:3200::1 (IPv6)
    │
    ├─→ hev_traffic_router_handle_udp
    │   ├─→ 端口 53 ✓
    │   ├─→ Forwarder 劫持 ✗
    │   ├─→ split-tunnel: true ✓
    │   ├─→ 缓存未命中 ✗
    │   ├─→ 2400:3200::1 = 国内 ✓
    │   └─→ DIRECT 连接
    │
    ├─→ direct_udp_recv_task 收到响应
    │   ├─→ 端口 53 ✓
    │   ├─→ split-tunnel: true ✓
    │   ├─→ 检测污染 → 污染！✓
    │   ├─→ dest_ip 是 IPv6 → prefer_ipv6 = 1
    │   ├─→ hev_dns_query_via_socks5()
    │   │   ├─→ 使用 IPv6 foreign-dns
    │   │   ├─→ 轮询选中: 2606:4700:4700::1111:53
    │   │   └─→ SOCKS5 → 2606:4700:4700::1111:53
    │   └─→ 收到干净响应
    │
    └─→ 返回干净响应给用户 ✅
```

## 六、优先级总结

### DNS 查询处理优先级

```
┌─────────────────────────────────────────────────────┐
│ 1. DNS Forwarder 劫持        （最高优先级，无条件） │
│ 2. split-tunnel 配置检查      （控制是否启用分流）   │
│ 3. DNS 缓存                  （仅分流启用时检查）   │
│ 4. 国内/国外 DNS 服务器判断  （仅分流启用时执行）   │
└─────────────────────────────────────────────────────┘
```

### DNS 响应处理优先级

```
┌─────────────────────────────────────────────────────┐
│ 1. split-tunnel 配置检查      （控制是否检测污染）   │
│ 2. 污染检测                  （仅分流启用时执行）   │
│ 3. SOCKS5 重新查询           （仅检测到污染时）     │
└─────────────────────────────────────────────────────┘
```

## 七、关键设计决策

### 1. DNS Forwarder 劫持优先级最高

**原因**: 用户配置的 DNS 转发规则应该始终生效，不受 split-tunnel 配置影响。

**代码位置**: `hev-traffic-router.c:304-319`

### 2. 响应层也检查 split-tunnel

**原因**: 即使路由层由于某种原因创建了 DIRECT UDP 连接，响应层也应该根据 split-tunnel 配置决定是否检测污染。

**代码位置**: `hev-session-manager.c:1664-1669`

### 3. 根据原 DNS 协议类型选择 foreign-dns

**原因**: 如果原 DNS 服务器是 IPv4，使用 IPv4 的 foreign-dns；如果是 IPv6，使用 IPv6 的 foreign-dns。避免协议不匹配导致的查询失败。

**代码位置**: `hev-session-manager.c:1694-1697`, `hev-dns-cache.c:932-979`

### 4. 延迟启动清理任务

**原因**: DNS 缓存初始化时任务系统可能还未初始化，因此清理任务延迟到第一次插入缓存时启动。

**代码位置**: `hev-dns-cache.c:366-377`, `565-566`

## 八、故障排查

### 问题 1: 所有 DNS 查询都走 SOCKS5 代理

**可能原因**:
- chnroutes 文件未正确加载
- DNS 服务器被识别为国外 IP

**检查方法**:
```bash
# 查看日志中是否有 chnroutes 加载信息
grep "Loaded chnroutes" /path/to/log
```

### 问题 2: 污染检测不生效

**可能原因**:
- `split-tunnel` 配置为 `false`
- DNS 查询未经过 DIRECT 连接

**检查方法**:
```bash
# 查看日志中的 split-tunnel 状态
grep "split-tunnel" /path/to/log
```

### 问题 3: IPv6 DNS 查询失败

**可能原因**:
- IPv6 不可用
- foreign-dns 中没有配置 IPv6 服务器

**检查方法**:
```bash
# 查看日志中的 IPv6 检测信息
grep "IPv6" /path/to/log
```

## 九、性能考虑

### DNS 缓存

- **分片锁**: 16 个分片，减少锁竞争
- **对象池**: 减少内存分配开销
- **自动清理**: 每 60 秒清理过期条目

### 轮询策略

- IPv4 和 IPv6 分别维护轮询索引
- 根据原 DNS 协议类型选择对应列表
- 避免跨协议查询导致的延迟
