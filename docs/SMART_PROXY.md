# 智能代理 (Smart Proxy) 功能文档

## 一、功能概述

智能代理 (Smart Proxy) 是一个针对国外 TCP 流量的智能回退机制。它通过"先直连，超时再代理"的策略，在保证可访问性的同时优化性能。

### 核心思想

```
对于国外 IP 的 TCP 连接：
    │
    ├─→ 第 1 次：尝试直接连接
    │   ├─→ 成功 → 使用直连 ✅
    │   └─→ 超时 → 切换到 SOCKS5 代理
    │
    ├─→ 第 2 次：直接走 SOCKS5（IP 已被标记为超时）
    │
    └─→ N 分钟后：重新尝试直接连接（超时标记过期）
```

## 二、工作流程

### TCP 路由判断流程 (`hev_traffic_router_handle_tcp`)

```
TCP 连接请求
    │
    ├─→ 【优先级1】ACL IP 封锁检查
    │   └─→ 在黑名单 → 阻止并终止连接
    │
    ├─→ 【优先级2】探测端口检查 (probe-ports)
    │   └─→ 是探测端口 → DOMAIN-FIRST 路由
    │       └─→ 获取域名后再决定路由方式
    │
    ├─→ 【优先级3】国内 IP 检查 (chnroutes)
    │   └─→ 国内 IP → DIRECT 连接
    │
    ├─→ 【优先级4】智能代理检查
    │   │
    │   ├─→ smart-proxy 启用？
    │   │   ├─→ 否 → 跳过 ↓
    │   │   └─→ 是 ↓
    │   │
    │   ├─→ IP 在黑名单中？
    │   │   ├─→ 是 → 跳过（已超时过）↓
    │   │   └─→ 否 ↓
    │   │
    │   └─→ SMART_PROXY 模式
    │       └─→ 先尝试直连，超时切换代理
    │
    └─→ 【优先级5】SOCKS5 代理
        └─→ 直接使用 SOCKS5 代理
```

### 智能代理执行流程 (`run_smart_proxy_task`)

```
SMART_PROXY 模式启动
    │
    ├─→ 创建 DIRECT 连接
    │   │
    │   ├─→ 连接成功？
    │   │   ├─→ 是 → 使用直连 ✅
    │   │   │
    │   │   └─→ 否 ↓
    │   │
    │   └─→ 连接超时/失败
    │       │
    │       ├─→ 记录超时
    │       │   ├─→ 将 IP 添加到黑名单
    │       │   ├─→ 设置过期时间 (blocked-ip-expiry-minutes)
    │       │   └─→ 记录超时统计
    │       │
    │       └─→ 切换到 SOCKS5 代理
    │           │
    │           ├─→ 连接成功 → 使用代理 ✅
    │           │
    │           └─→ 连接失败 → 返回错误 ❌
```

## 三、配置文件 (`conf/main.yml`)

```yaml
smart-proxy:
  # 智能代理启用条件：
  # - timeout-ms > 0
  # - blocked-ip-expiry-minutes > 0
  # 两者都设置且非零时才启用

  # 直连超时时间（毫秒）
  # 超过此时间未建立连接则认为超时
  timeout-ms: 2000

  # 超时 IP 缓存过期时间（分钟）
  # 被标记为超时的 IP 在此时间内会直接走代理
  blocked-ip-expiry-minutes: 360

  # 探测端口列表
  # 这些端口会触发 DOMAIN-FIRST 路由（先获取域名）
  # 常见端口：80(HTTP), 443(HTTPS), 8080, 8443
  probe-ports:
    - 80    # HTTP
    - 443   # HTTPS
    - 8080  # HTTP Alt
    - 8443  # HTTPS Alt
```

### 配置说明

| 参数 | 说明 | 推荐值 | 备注 |
|------|------|--------|------|
| `timeout-ms` | 直连超时时间 | 2000-5000ms | 太短可能误判正常慢速连接，太长影响用户体验 |
| `blocked-ip-expiry-minutes` | 超时 IP 缓存时间 | 360 分钟 (6小时) | 平衡性能和灵活性 |
| `probe-ports` | 探测端口 | 80, 443 | 支持协议检测的端口列表 |

## 四、关键代码位置

| 功能 | 文件 | 行号 |
|------|------|------|
| **路由层** | | |
| TCP 路由入口 | `hev-traffic-router.c` | 210-278 |
| 智能代理检查 | `hev-traffic-router.c` | 257-269 |
| 探测端口检查 | `hev-traffic-router.c` | 236-246 |
| **配置解析** | | |
| smart-proxy 配置解析 | `hev-config.c` | 555-620 |
| 获取超时配置 | `hev-config.c` | 1043-1046 |
| 获取过期时间配置 | `hev-config.c` | 1049-1052 |
| 检查是否探测端口 | `hev-config.c` | 1055-1064 |
| **会话管理** | | |
| 启动智能代理会话 | `hev-session-manager.c` | ~400-500 |
| 智能代理任务 | `hev-session-manager.c` | ~2000-2500 |
| **黑名单功能** | | |
| 黑名单数据结构 | `hev-filter.c` | 130-134 |
| 添加 IP 到黑名单 | `hev-filter.c` | 1626-1631 |
| 检查 IP 是否在黑名单 | `hev-filter.c` | 1641-1646 |
| 通用条目检查 | `hev-filter.c` | 1649-1772 |

## 五、黑名单机制

### 黑名单类型

```c
typedef enum {
    HEV_BLACKLIST_ENTRY_IP,      // IP 地址
    HEV_BLACKLIST_ENTRY_PORT,    // 端口
    HEV_BLACKLIST_ENTRY_SNI,     // TLS SNI
    HEV_BLACKLIST_ENTRY_DOMAIN   // 域名
} HevBlacklistEntryType;
```

### 黑名单条目结构

```c
typedef struct _HevBlacklistEntry {
    HevBlacklistEntryType type;
    ip_addr_t ip_addr;           // IP 地址
    char hostname[256];          // 域名/SNI
    int port;                    // 端口
    time_t added_time;           // 添加时间
    time_t expiry_time;          // 过期时间
    time_t first_seen;           // 首次发现时间
    time_t last_seen;            // 最后发现时间
    uint64_t hit_count;          // 命中次数
    uint64_t bytes_blocked;      // 阻止字节数
    int severity;                // 严重程度
    int is_active;               // 是否活跃
    char id[37];                 // 唯一标识
    struct _HevBlacklistEntry *next;
} HevBlacklistEntry;
```

### 黑名单操作

| 操作 | 函数 | 说明 |
|------|------|------|
| 添加 IP | `hev_filter_blacklist_add_ip()` | 添加 IP 到黑名单 |
| 添加域名 | `hev_filter_blacklist_add_domain()` | 添加域名到黑名单 |
| 检查 IP | `hev_filter_blacklist_check_ip()` | 检查 IP 是否在黑名单 |
| 通用检查 | `hev_filter_blacklist_check_entry()` | 通用条目检查 |
| 获取统计 | `hev_filter_blacklist_get_stats()` | 获取黑名单统计 |
| 清空黑名单 | `hev_filter_blacklist_clear()` | 清空所有条目 |

### 自动过期机制

```c
// 在检查时自动清理过期条目
if (now > entry->expiry_time) {
    *current = entry->next;  // 从链表移除
    blacklist_count--;
    hev_free(entry);          // 释放内存
}
```

## 六、数据流示例

### 示例 1: 首次访问国外网站（直连成功）

```
用户访问: example.com (93.184.216.34)
    │
    ├─→ hev_traffic_router_handle_tcp
    │   ├─→ ACL 检查 ✗
    │   ├─→ 探测端口 ✗ (端口随机非 80/443)
    │   ├─→ 国内 IP ✗ (国外 IP)
    │   ├─→ 智能代理检查
    │   │   ├─→ smart-proxy 启用 ✓
    │   │   ├─→ 黑名单检查 ✗ (首次访问)
    │   │   └─→ SMART_PROXY 模式 ✓
    │   └─→ hev_session_manager_start_smart_proxy
    │
    ├─→ run_smart_proxy_task
    │   ├─→ 尝试 DIRECT 连接
    │   ├─→ 连接成功 (200ms) ✅
    │   └─→ 使用直连传输数据
    │
    └─→ 连接完成 ✅
```

### 示例 2: 首次访问国外网站（直连超时）

```
用户访问: twitter.com (某 IP)
    │
    ├─→ hev_traffic_router_handle_tcp
    │   └─→ SMART_PROXY 模式 ✓
    │
    ├─→ run_smart_proxy_task
    │   ├─→ 尝试 DIRECT 连接
    │   ├─→ 连接超时 (>2000ms) ⏱️
    │   │
    │   ├─→ 记录超时
    │   │   ├─→ hev_filter_blacklist_add_ip()
    │   │   ├─→ 设置过期时间 (当前时间 + 360 分钟)
    │   │   └─→ 记录日志
    │   │
    │   ├─→ 切换到 SOCKS5 代理
    │   ├─→ 连接成功 ✅
    │   └─→ 使用代理传输数据
    │
    └─→ 连接完成 ✅ (通过代理)
```

### 示例 3: 再次访问已超时的 IP

```
用户访问: example.com (93.184.216.34) - 已在黑名单
    │
    ├─→ hev_traffic_router_handle_tcp
    │   ├─→ 国内 IP ✗
    │   ├─→ 智能代理检查
    │   │   ├─→ smart-proxy 启用 ✓
    │   │   ├─→ 黑名单检查 ✓ (IP 在黑名单中)
    │   │   └─→ 跳过 SMART_PROXY，直接使用 SOCKS5
    │   │
    │   └─→ hev_session_manager_start_socks5_tcp
    │
    ├─→ SOCKS5 代理连接
    ├─→ 连接成功 ✅
    │
    └─→ 连接完成 ✅ (跳过直连尝试)
```

### 示例 4: 探测端口的 DOMAIN-FIRST 路由

```
用户访问: example.com:443
    │
    ├─→ hev_traffic_router_handle_tcp
    │   ├─→ ACL 检查 ✗
    │   ├─→ 探测端口检查 ✓ (端口 443)
    │   │
    │   └─→ DOMAIN-FIRST 模式
    │       ├─→ 发送假响应，快速获取 TLS SNI
    │       ├─→ 解析域名: example.com
    │       ├─→ 域名路由决策
    │       │   ├─→ 域名在黑名单？
    │       │   │   ├─→ 是 → SOCKS5 代理
    │       │   │   └─→ 否 → 继续
    │       │   │
    │       │   └─→ 最终路由选择
    │       │
    │       └─→ 建立实际连接
    │
    └─→ 数据传输
```

## 七、性能优化

### 1. 跳过已知超时的 IP

```
首次: 尝试直连 → 超时 → 切换代理 (耗时: ~2秒)
再次: 直接代理 (耗时: ~200ms)
```

### 2. 探测端口优化

对于 HTTP/HTTPS 端口，使用 DOMAIN-FIRST 路由：
- 发送假响应快速触发客户端 TLS 握手
- 获取 SNI 后基于域名做路由决策
- 避免 IP 污染问题

### 3. 黑名单自动过期

```
时间线：
0分钟:  IP 被标记为超时
5分钟:  直接使用代理（跳过直连尝试）
360分钟: 黑名单过期，重新尝试直连
```

## 八、故障排查

### 问题 1: 所有流量都走代理

**可能原因**:
- chnroutes 文件未加载，所有 IP 被识别为国外
- smart-proxy 超时时间设置过短

**检查方法**:
```bash
# 查看日志中的 chnroutes 加载信息
grep "Loaded chnroutes" /path/to/log

# 查看智能代理配置
grep "smart-proxy" /path/to/log
```

### 问题 2: 直连成功但仍然切换到代理

**可能原因**:
- timeout-ms 设置过短，正常慢速连接被误判为超时

**解决方法**:
```yaml
smart-proxy:
  timeout-ms: 5000  # 增加超时时间到 5 秒
```

### 问题 3: 黑名单中的 IP 永远无法恢复

**可能原因**:
- 黑名单过期时间设置过长，或自动过期机制失效

**检查方法**:
```bash
# 查看黑名单统计
grep "blacklist" /path/to/log | grep "entries"
```

## 九、配置建议

### 推荐配置（家庭网络）

```yaml
smart-proxy:
  timeout-ms: 3000
  blocked-ip-expiry-minutes: 360
  probe-ports:
    - 80
    - 443
```

### 推荐配置（服务器/VPS）

```yaml
smart-proxy:
  timeout-ms: 2000
  blocked-ip-expiry-minutes: 60
  probe-ports:
    - 80
    - 443
    - 8080
```

### 推荐配置（移动网络）

```yaml
smart-proxy:
  timeout-ms: 5000
  blocked-ip-expiry-minutes: 720
  probe-ports:
    - 443
```

## 十、与其他功能的配合

### 1. 与 DNS 分流的配合

| 功能 | 作用范围 |
|------|----------|
| DNS 分流 | DNS 查询（端口 53） |
| 智能代理 | TCP 连接（所有端口） |

### 2. 与 ACL 的配合

```
ACL 优先级 > 智能代理

ACL 封锁 → 直接阻止
智能代理 → 直连超时后切换代理
```

### 3. 与 chnroutes 的配合

```
chnroutes 匹配 → 直连（不经过智能代理）
chnroutes 不匹配 → 智能代理检查
```

## 十一、统计信息

### 查看黑名单统计

```c
size_t total_entries, active_entries;
uint64_t total_hits, total_blocked;

hev_filter_blacklist_get_stats(&total_entries, &active_entries,
                                &total_hits, &total_blocked);

printf("Total entries: %zu\n", total_entries);
printf("Active entries: %zu\n", active_entries);
printf("Total hits: %llu\n", total_hits);
printf("Bytes blocked: %llu\n", total_blocked);
```

### 日志示例

```
[INFO] filter: Added IP 93.184.216.34 to blacklist (id=xxx, ttl=360m)
[DEBUG] filter: IP 93.184.216.34 found in blacklist (id=xxx, hits=5, expires in 21540 seconds)
[INFO] router: TCP routing via SMART_PROXY (foreign IP, trying direct first)
```
