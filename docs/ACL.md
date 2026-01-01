# ACL (访问控制列表) 功能文档

## 一、功能概述

ACL (Access Control List) 是一个强大的访问控制系统，用于允许或阻止特定 IP、端口、域名和 CIDR 范围的连接。它是流量控制的第一道防线，具有最高优先级。

### 核心特性

- **多种匹配类型**: IP 地址、CIDR 范围、端口号、域名（支持通配符）
- **两种操作**: ALLOW（允许）和 BLOCK（阻止）
- **高优先级**: 在所有路由决策之前执行
- **高性能**: 使用 Radix Tree 实现 IP/CIDR 的 O(1) 查找
- **灵活格式**: 支持简化格式和完整格式

## 二、工作流程

### TCP 连接 ACL 检查流程

```
TCP 连接请求
    │
    ├─→ 【优先级1】ACL IP 检查
    │   │
    │   ├─→ IP 在 ACL BLOCK 列表中？
    │   │   ├─→ 是 → 阻止连接 ❌
    │   │   │       └─→ 终止 PCB，返回
    │   │   │
    │   │   └─→ 否 ↓
    │   │
    │   └─→ 继续其他路由决策
    │       ├─→ 探测端口检查
    │       ├─→ 国内 IP 检查
    │       ├─→ 智能代理检查
    │       └─→ SOCKS5 代理
    │
    └─→ 建立连接
```

### UDP 数据包 ACL 检查流程

```
UDP 数据包
    │
    ├─→ 【优先级1】ACL IP 检查
    │   │
    │   ├─→ 目标 IP 在 ACL BLOCK 列表中？
    │   │   ├─→ 是 → 丢弃数据包 ❌
    │   │   │       └─→ 返回处理完成
    │   │   │
    │   │   └─→ 否 ↓
    │   │
    │   └─→ 继续其他路由决策
    │       ├─→ DNS 查询处理
    │       ├─→ 国内 IP 检查
    │       └─→ SOCKS5 代理
    │
    └─→ 转发数据包
```

### 域名 ACL 检查流程（用于协议解析后）

```
协议解析获取域名
    │
    ├─→ 域名精确匹配
    │   ├─→ 找到 BLOCK 规则 → 阻止 ❌
    │   └─→ 找到 ALLOW 规则 → 允许 ✅
    │
    ├─→ 域名后缀匹配
    │   ├─→ 找到 BLOCK 规则 → 阻止 ❌
    │   └─→ 找到 ALLOW 规则 → 允许 ✅
    │
    ├─→ 域名通配符匹配
    │   ├─→ 找到 BLOCK 规则 → 阻止 ❌
    │   └─→ 找到 ALLOW 规则 → 允许 ✅
    │
    └─→ 未匹配到规则 → 继续正常流程
```

## 三、配置文件

### 主配置 (`conf/main.yml`)

```yaml
acl:
  # ACL 规则文件路径
  # 留空则不加载 ACL
  file-path: "conf/acl.txt"
```

### ACL 规则文件格式 (`conf/acl.txt`)

```bash
# ========================================
# ACL 规则文件
# 格式: <action> <type> <value>
#   action: allow | block
#   type:   ip | cidr | port | domain
#   value:  具体值（根据类型不同）
# ========================================

# 阻止特定 IP
block ip 1.2.3.4
block ip 192.168.1.100

# 阻止 IP 范围（CIDR）
block cidr 10.0.0.0/8
block cidr 192.168.0.0/16

# 阻止端口
block port 23      # Telnet
block port 135     # Windows RPC

# 阻止域名
block domain ads.example.com
block domain tracker.server.com

# 阻止通配符域名
block domain *.adnetwork.com
block domain *.analytics.com

# 阻止后缀域名
block domain .spam-site.com

# ========================================
# 简化格式（自动检测类型）
# 格式: <action> <value>
# ========================================

# 自动检测为 IP
block 5.6.7.8

# 自动检测为 CIDR（包含 /）
block 172.16.0.0/12

# 自动检测为端口（纯数字）
block 8080

# 自动检测为域名（包含字母或通配符）
block malware.example.com
block *.tracker.com

# ========================================
# ALLOW 规则
# ========================================

# 允许特定 IP（白名单模式）
allow ip 8.8.8.8
allow ip 1.1.1.1

# 允许端口
allow port 22     # SSH
allow port 443    # HTTPS

# 允许域名
allow domain trusted.service.com
allow domain *.internal.net

# ========================================
# 注释
# 以 # 开头的行为注释
# 这行会被忽略
```

### 规则格式说明

| 格式 | 说明 | 示例 |
|------|------|------|
| **完整格式** | `block ip 1.2.3.4` | 明确指定类型 |
| **简化格式** | `block 1.2.3.4` | 自动检测类型 |
| **注释** | `# This is a comment` | 以 # 开头 |

### 类型自动检测规则

| 值格式 | 自动检测为类型 |
|--------|---------------|
| `1.2.3.4` | IP 地址 |
| `192.168.0.0/24` | CIDR 范围 |
| `80`, `443` | 端口号 |
| `example.com` | 域名 |
| `*.example.com` | 域名（通配符） |

## 四、ACL 规则类型详解

### 1. IP 地址规则

```
block ip 1.2.3.4
allow ip 8.8.8.8
```

- **精确匹配**: 单个 IPv4 或 IPv6 地址
- **存储**: Radix Tree（O(1) 查找）
- **用途**: 阻止/允许特定服务器

### 2. CIDR 范围规则

```
block cidr 10.0.0.0/8
allow cidr 192.168.1.0/24
```

- **范围匹配**: IP 地址段
- **存储**: Radix Tree（O(prefix) 查找）
- **用途**: 阻止/允许整个网段

### 3. 端口规则

```
block port 23
block port 135-139
allow port 22
```

- **端口匹配**: TCP/UDP 端口号
- **存储**: 哈希表（索引为端口号）
- **用途**: 阻止/允许特定服务端口

### 4. 域名规则

```
# 精确匹配
block domain ads.example.com

# 通配符匹配（*.example.com）
block domain *.adnetwork.com

# 后缀匹配（.example.com）
block domain .spam-site.com
```

- **域名匹配**: 精确、通配符、后缀
- **存储**: 三个独立哈希表
- **用途**: 基于域名阻止/允许连接

## 五、关键代码位置

| 功能 | 文件 | 行号 |
|------|------|------|
| **路由层** | | |
| TCP ACL 检查 | `hev-traffic-router.c` | 224-233 |
| UDP ACL 检查 | `hev-traffic-router.c` | 294-300 |
| **配置解析** | | |
| ACL 配置解析 | `hev-config.c` | 629-657 |
| **ACL 加载** | | |
| ACL 加载函数 | `hev-filter.c` | 979-1194 |
| IP 规则处理 | `hev-filter.c` | 1102-1126 |
| CIDR 规则处理 | `hev-filter.c` | 1127-1155 |
| 端口规则处理 | `hev-filter.c` | 1088-1101 |
| 域名规则处理 | `hev-filter.c` | 1156-1183 |
| **ACL 检查** | | |
| IP 封锁检查 | `hev-filter.c` | 1314-1337 |
| 域名封锁检查 | `hev-filter.c` | 1340-1358 |
| 端口封锁检查 | `hev-filter.c` | 1360-1367 |
| **Radix Tree** | | |
| IPv4 插入 | `hev-filter.c` | ~700-800 |
| IPv4 查找 | `hev-filter.c` | ~800-900 |
| IPv6 插入 | `hev-filter.c` | ~900-1000 |
| IPv6 查找 | `hev-filter.c` | ~1000-1100 |

## 六、数据结构

### ACL 规则结构

```c
typedef enum {
    HEV_ACL_ACTION_ALLOW,    // 允许
    HEV_ACL_ACTION_BLOCK     // 阻止
} HevACLAction;

typedef enum {
    HEV_ACL_TYPE_IP,        // IP 地址
    HEV_ACL_TYPE_CIDR,      // CIDR 范围
    HEV_ACL_TYPE_PORT,      // 端口
    HEV_ACL_TYPE_DOMAIN     // 域名
} HevACLType;

typedef struct _HevACLRule {
    HevACLAction action;     // ALLOW 或 BLOCK
    HevACLType type;         // 规则类型
    char value[256];         // 规则值
    struct _HevACLRule *next; // 链表下一节点
} HevACLRule;
```

### 存储结构

```
ACL 规则存储:
├── acl_ip_rules          → IP 规则链表
├── acl_cidr_rules        → CIDR 规则链表
├── acl_port_rules[65536] → 端口规则数组（直接索引）
├── acl_domain_exact[]    → 精确域名哈希表
├── acl_domain_suffix[]   → 后缀域名哈希表
└── acl_domain_wildcard[] → 通配符域名哈希表

Radix Tree:
├── acl_ipv4_tree         → IPv4 Radix Tree（O(1) 查找）
└── acl_ipv6_tree         → IPv6 Radix Tree（O(prefix) 查找）
```

## 七、数据流示例

### 示例 1: 阻止特定 IP

```
ACL 规则: block ip 1.2.3.4

用户尝试连接: 1.2.3.4:80
    │
    ├─→ hev_traffic_router_handle_tcp
    │   ├─→ ACL IP 检查
    │   │   ├─→ radix_tree_lookup_ipv4(1.2.3.4)
    │   │   ├─→ 返回 HEV_ACL_ACTION_BLOCK
    │   │   └─→ 阻止连接 ❌
    │   │
    │   └─→ 终止 PCB
    │       └─→ 返回 RST 给客户端
    │
    └─→ 连接被阻止
```

### 示例 2: 允许特定端口，阻止其他

```
ACL 规则:
  allow port 443
  block port 80

用户尝试连接: example.com:80
    │
    ├─→ hev_traffic_router_handle_tcp
    │   ├─→ ACL IP 检查 ✗
    │   ├─→ 端口 80 在 BLOCK 列表中 ✓
    │   │
    │   └─→ 阻止连接 ❌

用户尝试连接: example.com:443
    │
    ├─→ hev_traffic_router_handle_tcp
    │   ├─→ ACL IP 检查 ✗
    │   ├─→ 端口 443 在 ALLOW 列表中 ✓
    │   │
    │   └─→ 继续正常路由 ✅
```

### 示例 3: 域名通配符匹配

```
ACL 规则: block domain *.adnetwork.com

用户访问: tracker.adnetwork.com:443
    │
    ├─→ 域名解析获取 SNI: tracker.adnetwork.com
    │
    ├─→ 域名精确匹配
    │   └─→ 未匹配
    │
    ├─→ 域名后缀匹配
    │   └─→ 未匹配
    │
    ├─→ 域名通配符匹配
    │   ├─→ 检查 *.adnetwork.com
    │   ├─→ 匹配成功 ✓
    │   └─→ 阻止连接 ❌
```

### 示例 4: CIDR 范围阻止

```
ACL 规则: block cidr 10.0.0.0/8

用户尝试连接: 10.1.2.3:80
    │
    ├─→ hev_traffic_router_handle_tcp
    │   ├─→ ACL IP 检查
    │   │   ├─→ radix_tree_lookup_ipv4(10.1.2.3)
    │   │   ├─→ 匹配 10.0.0.0/8 前缀
    │   │   ├─→ 返回 HEV_ACL_ACTION_BLOCK
    │   │   └─→ 阻止连接 ❌
    │   │
    │   └─→ 连接被阻止
```

## 八、规则优先级

### 优先级顺序

```
ACL 规则匹配优先级（从高到低）:
┌─────────────────────────────────────────┐
│ 1. IP 精确匹配（Radix Tree 最长前缀） │
│ 2. CIDR 范围匹配（Radix Tree 前缀匹配） │
│ 3. 端口精确匹配（哈希表直接索引）     │
│ 4. 域名精确匹配（哈希表）             │
│ 5. 域名后缀匹配（哈希表）             │
│ 6. 域名通配符匹配（哈希表）           │
└─────────────────────────────────────────┘
```

### 规则冲突处理

```
规则冲突处理原则:
┌──────────────────────────────────────┐
│ 1. BLOCK 优先于 ALLOW（安全第一）  │
│ 2. 更具体的规则优先                │
│    - IP > CIDR                      │
│    - 精确域名 > 通配符域名          │
│ 3. 先匹配的规则生效                │
└──────────────────────────────────────┘
```

### 冲突示例

```
示例 1: IP 规则冲突
block ip 10.0.0.0/24
allow ip 10.0.0.5
结果: 10.0.0.5 被阻止（CIDR 覆盖了单个 IP）

示例 2: 域名规则冲突
block domain *.example.com
allow domain api.example.com
结果: api.example.com 被阻止（通配符覆盖了子域名）

示例 3: 不同类型规则
block ip 1.2.3.4
allow domain example.com (解析到 1.2.3.4)
结果: 1.2.3.4 被阻止（IP 规则在路由层优先检查）
```

## 九、性能特性

### Radix Tree 优势

```
IP/CIDR 查找性能:
┌──────────────────────────────────────┐
│ Radix Tree: O(1) 或 O(prefix)       │
│   - IPv4: 最多 32 次比较            │
│   - IPv6: 最多 128 次比较           │
│                                    │
│ 链表查找: O(n)                     │
│   - 需要遍历所有规则              │
└──────────────────────────────────────┘
```

### 域名哈希优化

```
域名匹配优化:
┌──────────────────────────────────────┐
│ 三个独立哈希表（1024 桶）:          │
│ 1. 精确域名 → hash → O(1)          │
│ 2. 后缀域名 (.example.com)           │
│ 3. 通配符域名 (*.example.com)       │
│                                    │
│ 分离存储避免不必要的检查            │
└──────────────────────────────────────┘
```

### 内存使用

```
内存占用估算:
├── 每个 ACL 规则: ~300 字节
├── Radix Tree 节点: ~64 字节/节点
├── IPv4 Tree: 约 32 * 节点数 字节
└── IPv6 Tree: 约 128 * 节点数 字节

示例（1000 条规则）:
├── 规则存储: ~300 KB
├── Radix Tree: ~100-200 KB
└── 总计: ~400-500 KB
```

## 十、故障排查

### 问题 1: ACL 规则不生效

**可能原因**:
1. ACL 文件路径配置错误
2. ACL 文件格式不正确
3. 规则类型不匹配

**检查方法**:
```bash
# 查看日志中的 ACL 加载信息
grep "Loading ACL" /path/to/log

# 查看 ACL 规则加载统计
grep "Loaded ACL rules" /path/to/log

# 验证 ACL 文件格式
cat /path/to/acl.txt | grep -v "^#" | grep -v "^$"
```

### 问题 2: 应该被阻止的流量通过了

**可能原因**:
1. 规则格式错误（被跳过）
2. 规则类型不匹配
3. 规则优先级问题

**检查方法**:
```bash
# 查看规则跳过警告
grep "Invalid ACL line" /path/to/log

# 查看实际匹配的规则
grep "ACL action" /path/to/log
```

### 问题 3: 所有流量都被阻止

**可能原因**:
1. ACL 规则配置过于宽泛
2. CIDR 范围配置错误

**检查方法**:
```bash
# 查看阻止统计
grep "ip_blocked" /path/to/log

# 检查 CIDR 规则
grep "cidr" /path/to/acl.txt
```

## 十一、配置示例

### 示例 1: 基础安全配置

```bash
# conf/acl.txt - 基础安全配置

# 阻止常见攻击端口
block port 23     # Telnet
block port 135    # Windows RPC
block port 139    # NetBIOS
block port 445    # SMB
block port 1433   # MySQL
block port 3389   # RDP

# 阻止已知恶意 IP
block ip 1.2.3.4
block ip 5.6.7.8
```

### 示例 2: 广告拦截配置

```bash
# conf/acl.txt - 广告拦截

# 阻止广告域名
block domain *.doubleclick.net
block domain *.googleadservices.com
block domain *.googlesyndication.com
block domain *.adnetwork.com
block domain *.analytics.com

# 阻止跟踪器
block domain tracker.example.com
block domain *.tracker.net
```

### 示例 3: 白名单模式

```bash
# conf/acl.txt - 白名单模式

# 首先阻止所有端口
block port 1-65535

# 然后允许特定端口
allow port 22     # SSH
allow port 80     # HTTP
allow port 443    # HTTPS
allow port 3306   # MySQL
```

### 示例 4: 企业网络配置

```bash
# conf/acl.txt - 企业网络

# 阻止外部访问内网 IP
block cidr 10.0.0.0/8
block cidr 172.16.0.0/12
block cidr 192.168.0.0/16

# 阻止非业务端口
block port 23     # Telnet
block port 135-139 # Windows RPC
block port 445    # SMB

# 允许业务端口
allow port 80     # HTTP
allow port 443    # HTTPS
allow port 22     # SSH
```

## 十二、与其他功能的配合

### 优先级对比

```
功能优先级（从高到低）:
┌─────────────────────────────────────────┐
│ 1. ACL 封锁检查                         │
│ 2. DNS Forwarder 劫持                   │
│ 3. 探测端口（DOMAIN-FIRST）              │
│ 4. DNS 分流检查                         │
│ 5. 国内 IP 检查（chnroutes）            │
│ 6. 智能代理检查                         │
│ 7. SOCKS5 代理                          │
└─────────────────────────────────────────┘
```

### 与黑名单的区别

```
┌─────────────────┬──────────────────┬──────────────────┐
│      特性        │      ACL         │   黑名单        │
├─────────────────┼──────────────────┼──────────────────┤
│ 用途            │ 安全访问控制     │ 性能优化        │
│ 优先级          │ 最高（第一道防线）│ 较低            │
│ 效果            │ 阻止连接         │ 路过直连        │
│ 持久性          │ 永久（手动配置） │ 临时（自动过期） │
│ 规则类型        │ allow/block     │ block           │
│ 配置方式        │ 文件            │ 动态添加        │
└─────────────────┴──────────────────┴──────────────────┘
```

## 十三、统计信息

### 查看 ACL 统计

```bash
# 查看日志中的统计信息
grep "stats" /path/to/log | grep -i acl
```

### 统计字段

```c
typedef struct _HevFilterStats {
    uint64_t total_packets;
    uint64_t blocked_packets;
    uint64_t ip_blocked;
    uint64_t port_blocked;
    uint64_t domain_blocked;
    uint64_t domestic_hits;
    uint64_t foreign_hits;
    // ...更多字段
} HevFilterStats;
```

### 日志示例

```
[INFO] filter: Loading ACL from conf/acl.txt (new format)
[INFO] filter: Loaded ACL rules (total:150, allow:10, block:140) [ip:50, cidr:20, port:15, domain:65]
[WARN] router: TCP connection blocked to IP: 1.2.3.4:80 (from 192.168.1.100:54321) by ACL
```

## 十四、最佳实践

### 1. 规则组织

```bash
# 按类型组织规则
# ========================================
# 端口规则
# ========================================
block port 23
block port 135

# ========================================
# IP 规则
# ========================================
block ip 1.2.3.4

# ========================================
# CIDR 规则
# ========================================
block cidr 10.0.0.0/8

# ========================================
# 域名规则
# ========================================
block domain *.example.com
```

### 2. 注释使用

```bash
# 阻止 Telnet（不安全的明文协议）
block port 23

# 阻止已知恶意 IP（来自威胁情报）
block ip 1.2.3.4  # C2 Server
block ip 5.6.7.8  # Botnet
```

### 3. 规则测试

```bash
# 加载前测试规则格式
grep -v "^#" conf/acl.txt | while read line; do
    echo "Testing: $line"
    # 验证格式
done

# 加载后验证规则
# 查看日志确认规则数量
```

### 4. 定期维护

```bash
# 定期审查 ACL 规则
# 移除过期的规则
# 更新新的威胁情报
# 检查规则冲突
```
