# 性能优化分析报告

## 概述

hev-socks5-tunnel 是一个高性能 SOCKS5 代理实现，使用 HevTask 协程框架和 lwIP TCP/IP 协议栈。代码库展示了多种成熟的优化模式，但仍有一些可以改进的地方。

---

## 🔴 高优先级（立即可见的性能提升）

### 1. 锁竞争优化

**问题描述**: DNS 缓存和黑名单使用全局互斥锁

**代码位置**:
```c
// src/hev-dns-cache.c:308
// src/hev-filter.c:1591
hev_task_mutex_lock(&dns_cache_mutex);  // 全局锁，所有查询竞争
```

**影响**: 每个 DNS 查询和 IP 检查都要获取全局锁，高并发下成为瓶颈

**优化方案**: 分片锁（Per-bucket mutexes）
```c
// 将单个大哈希表拆分成多个分片，每个分片独立锁
#define DNS_SHARD_COUNT 16
static HevTaskMutex dns_cache_shards[DNS_SHARD_COUNT];

// 根据哈希值选择分片
int shard = hash % DNS_SHARD_COUNT;
hev_task_mutex_lock(&dns_cache_shards[shard]);
```

**预期收益**: **50-80%** 的并发性能提升

---

### 2. IP 字符串转换优化

**问题描述**: 频繁调用 `ipaddr_ntoa_r()` 用于日志

**代码位置**:
```c
// src/hev-traffic-router.c:218-219
ipaddr_ntoa_r(addr, dst_ip, sizeof(dst_ip));  // 每次路由都转换
```

**优化方案**:
- 日志中直接使用二进制 IP 地址（用十六进制显示）
- 或只在 DEBUG 级别才转换

**预期收益**: 减少 **10-20%** 路由决策开销

---

### 3. DNS 缓存对象池化

**问题描述**: 每个 DNS 缓存条目单独分配

**代码位置**:
```c
// src/hev-dns-cache.c:347
entry = hev_malloc0(sizeof(HevDNSCacheEntry));  // 频繁分配
```

**优化方案**: 使用对象池预分配缓存条目

```c
// 为 DNS 缓存条目创建对象池
static HevObjectPool *dns_entry_pool;

entry = hev_object_pool_get(dns_entry_pool);
// 使用后放回池中
hev_object_pool_put(dns_entry_pool, entry);
```

**预期收益**: 减少 **30%** 内存分配开销

---

## 🟡 中优先级（结构性优化）

### 4. ACL 规则匹配优化

**问题描述**: 多级顺序遍历

**代码位置**:
```c
// src/hev-filter.c:1992-2164
// Stage 1 → Stage 2，每次都遍历链表
```

**优化方案**:
- 域名规则使用 Trie 树
- IP 端口规则使用位图索引

**预期收益**: **20-40%** ACL 查询性能提升

---

### 5. TCP 连接池复用

**问题描述**: 每个连接创建新 socket

**代码位置**:
```c
// src/hev-session-manager.c
// 每次都要创建、握手、认证
```

**优化方案**:
- SOCKS5 连接池
- 预建立 N 个热连接

```c
// 连接池结构
typedef struct {
    int fd;
    time_t last_used;
    int in_use;
} SOCKS5ConnPoolEntry;

// 预建立连接池
static SOCKS5ConnPoolEntry conn_pool[16];
```

**预期收益**: 减少 **30-50ms** 建立连接延迟

---

### 6. 批量化 I/O 操作

**问题描述**: 单次 `writev()` 传递少量数据

**代码位置**:
```c
// src/hev-socks5-session-tcp.c:70
writev(fd, iov, iov_cnt);  // iov_cnt 可能很小
```

**优化方案**: 聚合多个小包，增加 iov 数组大小

**预期收益**: **10-15%** 吞吐量提升

---

## 🟢 低优先级（微优化）

### 7. 分支预测优化

```c
// 使用 likely/unlikely 宏提示编译器
if (unlikely(port == 53)) {
    // DNS 处理逻辑
}
```

### 8. 缓存行友好性

```c
// 确保热数据在同一缓存行
struct __attribute__((aligned(64))) HotData {
    // 频繁访问的数据
};
```

### 9. 零拷贝优化

- 扩展 ring buffer 使用范围
- 减少 pbuf 复制

---

## 建议实施顺序

| 优先级 | 优化项         | 预期收益            | 实施难度 |
|--------|----------------|---------------------|----------|
| 🔴 P0  | DNS 缓存分片锁 | 50-80% 并发提升     | 中       |
| 🔴 P0  | IP 转换优化    | 10-20% 路由提升      | 低       |
| 🟡 P1  | DNS 对象池     | 30% 内存提升         | 低       |
| 🟡 P1  | ACL Trie 优化  | 20-40% ACL 提升      | 高       |
| 🟢 P2  | SOCKS5 连接池  | 30-50ms 延迟降低     | 高       |

---

## 热点路径

1. **Traffic Router**: `hev_traffic_router_handle_tcp()` - 首包路由决策
2. **Filter Checks**: `hev_filter_is_domestic()` 和黑名单查找
3. **DNS Cache**: `hev_dns_cache_lookup()` - 每个 DNS 查询
4. **Session Handling**: TCP/UDP splice 数据传输操作
5. **ACL Matching**: 多阶段规则评估

---

## 当前优化状态

✅ **已实现的优化**:
- 对象池（UDP 帧）
- Radix Tree IP 查找
- Ring Buffer 零拷贝
- 协程架构

⏳ **待实施的优化**:
- DNS 缓存分片锁
- IP 字符串转换优化
- DNS 对象池化
- ACL Trie 优化
- SOCKS5 连接池
