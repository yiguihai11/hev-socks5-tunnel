# hev-task-system 协程框架分析

## 项目概述

**HevTaskSystem** 是一个轻量级的协程（任务）系统，专为高性能网络编程设计。该项目采用非抢占式调度策略，基于 setjmp/longjmp 实现上下文切换，具有极高的可移植性和可扩展性。

## 1. 项目整体结构

```
hev-task-system/
├── src/                    # 源代码目录
│   ├── kern/              # 内核模块
│   │   ├── core/          # 核心调度器
│   │   ├── task/          # 任务管理
│   │   ├── io/            # I/O 反应器
│   │   ├── itc/           # 任务间通信
│   │   ├── sync/          # 同步原语
│   │   └── time/          # 定时器
│   ├── lib/               # 基础库
│   │   ├── object/        # 对象模型
│   │   ├── list/          # 链表
│   │   ├── rbtree/        # 红黑树
│   │   └── misc/          # 杂项工具
│   ├── mem/               # 内存管理
│   │   ├── api/           # 内存分配接口
│   │   ├── slice/         # 分片内存分配器
│   │   └── base/          # 基础分配器
│   └── arch/              # 架构相关代码
├── include/               # 公共头文件
├── apps/                  # 示例程序
├── tests/                 # 测试代码
└── Makefile              # 构建文件
```

## 2. 主要源文件和功能

### 2.1 核心调度器 (src/kern/core/)

#### hev-task-system.c
- 任务系统初始化
- 主事件循环
- 资源清理

```c
int hev_task_system_init(void);
void hev_task_system_run(void);
void hev_task_system_fini(void);
```

#### hev-task-system-schedule.c
- 任务调度算法实现
- 上下文切换逻辑
- 调度策略管理

```c
void hev_task_system_schedule(HevTaskYieldType type);
void hev_task_system_wakeup(HevTask *task);
```

### 2.2 任务管理 (src/kern/task/)

#### hev-task.c
- 任务对象的创建、销毁和管理
- 任务状态控制
- 优先级管理

```c
HevTask *hev_task_new(int stack_size);
void hev_task_run(HevTask *task, HevTaskEntry entry, void *data);
void hev_task_exit(void);
```

#### hev-task-executer.c
- 任务执行器实现
- 上下文切换处理
- 栈管理

#### hev-task-stack-heap.c / hev-task-stack-mmap.c
- 栈的两种实现方式
  - heap: 使用 malloc 分配
  - mmap: 使用 mmap 系统调用

```c
HevTaskStack *hev_task_stack_new(size_t size);
void hev_task_stack_free(HevTaskStack *stack);
```

#### hev-task-call.c
- 在新栈上执行函数
- 栈帧管理
- 异常处理

### 2.3 I/O 反应器 (src/kern/io/)

#### 多平台实现
- **hev-task-io-reactor-epoll.c**: Linux epoll 实现
- **hev-task-io-reactor-kqueue.c**: BSD/kqueue 实现
- **hev-task-io-reactor-iocp.c**: Windows IOCP 实现

```c
int hev_task_io_reactor_add_fd(HevTaskIOReactor *reactor, int fd, unsigned int events);
int hev_task_io_reactor_mod_fd(HevTaskIOReactor *reactor, int fd, unsigned int events);
int hev_task_io_reactor_del_fd(HevTaskIOReactor *reactor, int fd);
```

### 2.4 任务间通信 (src/kern/itc/)

#### hev-task-channel.c
- 通道实现
- 支持同步和异步通信
- 缓冲区管理

```c
int hev_task_channel_new(HevTaskChannel **chan1, HevTaskChannel **chan2);
ssize_t hev_task_channel_read(HevTaskChannel *chan, void *buffer, size_t count);
ssize_t hev_task_channel_write(HevTaskChannel *chan, const void *buffer, size_t count);
```

#### hev-task-channel-select.c
- 多路选择器
- 支持多通道监控
- 超时控制

### 2.5 同步原语 (src/kern/sync/)

#### hev-task-mutex.c
- 互斥锁实现
- 递归锁支持
- 死锁检测

```c
int hev_task_mutex_lock(HevTaskMutex *mutex);
int hev_task_mutex_unlock(HevTaskMutex *mutex);
```

#### hev-task-cond.c
- 条件变量实现
- 信号/广播支持
- 与互斥锁配合

```c
int hev_task_cond_wait(HevTaskCond *cond, HevTaskMutex *mutex);
int hev_task_cond_signal(HevTaskCond *cond);
int hev_task_cond_broadcast(HevTaskCond *cond);
```

### 2.6 基础库 (src/lib/)

#### 数据结构
- **src/lib/list/**: 双向链表实现
- **src/lib/rbtree/**: 红黑树实现（用于任务调度）
- **src/lib/object/**: 对象引用计数模型

#### 内存管理
- **src/mem/slice/**: 分片内存分配器，减少内存碎片
- **src/mem/base/**: 基础内存分配器

## 3. 协程实现机制

### 3.1 调度器架构

#### 核心数据结构

```c
struct _HevTaskSystemContext {
    HevTask *current_task;        // 当前运行的任务
    HevRBTreeCached running_tasks; // 运行任务的红黑树
    HevTaskTimer *timer;          // 定时器
    HevTaskIOReactor *reactor;    // I/O 反应器
    jmp_buf kernel_context;       // 内核上下文
};
```

#### 调度算法

- **非抢占式调度**: 任务主动让出 CPU
- **优先级调度**: `sched_key = 运行时间 × 优先级`
- **红黑树队列**: O(log n) 的插入和删除
- **动态优先级**: 支持运行时调整

### 3.2 任务状态转换

```c
typedef enum {
    HEV_TASK_STOPPED,  // 停止状态
    HEV_TASK_RUNNING,  // 运行状态
    HEV_TASK_WAITING,  // 等待状态
} HevTaskState;
```

#### 状态转换图

```
STOPPED → RUNNING → WAITING → RUNNING
                ↓              ↓
              YIELD         I/O就绪/定时器
```

#### 状态转换说明

1. **RUNNING → WAITING**
   - 任务调用 `hev_task_yield(HEV_TASK_WAITIO)` 等待 I/O
   - 任务调用 `hev_task_yield(HEV_TASK_SLEEP)` 睡眠

2. **RUNNING → RUNNING**
   - 任务调用 `hev_task_yield(HEV_TASK_YIELD)` 主动让出 CPU

3. **WAITING → RUNNING**
   - I/O 事件触发
   - 定时器到期
   - 被其他任务唤醒

### 3.3 调度流程

```c
void hev_task_system_schedule(HevTaskYieldType type) {
    // 1. 保存当前任务上下文
    if (_setjmp(ctx->current_task->context))
        return; // 恢复到任务上下文

    // 2. 内核上下文处理
    switch (_longjmp(ctx->kernel_context, type)) {
    case HEV_TASK_SCHED_SWITCH:
        // 重新插入运行队列
        hev_task_system_insert_task(ctx, task);
        break;
    case HEV_TASK_SCHED_WAITIO:
        // 移到等待队列
        break;
    case HEV_TASK_SCHED_REMOVE:
        // 移除任务
        break;
    }

    // 3. 选择下一个任务
    hev_task_system_pick_current_task(ctx);

    // 4. 切换到新任务
    _longjmp(ctx->current_task->context, 1);
}
```

## 4. 核心数据结构

### 4.1 任务结构体

```c
struct _HevTask {
    void *stack_bottom;           // 栈底地址
    HevTaskEntry entry;          // 任务入口函数
    void *data;                  // 用户数据

    uint64_t sched_key;          // 调度键值
    HevRBTreeNode sched_node;    // 调度节点
    HevTaskSchedEntity sched_entity; // I/O 调度实体

    HevTaskStack *stack;        // 任务栈
    HevTask *joiner;            // 等待此任务的任务

    int ref_count;              // 引用计数
    int priority;               // 当前优先级
    int next_priority;          // 下次调度优先级
    HevTaskState state;         // 任务状态

    jmp_buf context;            // 上下文信息
    HevListNode list_node;      // 全局任务链表节点
};
```

### 4.2 红黑树调度队列

使用红黑树维护运行队列：
- 根据 `sched_key` 排序
- `sched_key = 运行时间 × 优先级`
- 数值越小，优先级越高
- 支持动态插入、删除和遍历

### 4.3 I/O 反应器模式

#### 工作流程

1. 任务注册文件描述符到反应器
2. 任务调用 `yield(HEV_TASK_WAITIO)` 进入等待状态
3. I/O 事件触发时，任务被唤醒并重新插入运行队列

#### 多平台支持

| 平台 | API | 实现文件 |
|------|-----|----------|
| Linux | epoll | epoll.c |
| BSD/macOS | kqueue | kqueue.c |
| Windows | IOCP | iocp.c |

## 5. 内存管理和上下文切换

### 5.1 栈管理

#### 堆栈分配 (STACK_HEAP)

```c
// 使用 malloc 分配连续内存
void *stack = malloc(size);

#ifdef ENABLE_STACK_OVERFLOW_DETECTION
// 支持栈溢出检测
#endif
```

**特点**：
- 使用 `malloc` 分配连续内存
- 支持栈溢出检测
- 适合 32 位系统

#### 内存映射栈 (STACK_MMAP) - 推荐

```c
// 使用 mmap 分配
void *stack = mmap(NULL, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANON | MAP_STACK, -1, 0);

#ifdef ENABLE_STACK_OVERFLOW_DETECTION
// 保护页用于检测栈溢出
mprotect(stack, page_size, PROT_NONE);
#endif
```

**特点**：
- 使用 `mmap(MAP_STACK)` 分配
- 支持保护页检测栈溢出
- 更安全的内存隔离
- 默认方式

### 5.2 上下文切换机制

#### 使用 setjmp/longjmp 实现

```c
// 任务创建
if (_setjmp(task->context) == 0) {
    return; // 第一次设置
}
task->entry(task->data);  // 恢复后执行
hev_task_system_kill_current_task();

// 上下文切换
_setjmp(current->context);
_longjmp(target->context, 1);
```

**优势**：
- 可移植性强，支持 15+ 架构
- 代码简洁，易于维护
- 无需汇编优化
- 标准库支持

### 5.3 内存分配器

#### 分片内存分配器 (Slice Allocator)

- 将大块内存切分为固定大小的片
- 减少内存碎片
- 提高分配/释放效率

```c
struct _HevMemoryAllocatorSlice {
    // 分片分配器实现
};
```

## 6. API 接口设计

### 6.1 任务系统 API

```c
// 初始化/清理
int hev_task_system_init(void);
void hev_task_system_fini(void);
void hev_task_system_run(void);

// 任务管理
HevTask *hev_task_new(int stack_size);
void hev_task_run(HevTask *task, HevTaskEntry entry, void *data);
void hev_task_yield(HevTaskYieldType type);
void hev_task_exit(void);

// 优先级控制
void hev_task_set_priority(HevTask *task, int priority);
int hev_task_get_priority(HevTask *task);

// I/O 操作
int hev_task_add_fd(HevTask *task, int fd, unsigned int events);
int hev_task_mod_fd(HevTask *task, int fd, unsigned int events);
int hev_task_del_fd(HevTask *task, int fd);

// 定时器
int hev_task_sleep(struct timespec *timespec);
```

### 6.2 通道 API

```c
// 创建通道对
int hev_task_channel_new(HevTaskChannel **chan1, HevTaskChannel **chan2);
int hev_task_channel_new_with_buffers(HevTaskChannel **chan1,
                                      HevTaskChannel **chan2,
                                      unsigned int size, unsigned int buffers);

// 通道通信
ssize_t hev_task_channel_read(HevTaskChannel *chan, void *buffer, size_t count);
ssize_t hev_task_channel_write(HevTaskChannel *chan, const void *buffer, size_t count);

// 多路选择
int hev_task_channel_select(HevTaskChannelSelectEntry *entries, unsigned int n);
```

### 6.3 同步原语 API

```c
// 互斥锁
int hev_task_mutex_new(HevTaskMutex **mutex);
int hev_task_mutex_lock(HevTaskMutex *mutex);
int hev_task_mutex_unlock(HevTaskMutex *mutex);
void hev_task_mutex_free(HevTaskMutex *mutex);

// 条件变量
int hev_task_cond_new(HevTaskCond **cond);
int hev_task_cond_wait(HevTaskCond *cond, HevTaskMutex *mutex);
int hev_task_cond_signal(HevTaskCond *cond);
int hev_task_cond_broadcast(HevTaskCond *cond);
void hev_task_cond_free(HevTaskCond *cond);
```

## 7. 与其他协程库对比

### 7.1 与 libco 对比

| 特性 | HevTaskSystem | libco |
|------|---------------|-------|
| 调度方式 | 非抢占式 | 非抢占式 |
| 上下文切换 | setjmp/longjmp | 汇编优化 |
| I/O 模型 | 反应器模式 | 阻塞 I/O |
| 内存管理 | 分片分配器 | malloc |
| 跨平台 | Linux/BSD/macOS/Windows | Linux/Windows |
| 多线程 | 支持 | 不支持 |
| 代码复杂度 | 低 | 中 |

### 7.2 与 Go 协程对比

| 特性 | HevTaskSystem | Go 协程 |
|------|---------------|---------|
| 调度器 | 单调度器 | 多调度器 |
| 栈管理 | 固定大小/动态 | 动态增长 |
| GOMAXPROCS | 不支持 | 支持 |
| channel | 支持但较简单 | 一等公民 |
| 垃圾回收 | 不需要 | 需要 |
| 语言 | C | Go |
| 性能 | 高 | 高 |

### 7.3 与 Boost.Coroutine 对比

| 特性 | HevTaskSystem | Boost.Coroutine |
|------|---------------|-----------------|
| 设计目标 | 轻量级、嵌入式 | 通用、高性能 |
| 依赖 | 无外部依赖 | Boost 库 |
| API 风格 | 简洁 C 风格 | 现代 C++ |
| 异步 I/O | 内置支持 | 需要配合 ASIO |
| 学习曲线 | 低 | 中高 |

### 7.4 HevTaskSystem 的特点

#### 优势

1. **轻量级设计**
   - 最小化内存占用
   - 零动态内存分配（运行时）
   - 适合嵌入式系统

2. **高性能调度**
   - 红黑树调度队列
   - 基于时间的优先级计算
   - 避免 O(n) 调度

3. **跨平台兼容**
   - 支持 15+ 架构
   - 统一 API 接口
   - 条件编译优化

4. **I/O 优化**
   - 原生支持 epoll/kqueue/IOCP
   - 零拷贝 I/O 操作
   - 边缘触发模式

5. **丰富的同步机制**
   - 通道（Channel）
   - 互斥锁
   - 条件变量
   - 多路选择器

#### 劣势

1. **单调度器**: 无法利用多核
2. **非抢占式**: 需要主动让出 CPU
3. **固定栈大小**: 可能浪费内存

## 8. 应用场景

### 8.1 网络编程

- 高性能网络服务器
- 代理服务器
- 网关应用
- 负载均衡器

### 8.2 嵌入式系统

- 物联网设备
- 路由器
- 交换机
- 工业控制系统

### 8.3 其他场景

- 异步 I/O 密集型应用
- 高并发服务
- 资源受限环境
- 需要精细控制的应用

## 9. 性能优化建议

### 9.1 协程使用

1. **合理设置栈大小**: 避免过大浪费内存
2. **主动让出 CPU**: 在长时间操作中调用 yield
3. **优先级设置**: 重要任务设置高优先级
4. **避免阻塞**: 使用异步 I/O 而非阻塞调用

### 9.2 内存管理

1. **复用协程对象**: 减少创建销毁开销
2. **控制协程数量**: 避免过多协程导致调度开销
3. **使用内存池**: 减少内存分配次数

### 9.3 I/O 优化

1. **批量处理**: 合并多个 I/O 操作
2. **边缘触发**: 使用边缘触发模式提高效率
3. **零拷贝**: 尽可能使用零拷贝技术

## 10. 总结

HevTaskSystem 是一个设计精良的协程库，特别适合网络编程和高并发场景。

### 核心优势

1. **简单高效**: 基于 setjmp/longjmp 的实现简洁可靠
2. **资源友好**: 内存占用小，适合长期运行的系统
3. **跨平台**: 支持广泛的操作系统和架构
4. **I/O 优化**: 原生支持各种 I/O 多路复用机制
5. **扩展性好**: 模块化设计便于扩展新功能

### 技术特点

- 非抢占式调度策略
- 红黑树优先级队列
- 反应器 I/O 模式
- 多平台兼容性
- 丰富的同步原语

### 适用场景

- 高性能网络服务器
- 代理服务和网关
- 嵌入式系统
- 异步 I/O 密集型应用
- 资源受限环境

该库的设计理念与微服务、异步编程等现代软件开发趋势高度契合，特别适合构建高性能的网络服务和中间件。在与 hev-socks5-tunnel 的结合中，展现了协程在网络编程中的巨大优势。
