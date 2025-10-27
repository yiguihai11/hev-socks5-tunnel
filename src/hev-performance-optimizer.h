/*
 ============================================================================
 Name        : hev-performance-optimizer.h
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2025 hev
 Description : Unified Performance Optimization Module
 ============================================================================
 */

#ifndef __HEV_PERFORMANCE_OPTIMIZER_H__
#define __HEV_PERFORMANCE_OPTIMIZER_H__

#include <hev-task.h>
#include <lwip/pbuf.h>
#include <lwip/udp.h>
#include <lwip/ip_addr.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
   Connection Pool Module
   ============================================================================ */

/* 连接池条目 */
typedef struct _HevConnectionPoolEntry
{
    int fd; // 连接文件描述符
    char addr[256]; // 服务器地址
    int port; // 服务器端口
    int type; // 连接类型 (0=NONE, 1=TCP, 2=UDP)
    int in_use; // 是否正在使用
    time_t last_used; // 最后使用时间
    time_t created_time; // 创建时间
} HevConnectionPoolEntry;

/* 连接池统计信息 */
typedef struct _HevConnectionPoolStats
{
    int max_size; // 最大连接数
    int current_size; // 当前连接数
    unsigned long total_connections; // 总连接数
    unsigned long pool_hits; // 连接池命中数
    unsigned long pool_misses; // 连接池未命中数
    double hit_ratio; // 命中率（百分比）
} HevConnectionPoolStats;

/* 连接池接口函数 */
void hev_connection_pool_init (int max_size, int min_idle_time,
                               int max_idle_time);
void hev_connection_pool_fini (void);
HevConnectionPoolEntry *hev_connection_pool_get (const char *addr, int port,
                                                 int type);
void hev_connection_pool_put (HevConnectionPoolEntry *entry);
void hev_connection_pool_remove (HevConnectionPoolEntry *entry);
void hev_connection_pool_get_stats (HevConnectionPoolStats *stats);

/* ============================================================================
   Batch Processor Module
   ============================================================================ */

/* 批量处理类型 */
typedef enum
{
    HEV_BATCH_TYPE_NETWORK_IO = 0, /* 网络I/O批量处理 */
    HEV_BATCH_TYPE_PACKET_FORWARD, /* 数据包批量转发 */
    HEV_BATCH_TYPE_SESSION_MGMT, /* 会话批量管理 */
    HEV_BATCH_TYPE_BUFFER_OPS, /* 缓冲区批量操作 */
    HEV_BATCH_TYPE_COUNT
} HevBatchType;

/* 网络I/O批量项 */
typedef struct
{
    int fd; /* 文件描述符 */
    void *buffer; /* 缓冲区指针 */
    size_t size; /* 数据大小 */
    int is_write; /* 读写标志：1=写，0=读 */
    int result; /* 操作结果 */
} HevBatchNetworkIOItem;

/* 数据包批量转发项 */
typedef struct
{
    struct pbuf *pbuf; /* 数据包缓冲区 */
    struct udp_pcb *pcb; /* UDP PCB */
    ip_addr_t *addr; /* 目标地址 */
    u16_t port; /* 目标端口 */
    int priority; /* 优先级 */
} HevBatchPacketItem;

/* 会话批量管理项 */
typedef struct
{
    void *session; /* 会话指针 */
    int operation; /* 操作类型 */
    void *data; /* 操作数据 */
    size_t data_size; /* 数据大小 */
} HevBatchSessionItem;

/* 缓冲区批量操作项 */
typedef struct
{
    void *src; /* 源缓冲区 */
    void *dst; /* 目标缓冲区 */
    size_t size; /* 操作大小 */
    int operation; /* 操作类型：0=复制，1=清零，2=比较 */
} HevBatchBufferItem;

/* 批量处理上下文 */
typedef struct
{
    HevBatchType type; /* 批量处理类型 */
    void *items; /* 批量项数组 */
    int count; /* 当前项数量 */
    int capacity; /* 数组容量 */
    int max_batch_size; /* 最大批量大小 */
    unsigned long total_processed; /* 总处理数量 */
    unsigned long total_batches; /* 总批次数 */
    double avg_batch_time_us; /* 平均批处理时间 */
    int enabled; /* 是否启用 */
} HevBatchContext;

/* 批量处理配置 */
typedef struct
{
    int network_io_enabled; /* 启用网络I/O批量处理 */
    int packet_forward_enabled; /* 启用数据包批量转发 */
    int session_mgmt_enabled; /* 启用会话批量管理 */
    int buffer_ops_enabled; /* 启用缓冲区批量操作 */
    int max_network_io_batch; /* 网络I/O最大批量大小 */
    int max_packet_batch; /* 数据包最大批量大小 */
    int max_session_batch; /* 会话管理最大批量大小 */
    int max_buffer_batch; /* 缓冲区操作最大批量大小 */
    double batch_timeout_us; /* 批处理超时时间（微秒） */
} HevBatchProcessorConfig;

/* 批量处理器接口函数 */
void hev_batch_processor_init (HevBatchProcessorConfig *config);
void hev_batch_processor_fini (void);
HevBatchContext *hev_batch_processor_get_context (HevBatchType type);
int hev_batch_processor_add_network_io (int fd, void *buffer, size_t size,
                                        int is_write);
int hev_batch_processor_process_network_io (void);
int hev_batch_processor_add_packet (struct pbuf *pbuf, struct udp_pcb *pcb,
                                    ip_addr_t *addr, u16_t port, int priority);
int hev_batch_processor_process_packets (void);
void hev_batch_processor_flush_all (void);
void hev_batch_processor_get_stats (HevBatchType type,
                                    unsigned long *total_processed,
                                    unsigned long *total_batches,
                                    double *avg_batch_time_us);

/* ============================================================================
   Memory Pool Module
   ============================================================================ */

/* 内存池管理器结构 */
typedef struct _HevMemoryPool
{
    int current_size; // 当前池大小
    int min_size; // 最小池大小
    int max_size; // 最大池大小
    double high_watermark; // 高水位（扩容阈值）
    double low_watermark; // 低水位（缩容阈值）
    time_t last_adjust_time; // 上次调整时间
    int adjust_interval; // 调整间隔（秒）
} HevMemoryPool;

/* 内存池接口函数 */
void hev_memory_pool_init (void);
void hev_memory_pool_fini (void);
int hev_memory_pool_adjust_udp_size (int current_usage, int total_capacity);
int hev_memory_pool_get_udp_size (void);
void hev_memory_pool_set_udp_size (int size);

/* ============================================================================
   Task Monitor Module
   ============================================================================ */

/* 任务监控上下文 */
typedef struct
{
    HevTask *task;
    unsigned long start_time_us;
    unsigned long end_time_us;
    int is_monitoring;
} HevTaskMonitorContext;

/* 任务监控接口函数 */
void hev_task_monitor_start (HevTaskMonitorContext *ctx, HevTask *task);
void hev_task_monitor_end (HevTaskMonitorContext *ctx);
unsigned long hev_task_monitor_get_runtime_us (HevTaskMonitorContext *ctx);

/* 自动监控宏 */
#define HEV_TASK_MONITOR_START(task)     \
    HevTaskMonitorContext __monitor_ctx; \
    hev_task_monitor_start (&__monitor_ctx, task);
#define HEV_TASK_MONITOR_END() hev_task_monitor_end (&__monitor_ctx);

/* ============================================================================
   Task Optimizer Module
   ============================================================================ */

/* 任务优先级定义 */
typedef enum
{
    HEV_TASK_OPT_PRIORITY_CRITICAL = 0, /* 关键任务 */
    HEV_TASK_OPT_PRIORITY_HIGH = 1, /* 高优先级任务 */
    HEV_TASK_OPT_PRIORITY_NORMAL = 2, /* 普通任务 */
    HEV_TASK_OPT_PRIORITY_LOW = 3, /* 低优先级任务 */
    HEV_TASK_OPT_PRIORITY_LEVELS
} HevTaskPriorityLevel;

/* 任务类型定义 */
typedef enum
{
    HEV_TASK_TYPE_IO = 0, /* I/O密集型任务 */
    HEV_TASK_TYPE_NETWORK = 1, /* 网络处理任务 */
    HEV_TASK_TYPE_TIMER = 2, /* 定时器任务 */
    HEV_TASK_TYPE_SESSION = 3, /* 会话处理任务 */
    HEV_TASK_TYPE_SYSTEM = 4, /* 系统任务 */
    HEV_TASK_TYPE_COUNT
} HevTaskType;

/* 任务性能统计 */
typedef struct
{
    unsigned long total_runs; /* 总运行次数 */
    unsigned long total_yield_count; /* 总让出次数 */
    double avg_runtime_us; /* 平均运行时间（微秒） */
    double last_runtime_us; /* 最近运行时间（微秒） */
    unsigned long io_wait_count; /* I/O等待次数 */
    unsigned long cache_misses; /* 缓存未命中次数 */
    time_t last_run_time; /* 最后运行时间 */
    int priority_boost; /* 优先级提升值 */
} HevTaskStats;

/* 批量唤醒上下文 */
typedef struct
{
    HevTask **tasks; /* 待唤醒任务数组 */
    int count; /* 任务数量 */
    int capacity; /* 数组容量 */
    unsigned long batch_id; /* 批次ID */
} HevTaskBatchContext;

/* 调度器优化配置 */
typedef struct
{
    int batch_wakeup_enabled; /* 启用批量唤醒 */
    int max_batch_size; /* 最大批量大小 */
    int priority_boost_enabled; /* 启用优先级提升 */
    double boost_threshold_us; /* 提升阈值（微秒） */
    int load_balance_enabled; /* 启用负载均衡 */
    int stats_enabled; /* 启用性能统计 */
} HevTaskOptimizerConfig;

/* 任务优化器接口函数 */
void hev_task_optimizer_init (HevTaskOptimizerConfig *config);
void hev_task_optimizer_fini (void);
void hev_task_optimizer_set_task_type (HevTask *task, HevTaskType type);
void hev_task_optimizer_set_task_priority (HevTask *task,
                                           HevTaskPriorityLevel priority);
void hev_task_optimizer_adjust_priority (HevTask *task);
HevTaskStats *hev_task_optimizer_get_task_stats (HevTask *task);
void hev_task_optimizer_batch_wakeup_begin (void);
void hev_task_optimizer_batch_wakeup_add (HevTask *task);
void hev_task_optimizer_batch_wakeup_end (void);
HevTask *hev_task_optimizer_select_next_task (void);
void hev_task_optimizer_update_runtime (HevTask *task, double runtime_us);
void hev_task_optimizer_report_stats (void);
void hev_task_optimizer_get_global_stats (unsigned long *total_tasks,
                                          unsigned long *avg_runtime_us,
                                          double *cpu_utilization);

/* ============================================================================
   Unified Performance Optimizer Interface
   ============================================================================ */

/* 统一初始化和清理函数 */
void hev_performance_optimizer_init_all (void);
void hev_performance_optimizer_fini_all (void);

/* 统一配置结构 */
typedef struct
{
    /* 连接池配置 */
    int conn_pool_max_size;
    int conn_pool_min_idle_time;
    int conn_pool_max_idle_time;

    /* 批量处理器配置 */
    HevBatchProcessorConfig batch_config;

    /* 内存池配置 */
    int mem_pool_min_size;
    int mem_pool_max_size;
    double mem_pool_high_watermark;
    double mem_pool_low_watermark;

    /* 任务优化器配置 */
    HevTaskOptimizerConfig task_config;
} HevPerformanceOptimizerConfig;

/* 统一配置接口 */
void
hev_performance_optimizer_configure (HevPerformanceOptimizerConfig *config);
void hev_performance_optimizer_get_status (void);

#ifdef __cplusplus
}
#endif

#endif /* __HEV_PERFORMANCE_OPTIMIZER_H__ */