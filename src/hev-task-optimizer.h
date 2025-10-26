/*
 ============================================================================
 Name        : hev-task-optimizer.h
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2025 hev
 Description : Task Scheduler Optimizer for High Performance
 ============================================================================
 */

#ifndef __HEV_TASK_OPTIMIZER_H__
#define __HEV_TASK_OPTIMIZER_H__

#include <hev-task.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 任务优先级定义 */
typedef enum
{
    HEV_TASK_OPT_PRIORITY_CRITICAL = 0, /* 关键任务（如心跳、定时器） */
    HEV_TASK_OPT_PRIORITY_HIGH = 1, /* 高优先级任务（如I/O处理） */
    HEV_TASK_OPT_PRIORITY_NORMAL = 2, /* 普通任务（如会话处理） */
    HEV_TASK_OPT_PRIORITY_LOW = 3, /* 低优先级任务（如清理、统计） */
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

/* 初始化任务调度器优化器 */
void hev_task_optimizer_init (HevTaskOptimizerConfig *config);

/* 清理任务调度器优化器 */
void hev_task_optimizer_fini (void);

/* 设置任务类型和优先级 */
void hev_task_optimizer_set_task_type (HevTask *task, HevTaskType type);
void hev_task_optimizer_set_task_priority (HevTask *task,
                                           HevTaskPriorityLevel priority);

/* 动态调整任务优先级 */
void hev_task_optimizer_adjust_priority (HevTask *task);

/* 获取任务统计信息 */
HevTaskStats *hev_task_optimizer_get_task_stats (HevTask *task);

/* 批量唤醒任务 */
void hev_task_optimizer_batch_wakeup_begin (void);
void hev_task_optimizer_batch_wakeup_add (HevTask *task);
void hev_task_optimizer_batch_wakeup_end (void);

/* 负载均衡调度 */
HevTask *hev_task_optimizer_select_next_task (void);

/* 性能监控和报告 */
void hev_task_optimizer_update_runtime (HevTask *task, double runtime_us);
void hev_task_optimizer_report_stats (void);

/* 获取优化器统计信息 */
void hev_task_optimizer_get_global_stats (unsigned long *total_tasks,
                                          unsigned long *avg_runtime_us,
                                          double *cpu_utilization);

#ifdef __cplusplus
}
#endif

#endif /* __HEV_TASK_OPTIMIZER_H__ */