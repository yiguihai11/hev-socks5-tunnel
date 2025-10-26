/*
 ============================================================================
 Name        : hev-task-optimizer.c
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2025 hev
 Description : Task Scheduler Optimizer for High Performance
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>

#include "hev-task-optimizer.h"
#include "hev-logger.h"

/* 全局优化器状态 */
static struct
{
    HevTaskOptimizerConfig config;
    HevTaskBatchContext batch_context;
    HevTaskStats *task_stats;
    int task_stats_capacity;
    int task_stats_count;
    unsigned long total_runs;
    unsigned long total_runtime_us;
    time_t start_time;
    unsigned long batch_counter;
    int initialized;
} optimizer = { 0 };

/* 任务统计哈希函数 */
static int
get_task_stats_index (HevTask *task)
{
    return ((unsigned long)task >> 3) % optimizer.task_stats_capacity;
}

/* 获取或创建任务统计信息 */
static HevTaskStats *
get_or_create_task_stats (HevTask *task)
{
    int index, i;
    HevTaskStats *stats;

    if (!optimizer.task_stats) {
        optimizer.task_stats_capacity = 1024;
        optimizer.task_stats =
            calloc (optimizer.task_stats_capacity, sizeof (HevTaskStats));
        if (!optimizer.task_stats) {
            LOG_E ("task_optimizer: failed to allocate task stats");
            return NULL;
        }
    }

    index = get_task_stats_index (task);

    /* 线性探测查找现有统计 */
    for (i = 0; i < 8; i++) {
        stats =
            &optimizer.task_stats[(index + i) % optimizer.task_stats_capacity];
        if (stats->total_runs > 0 && stats->last_run_time > 0) {
            /* 检查是否是同一个任务（简单的指针匹配） */
            if ((uintptr_t)stats->last_run_time == (uintptr_t)task) {
                return stats;
            }
        }
    }

    /* 创建新的统计记录 */
    stats = &optimizer.task_stats[index];
    memset (stats, 0, sizeof (HevTaskStats));
    stats->last_run_time = (time_t)(uintptr_t)task; /* 使用指针作为临时标识 */
    optimizer.task_stats_count++;

    LOG_D ("task_optimizer: created stats for task %p", task);
    return stats;
}

/* 初始化任务调度器优化器 */
void
hev_task_optimizer_init (HevTaskOptimizerConfig *config)
{
    if (optimizer.initialized) {
        LOG_W ("task_optimizer: already initialized");
        return;
    }

    /* 设置默认配置 */
    if (config) {
        optimizer.config = *config;
    } else {
        optimizer.config.batch_wakeup_enabled = 1;
        optimizer.config.max_batch_size = 16;
        optimizer.config.priority_boost_enabled = 1;
        optimizer.config.boost_threshold_us = 1000.0; /* 1ms */
        optimizer.config.load_balance_enabled = 1;
        optimizer.config.stats_enabled = 1;
    }

    /* 初始化批量唤醒上下文 */
    if (optimizer.config.batch_wakeup_enabled) {
        optimizer.batch_context.capacity = optimizer.config.max_batch_size;
        optimizer.batch_context.tasks =
            calloc (optimizer.batch_context.capacity, sizeof (HevTask *));
        if (!optimizer.batch_context.tasks) {
            LOG_E ("task_optimizer: failed to allocate batch context");
            return;
        }
    }

    optimizer.start_time = time (NULL);
    optimizer.initialized = 1;

    LOG_I ("task_optimizer: initialized with batch_size=%d, priority_boost=%d",
           optimizer.config.max_batch_size,
           optimizer.config.priority_boost_enabled);
}

/* 清理任务调度器优化器 */
void
hev_task_optimizer_fini (void)
{
    if (!optimizer.initialized) {
        return;
    }

    if (optimizer.config.stats_enabled) {
        hev_task_optimizer_report_stats ();
    }

    if (optimizer.batch_context.tasks) {
        free (optimizer.batch_context.tasks);
        optimizer.batch_context.tasks = NULL;
    }

    if (optimizer.task_stats) {
        free (optimizer.task_stats);
        optimizer.task_stats = NULL;
    }

    optimizer.initialized = 0;
    LOG_I ("task_optimizer: finalized");
}

/* 设置任务类型 */
void
hev_task_optimizer_set_task_type (HevTask *task, HevTaskType type)
{
    if (!optimizer.initialized || !task) {
        return;
    }

    /* 这里可以通过任务的优先级字段来存储类型信息 */
    /* 实际实现可能需要扩展任务结构 */
    LOG_D ("task_optimizer: set task %p type=%d", task, type);
}

/* 设置任务优先级 */
void
hev_task_optimizer_set_task_priority (HevTask *task,
                                      HevTaskPriorityLevel priority)
{
    if (!optimizer.initialized || !task) {
        return;
    }

    hev_task_set_priority (task, priority);
    LOG_D ("task_optimizer: set task %p priority=%d", task, priority);
}

/* 动态调整任务优先级 */
void
hev_task_optimizer_adjust_priority (HevTask *task)
{
    HevTaskStats *stats;
    HevTaskPriorityLevel new_priority;

    if (!optimizer.initialized || !task ||
        !optimizer.config.priority_boost_enabled) {
        return;
    }

    stats = hev_task_optimizer_get_task_stats (task);
    if (!stats) {
        return;
    }

    /* 根据运行时间和I/O等待模式调整优先级 */
    new_priority = HEV_TASK_OPT_PRIORITY_NORMAL;

    if (stats->avg_runtime_us < optimizer.config.boost_threshold_us) {
        /* 运行时间短，可能是I/O密集型，提高优先级 */
        if (stats->io_wait_count > stats->total_runs / 2) {
            new_priority = HEV_TASK_OPT_PRIORITY_HIGH;
            stats->priority_boost = 1;
        }
    } else if (stats->avg_runtime_us >
               optimizer.config.boost_threshold_us * 10) {
        /* 运行时间长，可能是计算密集型，降低优先级 */
        new_priority = HEV_TASK_OPT_PRIORITY_LOW;
        stats->priority_boost = -1;
    }

    /* 将优化器优先级映射到系统优先级（反向映射：低数值=高优先级） */
    int system_priority;
    switch (new_priority) {
    case HEV_TASK_OPT_PRIORITY_CRITICAL:
        system_priority = 0; /* 最高系统优先级 */
        break;
    case HEV_TASK_OPT_PRIORITY_HIGH:
        system_priority = 3; /* 高系统优先级 */
        break;
    case HEV_TASK_OPT_PRIORITY_NORMAL:
        system_priority = 7; /* 普通系统优先级 */
        break;
    case HEV_TASK_OPT_PRIORITY_LOW:
        system_priority = 12; /* 低系统优先级 */
        break;
    default:
        system_priority = 7;
        break;
    }

    if (system_priority != hev_task_get_priority (task)) {
        hev_task_set_priority (task, system_priority);
        LOG_D (
            "task_optimizer: adjusted task %p priority to %d (runtime=%.2fus)",
            task, system_priority, stats->avg_runtime_us);
    }
}

/* 获取任务统计信息 */
HevTaskStats *
hev_task_optimizer_get_task_stats (HevTask *task)
{
    if (!optimizer.initialized || !task || !optimizer.config.stats_enabled) {
        return NULL;
    }

    return get_or_create_task_stats (task);
}

/* 开始批量唤醒 */
void
hev_task_optimizer_batch_wakeup_begin (void)
{
    if (!optimizer.initialized || !optimizer.config.batch_wakeup_enabled) {
        return;
    }

    optimizer.batch_context.count = 0;
    optimizer.batch_context.batch_id = ++optimizer.batch_counter;
}

/* 添加任务到批量唤醒列表 */
void
hev_task_optimizer_batch_wakeup_add (HevTask *task)
{
    if (!optimizer.initialized || !optimizer.config.batch_wakeup_enabled ||
        !task) {
        return;
    }

    if (optimizer.batch_context.count >= optimizer.batch_context.capacity) {
        LOG_W ("task_optimizer: batch context full, dropping task %p", task);
        return;
    }

    optimizer.batch_context.tasks[optimizer.batch_context.count] = task;
    optimizer.batch_context.count++;

    LOG_D ("task_optimizer: added task %p to batch %lu (count=%d)", task,
           optimizer.batch_context.batch_id, optimizer.batch_context.count);
}

/* 结束批量唤醒并执行 */
void
hev_task_optimizer_batch_wakeup_end (void)
{
    int i;

    if (!optimizer.initialized || !optimizer.config.batch_wakeup_enabled) {
        return;
    }

    if (optimizer.batch_context.count == 0) {
        return;
    }

    LOG_D ("task_optimizer: waking up %d tasks in batch %lu",
           optimizer.batch_context.count, optimizer.batch_context.batch_id);

    /* 批量唤醒任务 */
    for (i = 0; i < optimizer.batch_context.count; i++) {
        HevTask *task = optimizer.batch_context.tasks[i];
        hev_task_wakeup (task);
    }

    optimizer.batch_context.count = 0;
}

/* 负载均衡调度 */
HevTask *
hev_task_optimizer_select_next_task (void)
{
    /* 这里可以实现更复杂的负载均衡算法 */
    /* 当前返回NULL，让默认调度器处理 */
    return NULL;
}

/* 更新任务运行时间 */
void
hev_task_optimizer_update_runtime (HevTask *task, double runtime_us)
{
    HevTaskStats *stats;

    if (!optimizer.initialized || !task || !optimizer.config.stats_enabled) {
        return;
    }

    stats = get_or_create_task_stats (task);
    if (!stats) {
        return;
    }

    /* 更新统计信息 */
    stats->total_runs++;
    stats->last_runtime_us = runtime_us;

    /* 计算平均运行时间（指数移动平均） */
    if (stats->avg_runtime_us == 0) {
        stats->avg_runtime_us = runtime_us;
    } else {
        stats->avg_runtime_us = 0.9 * stats->avg_runtime_us + 0.1 * runtime_us;
    }

    stats->last_run_time = time (NULL);

    /* 更新全局统计 */
    optimizer.total_runs++;
    optimizer.total_runtime_us += (unsigned long)runtime_us;

    LOG_D ("task_optimizer: updated runtime for task %p: %.2fus (avg: %.2fus)",
           task, runtime_us, stats->avg_runtime_us);
}

/* 性能监控和报告 */
void
hev_task_optimizer_report_stats (void)
{
    double cpu_utilization = 0.0;
    time_t uptime = time (NULL) - optimizer.start_time;

    if (!optimizer.initialized || !optimizer.config.stats_enabled ||
        uptime <= 0) {
        return;
    }

    /* 计算CPU利用率 */
    if (uptime > 0) {
        cpu_utilization =
            (double)optimizer.total_runtime_us / (uptime * 1000000.0) * 100.0;
    }

    LOG_I ("task_optimizer: Performance Report:");
    LOG_I ("  - Uptime: %ld seconds", uptime);
    LOG_I ("  - Total task runs: %lu", optimizer.total_runs);
    LOG_I ("  - Total runtime: %.2f seconds",
           optimizer.total_runtime_us / 1000000.0);
    LOG_I ("  - Average runtime per run: %.2f us",
           optimizer.total_runs > 0 ?
               (double)optimizer.total_runtime_us / optimizer.total_runs :
               0.0);
    LOG_I ("  - CPU utilization: %.2f%%", cpu_utilization);
    LOG_I ("  - Tasks with stats: %d", optimizer.task_stats_count);
    LOG_I ("  - Batches processed: %lu", optimizer.batch_counter);
}

/* 获取全局统计信息 */
void
hev_task_optimizer_get_global_stats (unsigned long *total_tasks,
                                     unsigned long *avg_runtime_us,
                                     double *cpu_utilization)
{
    time_t uptime = time (NULL) - optimizer.start_time;

    if (total_tasks) {
        *total_tasks = optimizer.total_runs;
    }

    if (avg_runtime_us) {
        *avg_runtime_us =
            optimizer.total_runs > 0 ?
                optimizer.total_runtime_us / optimizer.total_runs :
                0;
    }

    if (cpu_utilization && uptime > 0) {
        *cpu_utilization =
            (double)optimizer.total_runtime_us / (uptime * 1000000.0) * 100.0;
    }
}