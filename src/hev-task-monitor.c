/*
 ============================================================================
 Name        : hev-task-monitor.c
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2025 hev
 Description : Task Performance Monitor Helper
 ============================================================================
 */

#include <sys/time.h>
#include <stddef.h>

#include "hev-task-monitor.h"
#include "hev-task-optimizer.h"
#include "hev-logger.h"

/* 获取当前时间（微秒） */
static unsigned long
get_current_time_us (void)
{
    struct timeval tv;
    gettimeofday (&tv, NULL);
    return (unsigned long)tv.tv_sec * 1000000 + tv.tv_usec;
}

/* 开始监控任务性能 */
void
hev_task_monitor_start (HevTaskMonitorContext *ctx, HevTask *task)
{
    if (!ctx || !task) {
        return;
    }

    ctx->task = task;
    ctx->start_time_us = get_current_time_us ();
    ctx->is_monitoring = 1;

    LOG_D ("task_monitor: started monitoring task %p", task);
}

/* 结束监控任务性能 */
void
hev_task_monitor_end (HevTaskMonitorContext *ctx)
{
    unsigned long runtime_us;

    if (!ctx || !ctx->is_monitoring || !ctx->task) {
        return;
    }

    ctx->end_time_us = get_current_time_us ();
    runtime_us = ctx->end_time_us - ctx->start_time_us;
    ctx->is_monitoring = 0;

    /* 更新任务调度器优化器的统计信息 */
    hev_task_optimizer_update_runtime (ctx->task, (double)runtime_us);

    /* 动态调整任务优先级 */
    hev_task_optimizer_adjust_priority (ctx->task);

    LOG_D ("task_monitor: task %p runtime = %lu us", ctx->task, runtime_us);
}

/* 获取任务运行时间（微秒） */
unsigned long
hev_task_monitor_get_runtime_us (HevTaskMonitorContext *ctx)
{
    if (!ctx || !ctx->is_monitoring) {
        return 0;
    }

    return get_current_time_us () - ctx->start_time_us;
}