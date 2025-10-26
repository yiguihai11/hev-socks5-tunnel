/*
 ============================================================================
 Name        : hev-task-monitor.h
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2025 hev
 Description : Task Performance Monitor Helper
 ============================================================================
 */

#ifndef __HEV_TASK_MONITOR_H__
#define __HEV_TASK_MONITOR_H__

#include <hev-task.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 任务监控上下文 */
typedef struct
{
    HevTask *task;
    unsigned long start_time_us;
    unsigned long end_time_us;
    int is_monitoring;
} HevTaskMonitorContext;

/* 开始监控任务性能 */
void hev_task_monitor_start (HevTaskMonitorContext *ctx, HevTask *task);

/* 结束监控任务性能 */
void hev_task_monitor_end (HevTaskMonitorContext *ctx);

/* 获取任务运行时间（微秒） */
unsigned long hev_task_monitor_get_runtime_us (HevTaskMonitorContext *ctx);

/* 自动监控宏 - 用于任务函数开始 */
#define HEV_TASK_MONITOR_START(task)     \
    HevTaskMonitorContext __monitor_ctx; \
    hev_task_monitor_start (&__monitor_ctx, task);

/* 自动监控宏 - 用于任务函数结束 */
#define HEV_TASK_MONITOR_END() hev_task_monitor_end (&__monitor_ctx);

/* 带条件监控的宏 */
#define HEV_TASK_MONITOR_START_IF(task, condition)     \
    HevTaskMonitorContext __monitor_ctx = { 0 };       \
    if (condition) {                                   \
        hev_task_monitor_start (&__monitor_ctx, task); \
    }

#define HEV_TASK_MONITOR_END_IF(condition)     \
    if (condition) {                           \
        hev_task_monitor_end (&__monitor_ctx); \
    }

#ifdef __cplusplus
}
#endif

#endif /* __HEV_TASK_MONITOR_H__ */