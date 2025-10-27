/*
 ============================================================================
 Name        : hev-task-monitor.h (Compatibility Layer)
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2025 hev
 Description : Task Performance Monitor Helper - Compatibility Header
 ============================================================================
 */

#ifndef __HEV_TASK_MONITOR_H__
#define __HEV_TASK_MONITOR_H__

/* Include the unified performance optimizer module */
#include "hev-performance-optimizer.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Re-export types and functions for backward compatibility */
typedef HevTaskMonitorContext HevTaskMonitorContext;

/* All functions are available through hev-performance-optimizer.h */

/* Re-export macros for backward compatibility */
#define HEV_TASK_MONITOR_START(task)     \
    HevTaskMonitorContext __monitor_ctx; \
    hev_task_monitor_start (&__monitor_ctx, task);

#define HEV_TASK_MONITOR_END() hev_task_monitor_end (&__monitor_ctx);

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