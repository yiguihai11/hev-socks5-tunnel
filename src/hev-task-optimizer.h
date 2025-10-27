/*
 ============================================================================
 Name        : hev-task-optimizer.h (Compatibility Layer)
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2025 hev
 Description : Task Scheduler Optimizer for High Performance - Compatibility Header
 ============================================================================
 */

#ifndef __HEV_TASK_OPTIMIZER_H__
#define __HEV_TASK_OPTIMIZER_H__

/* Include the unified performance optimizer module */
#include "hev-performance-optimizer.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Re-export types and functions for backward compatibility */
typedef HevTaskPriorityLevel HevTaskPriorityLevel;
typedef HevTaskType HevTaskType;
typedef HevTaskStats HevTaskStats;
typedef HevTaskBatchContext HevTaskBatchContext;
typedef HevTaskOptimizerConfig HevTaskOptimizerConfig;

/* All functions are available through hev-performance-optimizer.h */

#ifdef __cplusplus
}
#endif

#endif /* __HEV_TASK_OPTIMIZER_H__ */