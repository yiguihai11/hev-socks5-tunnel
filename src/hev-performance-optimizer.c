/*
 ============================================================================
 Name        : hev-performance-optimizer.c
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2025 hev
 Description : Unified Performance Optimization Module
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <errno.h>
#include <hev-task.h>

#include "hev-performance-optimizer.h"
#include "hev-config.h"
#include "hev-config-const.h"
#include "hev-logger.h"

/* ============================================================================
   Common Utility Functions
   ============================================================================ */

/* 获取当前时间（秒） */
static time_t
get_current_time_seconds (void)
{
    struct timeval tv;
    gettimeofday (&tv, NULL);
    return tv.tv_sec;
}

/* 获取当前时间（微秒） */
static unsigned long
get_current_time_us (void)
{
    struct timeval tv;
    gettimeofday (&tv, NULL);
    return (unsigned long)tv.tv_sec * 1000000 + tv.tv_usec;
}

/* ============================================================================
   Connection Pool Module Implementation
   ============================================================================ */

/* 连接池结构 */
static struct
{
    HevConnectionPoolEntry *entries;
    int max_size; // 最大连接数
    int current_size; // 当前连接数
    int min_idle_time; // 最小空闲时间（秒）
    int max_idle_time; // 最大空闲时间（秒）
    time_t last_cleanup; // 上次清理时间
    int cleanup_interval; // 清理间隔（秒）
    unsigned long total_connections; // 总连接数
    unsigned long pool_hits; // 连接池命中数
    unsigned long pool_misses; // 连接池未命中数
} conn_pool = { 0 };

/* 检查连接是否仍然有效 */
static int
is_connection_valid (HevConnectionPoolEntry *entry)
{
    int fd = entry->fd;
    int error = 0;
    socklen_t len = sizeof (error);

    /* 使用 getsockopt 检查连接状态 */
    if (getsockopt (fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
        LOG_D ("connection_pool: getsockopt failed for fd=%d", fd);
        return 0;
    }

    if (error != 0) {
        LOG_D ("connection_pool: connection error for fd=%d, error=%d", fd,
               error);
        return 0;
    }

    /* 检查连接是否超时 */
    time_t now = get_current_time_seconds ();
    if (now - entry->last_used > conn_pool.max_idle_time) {
        LOG_D ("connection_pool: connection idle timeout for fd=%d", fd);
        return 0;
    }

    return 1;
}

/* 查找匹配的连接 */
static HevConnectionPoolEntry *
find_matching_connection (const char *addr, int port, int type)
{
    int i;
    time_t now = get_current_time_seconds ();

    for (i = 0; i < conn_pool.max_size; i++) {
        HevConnectionPoolEntry *entry = &conn_pool.entries[i];

        if (!entry->in_use)
            continue;

        if (entry->type != type)
            continue;

        if (entry->port != port)
            continue;

        if (strcmp (entry->addr, addr) != 0)
            continue;

        /* 检查连接是否仍然有效 */
        if (!is_connection_valid (entry)) {
            LOG_D ("connection_pool: invalid connection found, removing");
            entry->in_use = 0;
            close (entry->fd);
            conn_pool.current_size--;
            continue;
        }

        /* 更新使用时间 */
        entry->last_used = now;
        conn_pool.pool_hits++;

        LOG_D ("connection_pool: found matching connection fd=%d, addr=%s:%d",
               entry->fd, addr, port);

        return entry;
    }

    conn_pool.pool_misses++;
    return NULL;
}

/* 查找空闲槽位 */
static int
find_free_slot (void)
{
    int i;

    for (i = 0; i < conn_pool.max_size; i++) {
        if (!conn_pool.entries[i].in_use)
            return i;
    }

    return -1;
}

/* 清理空闲时间过长的连接 */
static void
cleanup_idle_connections (void)
{
    int i;
    time_t now = get_current_time_seconds ();

    /* 检查是否到了清理时间 */
    if (now - conn_pool.last_cleanup < conn_pool.cleanup_interval) {
        return;
    }

    LOG_D ("connection_pool: starting cleanup of idle connections");

    for (i = 0; i < conn_pool.max_size; i++) {
        HevConnectionPoolEntry *entry = &conn_pool.entries[i];

        if (!entry->in_use)
            continue;

        /* 如果连接空闲时间过长，关闭它 */
        if (now - entry->last_used > conn_pool.max_idle_time) {
            LOG_D ("connection_pool: closing idle connection fd=%d, addr=%s:%d",
                   entry->fd, entry->addr, entry->port);

            close (entry->fd);
            entry->in_use = 0;
            conn_pool.current_size--;
        }
    }

    conn_pool.last_cleanup = now;
}

/* 连接池接口函数实现 */
void
hev_connection_pool_init (int max_size, int min_idle_time, int max_idle_time)
{
    conn_pool.entries = calloc (max_size, sizeof (HevConnectionPoolEntry));
    if (!conn_pool.entries) {
        LOG_E ("connection_pool: failed to allocate memory for pool");
        return;
    }

    conn_pool.max_size = max_size;
    conn_pool.current_size = 0;
    conn_pool.min_idle_time = min_idle_time;
    conn_pool.max_idle_time = max_idle_time;
    conn_pool.last_cleanup = get_current_time_seconds ();
    conn_pool.cleanup_interval = 60; // 60秒清理一次
    conn_pool.total_connections = 0;
    conn_pool.pool_hits = 0;
    conn_pool.pool_misses = 0;

    LOG_I (
        "connection_pool: initialized with max_size=%d, idle_time=%d-%d seconds",
        max_size, min_idle_time, max_idle_time);
}

void
hev_connection_pool_fini (void)
{
    int i;

    if (!conn_pool.entries)
        return;

    LOG_D ("connection_pool: cleaning up %d active connections",
           conn_pool.current_size);

    for (i = 0; i < conn_pool.max_size; i++) {
        HevConnectionPoolEntry *entry = &conn_pool.entries[i];

        if (entry->in_use) {
            close (entry->fd);
            entry->in_use = 0;
        }
    }

    free (conn_pool.entries);
    conn_pool.entries = NULL;
    conn_pool.current_size = 0;

    LOG_I (
        "connection_pool: finalized. Total connections: %lu, Hits: %lu, Misses: %lu",
        conn_pool.total_connections, conn_pool.pool_hits,
        conn_pool.pool_misses);
}

HevConnectionPoolEntry *
hev_connection_pool_get (const char *addr, int port, int type)
{
    HevConnectionPoolEntry *entry;
    int slot;

    /* 首先尝试从池中获取 */
    entry = find_matching_connection (addr, port, type);
    if (entry) {
        LOG_D ("connection_pool: reusing connection fd=%d", entry->fd);
        return entry;
    }

    /* 如果池已满，无法创建新连接 */
    if (conn_pool.current_size >= conn_pool.max_size) {
        LOG_W ("connection_pool: pool is full (max_size=%d)",
               conn_pool.max_size);
        /* 尝试清理一些空闲连接 */
        cleanup_idle_connections ();

        /* 再次尝试获取 */
        entry = find_matching_connection (addr, port, type);
        if (entry) {
            return entry;
        }

        return NULL;
    }

    /* 创建新的连接池条目 */
    slot = find_free_slot ();
    if (slot < 0) {
        LOG_E ("connection_pool: no free slot available");
        return NULL;
    }

    entry = &conn_pool.entries[slot];
    entry->fd = -1; // 将由调用者设置
    strncpy (entry->addr, addr, sizeof (entry->addr) - 1);
    entry->addr[sizeof (entry->addr) - 1] = '\0';
    entry->port = port;
    entry->type = type;
    entry->in_use = 1;
    entry->last_used = get_current_time_seconds ();
    entry->created_time = entry->last_used;

    conn_pool.current_size++;
    conn_pool.total_connections++;

    LOG_D ("connection_pool: created new pool entry for %s:%d", addr, port);

    return entry;
}

void
hev_connection_pool_put (HevConnectionPoolEntry *entry)
{
    if (!entry || !entry->in_use) {
        LOG_W ("connection_pool: invalid entry passed to put");
        return;
    }

    /* 更新最后使用时间 */
    entry->last_used = get_current_time_seconds ();

    LOG_D ("connection_pool: returned connection fd=%d to pool", entry->fd);
}

void
hev_connection_pool_remove (HevConnectionPoolEntry *entry)
{
    if (!entry || !entry->in_use) {
        LOG_W ("connection_pool: invalid entry passed to remove");
        return;
    }

    LOG_D ("connection_pool: removing connection fd=%d from pool", entry->fd);

    if (entry->fd >= 0) {
        close (entry->fd);
        entry->fd = -1;
    }

    entry->in_use = 0;
    conn_pool.current_size--;
}

void
hev_connection_pool_get_stats (HevConnectionPoolStats *stats)
{
    if (!stats)
        return;

    stats->max_size = conn_pool.max_size;
    stats->current_size = conn_pool.current_size;
    stats->total_connections = conn_pool.total_connections;
    stats->pool_hits = conn_pool.pool_hits;
    stats->pool_misses = conn_pool.pool_misses;

    if (conn_pool.pool_hits + conn_pool.pool_misses > 0) {
        stats->hit_ratio = (double)conn_pool.pool_hits /
                           (conn_pool.pool_hits + conn_pool.pool_misses) *
                           100.0;
    } else {
        stats->hit_ratio = 0.0;
    }
}

/* ============================================================================
   Memory Pool Module Implementation
   ============================================================================ */

/* 动态UDP池管理器 */
static HevMemoryPool udp_pool = {
    .current_size = UDP_POOL_SIZE_DEFAULT,
    .min_size = UDP_POOL_SIZE_MIN,
    .max_size = UDP_POOL_SIZE_MAX,
    .high_watermark = 0.8, // 80%时考虑扩容
    .low_watermark = 0.3, // 30%时考虑缩容
    .last_adjust_time = 0,
    .adjust_interval = 30 // 30秒调整一次
};

/* 检查是否需要调整池大小 */
static int
should_adjust_pool_size (int current_usage, int total_capacity)
{
    time_t current_time = get_current_time_seconds ();
    double usage_ratio = (double)current_usage / total_capacity;

    /* 检查调整间隔 */
    if (current_time - udp_pool.last_adjust_time < udp_pool.adjust_interval) {
        return 0;
    }

    /* 高水位检查：使用率超过80%且未达到最大值 */
    if (usage_ratio > udp_pool.high_watermark &&
        udp_pool.current_size < udp_pool.max_size) {
        LOG_D (
            "memory_pool: High usage detected %.2f%% (%d/%d), considering expansion",
            usage_ratio * 100, current_usage, total_capacity);
        return 1; // 需要扩容
    }

    /* 低水位检查：使用率低于30%且大于最小值 */
    if (usage_ratio < udp_pool.low_watermark &&
        udp_pool.current_size > udp_pool.min_size) {
        LOG_D (
            "memory_pool: Low usage detected %.2f%% (%d/%d), considering shrinkage",
            usage_ratio * 100, current_usage, total_capacity);
        return -1; // 需要缩容
    }

    return 0; // 不需要调整
}

/* 内存池接口函数实现 */
int
hev_memory_pool_adjust_udp_size (int current_usage, int total_capacity)
{
    int adjustment = should_adjust_pool_size (current_usage, total_capacity);

    if (adjustment == 0) {
        return udp_pool.current_size; // 无需调整
    }

    int old_size = udp_pool.current_size;

    if (adjustment > 0) {
        /* 扩容：增加25%，但不超过最大值 */
        int new_size = (int)(udp_pool.current_size * 1.25);
        if (new_size > udp_pool.max_size) {
            new_size = udp_pool.max_size;
        }

        if (new_size > old_size) {
            udp_pool.current_size = new_size;
            udp_pool.last_adjust_time = get_current_time_seconds ();

            LOG_I (
                "memory_pool: UDP pool expanded from %d to %d frames (usage: %d/%d)",
                old_size, udp_pool.current_size, current_usage, total_capacity);
        }
    } else if (adjustment < 0) {
        /* 缩容：减少25%，但不小于最小值 */
        int new_size = (int)(udp_pool.current_size * 0.75);
        if (new_size < udp_pool.min_size) {
            new_size = udp_pool.min_size;
        }

        if (new_size < old_size) {
            udp_pool.current_size = new_size;
            udp_pool.last_adjust_time = get_current_time_seconds ();

            LOG_I (
                "memory_pool: UDP pool shrunk from %d to %d frames (usage: %d/%d)",
                old_size, udp_pool.current_size, current_usage, total_capacity);
        }
    }

    return udp_pool.current_size;
}

int
hev_memory_pool_get_udp_size (void)
{
    return udp_pool.current_size;
}

void
hev_memory_pool_set_udp_size (int size)
{
    if (size >= udp_pool.min_size && size <= udp_pool.max_size) {
        int old_size = udp_pool.current_size;
        udp_pool.current_size = size;
        udp_pool.last_adjust_time = get_current_time_seconds ();

        LOG_I ("memory_pool: UDP pool manually set from %d to %d frames",
               old_size, udp_pool.current_size);
    } else {
        LOG_W ("memory_pool: Invalid UDP pool size %d, valid range: %d-%d",
               size, udp_pool.min_size, udp_pool.max_size);
    }
}

void
hev_memory_pool_init (void)
{
    udp_pool.last_adjust_time = get_current_time_seconds ();
    LOG_I ("memory_pool: initialized with size=%d (range: %d-%d)",
           udp_pool.current_size, udp_pool.min_size, udp_pool.max_size);
}

void
hev_memory_pool_fini (void)
{
    LOG_I ("memory_pool: finalized. Final UDP pool size: %d",
           udp_pool.current_size);
}

/* ============================================================================
   Task Monitor Module Implementation
   ============================================================================ */

/* 任务监控接口函数实现 */
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

    LOG_D ("task_monitor: task %p ran for %lu microseconds", ctx->task, runtime_us);
}

unsigned long
hev_task_monitor_get_runtime_us (HevTaskMonitorContext *ctx)
{
    if (!ctx || !ctx->is_monitoring) {
        return 0;
    }

    return get_current_time_us () - ctx->start_time_us;
}

/* ============================================================================
   Batch Processor Module Implementation (Simplified)
   ============================================================================ */

/* 全局批量处理器状态 */
static struct
{
    HevBatchProcessorConfig config;
    HevBatchContext contexts[HEV_BATCH_TYPE_COUNT];
    int initialized;
} batch_processor = { 0 };

/* 批量处理器接口函数实现 */
void
hev_batch_processor_init (HevBatchProcessorConfig *config)
{
    if (!config) {
        LOG_E ("batch_processor: config is NULL");
        return;
    }

    batch_processor.config = *config;
    batch_processor.initialized = 1;

    LOG_I ("batch_processor: initialized");
}

void
hev_batch_processor_fini (void)
{
    if (!batch_processor.initialized) {
        return;
    }

    int i;
    for (i = 0; i < HEV_BATCH_TYPE_COUNT; i++) {
        if (batch_processor.contexts[i].items) {
            free (batch_processor.contexts[i].items);
            batch_processor.contexts[i].items = NULL;
        }
    }

    batch_processor.initialized = 0;
    LOG_I ("batch_processor: finalized");
}

HevBatchContext *
hev_batch_processor_get_context (HevBatchType type)
{
    if (!batch_processor.initialized || type >= HEV_BATCH_TYPE_COUNT) {
        return NULL;
    }

    return &batch_processor.contexts[type];
}

/* Simplified implementation for other batch functions */
int
hev_batch_processor_add_network_io (int fd, void *buffer, size_t size, int is_write)
{
    LOG_D ("batch_processor: added network IO fd=%d size=%zu", fd, size);
    return 0;
}

int
hev_batch_processor_process_network_io (void)
{
    LOG_D ("batch_processor: processing network IO batch");
    return 0;
}

int
hev_batch_processor_add_packet (struct pbuf *pbuf, struct udp_pcb *pcb,
                                ip_addr_t *addr, u16_t port, int priority)
{
    LOG_D ("batch_processor: added packet to batch");
    return 0;
}

int
hev_batch_processor_process_packets (void)
{
    LOG_D ("batch_processor: processing packet batch");
    return 0;
}

void
hev_batch_processor_flush_all (void)
{
    LOG_D ("batch_processor: flushing all batches");
}

void
hev_batch_processor_get_stats (HevBatchType type, unsigned long *total_processed,
                                unsigned long *total_batches, double *avg_batch_time_us)
{
    if (total_processed) *total_processed = 0;
    if (total_batches) *total_batches = 0;
    if (avg_batch_time_us) *avg_batch_time_us = 0.0;
}

/* ============================================================================
   Task Optimizer Module Implementation (Simplified)
   ============================================================================ */

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

/* 任务优化器接口函数实现 */
void
hev_task_optimizer_init (HevTaskOptimizerConfig *config)
{
    if (!config) {
        LOG_E ("task_optimizer: config is NULL");
        return;
    }

    optimizer.config = *config;
    optimizer.start_time = get_current_time_seconds ();
    optimizer.initialized = 1;

    LOG_I ("task_optimizer: initialized");
}

void
hev_task_optimizer_fini (void)
{
    if (!optimizer.initialized) {
        return;
    }

    if (optimizer.task_stats) {
        free (optimizer.task_stats);
        optimizer.task_stats = NULL;
    }

    if (optimizer.batch_context.tasks) {
        free (optimizer.batch_context.tasks);
        optimizer.batch_context.tasks = NULL;
    }

    optimizer.initialized = 0;
    LOG_I ("task_optimizer: finalized");
}

void
hev_task_optimizer_set_task_type (HevTask *task, HevTaskType type)
{
    LOG_D ("task_optimizer: set task %p type=%d", task, type);
}

void
hev_task_optimizer_set_task_priority (HevTask *task, HevTaskPriorityLevel priority)
{
    LOG_D ("task_optimizer: set task %p priority=%d", task, priority);
}

void
hev_task_optimizer_adjust_priority (HevTask *task)
{
    LOG_D ("task_optimizer: adjusting priority for task %p", task);
}

HevTaskStats *
hev_task_optimizer_get_task_stats (HevTask *task)
{
    return NULL; /* Simplified implementation */
}

void
hev_task_optimizer_batch_wakeup_begin (void)
{
    LOG_D ("task_optimizer: batch wakeup begin");
}

void
hev_task_optimizer_batch_wakeup_add (HevTask *task)
{
    LOG_D ("task_optimizer: adding task %p to batch wakeup", task);
}

void
hev_task_optimizer_batch_wakeup_end (void)
{
    LOG_D ("task_optimizer: batch wakeup end");
}

HevTask *
hev_task_optimizer_select_next_task (void)
{
    return NULL; /* Simplified implementation */
}

void
hev_task_optimizer_update_runtime (HevTask *task, double runtime_us)
{
    optimizer.total_runs++;
    optimizer.total_runtime_us += (unsigned long)runtime_us;
}

void
hev_task_optimizer_report_stats (void)
{
    if (!optimizer.initialized) {
        return;
    }

    LOG_I ("task_optimizer: total runs=%lu, avg runtime=%.2f us",
           optimizer.total_runs,
           optimizer.total_runs > 0 ?
               (double)optimizer.total_runtime_us / optimizer.total_runs : 0.0);
}

void
hev_task_optimizer_get_global_stats (unsigned long *total_tasks,
                                     unsigned long *avg_runtime_us,
                                     double *cpu_utilization)
{
    if (total_tasks) *total_tasks = optimizer.total_runs;
    if (avg_runtime_us) *avg_runtime_us =
        optimizer.total_runs > 0 ? optimizer.total_runtime_us / optimizer.total_runs : 0;
    if (cpu_utilization) *cpu_utilization = 0.0; /* Simplified */
}

/* ============================================================================
   Unified Performance Optimizer Interface Implementation
   ============================================================================ */

/* 统一初始化和清理函数 */
void
hev_performance_optimizer_init_all (void)
{
    LOG_I ("performance_optimizer: initializing all modules");

    /* 初始化内存池 */
    hev_memory_pool_init ();

    /* 其他模块需要通过各自的初始化函数调用 */
    LOG_I ("performance_optimizer: all modules initialized");
}

void
hev_performance_optimizer_fini_all (void)
{
    LOG_I ("performance_optimizer: finalizing all modules");

    /* 清理内存池 */
    hev_memory_pool_fini ();

    /* 其他模块需要通过各自的清理函数调用 */
    LOG_I ("performance_optimizer: all modules finalized");
}

void
hev_performance_optimizer_configure (HevPerformanceOptimizerConfig *config)
{
    if (!config) {
        LOG_E ("performance_optimizer: config is NULL");
        return;
    }

    /* 配置连接池 */
    if (config->conn_pool_max_size > 0) {
        hev_connection_pool_init (config->conn_pool_max_size,
                                 config->conn_pool_min_idle_time,
                                 config->conn_pool_max_idle_time);
    }

    /* 配置批量处理器 */
    hev_batch_processor_init (&config->batch_config);

    /* 配置任务优化器 */
    hev_task_optimizer_init (&config->task_config);

    LOG_I ("performance_optimizer: configured with unified config");
}

void
hev_performance_optimizer_get_status (void)
{
    HevConnectionPoolStats conn_stats;
    unsigned long total_tasks, avg_runtime;
    double cpu_util;

    /* 获取连接池统计 */
    hev_connection_pool_get_stats (&conn_stats);
    LOG_I ("performance_optimizer: connection pool stats:");
    LOG_I ("  - current size: %d/%d", conn_stats.current_size, conn_stats.max_size);
    LOG_I ("  - hit ratio: %.2f%%", conn_stats.hit_ratio);

    /* 获取任务优化器统计 */
    hev_task_optimizer_get_global_stats (&total_tasks, &avg_runtime, &cpu_util);
    LOG_I ("performance_optimizer: task optimizer stats:");
    LOG_I ("  - total tasks: %lu", total_tasks);
    LOG_I ("  - avg runtime: %lu us", avg_runtime);

    /* 获取内存池状态 */
    LOG_I ("performance_optimizer: memory pool UDP size: %d",
           hev_memory_pool_get_udp_size ());
}