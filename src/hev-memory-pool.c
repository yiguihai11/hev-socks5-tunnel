/*
 ============================================================================
 Name        : hev-memory-pool.c
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2025 hev
 Description : Dynamic Memory Pool Manager
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <hev-task.h>

#include "hev-memory-pool.h"
#include "hev-config-const.h"
#include "hev-logger.h"

/* 动态UDP池管理器 */
static HevMemoryPool udp_pool = {
    .current_size = UDP_POOL_SIZE_DEFAULT,
    .min_size = UDP_POOL_SIZE_MIN,
    .max_size = UDP_POOL_SIZE_MAX,
    .high_watermark = 0.8,    // 80%时考虑扩容
    .low_watermark = 0.3,     // 30%时考虑缩容
    .last_adjust_time = 0,
    .adjust_interval = 30      // 30秒调整一次
};

/* 获取当前时间（秒） */
static time_t
get_current_time_seconds (void)
{
    struct timeval tv;
    gettimeofday (&tv, NULL);
    return tv.tv_sec;
}

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
        LOG_D ("memory_pool: High usage detected %.2f%% (%d/%d), considering expansion",
               usage_ratio * 100, current_usage, total_capacity);
        return 1;  // 需要扩容
    }

    /* 低水位检查：使用率低于30%且大于最小值 */
    if (usage_ratio < udp_pool.low_watermark &&
        udp_pool.current_size > udp_pool.min_size) {
        LOG_D ("memory_pool: Low usage detected %.2f%% (%d/%d), considering shrinkage",
               usage_ratio * 100, current_usage, total_capacity);
        return -1; // 需要缩容
    }

    return 0; // 不需要调整
}

/* 动态调整UDP池大小 */
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

            LOG_I ("memory_pool: UDP pool expanded from %d to %d frames (usage: %d/%d)",
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

            LOG_I ("memory_pool: UDP pool shrunk from %d to %d frames (usage: %d/%d)",
                   old_size, udp_pool.current_size, current_usage, total_capacity);
        }
    }

    return udp_pool.current_size;
}

/* 获取当前UDP池大小 */
int
hev_memory_pool_get_udp_size (void)
{
    return udp_pool.current_size;
}

/* 手动设置UDP池大小（用于测试或特殊配置） */
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

/* 初始化内存池管理器 */
void
hev_memory_pool_init (void)
{
    udp_pool.last_adjust_time = get_current_time_seconds ();
    LOG_D ("memory_pool: Initialized with UDP pool size %d (range: %d-%d)",
           udp_pool.current_size, udp_pool.min_size, udp_pool.max_size);
}

/* 清理内存池管理器 */
void
hev_memory_pool_fini (void)
{
    LOG_D ("memory_pool: Finalized with UDP pool size %d", udp_pool.current_size);
}