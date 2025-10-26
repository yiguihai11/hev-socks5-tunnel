/*
 ============================================================================
 Name        : hev-memory-pool.h
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2025 hev
 Description : Dynamic Memory Pool Manager
 ============================================================================
 */

#ifndef __HEV_MEMORY_POOL_H__
#define __HEV_MEMORY_POOL_H__

#include <time.h>

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

/* 动态调整UDP池大小
 * @param current_usage: 当前使用量
 * @param total_capacity: 当前总容量
 * @return: 调整后的池大小
 */
int hev_memory_pool_adjust_udp_size (int current_usage, int total_capacity);

/* 获取当前UDP池大小 */
int hev_memory_pool_get_udp_size (void);

/* 手动设置UDP池大小（用于测试或特殊配置） */
void hev_memory_pool_set_udp_size (int size);

/* 初始化内存池管理器 */
void hev_memory_pool_init (void);

/* 清理内存池管理器 */
void hev_memory_pool_fini (void);

#endif /* __HEV_MEMORY_POOL_H__ */