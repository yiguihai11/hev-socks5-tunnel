/*
 ============================================================================
 Name        : hev-object-pool.h
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2025 hev
 Description : Generic Object Pool for Performance Optimization
 ============================================================================
 */

#ifndef __HEV_OBJECT_POOL_H__
#define __HEV_OBJECT_POOL_H__

#include <stddef.h>
#include <pthread.h>

typedef struct _HevObjectPool HevObjectPool;

/**
 * HevObjectPool:
 *
 * 通用对象池，用于减少频繁的 malloc/free 开销
 */
struct _HevObjectPool
{
    void **free_list;      /* 空闲对象列表 */
    size_t free_count;     /* 空闲对象数量 */
    size_t capacity;       /* 池容量 */
    size_t obj_size;       /* 单个对象大小 */
    pthread_mutex_t lock;  /* 线程安全锁 */
};

typedef struct _HevObjectPoolConfig HevObjectPoolConfig;

struct _HevObjectPoolConfig
{
    size_t obj_size;       /* 对象大小 */
    size_t init_capacity;  /* 初始容量 */
    size_t max_capacity;   /* 最大容量 (0 = 无限制) */
};

/**
 * hev_object_pool_new:
 * @config: 池配置
 *
 * 创建新对象池
 *
 * Returns: 对象池指针，失败返回 NULL
 */
HevObjectPool *hev_object_pool_new (const HevObjectPoolConfig *config);

/**
 * hev_object_pool_destroy:
 * @pool: 对象池
 *
 * 销毁对象池，释放所有内存
 */
void hev_object_pool_destroy (HevObjectPool *pool);

/**
 * hev_object_pool_get:
 * @pool: 对象池
 *
 * 从池中获取一个对象
 *
 * Returns: 对象指针，失败返回 NULL
 */
void *hev_object_pool_get (HevObjectPool *pool);

/**
 * hev_object_pool_put:
 * @pool: 对象池
 * @obj: 对象指针
 *
 * 将对象放回池中
 */
void hev_object_pool_put (HevObjectPool *pool, void *obj);

/**
 * hev_object_pool_get_stats:
 * @pool: 对象池
 * @free_count: 输出空闲对象数量
 * @capacity: 输出总容量
 *
 * 获取池统计信息
 */
void hev_object_pool_get_stats (HevObjectPool *pool, size_t *free_count,
                                size_t *capacity);

#endif /* __HEV_OBJECT_POOL_H__ */
