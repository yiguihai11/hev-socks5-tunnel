/*
 ============================================================================
 Name        : hev-object-pool.c
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2025 hev
 Description : Generic Object Pool Implementation
 ============================================================================
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "hev-memory-allocator.h"
#include "hev-logger.h"
#include "hev-object-pool.h"

HevObjectPool *
hev_object_pool_new (const HevObjectPoolConfig *config)
{
    HevObjectPool *pool;

    if (!config || config->obj_size == 0 || config->init_capacity == 0)
        return NULL;

    pool = hev_malloc0 (sizeof (HevObjectPool));
    if (!pool)
        return NULL;

    pool->free_list = hev_malloc0 (sizeof (void *) * config->init_capacity);
    if (!pool->free_list) {
        hev_free (pool);
        return NULL;
    }

    pool->capacity = config->init_capacity;
    pool->obj_size = config->obj_size;
    pool->free_count = 0;

    pthread_mutex_init (&pool->lock, NULL);

    LOG_D ("Object pool created: obj_size=%zu, capacity=%zu", config->obj_size,
           config->init_capacity);

    return pool;
}

void
hev_object_pool_destroy (HevObjectPool *pool)
{
    size_t i;

    if (!pool)
        return;

    pthread_mutex_lock (&pool->lock);

    /* 释放所有空闲对象 */
    for (i = 0; i < pool->free_count; i++) {
        /* 检查指针是否有效 */
        void *obj = pool->free_list[i];
        if (obj) {
            LOG_D ("Object pool: freeing object %p (i=%zu/%zu)", obj, i,
                   pool->free_count);
            hev_free (obj);
        }
    }

    pthread_mutex_unlock (&pool->lock);

    pthread_mutex_destroy (&pool->lock);
    hev_free (pool->free_list);
    hev_free (pool);
}

void *
hev_object_pool_get (HevObjectPool *pool)
{
    void *obj = NULL;

    if (!pool)
        return NULL;

    pthread_mutex_lock (&pool->lock);

    if (pool->free_count > 0) {
        /* 从池中获取 */
        obj = pool->free_list[--pool->free_count];
        LOG_D ("Object pool: reuse object (free_count=%zu)", pool->free_count);
    } else {
        /* 池为空，分配新对象 */
        obj = hev_malloc0 (pool->obj_size);
        if (obj) {
            LOG_D ("Object pool: allocate new object (size=%zu)",
                   pool->obj_size);
        }
    }

    pthread_mutex_unlock (&pool->lock);

    return obj;
}

void
hev_object_pool_put (HevObjectPool *pool, void *obj)
{
    size_t new_capacity;

    if (!pool || !obj)
        return;

    pthread_mutex_lock (&pool->lock);

    /* 检查是否需要扩容 */
    if (pool->free_count >= pool->capacity) {
        new_capacity = pool->capacity * 2;
        void **new_list =
            hev_realloc (pool->free_list, sizeof (void *) * new_capacity);
        if (new_list) {
            pool->free_list = new_list;
            pool->capacity = new_capacity;
            LOG_D ("Object pool: expanded to %zu", new_capacity);
        } else {
            /* 扩容失败，直接释放对象 */
            pthread_mutex_unlock (&pool->lock);
            hev_free (obj);
            LOG_W ("Object pool: expansion failed, freeing object");
            return;
        }
    }

    /* 放回池中 */
    pool->free_list[pool->free_count++] = obj;
    LOG_D ("Object pool: return object (free_count=%zu)", pool->free_count);

    pthread_mutex_unlock (&pool->lock);
}

void
hev_object_pool_get_stats (HevObjectPool *pool, size_t *free_count,
                           size_t *capacity)
{
    if (!pool)
        return;

    pthread_mutex_lock (&pool->lock);

    if (free_count)
        *free_count = pool->free_count;
    if (capacity)
        *capacity = pool->capacity;

    pthread_mutex_unlock (&pool->lock);
}
