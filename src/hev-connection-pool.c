/*
 ============================================================================
 Name        : hev-connection-pool.c
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2025 hev
 Description : SOCKS5 Connection Pool for High Performance
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include <hev-task.h>

#include "hev-connection-pool.h"
#include "hev-config.h"
#include "hev-logger.h"

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

/* 获取当前时间（秒） */
static time_t
get_current_time_seconds (void)
{
    struct timeval tv;
    gettimeofday (&tv, NULL);
    return tv.tv_sec;
}

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
find_matching_connection (const char *addr, int port, HevSocks5Type type)
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

/* 初始化连接池 */
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

/* 清理连接池 */
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

/* 从连接池获取连接 */
HevConnectionPoolEntry *
hev_connection_pool_get (const char *addr, int port, HevSocks5Type type)
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

/* 将连接放回池中 */
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

/* 关闭并从池中移除连接 */
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

/* 获取连接池统计信息 */
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