/*
 ============================================================================
 Name        : hev-connection-pool.h
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2025 hev
 Description : SOCKS5 Connection Pool for High Performance
 ============================================================================
 */

#ifndef __HEV_CONNECTION_POOL_H__
#define __HEV_CONNECTION_POOL_H__

#include <hev-socks5.h>

/* 连接池条目 */
typedef struct _HevConnectionPoolEntry
{
    int fd; // 连接文件描述符
    char addr[256]; // 服务器地址
    int port; // 服务器端口
    HevSocks5Type type; // 连接类型
    int in_use; // 是否正在使用
    time_t last_used; // 最后使用时间
    time_t created_time; // 创建时间
} HevConnectionPoolEntry;

/* 连接池统计信息 */
typedef struct _HevConnectionPoolStats
{
    int max_size; // 最大连接数
    int current_size; // 当前连接数
    unsigned long total_connections; // 总连接数
    unsigned long pool_hits; // 连接池命中数
    unsigned long pool_misses; // 连接池未命中数
    double hit_ratio; // 命中率（百分比）
} HevConnectionPoolStats;

/* 初始化连接池 */
void hev_connection_pool_init (int max_size, int min_idle_time,
                               int max_idle_time);

/* 清理连接池 */
void hev_connection_pool_fini (void);

/* 从连接池获取连接 */
HevConnectionPoolEntry *hev_connection_pool_get (const char *addr, int port,
                                                 HevSocks5Type type);

/* 将连接放回池中 */
void hev_connection_pool_put (HevConnectionPoolEntry *entry);

/* 关闭并从池中移除连接 */
void hev_connection_pool_remove (HevConnectionPoolEntry *entry);

/* 获取连接池统计信息 */
void hev_connection_pool_get_stats (HevConnectionPoolStats *stats);

#endif /* __HEV_CONNECTION_POOL_H__ */