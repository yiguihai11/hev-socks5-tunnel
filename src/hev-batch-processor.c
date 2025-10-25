/*
 ============================================================================
 Name        : hev-batch-processor.c
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2025 hev
 Description : Batch Processor for High Performance Operations
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>

#include "hev-batch-processor.h"
#include "hev-logger.h"

/* 全局批量处理器状态 */
static struct {
    HevBatchProcessorConfig config;
    HevBatchContext contexts[HEV_BATCH_TYPE_COUNT];
    int initialized;
} batch_processor = {0};

/* 获取当前时间（微秒） */
static unsigned long
get_current_time_us (void)
{
    struct timeval tv;
    gettimeofday (&tv, NULL);
    return (unsigned long)tv.tv_sec * 1000000 + tv.tv_usec;
}

/* 初始化批量处理上下文 */
static int
init_batch_context (HevBatchType type, int max_batch_size)
{
    HevBatchContext *ctx = &batch_processor.contexts[type];
    size_t item_size;

    switch (type) {
    case HEV_BATCH_TYPE_NETWORK_IO:
        item_size = sizeof (HevBatchNetworkIOItem);
        break;
    case HEV_BATCH_TYPE_PACKET_FORWARD:
        item_size = sizeof (HevBatchPacketItem);
        break;
    case HEV_BATCH_TYPE_SESSION_MGMT:
        item_size = sizeof (HevBatchSessionItem);
        break;
    case HEV_BATCH_TYPE_BUFFER_OPS:
        item_size = sizeof (HevBatchBufferItem);
        break;
    default:
        return -1;
    }

    ctx->items = calloc (max_batch_size, item_size);
    if (!ctx->items) {
        LOG_E ("batch_processor: failed to allocate batch context for type %d", type);
        return -1;
    }

    ctx->type = type;
    ctx->count = 0;
    ctx->capacity = max_batch_size;
    ctx->max_batch_size = max_batch_size;
    ctx->total_processed = 0;
    ctx->total_batches = 0;
    ctx->avg_batch_time_us = 0.0;
    ctx->enabled = 1;

    return 0;
}

/* 初始化批量处理器 */
void
hev_batch_processor_init (HevBatchProcessorConfig *config)
{
    int i, res;

    if (batch_processor.initialized) {
        LOG_W ("batch_processor: already initialized");
        return;
    }

    /* 设置默认配置 */
    if (config) {
        batch_processor.config = *config;
    } else {
        batch_processor.config.network_io_enabled = 1;
        batch_processor.config.packet_forward_enabled = 1;
        batch_processor.config.session_mgmt_enabled = 1;
        batch_processor.config.buffer_ops_enabled = 1;
        batch_processor.config.max_network_io_batch = 32;
        batch_processor.config.max_packet_batch = 64;
        batch_processor.config.max_session_batch = 16;
        batch_processor.config.max_buffer_batch = 128;
        batch_processor.config.batch_timeout_us = 1000.0; /* 1ms */
    }

    /* 初始化各种批量处理上下文 */
    res = init_batch_context (HEV_BATCH_TYPE_NETWORK_IO,
                             batch_processor.config.max_network_io_batch);
    if (res < 0) {
        goto error;
    }

    res = init_batch_context (HEV_BATCH_TYPE_PACKET_FORWARD,
                             batch_processor.config.max_packet_batch);
    if (res < 0) {
        goto error;
    }

    res = init_batch_context (HEV_BATCH_TYPE_SESSION_MGMT,
                             batch_processor.config.max_session_batch);
    if (res < 0) {
        goto error;
    }

    res = init_batch_context (HEV_BATCH_TYPE_BUFFER_OPS,
                             batch_processor.config.max_buffer_batch);
    if (res < 0) {
        goto error;
    }

    batch_processor.initialized = 1;

    LOG_I ("batch_processor: initialized with network_io=%d, packet_forward=%d, session_mgmt=%d",
           batch_processor.config.network_io_enabled,
           batch_processor.config.packet_forward_enabled,
           batch_processor.config.session_mgmt_enabled);
    return;

error:
    for (i = 0; i < HEV_BATCH_TYPE_COUNT; i++) {
        if (batch_processor.contexts[i].items) {
            free (batch_processor.contexts[i].items);
            batch_processor.contexts[i].items = NULL;
        }
    }
}

/* 清理批量处理器 */
void
hev_batch_processor_fini (void)
{
    int i;

    if (!batch_processor.initialized) {
        return;
    }

    /* 清理所有批量处理上下文 */
    for (i = 0; i < HEV_BATCH_TYPE_COUNT; i++) {
        HevBatchContext *ctx = &batch_processor.contexts[i];

        if (ctx->items) {
            /* 输出统计信息 */
            LOG_I ("batch_processor: type %d stats - processed: %lu, batches: %lu, avg_time: %.2fus",
                   i, ctx->total_processed, ctx->total_batches, ctx->avg_batch_time_us);

            free (ctx->items);
            ctx->items = NULL;
        }
    }

    batch_processor.initialized = 0;
    LOG_I ("batch_processor: finalized");
}

/* 获取批量处理上下文 */
HevBatchContext *
hev_batch_processor_get_context (HevBatchType type)
{
    if (!batch_processor.initialized || type >= HEV_BATCH_TYPE_COUNT) {
        return NULL;
    }

    return &batch_processor.contexts[type];
}

/* 网络I/O批量处理 - 添加项 */
int
hev_batch_processor_add_network_io (int fd, void *buffer, size_t size, int is_write)
{
    HevBatchContext *ctx;
    HevBatchNetworkIOItem *items;

    if (!batch_processor.config.network_io_enabled) {
        return -1;
    }

    ctx = hev_batch_processor_get_context (HEV_BATCH_TYPE_NETWORK_IO);
    if (!ctx || !ctx->enabled || ctx->count >= ctx->capacity) {
        return -1;
    }

    items = (HevBatchNetworkIOItem *)ctx->items;
    items[ctx->count].fd = fd;
    items[ctx->count].buffer = buffer;
    items[ctx->count].size = size;
    items[ctx->count].is_write = is_write;
    items[ctx->count].result = 0;
    ctx->count++;

    LOG_D ("batch_processor: added network I/O item (fd=%d, size=%zu, write=%d)",
           fd, size, is_write);

    return 0;
}

/* 网络I/O批量处理 - 处理 */
int
hev_batch_processor_process_network_io (void)
{
    HevBatchContext *ctx;
    HevBatchNetworkIOItem *items;
    unsigned long start_time, end_time;
    int i, processed = 0;

    ctx = hev_batch_processor_get_context (HEV_BATCH_TYPE_NETWORK_IO);
    if (!ctx || ctx->count == 0) {
        return 0;
    }

    start_time = get_current_time_us ();
    items = (HevBatchNetworkIOItem *)ctx->items;

    LOG_D ("batch_processor: processing %d network I/O items", ctx->count);

    /* 批量处理网络I/O操作 */
    for (i = 0; i < ctx->count; i++) {
        if (items[i].is_write) {
            items[i].result = write (items[i].fd, items[i].buffer, items[i].size);
        } else {
            items[i].result = read (items[i].fd, items[i].buffer, items[i].size);
        }

        if (items[i].result > 0) {
            processed++;
        }
    }

    end_time = get_current_time_us ();

    /* 更新统计信息 */
    ctx->total_processed += processed;
    ctx->total_batches++;
    if (ctx->avg_batch_time_us == 0) {
        ctx->avg_batch_time_us = (double)(end_time - start_time);
    } else {
        ctx->avg_batch_time_us = 0.9 * ctx->avg_batch_time_us +
                                0.1 * (double)(end_time - start_time);
    }

    /* 清空批量处理上下文 */
    ctx->count = 0;

    LOG_D ("batch_processor: processed %d/%d network I/O items in %.2fus",
           processed, ctx->count, (double)(end_time - start_time));

    return processed;
}

/* 数据包批量转发 - 添加项 */
int
hev_batch_processor_add_packet (struct pbuf *pbuf, struct udp_pcb *pcb,
                               ip_addr_t *addr, u16_t port, int priority)
{
    HevBatchContext *ctx;
    HevBatchPacketItem *items;

    if (!batch_processor.config.packet_forward_enabled) {
        return -1;
    }

    ctx = hev_batch_processor_get_context (HEV_BATCH_TYPE_PACKET_FORWARD);
    if (!ctx || !ctx->enabled || ctx->count >= ctx->capacity) {
        return -1;
    }

    items = (HevBatchPacketItem *)ctx->items;
    items[ctx->count].pbuf = pbuf;
    items[ctx->count].pcb = pcb;
    items[ctx->count].addr = addr;
    items[ctx->count].port = port;
    items[ctx->count].priority = priority;
    ctx->count++;

    /* 增加pbuf引用计数 */
    pbuf_ref (pbuf);

    LOG_D ("batch_processor: added packet item (priority=%d)", priority);

    return 0;
}

/* 数据包批量转发 - 处理 */
int
hev_batch_processor_process_packets (void)
{
    HevBatchContext *ctx;
    HevBatchPacketItem *items;
    unsigned long start_time, end_time;
    int i, processed = 0;
    err_t err;

    ctx = hev_batch_processor_get_context (HEV_BATCH_TYPE_PACKET_FORWARD);
    if (!ctx || ctx->count == 0) {
        return 0;
    }

    start_time = get_current_time_us ();
    items = (HevBatchPacketItem *)ctx->items;

    LOG_D ("batch_processor: processing %d packet items", ctx->count);

    /* 批量处理数据包转发 */
    for (i = 0; i < ctx->count; i++) {
        if (items[i].pbuf && items[i].pcb) {
            err = udp_sendto (items[i].pcb, items[i].pbuf, items[i].addr, items[i].port);
            if (err == ERR_OK) {
                processed++;
            }
        }

        /* 释放pbuf引用 */
        if (items[i].pbuf) {
            pbuf_free (items[i].pbuf);
        }
    }

    end_time = get_current_time_us ();

    /* 更新统计信息 */
    ctx->total_processed += processed;
    ctx->total_batches++;
    if (ctx->avg_batch_time_us == 0) {
        ctx->avg_batch_time_us = (double)(end_time - start_time);
    } else {
        ctx->avg_batch_time_us = 0.9 * ctx->avg_batch_time_us +
                                0.1 * (double)(end_time - start_time);
    }

    /* 清空批量处理上下文 */
    ctx->count = 0;

    LOG_D ("batch_processor: processed %d/%d packet items in %.2fus",
           processed, ctx->count, (double)(end_time - start_time));

    return processed;
}

/* 会话批量管理 - 添加项 */
int
hev_batch_processor_add_session_op (void *session, int operation,
                                   void *data, size_t data_size)
{
    HevBatchContext *ctx;
    HevBatchSessionItem *items;

    if (!batch_processor.config.session_mgmt_enabled) {
        return -1;
    }

    ctx = hev_batch_processor_get_context (HEV_BATCH_TYPE_SESSION_MGMT);
    if (!ctx || !ctx->enabled || ctx->count >= ctx->capacity) {
        return -1;
    }

    items = (HevBatchSessionItem *)ctx->items;
    items[ctx->count].session = session;
    items[ctx->count].operation = operation;
    items[ctx->count].data = data;
    items[ctx->count].data_size = data_size;
    ctx->count++;

    LOG_D ("batch_processor: added session operation (op=%d)", operation);

    return 0;
}

/* 会话批量管理 - 处理 */
int
hev_batch_processor_process_sessions (void)
{
    HevBatchContext *ctx;
    HevBatchSessionItem *items;
    unsigned long start_time, end_time;
    int i, processed = 0;

    ctx = hev_batch_processor_get_context (HEV_BATCH_TYPE_SESSION_MGMT);
    if (!ctx || ctx->count == 0) {
        return 0;
    }

    start_time = get_current_time_us ();
    items = (HevBatchSessionItem *)ctx->items;

    LOG_D ("batch_processor: processing %d session operations", ctx->count);

    /* 批量处理会话管理操作 */
    for (i = 0; i < ctx->count; i++) {
        /* 这里需要根据具体的会话管理逻辑来实现 */
        /* 目前只是模拟处理 */
        if (items[i].session) {
            /* 执行会话操作 */
            switch (items[i].operation) {
            case 0: /* 创建 */
            case 1: /* 更新 */
            case 2: /* 删除 */
                processed++;
                break;
            default:
                break;
            }
        }
    }

    end_time = get_current_time_us ();

    /* 更新统计信息 */
    ctx->total_processed += processed;
    ctx->total_batches++;
    if (ctx->avg_batch_time_us == 0) {
        ctx->avg_batch_time_us = (double)(end_time - start_time);
    } else {
        ctx->avg_batch_time_us = 0.9 * ctx->avg_batch_time_us +
                                0.1 * (double)(end_time - start_time);
    }

    /* 清空批量处理上下文 */
    ctx->count = 0;

    LOG_D ("batch_processor: processed %d/%d session operations in %.2fus",
           processed, ctx->count, (double)(end_time - start_time));

    return processed;
}

/* 缓冲区批量操作 - 添加项 */
int
hev_batch_processor_add_buffer_op (void *src, void *dst, size_t size, int operation)
{
    HevBatchContext *ctx;
    HevBatchBufferItem *items;

    if (!batch_processor.config.buffer_ops_enabled) {
        return -1;
    }

    ctx = hev_batch_processor_get_context (HEV_BATCH_TYPE_BUFFER_OPS);
    if (!ctx || !ctx->enabled || ctx->count >= ctx->capacity) {
        return -1;
    }

    items = (HevBatchBufferItem *)ctx->items;
    items[ctx->count].src = src;
    items[ctx->count].dst = dst;
    items[ctx->count].size = size;
    items[ctx->count].operation = operation;
    ctx->count++;

    LOG_D ("batch_processor: added buffer operation (op=%d, size=%zu)", operation, size);

    return 0;
}

/* 缓冲区批量操作 - 处理 */
int
hev_batch_processor_process_buffers (void)
{
    HevBatchContext *ctx;
    HevBatchBufferItem *items;
    unsigned long start_time, end_time;
    int i, processed = 0;

    ctx = hev_batch_processor_get_context (HEV_BATCH_TYPE_BUFFER_OPS);
    if (!ctx || ctx->count == 0) {
        return 0;
    }

    start_time = get_current_time_us ();
    items = (HevBatchBufferItem *)ctx->items;

    LOG_D ("batch_processor: processing %d buffer operations", ctx->count);

    /* 批量处理缓冲区操作 */
    for (i = 0; i < ctx->count; i++) {
        switch (items[i].operation) {
        case 0: /* 复制 */
            if (items[i].src && items[i].dst && items[i].size > 0) {
                memcpy (items[i].dst, items[i].src, items[i].size);
                processed++;
            }
            break;
        case 1: /* 清零 */
            if (items[i].dst && items[i].size > 0) {
                memset (items[i].dst, 0, items[i].size);
                processed++;
            }
            break;
        case 2: /* 比较 */
            if (items[i].src && items[i].dst && items[i].size > 0) {
                if (memcmp (items[i].src, items[i].dst, items[i].size) == 0) {
                    processed++;
                }
            }
            break;
        default:
            break;
        }
    }

    end_time = get_current_time_us ();

    /* 更新统计信息 */
    ctx->total_processed += processed;
    ctx->total_batches++;
    if (ctx->avg_batch_time_us == 0) {
        ctx->avg_batch_time_us = (double)(end_time - start_time);
    } else {
        ctx->avg_batch_time_us = 0.9 * ctx->avg_batch_time_us +
                                0.1 * (double)(end_time - start_time);
    }

    /* 清空批量处理上下文 */
    ctx->count = 0;

    LOG_D ("batch_processor: processed %d/%d buffer operations in %.2fus",
           processed, ctx->count, (double)(end_time - start_time));

    return processed;
}

/* 刷新所有批量处理 */
void
hev_batch_processor_flush_all (void)
{
    if (batch_processor.config.network_io_enabled) {
        hev_batch_processor_process_network_io ();
    }

    if (batch_processor.config.packet_forward_enabled) {
        hev_batch_processor_process_packets ();
    }

    if (batch_processor.config.session_mgmt_enabled) {
        hev_batch_processor_process_sessions ();
    }

    if (batch_processor.config.buffer_ops_enabled) {
        hev_batch_processor_process_buffers ();
    }
}

/* 获取批量处理统计信息 */
void
hev_batch_processor_get_stats (HevBatchType type,
                              unsigned long *total_processed,
                              unsigned long *total_batches,
                              double *avg_batch_time_us)
{
    HevBatchContext *ctx;

    ctx = hev_batch_processor_get_context (type);
    if (!ctx) {
        if (total_processed) *total_processed = 0;
        if (total_batches) *total_batches = 0;
        if (avg_batch_time_us) *avg_batch_time_us = 0.0;
        return;
    }

    if (total_processed) *total_processed = ctx->total_processed;
    if (total_batches) *total_batches = ctx->total_batches;
    if (avg_batch_time_us) *avg_batch_time_us = ctx->avg_batch_time_us;
}

/* 性能监控 */
void
hev_batch_processor_update_performance (HevBatchType type, double batch_time_us)
{
    HevBatchContext *ctx;

    ctx = hev_batch_processor_get_context (type);
    if (!ctx) {
        return;
    }

    ctx->total_batches++;
    if (ctx->avg_batch_time_us == 0) {
        ctx->avg_batch_time_us = batch_time_us;
    } else {
        ctx->avg_batch_time_us = 0.9 * ctx->avg_batch_time_us + 0.1 * batch_time_us;
    }
}