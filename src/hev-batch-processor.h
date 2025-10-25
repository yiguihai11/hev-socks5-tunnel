/*
 ============================================================================
 Name        : hev-batch-processor.h
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2025 hev
 Description : Batch Processor for High Performance Operations
 ============================================================================
 */

#ifndef __HEV_BATCH_PROCESSOR_H__
#define __HEV_BATCH_PROCESSOR_H__

#include <hev-task.h>
#include <lwip/pbuf.h>
#include <lwip/udp.h>
#include <lwip/ip_addr.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 批量处理类型 */
typedef enum {
    HEV_BATCH_TYPE_NETWORK_IO = 0,    /* 网络I/O批量处理 */
    HEV_BATCH_TYPE_PACKET_FORWARD,    /* 数据包批量转发 */
    HEV_BATCH_TYPE_SESSION_MGMT,      /* 会话批量管理 */
    HEV_BATCH_TYPE_BUFFER_OPS,        /* 缓冲区批量操作 */
    HEV_BATCH_TYPE_COUNT
} HevBatchType;

/* 网络I/O批量项 */
typedef struct {
    int fd;                          /* 文件描述符 */
    void *buffer;                    /* 缓冲区指针 */
    size_t size;                     /* 数据大小 */
    int is_write;                    /* 读写标志：1=写，0=读 */
    int result;                      /* 操作结果 */
} HevBatchNetworkIOItem;

/* 数据包批量转发项 */
typedef struct {
    struct pbuf *pbuf;               /* 数据包缓冲区 */
    struct udp_pcb *pcb;             /* UDP PCB */
    ip_addr_t *addr;                 /* 目标地址 */
    u16_t port;                      /* 目标端口 */
    int priority;                    /* 优先级 */
} HevBatchPacketItem;

/* 会话批量管理项 */
typedef struct {
    void *session;                   /* 会话指针 */
    int operation;                   /* 操作类型 */
    void *data;                      /* 操作数据 */
    size_t data_size;                /* 数据大小 */
} HevBatchSessionItem;

/* 缓冲区批量操作项 */
typedef struct {
    void *src;                       /* 源缓冲区 */
    void *dst;                       /* 目标缓冲区 */
    size_t size;                     /* 操作大小 */
    int operation;                   /* 操作类型：0=复制，1=清零，2=比较 */
} HevBatchBufferItem;

/* 批量处理上下文 */
typedef struct {
    HevBatchType type;               /* 批量处理类型 */
    void *items;                     /* 批量项数组 */
    int count;                       /* 当前项数量 */
    int capacity;                    /* 数组容量 */
    int max_batch_size;              /* 最大批量大小 */
    unsigned long total_processed;   /* 总处理数量 */
    unsigned long total_batches;     /* 总批次数 */
    double avg_batch_time_us;        /* 平均批处理时间 */
    int enabled;                     /* 是否启用 */
} HevBatchContext;

/* 批量处理配置 */
typedef struct {
    int network_io_enabled;          /* 启用网络I/O批量处理 */
    int packet_forward_enabled;      /* 启用数据包批量转发 */
    int session_mgmt_enabled;        /* 启用会话批量管理 */
    int buffer_ops_enabled;          /* 启用缓冲区批量操作 */
    int max_network_io_batch;        /* 网络I/O最大批量大小 */
    int max_packet_batch;            /* 数据包最大批量大小 */
    int max_session_batch;           /* 会话管理最大批量大小 */
    int max_buffer_batch;            /* 缓冲区操作最大批量大小 */
    double batch_timeout_us;         /* 批处理超时时间（微秒） */
} HevBatchProcessorConfig;

/* 初始化批量处理器 */
void hev_batch_processor_init (HevBatchProcessorConfig *config);

/* 清理批量处理器 */
void hev_batch_processor_fini (void);

/* 获取批量处理上下文 */
HevBatchContext *hev_batch_processor_get_context (HevBatchType type);

/* 网络I/O批量处理 */
int hev_batch_processor_add_network_io (int fd, void *buffer, size_t size, int is_write);
int hev_batch_processor_process_network_io (void);

/* 数据包批量转发 */
int hev_batch_processor_add_packet (struct pbuf *pbuf, struct udp_pcb *pcb,
                                   ip_addr_t *addr, u16_t port, int priority);
int hev_batch_processor_process_packets (void);

/* 会话批量管理 */
int hev_batch_processor_add_session_op (void *session, int operation,
                                       void *data, size_t data_size);
int hev_batch_processor_process_sessions (void);

/* 缓冲区批量操作 */
int hev_batch_processor_add_buffer_op (void *src, void *dst, size_t size, int operation);
int hev_batch_processor_process_buffers (void);

/* 刷新所有批量处理 */
void hev_batch_processor_flush_all (void);

/* 获取批量处理统计信息 */
void hev_batch_processor_get_stats (HevBatchType type,
                                   unsigned long *total_processed,
                                   unsigned long *total_batches,
                                   double *avg_batch_time_us);

/* 性能监控 */
void hev_batch_processor_update_performance (HevBatchType type, double batch_time_us);

#ifdef __cplusplus
}
#endif

#endif /* __HEV_BATCH_PROCESSOR_H__ */