/*
 ============================================================================
 Name        : hev-batch-processor.h (Compatibility Layer)
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2025 hev
 Description : Batch Processor for High Performance Operations - Compatibility Header
 ============================================================================
 */

#ifndef __HEV_BATCH_PROCESSOR_H__
#define __HEV_BATCH_PROCESSOR_H__

/* Include the unified performance optimizer module */
#include "hev-performance-optimizer.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Re-export types and functions for backward compatibility */
typedef HevBatchType HevBatchType;
typedef HevBatchNetworkIOItem HevBatchNetworkIOItem;
typedef HevBatchPacketItem HevBatchPacketItem;
typedef HevBatchSessionItem HevBatchSessionItem;
typedef HevBatchBufferItem HevBatchBufferItem;
typedef HevBatchContext HevBatchContext;
typedef HevBatchProcessorConfig HevBatchProcessorConfig;

/* All functions are available through hev-performance-optimizer.h */

#ifdef __cplusplus
}
#endif

#endif /* __HEV_BATCH_PROCESSOR_H__ */