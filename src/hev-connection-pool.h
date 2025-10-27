/*
 ============================================================================
 Name        : hev-connection-pool.h (Compatibility Layer)
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2025 hev
 Description : SOCKS5 Connection Pool - Compatibility Header
 ============================================================================
 */

#ifndef __HEV_CONNECTION_POOL_H__
#define __HEV_CONNECTION_POOL_H__

/* Include the unified performance optimizer module */
#include "hev-performance-optimizer.h"

/* Re-export types and functions for backward compatibility */
typedef HevConnectionPoolEntry HevConnectionPoolEntry;
typedef HevConnectionPoolStats HevConnectionPoolStats;

/* All functions are available through hev-performance-optimizer.h */

#endif /* __HEV_CONNECTION_POOL_H__ */