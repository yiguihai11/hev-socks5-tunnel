/*
 ============================================================================
 Name        : hev-config-const.h
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2019 - 2024 hev
 Description : Config Constants
 ============================================================================
 */

#ifndef __HEV_CONFIG_CONST_H__
#define __HEV_CONFIG_CONST_H__

#define MAJOR_VERSION (2)
#define MINOR_VERSION (13)
#define MICRO_VERSION (0)

static const int UDP_BUF_SIZE = 1500;
static const int UDP_POOL_SIZE_MIN = 128; // 最小UDP池大小
static const int UDP_POOL_SIZE_DEFAULT = 512; // 默认UDP池大小
static const int UDP_POOL_SIZE_MAX = 2048; // 最大UDP池大小
static const int TASK_STACK_SIZE = 20480;

#endif /* __HEV_CONFIG_CONST_H__ */
