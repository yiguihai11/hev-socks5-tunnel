/*
 * hev-session-manager-patch.h
 *
 * Copyright (C) 2024 hev-socks5-tunnel contributors
 *
 * This file is part of hev-socks5-tunnel.
 *
 * hev-socks5-tunnel is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * hev-socks5-tunnel is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with hev-socks5-tunnel.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef HEV_SESSION_MANAGER_PATCH_H
#define HEV_SESSION_MANAGER_PATCH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 前向声明 */
struct pbuf;

/**
 * @brief 启用协议解析零拷贝优化
 *
 * @return int 成功返回0，失败返回-1
 */
int hev_session_manager_enable_protocol_zerocopy (void);

/**
 * @brief 禁用协议解析零拷贝优化
 */
void hev_session_manager_disable_protocol_zerocopy (void);

/**
 * @brief 检查协议解析零拷贝优化是否启用
 *
 * @return int 启用返回1，未启用返回0
 */
int hev_session_manager_is_protocol_zerocopy_enabled (void);

#ifdef __cplusplus
}
#endif

#endif /* HEV_SESSION_MANAGER_PATCH_H */