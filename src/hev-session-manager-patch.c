/*
 * hev-session-manager-patch.c
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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>

#include "hev-config.h"
#include "hev-logger.h"
#include "hev-session-manager.h"

#include "lwip/pbuf.h"

/**
 * @brief 零拷贝优化控制变量
 */
static int protocol_zerocopy_enabled = 0;

/**
 * @brief 跨pbuf链表进行字符串搜索（零拷贝版本）
 *
 * 直接在pbuf链表上搜索，避免线性化拷贝
 *
 * @param p pbuf链表头
 * @param pattern 要搜索的字符串
 * @param pattern_len 字符串长度
 * @param max_search_len 最大搜索长度
 * @param found_offset 输出找到的偏移量
 * @return const struct pbuf* 找到返回对应的pbuf指针，未找到返回NULL
 */
static const struct pbuf *
pbuf_chain_search_zerocopy(const struct pbuf *p, const char *pattern,
                          size_t pattern_len, size_t max_search_len, size_t *found_offset)
{
    size_t search_offset = 0;
    const struct pbuf *current = p;
    size_t current_offset = 0;
    char window_buffer[256];  /* 滑动窗口缓冲区 */

    if (pattern_len == 0 || pattern_len > sizeof(window_buffer))
        return NULL;

    while (current && search_offset < max_search_len) {
        /* 构建搜索窗口 */
        size_t window_size = 0;
        const struct pbuf *temp = current;
        size_t temp_offset = current_offset;

        /* 收集足够的数据用于搜索 */
        while (temp && window_size < pattern_len && window_size < sizeof(window_buffer)) {
            size_t available = temp->len - temp_offset;
            size_t to_copy = (available < (sizeof(window_buffer) - window_size)) ?
                            available : (sizeof(window_buffer) - window_size);

            memcpy(window_buffer + window_size, (char *)temp->payload + temp_offset, to_copy);
            window_size += to_copy;

            if (window_size >= pattern_len) {
                break;
            }

            temp = temp->next;
            temp_offset = 0;
        }

        /* 在当前窗口中搜索 */
        if (window_size >= pattern_len) {
            char *found = memmem(window_buffer, window_size, pattern, pattern_len);
            if (found) {
                *found_offset = search_offset + (found - window_buffer);
                return current;  /* 返回当前pbuf指针 */
            }
        }

        /* 移动搜索窗口 */
        search_offset += (window_size > 0) ? (window_size - pattern_len + 1) : 1;
        if (search_offset >= max_search_len) {
            break;
        }

        /* 更新当前位置 */
        size_t advance = 1;
        while (current && advance > 0) {
            size_t remaining = current->len - current_offset;
            if (remaining <= advance) {
                advance -= remaining;
                current = current->next;
                current_offset = 0;
            } else {
                current_offset += advance;
                advance = 0;
            }
        }
    }

    return NULL;
}

/**
 * @brief 从指定偏移量开始提取字符串（零拷贝版本）
 *
 * @param p pbuf链表头
 * @param start_offset 开始偏移量
 * @param end_marker 结束标记字符串
 * @param buffer 输出缓冲区
 * @param buffer_len 缓冲区长度
 * @return int 成功返回提取的长度，失败返回-1
 */
static int
extract_string_from_offset(const struct pbuf *p, size_t start_offset,
                          const char *end_marker, char *buffer, size_t buffer_len)
{
    size_t current_offset = 0;
    const struct pbuf *current = p;
    size_t skip_offset = start_offset;
    size_t extracted_len = 0;
    int found_end = 0;

    /* 跳过开始偏移量 */
    while (current && skip_offset > 0) {
        if (current->len <= skip_offset) {
            skip_offset -= current->len;
            current = current->next;
        } else {
            current_offset = skip_offset;
            skip_offset = 0;
        }
    }

    /* 开始提取字符串直到结束标记 */
    while (current && extracted_len < buffer_len - 1 && !found_end) {
        size_t available = current->len - current_offset;
        const char *src = (const char *)current->payload + current_offset;
        size_t copy_len = available;
        size_t end_marker_len = strlen(end_marker);

        /* 检查是否在当前pbuf中找到结束标记 */
        if (available >= end_marker_len) {
            char *end_pos = memmem(src, available, end_marker, end_marker_len);
            if (end_pos) {
                copy_len = end_pos - src;
                found_end = 1;
            }
        }

        /* 复制数据 */
        if (copy_len > 0) {
            size_t actual_copy = (copy_len < (buffer_len - 1 - extracted_len)) ?
                                copy_len : (buffer_len - 1 - extracted_len);
            memcpy(buffer + extracted_len, src, actual_copy);
            extracted_len += actual_copy;
        }

        current = current->next;
        current_offset = 0;
    }

    buffer[extracted_len] = '\0';
    return found_end ? extracted_len : -1;
}


/**
 * @brief 启用协议解析零拷贝优化
 *
 * @return int 成功返回0，失败返回-1
 */
int
hev_session_manager_enable_protocol_zerocopy(void)
{
    protocol_zerocopy_enabled = 1;
    LOG_I("Protocol zero-copy optimization enabled");
    return 0;
}

/**
 * @brief 禁用协议解析零拷贝优化
 */
void
hev_session_manager_disable_protocol_zerocopy(void)
{
    protocol_zerocopy_enabled = 0;
    LOG_I("Protocol zero-copy optimization disabled");
}

/**
 * @brief 检查协议解析零拷贝优化是否启用
 *
 * @return int 启用返回1，未启用返回0
 */
int
hev_session_manager_is_protocol_zerocopy_enabled(void)
{
    return protocol_zerocopy_enabled;
}

/**
 * @brief 零拷贝pbuf链表搜索工具函数
 *
 * @param p pbuf链表头
 * @param pattern 搜索模式
 * @param pattern_len 模式长度
 * @param max_search_len 最大搜索长度
 * @param found_offset 输出偏移量
 * @return const struct pbuf* 找到返回pbuf指针，未找到返回NULL
 */
const struct pbuf *
hev_pbuf_chain_search_zerocopy(const struct pbuf *p, const char *pattern,
                              size_t pattern_len, size_t max_search_len, size_t *found_offset)
{
    return pbuf_chain_search_zerocopy(p, pattern, pattern_len, max_search_len, found_offset);
}

/**
 * @brief 零拷贝字符串提取工具函数
 *
 * @param p pbuf链表头
 * @param start_offset 开始偏移量
 * @param end_marker 结束标记
 * @param buffer 输出缓冲区
 * @param buffer_len 缓冲区长度
 * @return int 成功返回长度，失败返回-1
 */
int
hev_extract_string_from_offset(const struct pbuf *p, size_t start_offset,
                              const char *end_marker, char *buffer, size_t buffer_len)
{
    return extract_string_from_offset(p, start_offset, end_marker, buffer, buffer_len);
}