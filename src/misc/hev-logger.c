/*
 ============================================================================
 Name        : hev-logger.c
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2019 - 2023 hev
 Description : Logger
 ============================================================================
 */

#include <time.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <pthread.h>
#include <stdlib.h>

#include "hev-logger.h"

#define LOG_BUFFER_SIZE (1024 * 1024) // 1MB

static int fd = -1;
static HevLoggerLevel req_level;
static char *log_buffer = NULL;
static size_t buffer_pos = 0;
static size_t buffer_used = 0;
static pthread_mutex_t buffer_mutex = PTHREAD_MUTEX_INITIALIZER;

int
hev_logger_init (HevLoggerLevel level, const char *path)
{
    req_level = level;

    if (0 == strcmp (path, "stdout"))
        fd = dup (1);
    else if (0 == strcmp (path, "stderr"))
        fd = dup (2);
    else
        fd = open (path, O_WRONLY | O_APPEND | O_CREAT, 0640);

    if (fd < 0)
        return -1;

    // Initialize memory buffer
    log_buffer = malloc (LOG_BUFFER_SIZE);
    if (!log_buffer) {
        close (fd);
        return -1;
    }
    buffer_pos = 0;
    buffer_used = 0;

    return 0;
}

void
hev_logger_fini (void)
{
    close (fd);
    if (log_buffer) {
        free (log_buffer);
        log_buffer = NULL;
    }
    buffer_pos = 0;
    buffer_used = 0;
}

int
hev_logger_enabled (HevLoggerLevel level)
{
    if (fd >= 0 && level >= req_level)
        return 1;

    return 0;
}

void
hev_logger_log (HevLoggerLevel level, const char *fmt, ...)
{
    struct iovec iov[4];
    const char *ts_fmt;
    char msg[1024];
    char full_msg[1152]; // ts(32) + level(4) + msg(1024) + newline(1) + padding
    struct tm *ti;
    char ts[32];
    time_t now;
    va_list ap;
    int len, total_len;

    if (fd < 0 || level < req_level)
        return;

    time (&now);
    ti = localtime (&now);

    ts_fmt = "[%04u-%02u-%02u %02u:%02u:%02u] ";
    len = snprintf (ts, sizeof (ts), ts_fmt, 1900 + ti->tm_year, 1 + ti->tm_mon,
                    ti->tm_mday, ti->tm_hour, ti->tm_min, ti->tm_sec);

    iov[0].iov_base = ts;
    iov[0].iov_len = len;

    switch (level) {
    case HEV_LOGGER_DEBUG:
        iov[1].iov_base = "[D] ";
        break;
    case HEV_LOGGER_INFO:
        iov[1].iov_base = "[I] ";
        break;
    case HEV_LOGGER_WARN:
        iov[1].iov_base = "[W] ";
        break;
    case HEV_LOGGER_ERROR:
        iov[1].iov_base = "[E] ";
        break;
    case HEV_LOGGER_UNSET:
        iov[1].iov_base = "[?] ";
        break;
    }
    iov[1].iov_len = 4;

    va_start (ap, fmt);
    iov[2].iov_base = msg;
    iov[2].iov_len = vsnprintf (msg, 1024, fmt, ap);
    va_end (ap);

    iov[3].iov_base = "\n";
    iov[3].iov_len = 1;

    total_len = len + 4 + iov[2].iov_len + 1;

    // Write to file
    if (writev (fd, iov, 4)) {
        /* ignore return value */
    }

    // Write to memory buffer
    if (log_buffer) {
        pthread_mutex_lock (&buffer_mutex);

        // Build complete message
        memcpy (full_msg, ts, len);
        memcpy (full_msg + len, iov[1].iov_base, 4);
        memcpy (full_msg + len + 4, msg, iov[2].iov_len);
        full_msg[len + 4 + iov[2].iov_len] = '\n';

        // Handle circular buffer
        if (buffer_used + total_len > LOG_BUFFER_SIZE) {
            // Buffer is full, wrap around
            size_t remaining = LOG_BUFFER_SIZE - buffer_pos;
            if (total_len <= remaining) {
                memcpy (log_buffer + buffer_pos, full_msg, total_len);
                buffer_pos += total_len;
            } else {
                memcpy (log_buffer + buffer_pos, full_msg, remaining);
                memcpy (log_buffer, full_msg + remaining,
                        total_len - remaining);
                buffer_pos = total_len - remaining;
            }
            buffer_used = LOG_BUFFER_SIZE;
        } else {
            // Buffer has space
            if (buffer_pos + total_len <= LOG_BUFFER_SIZE) {
                memcpy (log_buffer + buffer_pos, full_msg, total_len);
                buffer_pos += total_len;
            } else {
                // Need to wrap to beginning
                size_t remaining = LOG_BUFFER_SIZE - buffer_pos;
                memcpy (log_buffer + buffer_pos, full_msg, remaining);
                memcpy (log_buffer, full_msg + remaining,
                        total_len - remaining);
                buffer_pos = total_len - remaining;
            }
            buffer_used += total_len;
        }

        pthread_mutex_unlock (&buffer_mutex);
    }
}
