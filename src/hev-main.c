/*
 ============================================================================
 Name        : hev-main.c
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2019 - 2023 hev
 Description : Main
 ============================================================================
 */

#include <stdio.h>
#include <signal.h>
#include <string.h>

#include <lwip/init.h>

#include <hev-task.h>
#include <hev-task-system.h>

#include "hev-utils.h"
#include "hev-config.h"
#include "hev-config-const.h"
#include "hev-logger.h"
#include "hev-socks5-logger.h"
#include "hev-socks5-tunnel.h"
#include "hev-traffic-router.h"
#include "hev-session-manager.h"
#include "hev-filter.h"
#include "hev-test.h"
#include "hev-socks5-misc.h"

#include "hev-main.h"

static int
hev_socks5_tunnel_main_inner (int tun_fd)
{
    const char *pid_file;
    const char *log_file;
    int log_level;
    int nofile;
    int res;

    log_file = hev_config_get_misc_log_file ();
    log_level = hev_config_get_misc_log_level ();

    res = hev_logger_init (log_level, log_file);
    if (res < 0)
        return -2;

    // 添加测试日志确认日志系统工作
    LOG_I ("hev-socks5-tunnel starting, log_level=%d, log_file=%s", log_level,
           log_file);

    res = hev_socks5_logger_init (log_level, log_file);
    if (res < 0) {
        hev_logger_fini ();
        return -3;
    }

    res = hev_filter_init ();
    if (res < 0) {
        hev_socks5_logger_fini ();
        hev_logger_fini ();
        return -4;
    }

    const char *acl_path = hev_config_get_acl_file_path ();
    if (acl_path)
        hev_filter_load_acl (acl_path);

    const char *chnroutes_path = hev_config_get_chnroutes_file_path ();
    if (chnroutes_path)
        hev_filter_load_chnroutes (chnroutes_path);

    res = hev_traffic_router_init ();
    if (res < 0) {
        hev_filter_fini ();
        hev_socks5_logger_fini ();
        hev_logger_fini ();
        return -4;
    }

    hev_session_manager_init ();

    nofile = hev_config_get_misc_limit_nofile ();
    res = set_limit_nofile (nofile);
    if (res < 0)
        LOG_I ("set limit nofile");

    pid_file = hev_config_get_misc_pid_file ();
    if (pid_file)
        run_as_daemon (pid_file);

    res = hev_task_system_init ();
    if (res < 0) {
        hev_session_manager_fini ();
        hev_traffic_router_fini ();
        hev_filter_fini ();
        hev_socks5_logger_fini ();
        hev_logger_fini ();
        return -4;
    }

    lwip_init ();

    res = hev_socks5_tunnel_init (tun_fd);
    if (res < 0) {
        hev_task_system_fini ();
        hev_session_manager_fini ();
        hev_traffic_router_fini ();
        hev_filter_fini ();
        hev_socks5_logger_fini ();
        hev_logger_fini ();
        return -5;
    }

    hev_socks5_tunnel_run ();

    // ✅ 清理顺序:与初始化完全相反
    LOG_D ("main: Starting cleanup sequence");

    // 1. 先关闭隧道 (最后初始化的)
    hev_socks5_tunnel_fini ();

    // 2. 清理 lwIP 相关资源 (在 tunnel_fini 之后,因为 tunnel 依赖 lwIP)
    // lwIP 没有显式的 fini 函数,资源在 tunnel_fini 中处理

    // 3. 清理任务系统
    hev_task_system_fini ();

    // 4. 清理会话管理器
    hev_session_manager_fini ();

    // 5. 清理流量路由器 (依赖 filter)
    hev_traffic_router_fini ();

    // 6. 清理过滤器 (最早加载数据的组件)
    hev_filter_fini ();

    // 7. 清理日志系统
    hev_socks5_logger_fini ();
    hev_logger_fini ();

    // 8. 配置清理由调用者负责（在 main_from_file/main_from_str 中）
    // 注意：hev_config_fini() 不在这里调用，因为配置可能来自不同源

    LOG_D ("main: Cleanup sequence completed");

    return 0;
}

int
hev_socks5_tunnel_main_from_file (const char *config_path, int tun_fd)
{
    int res = hev_config_init_from_file (config_path);
    if (res < 0)
        return -1;

    res = hev_socks5_tunnel_main_inner (tun_fd);

    /* 清理配置资源 */
    hev_config_fini ();

    return res;
}

int
hev_socks5_tunnel_main_from_str (const unsigned char *config_str,
                                 unsigned int config_len, int tun_fd)
{
    int res = hev_config_init_from_str (config_str, config_len);
    if (res < 0)
        return -1;

    res = hev_socks5_tunnel_main_inner (tun_fd);

    /* 清理配置资源 */
    hev_config_fini ();

    return res;
}

int
hev_socks5_tunnel_main (const char *config_path, int tun_fd)
{
    // 添加调试日志确认主函数被调用
    printf (
        "DEBUG: hev_socks5_tunnel_main called with config_path=%s, tun_fd=%d\n",
        config_path ? config_path : "NULL", tun_fd);
    fflush (stdout);

    return hev_socks5_tunnel_main_from_file (config_path, tun_fd);
}

void
hev_socks5_tunnel_quit (void)
{
    hev_socks5_tunnel_stop ();
}

#ifndef ENABLE_LIBRARY
static void
show_help (const char *self_path)
{
    printf ("%s CONFIG_PATH\n", self_path);
    printf ("Version: %u.%u.%u %s\n", MAJOR_VERSION, MINOR_VERSION,
            MICRO_VERSION, COMMIT_ID);
}

static void
sigint_handler (int signum)
{
    hev_socks5_tunnel_stop ();
}

int
main (int argc, char *argv[])
{
    int res;

    if (argc < 2 || strcmp (argv[1], "--version") == 0) {
        show_help (argv[0]);
        return -1;
    }

    if (argc < 2 || strcmp (argv[1], "--test") == 0) {
        return hev_test_run ();
    }

    signal (SIGINT, sigint_handler);

    res = hev_socks5_tunnel_main (argv[1], -1);
    if (res < 0)
        return -2;

    return 0;
}
#endif /* ENABLE_LIBRARY */
