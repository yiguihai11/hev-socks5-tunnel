# HevSocks5Tunnel

HevSocks5Tunnel 是一个高性能的SOCKS5隧道工具，可将网络流量通过SOCKS5代理进行转发。

## 主要功能

*   **SOCKS5 隧道**: 创建一个虚拟网络接口 (TUN)，并将所有流量通过配置的SOCKS5代理进行转发。
*   **智能流量路由**: 支持基于IP地址列表（如 `chnroutes.txt`）的智能路由，可以区分国内外流量，实现国内直连、国外走代理。
*   **智能代理模式**: 对于国外流量，优先尝试直接连接，如果超时则自动切换到SOCKS5代理，并缓存结果以提高后续访问速度。
*   **DNS 转发**: 劫持发送到虚拟DNS地址的查询，并将其转发到指定的上游DNS服务器。
*   **跨平台**: 支持 Linux, macOS, Windows, Android, FreeBSD, NetBSD 等多种平台。

## 安装与运行

```bash
git clone --depth=1 --recursive https://ghfast.top/https://github.com/yiguihai11/hev-socks5-tunnel
cd hev-socks5-tunnel
make
```

修改 `conf/main.yml` 文件以配置您的SOCKS5服务器和其他选项，然后运行：

```bash
./hev-socks5-tunnel conf/main.yml
```