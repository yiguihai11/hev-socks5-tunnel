# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Communication Language

**Always reply in Chinese (中文) when interacting with users in this repository.** Use technical terms in English where appropriate (e.g., function names, file paths, technical concepts).

## Development Principles

**Revert failed changes**: If a modification does not solve the problem, **revert the changes** before attempting a new approach. Do not accumulate unsuccessful modifications as this creates technical debt ("屎山代码").

- Use `git diff` to review changes before committing
- Use `git checkout -- <file>` to revert uncommitted changes
- Use `git revert <commit>` to revert committed changes
- Start fresh with a clean codebase for each new debugging approach

## Build Commands

```bash
# Standard build (optimized release)
make

# Debug build (with symbols, no optimization)
make DEBUG=1
# or simply:
make dev

# Static library build
make static

# Shared library build
make shared

# Clean build artifacts
make clean

# Clean third-party dependencies
make tp-clean

# Build third-party dependencies as static
make tp-static

# Build third-party dependencies as shared
make tp-shared

# Install to /usr/local
make install

# Uninstall
make uninstall
```

The build system uses a Makefile with support for:
- `CROSS_PREFIX` for cross-compilation
- `DEBUG=1` for debug builds (adds `-g -O0 -DENABLE_DEBUG`)
- `STATIC=1` for static linking
- `V=1` for verbose build output

Build artifacts are placed in `bin/` (executables) and `build/` (object files).

## Test Commands

The project uses `test.py` (Python standard library only):

```bash
# Full functional test (starts tunnel, runs tests, stops tunnel)
python3 test.py

# Test without starting tunnel (for external tunnel testing)
python3 test.py --no-start-tunnel

# Performance benchmark only
python3 test.py --test
```

The test script includes:
- DNS resolution tests against multiple servers (domestic and foreign)
- TCP connectivity tests
- ACL rule validation
- Smart proxy functionality tests
- Performance benchmarks

## Architecture Overview

hev-socks5-tunnel is a high-performance SOCKS5 tunnel with intelligent routing features. The architecture uses coroutine-based async I/O (hev-task-system) and a lightweight TCP/IP stack (lwIP).

### Core Components

**Initialization Sequence** (hev-main.c:hev_socks5_tunnel_main_inner):
1. Logger initialization
2. Filter system (ACL, chnroutes)
3. Traffic router
4. Task system (hev-task-system)
5. lwIP stack
6. DNS latency optimizer
7. SOCKS5 tunnel

**Traffic Router** (hev-traffic-router.c):
- Central routing engine handling TCP/UDP traffic
- Delegates to session manager for connection handling
- Routes traffic based on filter results (ACL, chnroutes, smart-proxy)

**Session Manager** (hev-session-manager.c):
- Manages active tunnel sessions with different routing strategies:
  - `DIRECT`: Direct connection (domestic or whitelisted)
  - `SOCKS5`: Through SOCKS5 proxy (foreign or blocked)
  - `SMART_PROXY`: Try direct first, fallback to proxy on timeout
  - `DOMAIN_FIRST`: Probe with direct connection before deciding route
- Supports both TCP and UDP sessions

**Filter System** (hev-filter.c):
- ACL rules parsing and matching (IP, CIDR, port, domain patterns)
- chnroutes radix tree for China IP range detection
- Smart proxy black list for failed direct connections
- 50-100 million ops/sec lookup performance

**DNS Cache** (hev-dns-cache.c):
- 16-shard cache for parallel access
- DNS pollution detection (detects foreign IPs in domestic DNS responses)
- Automatic fallback to clean foreign DNS via SOCKS5 when pollution detected
- Protocol-aware re-query (IPv4 DNS -> IPv4 foreign DNS, IPv6 DNS -> IPv6 foreign DNS)

**DNS Latency Optimizer** (hev-dns-latency.c):
- When multiple IPs returned in DNS response, tests latency to find fastest
- Configurable timeout for latency testing
- Returns lowest-latency IP to client

**Smart Proxy** (configured in conf/main.yml):
- Direct connection attempts with configurable timeout
- Automatic fallback to SOCKS5 on timeout
- Temporary blacklisting of slow IPs (configurable expiry)
- Port-based probing for domain-first routing (typically 80, 443)

### Platform-Specific Tunnel

TUN device implementations are separated by platform:
- `hev-tunnel-linux.c` - Linux (ioctl-based)
- `hev-tunnel-freebsd.c` - FreeBSD
- `hev-tunnel-netbsd.c` - NetBSD
- `hev-tunnel-macos.c` - macOS
- `hev-tunnel-windows.c` - Windows (Wintun)

### Source Organization

```
src/
├── hev-main.c                 # Entry point, initialization/cleanup
├── hev-traffic-router.c       # Central routing dispatcher
├── hev-session-manager.c      # Session lifecycle management
├── hev-filter.c               # ACL, chnroutes, smart-proxy blacklist
├── hev-dns-cache.c            # DNS caching with pollution detection
├── hev-dns-latency.c          # DNS latency optimization
├── hev-config.c               # YAML configuration parsing
├── hev-mapped-dns.c           # Mapped DNS server
├── hev-socks5-tunnel.c        # Main tunnel logic
├── hev-socks5-session*.c      # SOCKS5 session implementations
├── hev-tunnel-*.c             # Platform-specific TUN devices
├── core/                      # SOCKS5 client library
└── misc/                      # Utilities (logger, ring buffer, object pool)
```

### Key Data Structures

- **Session types**: Defined in hev-session-manager.h, routing decisions happen here
- **Filter**: Radix tree for CIDR, hash table for IPs, pattern matching for domains
- **DNS cache**: Per-shard locking, LRU eviction
- **Task system**: Coroutine-based async I/O (stack size configurable in config)

## Dependencies (Git Submodules)

- `third-part/hev-task-system` - Coroutine framework for async I/O
- `third-part/lwip` - Lightweight TCP/IP stack
- `third-part/yaml` - YAML configuration parser
- `third-part/wintun` - Windows TUN driver (when building for Windows)

Initialize submodules after cloning:
```bash
git submodule update --init --recursive
```

## Configuration

Main configuration is in `conf/main.yml` (YAML format). Key sections:
- `tunnel`: TUN device settings (name, MTU, IPs)
- `socks5`: SOCKS5 proxy server (tcp/udp with separate credentials)
- `dns-split-tunnel`: DNS pollution detection and foreign DNS fallback
- `dns-latency-optimize`: Multi-IP latency testing
- `smart-proxy`: Direct-to-proxy timeout fallback
- `acl`: Access control list (file path)
- `chnroutes`: China IP ranges for split routing (file path)
- `misc`: Performance tuning, logging, timeouts

ACL file format (`conf/acl.txt`):
```
block ip 1.2.3.4
block cidr 10.0.0.0/8
block port 23
block domain *.example.com
allow port 443
```

## Important Notes

- The project uses GPL v3 license
- Memory usage is optimized (< 10MB typical)
- Designed for 10,000+ concurrent connections
- Cleanup must happen in reverse order of initialization (see hev-main.c:142-169)
- Signal handling: SIGINT (2) → SIGTERM (15) → SIGKILL (9) for graceful shutdown
- TUN device creation requires root privileges (use sudo)
