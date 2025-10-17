项目功能增强开发计划（完整版）

  一、DNS劫持转发功能 (dns-forwarder)

  1.1 功能概述

  - 劫持TUN接口内指定的DNS查询流量，不经过SOCKS5代理
  - 在本地直连转发到指定的DNS服务器
  - 完整支持IPv4和IPv6的DNS查询劫持
  - 优先级高于现有的mapdns功能

  1.2 配置参数解析

  dns-forwarder:
    virtual-ip4: 8.8.8.8                        # 劫持的IPv4 DNS地址
    virtual-ip6: '2001:4860:4860::8844'         # 劫持的IPv6 DNS地址
    target-ip4: 1.1.1.1                         # 转发目标IPv4地址（默认端口53）
    target-ip6: '[2606:4700:4700::1111]:53'     # 转发目标IPv6地址（可指定端口）

  1.3 实现细节

  新增文件：
  - src/hev-dns-forwarder.h - 头文件，定义接口
  - src/hev-dns-forwarder.c - 实现文件

  数据结构设计：
  typedef struct {
      // IPv4配置
      ip4_addr_t virtual_ip4;      // 网络序
      ip4_addr_t target_ip4;       // 网络序
      uint16_t target_port4;       // 主机序
      int enabled_v4;              // 是否启用IPv4劫持

      // IPv6配置
      ip6_addr_t virtual_ip6;      // 网络序
      ip6_addr_t target_ip6;       // 网络序
      uint16_t target_port6;       // 主机序
      int enabled_v6;              // 是否启用IPv6劫持
  } HevDnsForwarderConfig;

  核心函数：
  // 初始化，解析配置
  int hev_dns_forwarder_init(void);

  // 销毁，释放资源
  void hev_dns_forwarder_fini(void);

  // 检测并处理DNS流量（返回1表示已处理，0表示未处理，-1表示错误）
  int hev_dns_forwarder_handle(struct udp_pcb *pcb, struct pbuf *p,
                                const ip_addr_t *addr, u16_t port);

  实现逻辑：

  1. 初始化阶段 (hev_dns_forwarder_init)：
    - 从配置读取virtual-ip和target-ip
    - 使用 inet_pton() 解析IPv4和IPv6地址
    - 解析端口号（支持 ip:port 格式）
    - 如果配置为空则对应协议不启用
  2. DNS流量检测 (hev_dns_forwarder_handle)：
  // 判断流程
  if (目标端口 != 53) {
      return 0;  // 不是DNS流量
  }

  if (是IPv4地址) {
      if (!enabled_v4) return 0;
      if (目标IP != virtual_ip4) return 0;
      // 匹配成功，处理IPv4 DNS
      return hev_dns_forwarder_process_v4(pcb, p, addr, port);
  }
  else if (是IPv6地址) {
      if (!enabled_v6) return 0;
      if (目标IP != virtual_ip6) return 0;
      // 匹配成功，处理IPv6 DNS
      return hev_dns_forwarder_process_v6(pcb, p, addr, port);
  }

  return 0;  // 未匹配
  3. IPv4 DNS转发处理 (hev_dns_forwarder_process_v4)：
    - 创建IPv4 UDP socket：hev_task_io_socket_socket(AF_INET, SOCK_DGRAM, 0)
    - 构造目标地址：target_ip4:target_port4
    - 异步发送DNS查询：hev_task_io_socket_sendto()
    - 异步接收DNS响应：hev_task_io_socket_recvfrom()
    - 构造lwIP pbuf，伪装源地址为virtual_ip4
    - 通过lwIP发送回客户端：udp_sendfrom(pcb, pbuf, &virtual_ip4, 53)
    - 关闭socket
  4. IPv6 DNS转发处理 (hev_dns_forwarder_process_v6)：
    - 创建IPv6 UDP socket：hev_task_io_socket_socket(AF_INET6, SOCK_DGRAM, 0)
    - 构造目标地址：target_ip6:target_port6
    - 异步发送DNS查询：hev_task_io_socket_sendto()
    - 异步接收DNS响应：hev_task_io_socket_recvfrom()
    - 构造lwIP pbuf，伪装源地址为virtual_ip6
    - 通过lwIP发送回客户端：udp_sendfrom(pcb, pbuf, &virtual_ip6, 53)
    - 关闭socket

  集成点：
  - 在 hev-socks5-tunnel.c 的 udp_recv_handler 中，最优先调用
  - 示例代码：
  static void
  udp_recv_handler(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                   const ip_addr_t *addr, u16_t port)
  {
      int res;

      // 优先级1: DNS劫持
      res = hev_dns_forwarder_handle(pcb, p, addr, port);
      if (res == 1) {
          pbuf_free(p);
          return;  // 已处理
      }

      // 优先级2: mapdns
      res = hev_mapped_dns_handle(...);
      if (res == 1) {
          pbuf_free(p);
          return;
      }

      // 优先级3: chnroutes + socks5
      // ... 后续处理
  }

  技术要点：
  - 使用 IP_IS_V4(addr) 和 IP_IS_V6(addr) 判断IP版本
  - IPv4地址比较：ip4_addr_cmp(&addr->u_addr.ip4, &virtual_ip4)
  - IPv6地址比较：ip6_addr_cmp(&addr->u_addr.ip6, &virtual_ip6)
  - 源地址伪装必须使用 udp_sendfrom()，不能用 udp_send()
  - 每个DNS查询在独立的hev-task中处理，避免阻塞

  ---
  二、国内外分流功能 (chnroutes)

  2.1 功能概述

  - 根据中国IP地址段列表（CIDR格式），区分国内和国外流量
  - 完整支持IPv4和IPv6地址判断
  - 国内IP直连，国外IP走SOCKS5代理（或smart-proxy）
  - 同时处理TCP和UDP流量

  2.2 配置参数解析

  chnroutes:
    file-path: "conf/chnroutes.txt"  # CIDR列表文件路径

  2.3 文件格式说明

  conf/chnroutes.txt 每行一个CIDR地址，支持注释：
  # IPv4示例
  1.0.1.0/24
  1.0.2.0/23
  223.255.252.0/22

  # IPv6示例
  2001:250::/35
  2001:251::/32
  2400::/32

  2.4 实现细节

  新增文件：
  - src/hev-chnroutes.h - 头文件
  - src/hev-chnroutes.c - 实现文件

  数据结构设计：
  // IPv4 CIDR条目
  typedef struct {
      uint32_t network;    // 网络地址（网络序）
      uint32_t mask;       // 子网掩码（网络序）
      uint8_t prefix_len;  // 前缀长度（如24表示/24）
  } HevCIDRv4;

  // IPv6 CIDR条目
  typedef struct {
      uint8_t network[16]; // 网络地址（网络序，128位）
      uint8_t mask[16];    // 子网掩码（网络序，128位）
      uint8_t prefix_len;  // 前缀长度（如32表示/32）
  } HevCIDRv6;

  // 全局存储（静态变量）
  static HevCIDRv4 *cidr_v4_list = NULL;
  static size_t cidr_v4_count = 0;
  static size_t cidr_v4_capacity = 0;

  static HevCIDRv6 *cidr_v6_list = NULL;
  static size_t cidr_v6_count = 0;
  static size_t cidr_v6_capacity = 0;

  核心函数：
  // 初始化，加载CIDR列表
  int hev_chnroutes_init(void);

  // 销毁，释放内存
  void hev_chnroutes_fini(void);

  // 判断IP是否为国内地址（支持IPv4和IPv6）
  // 返回: 1=国内, 0=国外, -1=错误
  int hev_chnroutes_is_domestic(const ip_addr_t *ip);

  实现逻辑：

  2.4.1 初始化阶段 (hev_chnroutes_init)

  1. 读取配置文件：
  const char *file_path = hev_config_get_chnroutes_file_path();
  if (!file_path) {
      LOG_W("chnroutes: file-path not configured, disabled");
      return 0;  // 未配置，功能禁用
  }

  FILE *fp = fopen(file_path, "r");
  if (!fp) {
      LOG_E("chnroutes: failed to open %s", file_path);
      return -1;
  }
  2. 逐行解析CIDR：
  char line[256];
  while (fgets(line, sizeof(line), fp)) {
      // 去除空白和注释
      char *p = line;
      while (*p == ' ' || *p == '\t') p++;
      if (*p == '#' || *p == '\n' || *p == '\0') continue;

      // 查找 '/' 分隔符
      char *slash = strchr(p, '/');
      if (!slash) {
          LOG_W("chnroutes: invalid line (no /): %s", line);
          continue;
      }

      *slash = '\0';
      char *ip_str = p;
      char *prefix_str = slash + 1;
      int prefix_len = atoi(prefix_str);

      // 尝试解析IPv4
      struct in_addr addr4;
      if (inet_pton(AF_INET, ip_str, &addr4) == 1) {
          // 验证前缀长度
          if (prefix_len < 0 || prefix_len > 32) {
              LOG_W("chnroutes: invalid IPv4 prefix: %s/%d", ip_str, prefix_len);
              continue;
          }

          // 添加到IPv4列表
          add_cidr_v4(addr4.s_addr, prefix_len);
          continue;
      }

      // 尝试解析IPv6
      struct in6_addr addr6;
      if (inet_pton(AF_INET6, ip_str, &addr6) == 1) {
          // 验证前缀长度
          if (prefix_len < 0 || prefix_len > 128) {
              LOG_W("chnroutes: invalid IPv6 prefix: %s/%d", ip_str, prefix_len);
              continue;
          }

          // 添加到IPv6列表
          add_cidr_v6(addr6.s6_addr, prefix_len);
          continue;
      }

      LOG_W("chnroutes: invalid IP address: %s", ip_str);
  }
  fclose(fp);
  3. 添加CIDR条目：
  static void add_cidr_v4(uint32_t network_net, int prefix_len)
  {
      // 动态扩容
      if (cidr_v4_count >= cidr_v4_capacity) {
          cidr_v4_capacity = cidr_v4_capacity ? cidr_v4_capacity * 2 : 1024;
          cidr_v4_list = hev_realloc(cidr_v4_list,
                                     cidr_v4_capacity * sizeof(HevCIDRv4));
      }

      // 计算掩码（网络序）
      uint32_t mask = 0;
      if (prefix_len > 0) {
          mask = htonl(0xFFFFFFFF << (32 - prefix_len));
      }

      // 规范化网络地址（应用掩码）
      uint32_t network = network_net & mask;

      // 存储
      cidr_v4_list[cidr_v4_count].network = network;
      cidr_v4_list[cidr_v4_count].mask = mask;
      cidr_v4_list[cidr_v4_count].prefix_len = prefix_len;
      cidr_v4_count++;
  }

  static void add_cidr_v6(const uint8_t *network_bytes, int prefix_len)
  {
      // 动态扩容
      if (cidr_v6_count >= cidr_v6_capacity) {
          cidr_v6_capacity = cidr_v6_capacity ? cidr_v6_capacity * 2 : 1024;
          cidr_v6_list = hev_realloc(cidr_v6_list,
                                     cidr_v6_capacity * sizeof(HevCIDRv6));
      }

      // 计算掩码（IPv6是128位）
      uint8_t mask[16] = {0};
      for (int i = 0; i < prefix_len; i++) {
          mask[i / 8] |= (0x80 >> (i % 8));
      }

      // 规范化网络地址
      uint8_t network[16];
      for (int i = 0; i < 16; i++) {
          network[i] = network_bytes[i] & mask[i];
      }

      // 存储
      memcpy(cidr_v6_list[cidr_v6_count].network, network, 16);
      memcpy(cidr_v6_list[cidr_v6_count].mask, mask, 16);
      cidr_v6_list[cidr_v6_count].prefix_len = prefix_len;
      cidr_v6_count++;
  }
  4. 排序数组（关键：IPv4和IPv6分别排序）：
  // IPv4比较函数
  static int compare_cidr_v4(const void *a, const void *b)
  {
      const HevCIDRv4 *ca = (const HevCIDRv4 *)a;
      const HevCIDRv4 *cb = (const HevCIDRv4 *)b;

      // 先比较网络地址（网络序，直接用ntohl转为主机序比较）
      uint32_t na = ntohl(ca->network);
      uint32_t nb = ntohl(cb->network);
      if (na < nb) return -1;
      if (na > nb) return 1;

      // 网络地址相同，比较前缀长度（长的在前）
      if (ca->prefix_len > cb->prefix_len) return -1;
      if (ca->prefix_len < cb->prefix_len) return 1;

      return 0;
  }

  // IPv6比较函数
  static int compare_cidr_v6(const void *a, const void *b)
  {
      const HevCIDRv6 *ca = (const HevCIDRv6 *)a;
      const HevCIDRv6 *cb = (const HevCIDRv6 *)b;

      // 先比较网络地址（按字节比较）
      int cmp = memcmp(ca->network, cb->network, 16);
      if (cmp != 0) return cmp;

      // 网络地址相同，比较前缀长度（长的在前）
      if (ca->prefix_len > cb->prefix_len) return -1;
      if (ca->prefix_len < cb->prefix_len) return 1;

      return 0;
  }

  // 排序
  qsort(cidr_v4_list, cidr_v4_count, sizeof(HevCIDRv4), compare_cidr_v4);
  qsort(cidr_v6_list, cidr_v6_count, sizeof(HevCIDRv6), compare_cidr_v6);

  LOG_I("chnroutes: loaded %zu IPv4 CIDRs, %zu IPv6 CIDRs",
        cidr_v4_count, cidr_v6_count);

  2.4.2 查询阶段 (hev_chnroutes_is_domestic)

  int hev_chnroutes_is_domestic(const ip_addr_t *ip)
  {
      if (!cidr_v4_list && !cidr_v6_list) {
          return 0;  // 未加载，默认国外
      }

      if (IP_IS_V4(ip)) {
          return is_domestic_v4(ip_2_ip4(ip));
      } else if (IP_IS_V6(ip)) {
          return is_domestic_v6(ip_2_ip6(ip));
      }

      return 0;
  }

  // IPv4二分查找
  static int is_domestic_v4(const ip4_addr_t *ip)
  {
      if (!cidr_v4_list || cidr_v4_count == 0) {
          return 0;
      }

      uint32_t ip_net = ip4_addr_get_u32(ip);  // 网络序

      // 二分查找
      size_t left = 0;
      size_t right = cidr_v4_count;

      while (left < right) {
          size_t mid = left + (right - left) / 2;
          HevCIDRv4 *cidr = &cidr_v4_list[mid];

          // 检查是否匹配
          if ((ip_net & cidr->mask) == cidr->network) {
              return 1;  // 匹配，国内
          }

          // 继续二分
          uint32_t mid_net = ntohl(cidr->network);
          uint32_t ip_host = ntohl(ip_net);

          if (ip_host < mid_net) {
              right = mid;
          } else {
              left = mid + 1;
          }
      }

      return 0;  // 未匹配，国外
  }

  // IPv6二分查找
  static int is_domestic_v6(const ip6_addr_t *ip)
  {
      if (!cidr_v6_list || cidr_v6_count == 0) {
          return 0;
      }

      const uint8_t *ip_bytes = (const uint8_t *)ip->addr;

      // 二分查找
      size_t left = 0;
      size_t right = cidr_v6_count;

      while (left < right) {
          size_t mid = left + (right - left) / 2;
          HevCIDRv6 *cidr = &cidr_v6_list[mid];

          // 检查是否匹配
          int match = 1;
          for (int i = 0; i < 16; i++) {
              if ((ip_bytes[i] & cidr->mask[i]) != cidr->network[i]) {
                  match = 0;
                  break;
              }
          }
          if (match) {
              return 1;  // 匹配，国内
          }

          // 继续二分
          int cmp = memcmp(ip_bytes, cidr->network, 16);
          if (cmp < 0) {
              right = mid;
          } else {
              left = mid + 1;
          }
      }

      return 0;  // 未匹配，国外
  }

  集成点：
  - 在创建SOCKS5会话之前调用
  - 示例（TCP流量）：
  static void
  tcp_accept_handler(void *arg, struct tcp_pcb *pcb, err_t err)
  {
      ip_addr_t *dst_ip = &pcb->local_ip;  // lwIP魔改：local_ip是真实目标

      // 检查是否国内IP
      int is_domestic = hev_chnroutes_is_domestic(dst_ip);
      if (is_domestic == 1) {
          // 国内IP，创建直连会话
          create_direct_session(pcb);
          return;
      }

      // 国外IP，继续smart-proxy或SOCKS5流程
      // ...
  }

  技术要点：
  - 关键：IPv4和IPv6必须分开存储和查找，因为字节序不同
  - 二分查找时，匹配条件是 (ip & mask) == network
  - 查找复杂度 O(log n)，n为CIDR数量
  - 内存占用：每个IPv4 CIDR约9字节，每个IPv6 CIDR约34字节

  ---
  三、智能代理功能 (smart-proxy)

  3.1 功能概述

  - 仅处理TCP流量
  - 对国外流量（经过chnroutes判定）先尝试直连
  - 如果直连超时，回落到SOCKS5代理
  - 维护黑名单列表：记录直连失败的IP，避免重复尝试
  - 完整支持IPv4和IPv6地址
  - 黑名单条目在超过 blocked-ip-expiry-minutes 后自动过期清理

  3.2 配置参数解析

  smart-proxy:
    timeout-ms: 2000                    # 直连超时时间（毫秒）
    blocked-ip-expiry-minutes: 360      # IP屏蔽过期时间（分钟，6小时）

  3.3 实现细节

  新增文件：
  - src/hev-smart-proxy.h - 头文件
  - src/hev-smart-proxy.c - 实现文件

  数据结构设计：

  // 黑名单IP条目（使用红黑树存储）
  typedef struct _HevSmartProxyBlockedIP HevSmartProxyBlockedIP;
  struct _HevSmartProxyBlockedIP {
      HevRBTreeNode node;      // 红黑树节点
      ip_addr_t ip;            // 被屏蔽的IP（支持IPv4和IPv6）
      time_t block_time;       // 屏蔽时间戳（秒）
  };

  // 全局配置和状态
  static struct {
      int enabled;                        // 是否启用
      int timeout_ms;                     // 直连超时时间（毫秒）
      int expiry_minutes;                 // 黑名单过期时间（分钟）
      HevRBTree blocked_ips;              // 黑名单树（IPv4和IPv6混合存储）
      HevTask *cleanup_task;              // 后台清理任务
  } smart_proxy_ctx;

  核心函数：

  // 初始化
  int hev_smart_proxy_init(void);

  // 销毁
  void hev_smart_proxy_fini(void);

  // 尝试直连（返回socket fd或-1）
  // 成功返回已连接的socket，失败返回-1并自动加入黑名单
  int hev_smart_proxy_try_direct(const ip_addr_t *dst_ip, uint16_t dst_port);

  // 检查IP是否在黑名单中（返回1=在黑名单，0=不在）
  int hev_smart_proxy_is_blocked(const ip_addr_t *ip);

  // 添加IP到黑名单
  void hev_smart_proxy_add_blocked(const ip_addr_t *ip);

  // 清理过期黑名单（后台任务）
  static void hev_smart_proxy_cleanup_task_entry(void *data);

  实现逻辑：

  3.3.1 初始化 (hev_smart_proxy_init)

  int hev_smart_proxy_init(void)
  {
      int timeout = hev_config_get_smart_proxy_timeout_ms();
      int expiry = hev_config_get_smart_proxy_expiry_minutes();

      // 检查配置是否启用
      if (timeout <= 0 || expiry <= 0) {
          LOG_I("smart-proxy: disabled (timeout=%d, expiry=%d)", timeout, expiry);
          smart_proxy_ctx.enabled = 0;
          return 0;
      }

      smart_proxy_ctx.enabled = 1;
      smart_proxy_ctx.timeout_ms = timeout;
      smart_proxy_ctx.expiry_minutes = expiry;

      // 初始化红黑树
      hev_rbtree_init(&smart_proxy_ctx.blocked_ips);

      // 启动后台清理任务
      smart_proxy_ctx.cleanup_task = hev_task_new(-1);
      hev_task_run(smart_proxy_ctx.cleanup_task,
                   hev_smart_proxy_cleanup_task_entry, NULL);

      LOG_I("smart-proxy: enabled (timeout=%dms, expiry=%dmin)", timeout, expiry);
      return 0;
  }

  3.3.2 检查黑名单 (hev_smart_proxy_is_blocked)

  int hev_smart_proxy_is_blocked(const ip_addr_t *ip)
  {
      if (!smart_proxy_ctx.enabled) {
          return 0;
      }

      HevRBTreeNode *node = smart_proxy_ctx.blocked_ips.root;

      while (node) {
          HevSmartProxyBlockedIP *entry =
              container_of(node, HevSmartProxyBlockedIP, node);

          int cmp = ip_addr_cmp(ip, &entry->ip);

          if (cmp == 0) {
              // 找到，检查是否过期
              time_t now = time(NULL);
              time_t expiry = smart_proxy_ctx.expiry_minutes * 60;

              if ((now - entry->block_time) < expiry) {
                  LOG_D("smart-proxy: IP in blocklist (not expired)");
                  return 1;  // 在黑名单且未过期
              } else {
                  LOG_D("smart-proxy: IP in blocklist (expired)");
                  return 0;  // 已过期，视为不在黑名单
              }
          } else if (cmp < 0) {
              node = node->left;
          } else {
              node = node->right;
          }
      }

      return 0;  // 不在黑名单
  }

  // IP地址比较函数（支持IPv4和IPv6混合）
  static int ip_addr_cmp(const ip_addr_t *a, const ip_addr_t *b)
  {
      // 先比较类型
      if (IP_IS_V4(a) && IP_IS_V6(b)) return -1;
      if (IP_IS_V6(a) && IP_IS_V4(b)) return 1;

      if (IP_IS_V4(a)) {
          // 都是IPv4
          uint32_t a_val = ntohl(ip4_addr_get_u32(ip_2_ip4(a)));
          uint32_t b_val = ntohl(ip4_addr_get_u32(ip_2_ip4(b)));
          if (a_val < b_val) return -1;
          if (a_val > b_val) return 1;
          return 0;
      } else {
          // 都是IPv6
          return memcmp(ip_2_ip6(a)->addr, ip_2_ip6(b)->addr, 16);
      }
  }

  3.3.3 添加到黑名单 (hev_smart_proxy_add_blocked)

  void hev_smart_proxy_add_blocked(const ip_addr_t *ip)
  {
      if (!smart_proxy_ctx.enabled) {
          return;
      }

      // 先检查是否已存在
      HevRBTreeNode **new_node = &smart_proxy_ctx.blocked_ips.root;
      HevRBTreeNode *parent = NULL;

      while (*new_node) {
          HevSmartProxyBlockedIP *entry =
              container_of(*new_node, HevSmartProxyBlockedIP, node);
          parent = *new_node;

          int cmp = ip_addr_cmp(ip, &entry->ip);

          if (cmp == 0) {
              // 已存在，更新时间戳
              entry->block_time = time(NULL);
              LOG_D("smart-proxy: updated existing blocklist entry");
              return;
          } else if (cmp < 0) {
              new_node = &(*new_node)->left;
          } else {
              new_node = &(*new_node)->right;
          }
      }

      // 不存在，创建新条目
      HevSmartProxyBlockedIP *entry = hev_malloc(sizeof(HevSmartProxyBlockedIP));
      ip_addr_copy(entry->ip, *ip);
      entry->block_time = time(NULL);

      hev_rbtree_node_init(&entry->node);
      hev_rbtree_insert(&smart_proxy_ctx.blocked_ips, parent, new_node, &entry->node);

      // 日志
      char ip_str[64];
      if (IP_IS_V4(ip)) {
          inet_ntop(AF_INET, &ip->u_addr.ip4, ip_str, sizeof(ip_str));
          LOG_I("smart-proxy: added IPv4 %s to blocklist", ip_str);
      } else {
          inet_ntop(AF_INET6, &ip->u_addr.ip6, ip_str, sizeof(ip_str));
          LOG_I("smart-proxy: added IPv6 %s to blocklist", ip_str);
      }
  }

  3.3.4 尝试直连 (hev_smart_proxy_try_direct)

  int hev_smart_proxy_try_direct(const ip_addr_t *dst_ip, uint16_t dst_port)
  {
      if (!smart_proxy_ctx.enabled) {
          return -1;  // 未启用，直接失败
      }

      // 步骤1: 检查黑名单
      if (hev_smart_proxy_is_blocked(dst_ip)) {
          LOG_D("smart-proxy: IP in blocklist, skip direct");
          return -1;  // 在黑名单，直接失败
      }

      LOG_D("smart-proxy: trying direct connection");

      // 步骤2: 创建socket
      int fd;
      // ... (同原计划)

      // 步骤3: 构造目标地址
      // ... (同原计划)

      // 步骤4: 创建连接超时任务 (使用配置的 timeout-ms)
      HevTask *connect_timeout_task = hev_task_new(-1);
      int connect_timeout_triggered = 0;
      hev_task_run(connect_timeout_task, timeout_task_entry, &connect_timeout_triggered);

      // 步骤5: 异步连接
      int res = hev_task_io_socket_connect(fd, (struct sockaddr *)&addr, addr_len, NULL, NULL);

      // 取消连接超时任务
      hev_task_wakeup(connect_timeout_task);

      if (res < 0 || connect_timeout_triggered) {
          close(fd);
          if (connect_timeout_triggered) {
              LOG_I("smart-proxy: direct connect timeout");
          } else {
              LOG_I("smart-proxy: direct connect failed");
          }
          hev_smart_proxy_add_blocked(dst_ip);
          return -1;
      }

      // 步骤6: 验证链路可用性 (新增逻辑)
      // 创建一个独立的、更短的读取超时任务
      HevTask *read_timeout_task = hev_task_new(-1);
      int read_timeout_triggered = 0;
      hev_task_run(read_timeout_task, short_timeout_task_entry, &read_timeout_triggered);

      char dummy_buf[1];
      res = hev_task_io_socket_read(fd, dummy_buf, 1, NULL, NULL);

      // 取消读取超时任务
      hev_task_wakeup(read_timeout_task);

      // 如果读取失败(res<0)、立即收到EOF(res==0)或短超时，都视为直连失败
      if (res <= 0 || read_timeout_triggered) {
          close(fd);
          LOG_I("smart-proxy: direct link is not usable (read failed, EOF or short timeout)");
          hev_smart_proxy_add_blocked(dst_ip);
          return -1;
      }

      LOG_I("smart-proxy: direct connect and link validation success");
      // 注意：这里我们消费了1字节数据，在实际应用中可能需要一个更复杂的机制
      // 来处理这1字节数据。但在当前方案中，我们简化地认为只要能读通就成功。
      return fd;  // 成功，返回已连接的socket
  }

  // 连接超时任务 (使用配置的 timeout-ms)
  static void timeout_task_entry(void *data)
  {
      int *timeout_triggered = (int *)data;
      hev_task_sleep(smart_proxy_ctx.timeout_ms);
      *timeout_triggered = 1;
  }

  // 读取验证的短超时任务 (新增)
  static void short_timeout_task_entry(void *data)
  {
      int *timeout_triggered = (int *)data;
      // 使用一个较短的硬编码超时时间，如 500ms
      hev_task_sleep(500);
      *timeout_triggered = 1;
  }

  3.3.5 后台清理任务 (hev_smart_proxy_cleanup_task_entry)

  static void hev_smart_proxy_cleanup_task_entry(void *data)
  {
      while (smart_proxy_ctx.enabled) {
          // 每60秒清理一次
          hev_task_sleep(60 * 1000);

          LOG_D("smart-proxy: running cleanup");

          time_t now = time(NULL);
          time_t expiry = smart_proxy_ctx.expiry_minutes * 60;
          size_t removed = 0;

          // 遍历红黑树，删除过期条目
          HevRBTreeNode *node = hev_rbtree_first(&smart_proxy_ctx.blocked_ips);
          while (node) {
              HevSmartProxyBlockedIP *entry =
                  container_of(node, HevSmartProxyBlockedIP, node);

              HevRBTreeNode *next = hev_rbtree_next(node);

              if ((now - entry->block_time) >= expiry) {
                  // 过期，删除
                  hev_rbtree_erase(&smart_proxy_ctx.blocked_ips, node);
                  hev_free(entry);
                  removed++;
              }

              node = next;
          }

          if (removed > 0) {
              LOG_I("smart-proxy: cleaned %zu expired entries", removed);
          }
      }
  }

  集成点：
  - 在TCP流量经过chnroutes判断为国外后，且创建SOCKS5会话之前调用
  - 示例代码：
  static void tcp_accept_handler(void *arg, struct tcp_pcb *pcb, err_t err)
  {
      ip_addr_t *dst_ip = &pcb->local_ip;  // lwIP魔改
      uint16_t dst_port = pcb->local_port;

      // 步骤1: chnroutes判断
      int is_domestic = hev_chnroutes_is_domestic(dst_ip);
      if (is_domestic == 1) {
          // 国内，直连
          create_direct_tcp_session(pcb);
          return;
      }

      // 步骤2: smart-proxy尝试直连
      int direct_fd = hev_smart_proxy_try_direct(dst_ip, dst_port);
      if (direct_fd >= 0) {
          // 直连成功，创建直连会话
          create_direct_tcp_session_with_fd(pcb, direct_fd);
          return;
      }

      // 步骤3: 回落到SOCKS5
      create_socks5_tcp_session(pcb);
  }

  技术要点：
  - 黑名单使用红黑树存储，查找/插入/删除复杂度均为 O(log n)
  - IPv4和IPv6混合存储，通过比较函数先比较IP类型，再比较地址
  - 超时控制使用双任务机制：主任务connect，辅助任务sleep超时
  - 后台清理任务定期遍历红黑树，删除过期条目
  - 直连成功后返回socket fd，需要创建新的会话类型处理流量转发

  ---
  四、配置解析增强

  4.1 修改文件

  - src/hev-config.h - 添加新配置结构体和getter函数声明
  - src/hev-config.c - 实现YAML解析和getter函数

  4.2 新增配置结构体

  在 hev-config.h 中添加：

  // DNS转发配置
  typedef struct {
      char virtual_ip4[INET_ADDRSTRLEN];         // IPv4虚拟地址
      char virtual_ip6[INET6_ADDRSTRLEN];        // IPv6虚拟地址
      char target_ip4[INET_ADDRSTRLEN + 6];      // IPv4目标地址（可带端口）
      char target_ip6[INET6_ADDRSTRLEN + 8];     // IPv6目标地址（可带端口）
  } HevConfigDnsForwarder;

  // CHN路由配置
  typedef struct {
      char *file_path;                            // CIDR文件路径
  } HevConfigChnroutes;

  // 智能代理配置
  typedef struct {
      int timeout_ms;                             // 超时时间（毫秒）
      int blocked_ip_expiry_minutes;              // 黑名单过期时间（分钟）
  } HevConfigSmartProxy;

  // Getter函数声明
  HevConfigDnsForwarder * hev_config_get_dns_forwarder(void);
  HevConfigChnroutes * hev_config_get_chnroutes(void);
  HevConfigSmartProxy * hev_config_get_smart_proxy(void);

  4.3 YAML解析实现

  在 hev-config.c 中添加：

  // 全局配置变量
  static HevConfigDnsForwarder dns_forwarder_config;
  static HevConfigChnroutes chnroutes_config;
  static HevConfigSmartProxy smart_proxy_config;

  // 解析dns-forwarder块
  static int
  hev_config_parse_dns_forwarder(yaml_document_t *doc, yaml_node_t *base)
  {
      yaml_node_pair_t *pair;

      memset(&dns_forwarder_config, 0, sizeof(dns_forwarder_config));

      for (pair = base->data.mapping.pairs.start;
           pair < base->data.mapping.pairs.top; pair++) {
          yaml_node_t *key = yaml_document_get_node(doc, pair->key);
          yaml_node_t *value = yaml_document_get_node(doc, pair->value);

          if (!key || !value)
              continue;

          if (strcmp((char *)key->data.scalar.value, "virtual-ip4") == 0) {
              strncpy(dns_forwarder_config.virtual_ip4,
                     (char *)value->data.scalar.value,
                     sizeof(dns_forwarder_config.virtual_ip4) - 1);
          } else if (strcmp((char *)key->data.scalar.value, "virtual-ip6") == 0) {
              strncpy(dns_forwarder_config.virtual_ip6,
                     (char *)value->data.scalar.value,
                     sizeof(dns_forwarder_config.virtual_ip6) - 1);
          } else if (strcmp((char *)key->data.scalar.value, "target-ip4") == 0) {
              strncpy(dns_forwarder_config.target_ip4,
                     (char *)value->data.scalar.value,
                     sizeof(dns_forwarder_config.target_ip4) - 1);
          } else if (strcmp((char *)key->data.scalar.value, "target-ip6") == 0) {
              strncpy(dns_forwarder_config.target_ip6,
                     (char *)value->data.scalar.value,
                     sizeof(dns_forwarder_config.target_ip6) - 1);
          }
      }

      return 0;
  }

  // 解析chnroutes块
  static int
  hev_config_parse_chnroutes(yaml_document_t *doc, yaml_node_t *base)
  {
      yaml_node_pair_t *pair;

      memset(&chnroutes_config, 0, sizeof(chnroutes_config));

      for (pair = base->data.mapping.pairs.start;
           pair < base->data.mapping.pairs.top; pair++) {
          yaml_node_t *key = yaml_document_get_node(doc, pair->key);
          yaml_node_t *value = yaml_document_get_node(doc, pair->value);

          if (!key || !value)
              continue;

          if (strcmp((char *)key->data.scalar.value, "file-path") == 0) {
              chnroutes_config.file_path = strdup((char *)value->data.scalar.value);
          }
      }

      return 0;
  }

  // 解析smart-proxy块
  static int
  hev_config_parse_smart_proxy(yaml_document_t *doc, yaml_node_t *base)
  {
      yaml_node_pair_t *pair;

      memset(&smart_proxy_config, 0, sizeof(smart_proxy_config));

      for (pair = base->data.mapping.pairs.start;
           pair < base->data.mapping.pairs.top; pair++) {
          yaml_node_t *key = yaml_document_get_node(doc, pair->key);
          yaml_node_t *value = yaml_document_get_node(doc, pair->value);

          if (!key || !value)
              continue;

          if (strcmp((char *)key->data.scalar.value, "timeout-ms") == 0) {
              smart_proxy_config.timeout_ms = atoi((char *)value->data.scalar.value);
          } else if (strcmp((char *)key->data.scalar.value,
  "blocked-ip-expiry-minutes") == 0) {
              smart_proxy_config.blocked_ip_expiry_minutes =
                  atoi((char *)value->data.scalar.value);
          }
      }

      return 0;
  }

  // Getter函数
  HevConfigDnsForwarder *
  hev_config_get_dns_forwarder(void)
  {
      return &dns_forwarder_config;
  }

  HevConfigChnroutes *
  hev_config_get_chnroutes(void)
  {
      return &chnroutes_config;
  }

  HevConfigSmartProxy *
  hev_config_get_smart_proxy(void)
  {
      return &smart_proxy_config;
  }

  在 hev_config_init_from_file() 主解析函数中添加：

  // 在解析主配置块时添加
  } else if (strcmp((char *)key->data.scalar.value, "dns-forwarder") == 0) {
      res = hev_config_parse_dns_forwarder(doc, value);
      if (res < 0)
          return -1;
  } else if (strcmp((char *)key->data.scalar.value, "chnroutes") == 0) {
      res = hev_config_parse_chnroutes(doc, value);
      if (res < 0)
          return -1;
  } else if (strcmp((char *)key->data.scalar.value, "smart-proxy") == 0) {
      res = hev_config_parse_smart_proxy(doc, value);
      if (res < 0)
          return -1;
  }

  在 hev_config_fini() 中释放内存：

  void
  hev_config_fini(void)
  {
      if (chnroutes_config.file_path) {
          free(chnroutes_config.file_path);
          chnroutes_config.file_path = NULL;
      }
      // ... 其他释放逻辑
  }

  ---
  五、集成流程调整

  5.1 主初始化流程（hev-main.c）

  在 hev_socks5_tunnel_main_inner() 中添加初始化调用：

  // 在 hev_socks5_tunnel_init() 之前
  res = hev_dns_forwarder_init();
  if (res < 0) {
      LOG_W("dns-forwarder init failed");
      // 不致命，继续
  }

  res = hev_chnroutes_init();
  if (res < 0) {
      LOG_W("chnroutes init failed");
      // 不致命，继续
  }

  res = hev_smart_proxy_init();
  if (res < 0) {
      LOG_W("smart-proxy init failed");
      // 不致命，继续
  }

  在 hev_socks5_tunnel_fini() 中添加清理调用：

  hev_smart_proxy_fini();
  hev_chnroutes_fini();
  hev_dns_forwarder_fini();

  5.2 UDP流量处理流程（hev-socks5-tunnel.c）

  修改 udp_recv_handler()：

  static void
  udp_recv_handler(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                   const ip_addr_t *addr, u16_t port)
  {
      int res;

      // 优先级1: DNS劫持转发
      res = hev_dns_forwarder_handle(pcb, p, addr, port);
      if (res == 1) {
          pbuf_free(p);
          return;  // 已处理
      }

      // 优先级2: mapdns（原有功能）
      if (hev_mapped_dns_enabled()) {
          res = hev_mapped_dns_handle(pcb, p, addr, port);
          if (res == 1) {
              pbuf_free(p);
              return;
          }
      }

      // 优先级3: chnroutes判断
      ip_addr_t *dst_ip = &pcb->local_ip;  // lwIP魔改：local_ip是真实目标
      int is_domestic = hev_chnroutes_is_domestic(dst_ip);

      if (is_domestic == 1) {
          // 国内IP，创建直连UDP会话
          create_direct_udp_session(pcb, p, addr, port);
          pbuf_free(p);
          return;
      }

      // 优先级4: 国外IP，走SOCKS5 UDP
      create_socks5_udp_session(pcb, p, addr, port);
      pbuf_free(p);
  }

  5.3 TCP流量处理流程（hev-socks5-tunnel.c）

  修改 tcp_accept_handler()：

  static err_t
  tcp_accept_handler(void *arg, struct tcp_pcb *pcb, err_t err)
  {
      ip_addr_t *dst_ip = &pcb->local_ip;    // lwIP魔改
      uint16_t dst_port = pcb->local_port;

      LOG_D("tcp accept: dst=%s:%u", ipaddr_ntoa(dst_ip), dst_port);

      // 步骤1: chnroutes判断
      int is_domestic = hev_chnroutes_is_domestic(dst_ip);

      if (is_domestic == 1) {
          // 国内IP，创建直连TCP会话
          LOG_I("tcp: domestic IP, direct connect");
          create_direct_tcp_session(pcb);
          return ERR_OK;
      }

      // 步骤2: 国外IP，smart-proxy尝试直连
      int direct_fd = hev_smart_proxy_try_direct(dst_ip, dst_port);

      if (direct_fd >= 0) {
          // 直连成功
          LOG_I("tcp: smart-proxy direct success");
          create_direct_tcp_session_with_fd(pcb, direct_fd);
          return ERR_OK;
      }

      // 步骤3: 回落到SOCKS5
      LOG_I("tcp: fallback to SOCKS5");
      create_socks5_tcp_session(pcb);

      return ERR_OK;
  }

  5.4 新增直连会话处理

  需要创建新的会话类型处理直连流量：

  新增文件：
  - src/hev-direct-session.h
  - src/hev-direct-session.c

  功能：
  - TCP直连：在lwIP PCB和本地socket之间双向splice流量
  - UDP直连：转发UDP数据包

  示例代码：
  // TCP直连会话创建
  void create_direct_tcp_session(struct tcp_pcb *pcb)
  {
      // 创建socket连接到目标
      // 使用 hev_task_io_socket_splice 双向转发
  }

  // TCP直连会话（已有socket）
  void create_direct_tcp_session_with_fd(struct tcp_pcb *pcb, int fd)
  {
      // 使用现有socket，直接splice
  }

  // UDP直连会话
  void create_direct_udp_session(struct udp_pcb *pcb, struct pbuf *p,
                                  const ip_addr_t *addr, u16_t port)
  {
      // 创建UDP socket，转发数据包
  }

  ---
  六、开发顺序和时间估算

  阶段1：配置解析 （1天）
  - 修改 hev-config.h/c，添加三个新功能的配置结构体
  - 实现YAML解析函数
  - 实现getter函数
  - 测试配置文件能正确解析（打印日志验证）

  阶段2：chnroutes模块 （2-3天）
  - 创建 hev-chnroutes.h/c 文件
  - 实现CIDR文件读取和解析（支持IPv4和IPv6）
  - 实现IPv4和IPv6分别存储和排序
  - 实现IPv4二分查找
  - 实现IPv6二分查找
  - 单元测试验证查找正确性（测试边界case）
  - 集成到主流程并测试

  阶段3：dns-forwarder模块 （2天）
  - 创建 hev-dns-forwarder.h/c 文件
  - 实现配置解析和初始化
  - 实现DNS流量检测逻辑（端口53 + IP匹配）
  - 实现IPv4 DNS转发和源地址伪装
  - 实现IPv6 DNS转发和源地址伪装
  - 集成到UDP流量处理流程
  - 测试DNS查询（使用nslookup/dig验证）

  阶段4：smart-proxy模块 （3-4天）
  - 创建 hev-smart-proxy.h/c 文件
  - 实现黑名单数据结构（红黑树，IPv4+IPv6混合）
  - 实现黑名单查询、添加、删除
  - 实现直连尝试逻辑（含超时控制）
  - 实现后台清理任务
  - 集成到TCP流量处理流程
  - 测试直连成功和超时场景

  阶段5：直连会话模块 （2天）
  - 创建 hev-direct-session.h/c 文件
  - 实现TCP直连会话（socket splice）
  - 实现UDP直连会话（数据包转发）
  - 集成到主流程
  - 测试流量转发正确性

  阶段6：整体集成和测试 （2-3天）
  - 修改主初始化/清理流程
  - 修改UDP流量处理流程（调用顺序：dns-forwarder → mapdns → chnroutes → socks5）
  - 修改TCP流量处理流程（调用顺序：chnroutes → smart-proxy → socks5）
  - 功能独立测试
    - DNS劫持功能（IPv4和IPv6）
    - 国内外分流功能（IPv4和IPv6）
    - 智能代理功能（直连成功、超时、黑名单）
  - 联合测试（多功能同时启用）
  - 性能测试（高并发场景）
  - 边界测试（配置错误、文件缺失、非法CIDR等）
  - 内存泄漏检查（valgrind）

  总计：12-15天

  ---
  七、IPv4/IPv6适配总结

  所有新增功能都必须完整支持IPv4和IPv6，具体体现：

  7.1 dns-forwarder

  - ✅ 配置支持：virtual-ip4、virtual-ip6、target-ip4、target-ip6
  - ✅ 独立处理：IPv4和IPv6分别匹配和转发
  - ✅ Socket创建：根据IP类型创建 AF_INET 或 AF_INET6 socket
  - ✅ 地址伪装：使用 udp_sendfrom() 分别伪装IPv4或IPv6源地址

  7.2 chnroutes

  - ✅ 文件解析：同时解析IPv4 CIDR（如 1.0.1.0/24）和IPv6 CIDR（如 2001::/32）
  - ✅ 独立存储：IPv4和IPv6分别存储在不同数组
  - ✅ 独立排序：IPv4和IPv6分别排序（关键：避免字节序混淆）
  - ✅ 独立查找：根据IP类型选择对应的二分查找函数
  - ✅ 掩码计算：IPv4用32位，IPv6用128位

  7.3 smart-proxy

  - ✅ 黑名单混合存储：红黑树中IPv4和IPv6可混合存储
  - ✅ 比较函数：先比较IP类型，再比较地址值
  - ✅ Socket创建：根据目标IP类型创建 AF_INET 或 AF_INET6 socket
  - ✅ 地址构造：sockaddr_in（IPv4）或 sockaddr_in6（IPv6）
  - ✅ 日志输出：使用 inet_ntop() 分别格式化IPv4和IPv6地址

  7.4 通用适配

  - ✅ 使用lwIP的 ip_addr_t 类型（支持IPv4和IPv6）
  - ✅ 使用 IP_IS_V4() 和 IP_IS_V6() 宏判断IP类型
  - ✅ 使用 ip_2_ip4() 和 ip_2_ip6() 宏提取具体IP
  - ✅ 使用 ip4_addr_cmp() 和 ip6_addr_cmp() 比较地址
  - ✅ 所有网络字节序操作使用 htonl()、ntohl() 等函数

  ---
  八、注意事项和风险点

  8.1 lwIP魔改API

  - ⚠️ 关键：udp_pcb->local_ip/local_port 是真实目标地址，remote_ip/remote_port
  是真实源地址
  - ⚠️ 必须使用 udp_sendfrom() 伪装源地址，不能用 udp_send()
  - ⚠️ TCP PCB同样，local_ip 是目标，remote_ip 是源

  8.2 网络字节序

  - ⚠️ 所有IP地址存储和比较都使用网络序
  - ⚠️ IPv4和IPv6绝对不能混合排序，必须分开处理
  - ⚠️ 使用 memcmp() 比较IPv6地址时，确保是网络序

  8.3 hev-task异步

  - ⚠️ 所有网络IO必须使用 hev_task_io_* 系列函数
  - ⚠️ 避免阻塞调用（如普通的 read()、write()）
  - ⚠️ 超时控制使用 hev_task_sleep() + hev_task_wakeup()

  8.4 内存管理

  - ⚠️ 使用 hev_malloc()、hev_free()
  - ⚠️ lwIP的 pbuf 使用 pbuf_alloc() 和 pbuf_free()
  - ⚠️ 配置字符串需要 strdup() 拷贝，并在fini时 free()
  - ⚠️ 红黑树节点删除后必须 hev_free()

  8.5 错误处理

  - ⚠️ 所有函数返回负值表示错误
  - ⚠️ 配置文件解析失败应有明确日志
  - ⚠️ CIDR解析失败不应导致程序崩溃，应跳过该行

  8.6 性能考虑

  - ⚠️ chnroutes二分查找时间复杂度必须是 O(log n)
  - ⚠️ smart-proxy黑名单使用红黑树，不能用线性表
  - ⚠️ 避免每次数据包都重新解析配置

  8.7 测试要点

  - ⚠️ 必须测试IPv4和IPv6两种场景
  - ⚠️ 必须测试边界case（空配置、非法CIDR、超大文件等）
  - ⚠️ 必须测试并发场景（多个连接同时处理）
  - ⚠️ 使用valgrind检测内存泄漏

  ---
  开发计划完成检查清单

  DNS劫持转发 (dns-forwarder)

  - 配置解析（IPv4 + IPv6）
  - DNS流量检测（端口53 + IP匹配）
  - IPv4 DNS转发
  - IPv6 DNS转发
  - 源地址伪装（udp_sendfrom）
  - 集成到UDP流量处理流程（优先级最高）
  - 测试（IPv4和IPv6 DNS查询）

  国内外分流 (chnroutes)

  - 配置解析
  - CIDR文件读取
  - IPv4 CIDR解析和存储
  - IPv6 CIDR解析和存储
  - IPv4数组排序
  - IPv6数组排序
  - IPv4二分查找
  - IPv6二分查找
  - 集成到TCP流量处理
  - 集成到UDP流量处理
  - 测试（国内/国外IP判断）

  智能代理 (smart-proxy)

  - 配置解析
  - 黑名单红黑树（IPv4 + IPv6混合）
  - 黑名单查询
  - 黑名单添加
  - 黑名单删除
  - 直连尝试（IPv4）
  - 直连尝试（IPv6）
  - 超时控制
  - 后台清理任务
  - 集成到TCP流量处理（仅TCP）
  - 测试（直连成功、超时、黑名单）

  直连会话

  - TCP直连会话（splice）
  - TCP直连会话（已有socket）
  - UDP直连会话
  - 测试（流量转发正确性）

  整体集成

  - 主初始化流程修改
  - 主清理流程修改
  - UDP流量处理流程（dns-forwarder → mapdns → chnroutes → socks5）
  - TCP流量处理流程（chnroutes → smart-proxy → socks5）
  - 整体功能测试
  - 性能测试
  - 内存泄漏检查

  ---
  好了，这就是完整详细的开发计划，涵盖了所有需求，包括：
  1. ✅ DNS劫持转发（dns-forwarder），支持IPv4和IPv6
  2. ✅ 国内外分流（chnroutes），支持IPv4和IPv6 CIDR
  3. ✅ 智能代理（smart-proxy），含黑名单机制，支持IPv4和IPv6
  4. ✅ 所有功能的IPv4/IPv6双栈适配
  5. ✅ 详细的数据结构、函数接口、实现逻辑
  6. ✅ 集成流程和调用顺序
  7. ✅ 开发时间估算和检查清单