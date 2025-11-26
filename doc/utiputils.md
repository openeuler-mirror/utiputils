# iputils 工具文档

## utping(8) - 向网络主机发送ICMP ECHO_REQUEST

### 名称
`utping` - 向网络主机发送ICMP ECHO_REQUEST

### 描述
`utping`使用ICMP协议的强制ECHO_REQUEST数据报来从主机或网关获取ICMP ECHO_RESPONSE。支持IPv4和IPv6。

### 选项
(完整选项列表与之前相同，此处省略以节省空间...)

### IPv6链路本地目标
对于IPv6链路本地地址，必须指定输出接口：


### ICMP数据包详情
- IP头部：20字节
- ICMP头部：8字节
- 默认数据大小：56字节

### 常见问题
- **重复数据包**：通常由不适当的链路级重传引起
- **损坏数据包**：可能表明路径上的硬件问题
- **TTL值**：表示数据包在被丢弃前可通过的最大路由器数量

---

## utarping(8) - 向邻居主机发送ARP请求

### 名称
`utarping` - 向邻居主机发送ARP请求


### 描述
`utarping`使用ARP协议来探测局域网中的主机，仅支持IPv4。

### 选项
- `-A`：使用ARP REPLY而非ARP REQUEST
- `-b`：仅发送MAC级广播
- `-c count`：发送指定数量的ARP请求后停止
- `-I interface`：指定网络接口

---

## utclockdiff(8) - 测量主机间的时钟差异

### 名称
`utclockdiff` - 测量主机间的时钟差异


### 描述
测量本地主机与目标主机之间的时钟差异，精度为1毫秒。

### 选项
- `-o`：使用IP TIMESTAMP与ICMP ECHO
- `-o1`：使用三term IP TIMESTAMP
- `--time-format`：设置时间输出格式(ctime或iso)

---

## uttracepath(8) - 追踪网络路径并发现MTU

### 名称
`uttracepath` - 追踪网络路径并发现MTU

### 描述
追踪到目标的网络路径并发现路径MTU，类似于traceroute但不需要root权限。

### 选项
- `-4`：仅使用IPv4
- `-6`：仅使用IPv6
- `-n`：不解析主机名
- `-l pktlen`：设置初始数据包长度

---

## 通用信息

### 安全要求
大多数工具需要CAP_NET_RAW能力才能执行。

### 可用性
这些工具都是`iputils`软件包的一部分。

### 历史
- `ping`最早出现在4.3BSD中
- `ping6`已合并到`ping`中
- 其他工具由Alexey Kuznetsov等人开发

### 参见
- `ip(8)`
- `ss(8)`
- `traceroute(8)`

