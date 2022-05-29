# 简介

本文展示如何编写简单的 BPF 程序做 socket level 重定向（redirection）。对于源和目的端都在同一台机器的应用来说，这样可以绕过整个 TCP/IP 协议栈，直接将数据发送到 socket 对端。效果如右下图（直接从 Cilium 分享截图，所以其中 Cilium 字样，但本文不需要 Cilium）

![image](../images/sock-redir.png)

实现这个功能依赖两个东西：

1. sockmap：这是一个存储 socket 信息的映射表。作用：

    - 一段 BPF 程序监听所有的内核 socket 事件，并将新建的 socket 记录到这个 map；
    - 另一段 BPF 程序拦截所有 sendmsg 系统调用，然后去 map 里查找 socket 对端，之后 调用 BPF 函数绕过 TCP/IP 协议栈，直接将数据发送到对端的 socket queue。

2. cgroups：指定要监听哪个范围内的 sockets 事件，进而决定了稍后要对哪些 socket 做重定向。

    - sockmap 需要关联到某个 cgroup，然后这个 cgroup 内的所有 socket 就都会执行加载的 BPF 程序。

运行本文中的例子一台主机就够了，非常适合 BPF 练手。本文所用的[完整代码](../03-sockops/ebpf-sockops/)。

# 引言
## BPF 基础

通常情况下，eBPF 程序由两部分构成：

1. 内核空间部分：内核事件触发执行，例如网卡收到一个包、系统调用创建了一个 shell 进程等等；
2. 用户空间部分：通过某种共享数据的方式（例如 BPF maps）来读取内核部分产生的数据；


本文主要关注内核部分。内核支持不同类型的 eBPF 程序，它们各自可以 attach 到不同的 hook 点，如下图所示：

![image](../images/bpf-kernel-hooks.png)

当内核中触发了与这些 hook 相关的事件（例如，发生 setsockopt()系统调用）时， attach 到这里的 BPF 程序就会执行。

用户侧需要用到的所有 BPF 类型都定义在 UAPI [bpf.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h)。 本文将主要关注下面两种能拦截到 socket 操作（例如 TCP connect、sendmsg 等）的类型：

- BPF_PROG_TYPE_SOCK_OPS：socket operations 事件触发执行。
- BPF_PROG_TYPE_SK_MSG：sendmsg() 系统调用触发执行。

本文将

- 用 C 编写 eBPF 代码
- 用 LLVM Clang 前端来生成 ELF bytecode
- 用 [bpftool](https://manpages.ubuntu.com/manpages/focal/man8/bpftool-prog.8.html) 将代码加载到内核（以及从内核卸载）

## 本文 BPF 程序总体设计

首先创建一个全局的映射表（map）来记录所有的 socket 信息。基于这个 sockmap，编写两段 BPF 程序分别完成以下功能：

- 程序一：拦截所有 TCP connection 事件，然后将 socket 信息存储到这个 map；
- 程序二：拦截所有 sendmsg() 系统调用，然后从 map 中查 询这个socket 信息，之后直接将数据重定向到对端。

# BPF 程序一：监听 socket 事件，

## 监听 socket 事件

程序功能：

1. 系统中有 socket 操作时（例如 connection establishment、tcp retransmit 等），触发执行；
    - 指定加载位置来实现：__section("sockops")
2. 执行逻辑：提取 socket 信息，并以 key & value 形式存储到 sockmap。

```c++
__section("sockops") // 加载到 ELF 中的 `sockops` 区域，有 socket operations 时触发执行
int bpf_sockmap(struct bpf_sock_ops *skops)
{
	__u32 family, op;

	family = skops->family;
	op = skops->op;

	// printk("<<< op %d, port = %d --> %d\n", op, skops->local_port, skops->remote_port);
	switch (op)
	{
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: // 被动建连
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:  // 主动建连
		if (family == AF_INET6)
			bpf_sock_ops_ipv6(skops); // 将 socket 信息记录到到 sockmap
		else if (family == AF_INET)
			bpf_sock_ops_ipv4(skops); // 将 socket 信息记录到到 sockmap
		break;
	default:
		break;
	}
	return 0;
}
```

对于两端都在本节点的 socket 来说，这段代码会执行两次：

- 源端发送 SYN 时会产生一个事件，命中 case 2
- 目的端发送 SYN+ACK 时会产生一个事件，命中 case 1

因此对于每一个成功建连的 socket，sockmap 中会有两条记录（key 不同）。

提取 socket 信息以存储到 sockmap 是由函数 `bpf_sock_ops_ipv4()` 完成的，接下来看下它的实现。

## 将 socket 信息写入 sockmap

```c++
static inline void bpf_sock_ops_ipv4(struct bpf_sock_ops *skops)
{
	struct sock_key key = {};
	sk_extract4_key(skops, &key);

	int ret = sock_hash_update(skops, &sock_ops_map, &key, BPF_NOEXIST);
	if (ret != 0)
		printk("*** FAILED %d ***\n", ret);

	printk("<<< ipv4 op = %d, port %d --> %d\n", skops->op, key.sport, bpf_ntohl(key.dport));
}
```

三个步骤：

1. 调用 `extract_key4_from_ops()` 从 `struct bpf_sock_ops *skops`（socket metadata）中提取 key；
2. 调用 `sock_hash_update()` 将 key:value 写入全局的 `sockmap sock_ops_map`，这 个变量定义在我们的头文件中。
3. 打印一行日志，方面我们测试用，后面会看到效果。

### 从 socket metadata 中提取 sockmap key

map 的类型可以是：

- BPF_MAP_TYPE_SOCKMAP
- BPF_MAP_TYPE_SOCKHASH

本文用的是第二种，sockmap 定义如下，

```c++
struct bpf_map_def __section_maps sock_ops_map = {
	.type           = BPF_MAP_TYPE_SOCKHASH,
	.key_size       = sizeof(struct sock_key),
	.value_size     = sizeof(int),  // 存储 socket
	.max_entries    = 65535,
	.map_flags      = 0,
};
```

key 定义如下：

```c
struct sock_key {
	union {
		struct {
			__u32		sip4; // 源 IPv4
			__u32		pad1;
			__u32		pad2;
			__u32		pad3;
		};
		union v6addr	sip6; // 源 IPv6
	};
	union {
		struct {
			__u32		dip4; // 目的 IPv4
			__u32		pad4;
			__u32		pad5;
			__u32		pad6;
		};
		union v6addr	dip6; // 目的 IPv6
	};
	__u8 family;              // 协议类型
	__u8 pad7;
	__u16 pad8;
	__u32 sport;              // 源端口
	__u32 dport;              // 目的端口
} __attribute__((packed));
```

下面是提取 key 的实现，非常简单：

```c++
static inline void sk_extract4_key(struct bpf_sock_ops *ops, struct sock_key *key)
{
    // keep ip and port in network byte order
	key->dip4 = ops->remote_ip4;
	key->sip4 = ops->local_ip4;
	key->family = 1;

    // local_port is in host byte order, and remote_port is in network byte order
	key->sport = (bpf_htonl(ops->local_port) >> 16);
	key->dport = ops->remote_port >> 16;
}
```

### 插入 sockmap

`sock_hash_update()` 将 socket 信息写入到 sockmap，这个函数是我们定义的一个宏，会展开成内核提供的一个 hash update 函数，不再详细展开。

## 小结

至此，第一段代码就完成了，它能确保我们拦截到 socket 建连事件，并将 socket 信息写入一个全局的映射表（sockmap）。

# BPF 程序二：拦截 sendmsg 系统调用，socket 重定向

第二段 BPF 程序的功能：

1. 拦截所有的 sendmsg 系统调用，从消息中提取 key；
2. 根据 key 查询 sockmap，找到这个 socket 的对端，然后绕过 TCP/IP 协议栈，直接将数据重定向过去。

要完成这个功能，需要：

1. 在 socket 发起 sendmsg 系统调用时触发执行，

    - 指定加载位置来实现：__section("sk_msg")

2. 关联到前面已经创建好的 sockmap，因为要去里面查询 socket 的对端信息。

    - 通过将 sockmap attach 到 BPF 程序实现：map 中的所有 socket 都会继承这段程序， 因此其中的任何 socket 触发 sendmsg 系统调用时，都会执行到这段代码。

## 拦截 sendmsg 系统调用

```c++
__section("sk_msg") // 加载目标文件（ELF ）中的 `sk_msg` section，`sendmsg` 系统调用时触发执行
int bpf_redir(struct sk_msg_md *msg)
{
	__u64 flags = BPF_F_INGRESS;
	struct sock_key key = {};

	sk_msg_extract4_key(msg, &key);

	// int len1 = (__u64)msg->data_end - (__u64)msg->data;
	// printk("<<< redir_proxy port %d --> %d (%d)\n", key.sport, key.dport, len1);
	msg_redirect_hash(msg, &sock_ops_map, &key, flags);

	return SK_PASS;
}
```

当 attach 了这段程序的 socket 上有 sendmsg 系统调用时，内核就会执行这段代码。它会：

1. 从 socket metadata 中提取 key，
2. 调用 `bpf_socket_redirect_hash()` 寻找对应的 socket，并根据 flag（`BPF_F_INGRESS`）， 将数据重定向到 socket 的某个 queue。

## 从 socket message 中提取 key

```c
static inline void sk_msg_extract4_key(struct sk_msg_md *msg,struct sock_key *key)
{
	key->sip4 = msg->remote_ip4;
	key->dip4 = msg->local_ip4;
	key->family = 1;

	key->dport = (bpf_htonl(msg->local_port) >> 16);
	key->sport = msg->remote_port >> 16;
}
```

## Socket 重定向

`msg_redirect_hash()` 也是我们定义的一个宏，最终调用的是 BPF 内置的辅助函数。

> 最终需要用的其实是内核辅助函数 `bpf_msg_redirect_hash()`，但后者无法直接访问， 只能通过 UAPI [linux/bpf.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h) 预定义的 `BPF_FUNC_msg_redirect_hash` 来访问，否则校验器无法通过。

`msg_redirect_hash(msg, &sock_ops_map, &key, BPF_F_INGRESS)` 几个参数：

- `struct sk_msg_md *msg`：用户可访问的待发送数据的元信息（metadata）
- `&sock_ops_map`：这个 BPF 程序 attach 到的 sockhash map
- `key`：在 map 中索引用的 key
- `BPF_F_INGRESS`：放到对端的哪个 queue（rx 还是 tx）

# 编译、加载、运行

`bpftool` 是一个用户空间工具，能用来加载 BPF 代码到内核、创建和更新 maps，以及收集 BPF 程序和 maps 信息。其源代码位于 Linux 内核树中：[tools/bpf/bpftool](https://github.com/torvalds/linux/tree/master/tools/bpf/bpftool)。

## 编译


用 `LLVM Clang frontend` 来编译前面两段程序，生成目标代码（object code）：

```sh
$ clang -O2 -g -target bpf -c bpf_sockops.c -o bpf_sockops.o
$ clang -O2 -g -target bpf -c bpf_redir.c -o bpf_redir.o
```

## 加载（load）和 attach sockops 程序

### 加载到内核

```sh
$ sudo bpftool prog load bpf_sockops.o /sys/fs/bpf/bpf_sockops type sockops
```

- 这条命令将 object 代码加载到内核（但还没 attach 到 hook 点）
- 加载之后的代码会 pin 到一个 BPF [虚拟文件系统](https://lwn.net/Articles/664688/) 来持久存储，这样就能获得一个指向这个程序的文件句柄（handle）供稍后使用。
- bpftool 会在 ELF 目标文件中创建我们声明的 sockmap（`sock_ops_map` 变量，定 义在头文件中）。

### Attach 到 cgroups

```sh
$ sudo bpftool cgroup attach /sys/fs/cgroup/unified/ sock_ops pinned /sys/fs/bpf/bpf_sockops
```

- 这条命令将加载之后的 `sock_ops` 程序 attach 到指定的 cgroup，
- 这个 cgroup 内的所有进程的所有 sockets，都将会应用这段程序。如果使用的是 [cgroupv2](http://man7.org/conf/osseu2018/cgroups_v2-OSS.eu-2018-Kerrisk.pdf) 时，systemd 会在 `/sys/fs/cgroup/unified` 自动创建一个 mount 点。

下面的命令说明 /sys/fs/cgroup/unified/ 确实是 cgroupv2 挂载点：

```sh
$ mount | grep cgroup
cgroup2 on /sys/fs/cgroup/unified type cgroup2 (rw,nosuid,nodev,noexec,relatime,nsdelegate)
...
```

如果想自定义 cgroupv2 挂载点，可参考 [Cracking kubernetes node proxy (aka kube-proxy)](https://arthurchiao.art/blog/cracking-k8s-node-proxy/)，其中的第五种方式。

### 查看 map ID

至此，目标代码已经加载（load）和附着（attach）到 hook 点了，接下来查看 sock_ops 程序所使用的 map ID，因为后面要用这个 ID 来 attach sk_msg 程序：

```sh
MAP_ID=$(sudo bpftool prog show pinned /sys/fs/bpf/bpf_sockops | grep -o -E 'map_ids [0-9]+'| cut -d '' -f2-)
$ sudo bpftool map pin id $MAP_ID /sys/fs/bpf/sock_ops_map
```

## 加载和 attach sk_msg 程序

### 加载到内核

```sh
$ sudo bpftool prog load bpf_redir.o /sys/fs/bpf/bpf_redir \
    map name sock_ops_map \
    pinned /sys/fs/bpf/sock_ops_map
```

- 将程序加载到内核
- 将程序 pin 到 BPF 文件系统的 `/sys/fs/bpf/bpf_redir` 位置
- 重用已有的 sockmap，指定了 sockmap 的名字为 `sock_ops_map` 并且文件路径为 `/sys/fs/bpf/sock_ops_map`

### Attach

将已经加载到内核的 sk_msg 程序 attach 到 sockmap，

```sh
$ sudo bpftool prog attach pinned /sys/fs/bpf/bpf_redir msg_verdict pinned /sys/fs/bpf/sock_ops_map
```

从现在开始，sockmap 内的所有 socket 在 sendmsg 时都将触发执行这段 BPF 代码。

### 查看

查看系统中已经加载的所有 BPF 程序：

```sh
$ sudo bpftool prog show
...
38: sock_ops  name bpf_sockmap  tag d9aec8c151998c9c  gpl
        loaded_at 2021-01-28T22:52:06+0800  uid 0
        xlated 672B  jited 388B  memlock 4096B  map_ids 13
        btf_id 20
43: sk_msg  name bpf_redir  tag 550f6d3cfcae2157  gpl
        loaded_at 2021-01-28T22:52:06+0800  uid 0
        xlated 224B  jited 156B  memlock 4096B  map_ids 13
        btf_id 24
```

查看系统中所有的 map，以及 map 详情：

```sh
$ sudo bpftool map show
13: sockhash  name sock_ops_map  flags 0x0
        key 24B  value 4B  max_entries 65535  memlock 5767168B

# -p/--pretty：人类友好格式打印
$ sudo bpftool -p map show id 13
{
    "id": 13,
    "type": "sockhash",
    "name": "sock_ops_map",
    "flags": 0,
    "bytes_key": 24,
    "bytes_value": 4,
    "max_entries": 65535,
    "bytes_memlock": 5767168,
    "frozen": 0
}
```

打印 map 内的所有内容：

```sh
$ sudo bpftool -p map dump id 13
[{
  "key":
["0x7f", "0x00", "0x00", "0x01", "0x7f", "0x00", "0x00", "0x01", "0x01", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00", "0x03", "0xe8", "0x00", "0x00", "0xa1", "0x86", "0x00", "0x00"
  ],
  "value": {
   "error":"Operation not supported"
  }
 },{
  "key":
["0x7f", "0x00", "0x00", "0x01", "0x7f", "0x00", "0x00", "0x01", "0x01", "0x00", "0x00", "0x00", "0x00", "0x00","0x00", "0x00", "0xa1", "0x86", "0x00", "0x00", "0x03", "0xe8", "0x00", "0x00"
  ],
  "value": {
   "error":"Operation not supported"
  }
 }
]
```

其中的 error 是因为 sockhash map 不支持从用户空间获取 map 内的值（values）。

## 测试

在一个窗口中启动 socat 作为服务端，监听在 1000 端口：

```sh
# start a TCP listener at port 1000, and echo back the received data
$ sudo socat TCP4-LISTEN:1000,fork exec:cat
```

另一个窗口用 `nc` 作为客户端来访问服务端，建立 socket：

```sh
# connect to the local TCP listener at port 1000
$ nc localhost 1000
```

观察我们在 BPF 代码中打印的日志：

```sh
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
    nc-13227   [002] .... 105048.340802: 0: sockmap: op 4, port 50932 --> 1001
    nc-13227   [002] ..s1 105048.340811: 0: sockmap: op 5, port 1001 --> 50932
```

## 清理

从 sockmap 中 detach 第二段 BPF 程序，并将其从 BPF 文件系统中 unpin：

```sh
$ sudo bpftool prog detach pinned /sys/fs/bpf/bpf_redir msg_verdict pinned /sys/fs/bpf/sock_ops_map
$ sudo rm /sys/fs/bpf/bpf_redir
```

当 BPF 文件系统中某个文件的 [reference count](https://facebookmicrosites.github.io/bpf/blog/2018/08/31/object-lifetime.html) 为零时，该就会自动从 BPF 文件系统中删除。

同理，从 cgroups 中 detach 第一段 BPF 程序，并将其从 BPF 文件系统中 unpin：

```sh
$ sudo bpftool cgroup detach /sys/fs/cgroup/unified/ sock_ops pinned /sys/fs/bpf/bpf_sockops
$ sudo rm /sys/fs/bpf/bpf_sockops
```

最后删除 sockmaps：

```sh
$ sudo rm /sys/fs/bpf/sock_ops_map
```












