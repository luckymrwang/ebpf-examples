# xdp-drop-test in a Container

Started to read up on eBPF and XDP and wanted to try this out from within a 
Docker container, after having read about XDP also support veth interfaces.

Please check the [BFP and XDP Reference Guide](https://docs.cilium.io/en/v1.6/bpf/#bpf-and-xdp-reference-guide) for a great (but very deep) introduction.

A great intro into XDP on what it can and can't do, watch David S. Millers presentation
[Keynote by Netdev Maintainer David S. Miller given at Netdev conf 2.1 in Montreal on April 7th 2018](http://youtu.be/8Cxg7mpVIWw).

## Docker example

I copied and minimally modified an example code from the blog post
[Load XDP programs using the ip (iproute2) command](https://link.medium.com/LNpGdu4td3)
and build it within a Docker container, which, when executed, blocks ICMP packets coming
into the container over eth0, with verification other traffic still works. Then the XDP
code is removed and the ICMP packets reach the container again.

Build and run the example with running `make` or in separate steps:

```
$ make build
```

An example output of the build stage can be found in [build.log.txt](build.log.txt).
Then run the example with

```
$ make run

docker build -t xdp-drop-test .
Sending build context to Docker daemon  118.8kB
Step 1/9 : FROM ubuntu:18.04 as build
 ---> a2a15febcdf3
Step 2/9 : RUN export DEBIAN_FRONTEND=noninteractive   && apt-get update && apt-get install -y make gcc libssl-dev bc   libelf-dev libcap-dev clang gcc-multilib llvm libncurses5-dev git   pkg-config libmnl-dev bison flex graphviz
 ---> Using cache
 ---> 28d856e2ef1e
Step 3/9 : COPY *.c /
 ---> Using cache
 ---> 7fc05d3ca2d6
Step 4/9 : RUN clang -g -c -O2 -target bpf -c xdp-drop.c -o xdp-drop.o   && objdump -t xdp-drop.o
 ---> Using cache
 ---> 2fa46811e204
Step 5/9 : FROM ubuntu:18.04
 ---> a2a15febcdf3
Step 6/9 : RUN export DEBIAN_FRONTEND=noninteractive   && apt-get update && apt-get install -y iproute2 iputils-ping
 ---> Using cache
 ---> 1d430ccbc117
Step 7/9 : COPY --from=build /xdp-drop.o /
 ---> Using cache
 ---> a7f01d816001
Step 8/9 : COPY /entrypoint.sh /
 ---> Using cache
 ---> ebf527ab74e8
Step 9/9 : ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
 ---> Using cache
 ---> fb68eddd8b1e
Successfully built fb68eddd8b1e
Successfully tagged xdp-drop-test:latest
docker run --privileged -ti --rm --name xdp-drop-test xdp-drop-test
84: eth0@if85: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever

-------------------------------------------------------------
Without XDP drop app installed, ping to 172.17.0.1 works ...
84: eth0@if85: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default 
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
PING 172.17.0.1 (172.17.0.1) 56(84) bytes of data.
64 bytes from 172.17.0.1: icmp_seq=1 ttl=64 time=0.055 ms
64 bytes from 172.17.0.1: icmp_seq=2 ttl=64 time=0.090 ms
64 bytes from 172.17.0.1: icmp_seq=3 ttl=64 time=0.088 ms

--- 172.17.0.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2025ms
rtt min/avg/max/mdev = 0.055/0.077/0.090/0.019 ms
-------------------------------------------------------------
Installing xdp-drop.o app on eth0 ...
84: eth0@if85: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdp qdisc noqueue state UP mode DEFAULT group default 
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    prog/xdp id 21 tag 2e4d04fb1c2c6dc6 jited 
Now ping will fail ...
PING 172.17.0.1 (172.17.0.1) 56(84) bytes of data.

--- 172.17.0.1 ping statistics ---
3 packets transmitted, 0 received, 100% packet loss, time 2037ms

Good. ping failed

but apt-get update still works ...
Hit:1 http://archive.ubuntu.com/ubuntu bionic InRelease
Hit:2 http://archive.ubuntu.com/ubuntu bionic-updates InRelease
Hit:3 http://archive.ubuntu.com/ubuntu bionic-backports InRelease
Hit:4 http://security.ubuntu.com/ubuntu bionic-security InRelease
Reading package lists...
-------------------------------------------------------------
Uninstalling xdp-drop app ...
Now ping works again ...
PING 172.17.0.1 (172.17.0.1) 56(84) bytes of data.
64 bytes from 172.17.0.1: icmp_seq=1 ttl=64 time=0.023 ms
64 bytes from 172.17.0.1: icmp_seq=2 ttl=64 time=0.037 ms
64 bytes from 172.17.0.1: icmp_seq=3 ttl=64 time=0.093 ms

--- 172.17.0.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2049ms
rtt min/avg/max/mdev = 0.023/0.051/0.093/0.030 ms

it worked!
```

## Read the byte code ...

You can use llvm-objdump to look at the generated BPF bytecode, in line with the C code (requires recompiling it with -g):

```
$ make objdump
clang -Wall -g -target bpf -c xdp-drop.c -o xdp-drop.o
llvm-objdump -S xdp-drop.o

xdp-drop.o:     file format ELF64-BPF


Disassembly of section drop_icmp:

0000000000000000 xdp_drop:
; int xdp_drop(struct xdp_md *ctx) {
       0:       7b 1a f0 ff 00 00 00 00 *(u64 *)(r10 - 16) = r1
       1:       b7 01 00 00 00 00 00 00 r1 = 0
;   int ipsize = 0;
       2:       63 1a ec ff 00 00 00 00 *(u32 *)(r10 - 20) = r1
;   void *data = (void *)(long)ctx->data;
       3:       79 a1 f0 ff 00 00 00 00 r1 = *(u64 *)(r10 - 16)
       4:       61 11 00 00 00 00 00 00 r1 = *(u32 *)(r1 + 0)
       5:       7b 1a e0 ff 00 00 00 00 *(u64 *)(r10 - 32) = r1
;   void *data_end = (void *)(long)ctx->data_end;

 . . .
```


## Using Ubuntu 20.04

Upgraded Dockerfile from Ubuntu 18.04 ot 20.04, which leads now to a warning issued when loading the XDP code via iproute2. Demo still works fine. Seems to be an issue
with iproute2, according to this reported issue: 
https://github.com/xdp-project/xdp-tutorial/issues/38#issuecomment-584366781


## Trying this out on a RaspberryPi

```
i@neo:~/git/xdp-drop-test $ lsb_release -a
No LSB modules are available.
Distributor ID: Raspbian
Description:    Raspbian GNU/Linux 10 (buster)
Release:        10
Codename:       buster
```

```
$ make objdump
# include arm-linux-gnueabhif helps compiling (and using) it on RaspberryPi without the need for gcc-multilib ;)
clang -Wall -O2 -c -g -target bpf -I/usr/include/arm-linux-gnueabihf -c xdp-drop.c -o xdp-drop.o
llvm-objdump -S xdp-drop.o

xdp-drop.o:     file format ELF64-BPF

Disassembly of section drop_icmp:
drop_icmp_func:
; int drop_icmp_func(struct xdp_md *ctx) {
       0:       b7 00 00 00 02 00 00 00         r0 = 2
; void *data_end = (void *)(long)ctx->data_end;
       1:       61 12 04 00 00 00 00 00         r2 = *(u32 *)(r1 + 4)
; void *data = (void *)(long)ctx->data;
       2:       61 11 00 00 00 00 00 00         r1 = *(u32 *)(r1 + 0)
; if (data + ipsize > data_end) {
       3:       bf 13 00 00 00 00 00 00         r3 = r1
       4:       07 03 00 00 22 00 00 00         r3 += 34
       5:       2d 23 04 00 00 00 00 00         if r3 > r2 goto +4 <LBB0_3>
; if (ip->protocol == IPPROTO_ICMP) {
       6:       71 11 17 00 00 00 00 00         r1 = *(u8 *)(r1 + 23)
       7:       b7 00 00 00 01 00 00 00         r0 = 1
; return XDP_DROP;
       8:       15 01 01 00 01 00 00 00         if r1 == 1 goto +1 <LBB0_3>
       9:       b7 00 00 00 02 00 00 00         r0 = 2

LBB0_3:
; }
      10:       95 00 00 00 00 00 00 00         exit
pi@neo:~/git/xdp-drop-test $ ./install-app.sh wlan0
removing first any existing xdp object ...
4: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdpgeneric qdisc pfifo_fast state UP mode DORMANT group default qlen 1000                       
    link/ether dc:a6:32:6b:50:cb brd ff:ff:ff:ff:ff:ff
    prog/xdp id 42 tag 2e4d04fb1c2c6dc6
pi@neo:~/git/xdp-drop-test $ ping -c3 1.1.1.1
PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.

--- 1.1.1.1 ping statistics ---
3 packets transmitted, 0 received, 100% packet loss, time 49ms

# yeah!! ping failed.

pi@neo:~/git/xdp-drop-test $ ./remove-app.sh wlan0
removing existing xdp object ...
4: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DORMANT group default qlen 1000                                  
    link/ether dc:a6:32:6b:50:cb brd ff:ff:ff:ff:ff:ff
pi@neo:~/git/xdp-drop-test $ ping -c3 1.1.1.1
PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
64 bytes from 1.1.1.1: icmp_seq=1 ttl=56 time=3.85 ms
64 bytes from 1.1.1.1: icmp_seq=2 ttl=56 time=2.35 ms
64 bytes from 1.1.1.1: icmp_seq=3 ttl=56 time=2.31 ms

--- 1.1.1.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 5ms
rtt min/avg/max/mdev = 2.305/2.835/3.854/0.722 ms
```

## References

- [BPF and XDP Reference Guide](https://docs.cilium.io/en/v1.6/bpf/#bpf-and-xdp-reference-guide)
- [Load XDP programs using the ip (iproute2) command](https://link.medium.com/LNpGdu4td3)
- [AF_XDP kernel doc](https://www.kernel.org/doc/html/v5.3/networking/af_xdp.html)
- [xdp-tutorial](https://github.com/xdp-project/xdp-tutorial)
- [Fast Packet Processing with eBPF and XDP: Concepts, Code, Challenges, and Applications](https://www.researchgate.net/publication/339084847_Fast_Packet_Processing_with_eBPF_and_XDP_Concepts_Code_Challenges_and_Applications)
- [Apache-licensed library for executing eBPF programs](https://github.com/iovisor/ubpf)
- [The eXpress data path: fast programmable packet processing in the operating system kernel](https://dl.acm.org/doi/10.1145/3281411.3281443)
- [The power of XDP, blog post with xdping example](https://blogs.oracle.com/linux/the-power-of-xdp)
- [A practical introduction to XDP, LPC Vancouver 2018](https://linuxplumbersconf.org/event/2/contributions/71/attachments/17/9/presentation-lpc2018-xdp-tutorial.pdf)
