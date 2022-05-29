FROM ubuntu:20.04 as build

RUN export DEBIAN_FRONTEND=noninteractive && apt-get update \
  && apt-get install -y clang llvm 

COPY *.c /
RUN find /usr -name types.h
RUN clang -g -c -O2 -target bpf -I/usr/include/x86_64-linux-gnu/ -c xdp-drop.c -o xdp-drop.o \
  && objdump -t xdp-drop.o && llvm-objdump -S xdp-drop.o


FROM ubuntu:20.04

RUN export DEBIAN_FRONTEND=noninteractive \
  && apt-get update && apt-get install -y iproute2 iputils-ping

COPY --from=build /xdp-drop.o /
COPY /entrypoint.sh /

ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
