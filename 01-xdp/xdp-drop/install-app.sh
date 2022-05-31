#!/bin/sh
DEVICE=$1
if [ -z "$DEVICE" ]; then
  echo "Usage: $0 <interface>"
  exit 1
fi

echo "removing first any existing xdp object ..."
sudo ip link set dev $DEVICE xdp off
sudo ip link set dev $DEVICE xdp obj xdp-drop.o sec drop_icmp
sudo ip link show dev $DEVICE
