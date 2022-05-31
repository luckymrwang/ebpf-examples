#!/bin/sh

set -e  # exit script in case of errors

ip addr show dev eth0

GW=$(ip route |grep default | cut -d' ' -f3)
echo ""
echo "-------------------------------------------------------------"
echo "Without XDP drop app installed, ping to $GW works ..."
ip link show dev eth0
ping -c 3 $GW
#echo "-------------------------------------------------------------"
#llvm-objdump -S xdp-drop.o
echo "-------------------------------------------------------------"
echo "Installing xdp-drop.o app on eth0 ..."
ip link set dev eth0 xdp obj /xdp-drop.o sec drop_icmp
ip link show dev eth0

echo "Now ping will fail ..."
ping -c 3 -W 1 $GW || echo "Good. ping failed"

echo ""
echo "but apt-get update still works ..."
apt-get -q update
echo "-------------------------------------------------------------"
echo "Uninstalling xdp-drop app ..."
ip link set dev eth0 xdp off

echo "Now ping works again ..."
ping -c 3 $GW

echo ""
echo "it worked!"
exit 0 
