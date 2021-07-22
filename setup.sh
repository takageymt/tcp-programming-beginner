#!/bin/bash

ip netns add ns1
ip netns add ns2

ip link add ns1-eth type veth peer name ns2-eth

ip link set ns1-eth netns ns1 up
ip link set ns2-eth netns ns2 up

ip netns exec ns1 ip link set lo up
ip netns exec ns2 ip link set lo up

ip netns exec ns1 ip addr add 172.16.0.1/24 dev ns1-eth
ip netns exec ns2 ip addr add 172.16.0.2/24 dev ns2-eth

# ip netns exec ns1 ip addr add 127.0.0.1/8 dev lo
# ip netns exec ns2 ip addr add 127.0.0.1/8 dev lo

ip netns exec ns1 ethtool -K ns1-eth tx off
ip netns exec ns2 ethtool -K ns2-eth tx off

ip netns exec ns1 iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
ip netns exec ns2 iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
