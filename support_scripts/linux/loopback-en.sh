#!/bin/bash
# Allow Multicast IP on the enp0s6 interface and route it there instead of to the wired interface
sudo ifconfig lo -multicast
sudo ifconfig enp0s5 -multicast
sudo ifconfig enp0s6 multicast
sudo route del -net 224.0.0.0 netmask 240.0.0.0 dev lo
sudo route add -net 224.0.0.0 netmask 240.0.0.0 dev enp0s6

