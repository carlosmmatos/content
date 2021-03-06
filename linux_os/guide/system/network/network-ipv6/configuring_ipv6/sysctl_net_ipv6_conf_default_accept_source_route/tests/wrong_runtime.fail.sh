#!/bin/bash

# Clean sysctl config directories
rm -rf /usr/lib/sysctl.d/* /run/sysctl.d/* /etc/sysctl.d/*

sed -i "/net.ipv6.conf.default.accept_source_route/d" /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
# Setting wrong runtime value
sysctl -w net.ipv6.conf.default.accept_source_route=1
