package main

import "net"

var (
	_, privateNet8, _  = net.ParseCIDR("10.0.0.0/8")
	_, privateNet12, _ = net.ParseCIDR("172.16.0.0/12")
	_, privateNet16, _ = net.ParseCIDR("192.168.0.0/16")
)
