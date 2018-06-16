package main

import (
	"net"
	"fmt"
	"log"
)

func Dump(data... interface{}) {
	if *flagSilent {
		return
	}
	log.Println(data...)
}

func Log(f string, data... interface{}) {
	if *flagSilent {
		return
	}
	log.Printf(f, data...)
}

func OutputNets(nets []*net.IPNet) {
	for _, n := range nets {
		switch *flagOutputFormat {
		case "cidr":
			fmt.Printf("%s\n", n)
		case "ovpn":
			fmt.Printf("route %s %s\n", n.IP, net.IP(n.Mask))
		case "push-ovpn":
			fmt.Printf("push \"route %s %s\"\n", n.IP, net.IP(n.Mask))
		default:
			fmt.Printf("%s %s\n", n.IP, net.IP(n.Mask))
		}
	}
}