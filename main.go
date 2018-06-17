package main

import (
	"net"
	"flag"
	"os"
	"net/url"
	"strings"
	"bufio"
	"github.com/amkulikov/ipv4range"
)

var (
	flagSrc          = flag.String("src", "", "Location of blocklist file. It may be URL or filepath")
	flagMaxNets      = flag.Uint("max", uint(^uint32(0)), "Max subnets in output")
	flagSilent       = flag.Bool("silent", false, "Prevent errors at stderr")
	flagExcludeNets  = flag.String("exclude", "", "Comma-separated nets in CIDR that must be excluded from result. Private subnets always excluded.")
	flagOutputFormat = flag.String("output", "default", "Output format: default, cidr, ovpn, push-ovpn")
)

func main() {
	var (
		ips  map[ipv4range.IPv4]struct{}
		nets []*net.IPNet
		err  error
	)
	flag.Parse()

	if *flagSrc == "" {
		ips, nets, err = ParseBlocklist(os.Stdin)
	} else if u, err := url.Parse(*flagSrc); err == nil && u.IsAbs() {
		ips, nets, err = LoadBlocklistFromURL(u)
	} else {
		ips, nets, err = LoadBlocklistFromFile(*flagSrc)
	}

	if err != nil {
		Log("Unable to parse blocklist: %s", err)
		os.Exit(1)
	}

	netsTreeRoot := &IPTreeNode{}

	for _, n := range nets {
		netsTreeRoot.AddSubnet(n)
	}

	for ip := range ips {
		netsTreeRoot.AddIP(ip)
	}

	excludedNets := []*net.IPNet{privateNet8, privateNet12, privateNet16}

	if *flagExcludeNets != "" {
		f, err := os.Open(*flagExcludeNets)
		if err == nil {
			defer f.Close()
			br := bufio.NewReader(f)
			for {
				line, err := br.ReadString('\n')
				if err != nil {
					Dump(err)
					break
				}
				_, nt, err := net.ParseCIDR(strings.TrimSpace(line))
				if err == nil {
					excludedNets = append(excludedNets, nt)
				} else {
					Dump(err)
				}
			}
		} else {
			Dump(err)
			ns := strings.Split(*flagExcludeNets, ",")
			for _, n := range ns {
				_, nt, err := net.ParseCIDR(n)
				if err == nil {
					excludedNets = append(excludedNets, nt)
				}
			}
		}
	}


	ipNets := GetOptimizedNets(netsTreeRoot, excludedNets, *flagMaxNets)

	OutputNets(ipNets)

	Log("Total nets: %d, excluded: %d", len(ipNets), len(excludedNets))
}
