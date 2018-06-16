package main

import (
	"regexp"
	"net"
	"os"
	"bufio"
	"io"
	"strings"
	"encoding/binary"
	"net/http"
	"errors"
	"net/url"
	"github.com/amkulikov/ipv4range"
)

var (
	regexpCIDR = regexp.MustCompile(`(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}`)
	regexpIP   = regexp.MustCompile(`(?:\d{1,3}\.){3}\d{1,3}`)
)

func LoadBlocklistFromFile(path string) (ips map[ipv4range.IPv4]struct{}, nets []*net.IPNet, e error) {
	f, err := os.Open(path)
	if err != nil {
		e = err
		return
	}
	defer f.Close()

	return ParseBlocklist(f)
}

func LoadBlocklistFromURL(url *url.URL) (ips map[ipv4range.IPv4]struct{}, nets []*net.IPNet, e error) {
	res, err := http.Get(url.String())
	if err != nil {
		e = err
		return
	}
	if res.StatusCode != http.StatusOK {
		e = errors.New(res.Status)
	}
	defer res.Body.Close()

	return ParseBlocklist(res.Body)
}

func ParseBlocklist(r io.Reader) (ips map[ipv4range.IPv4]struct{}, nets []*net.IPNet, e error) {
	ips = make(map[ipv4range.IPv4]struct{})
	br := bufio.NewReader(r)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			} else {
				e = err
				return
			}
		}

		ipLine := line[:]
		//domainLine := line[:]
		if sep := strings.Index(ipLine, ";"); sep >= 0 {
			ipLine = ipLine[:sep]
			//domainLine = line[sep+1:]
		}
		/*if sep := strings.Index(domainLine, ";"); sep >= 0 {
			domainLine = domainLine[:sep]
		}*/

		matchesCIDR := regexpCIDR.FindAllStringSubmatch(ipLine, -1)
		for _, match := range matchesCIDR {
			if len(match) == 0 {
				continue
			}
			_, ipNet, err := net.ParseCIDR(match[0])
			if err != nil {
				continue
			}
			nets = append(nets, ipNet)
		}

		var ipBuf uint32
		matchesIP := regexpIP.FindAllStringSubmatch(ipLine, -1)
		for _, match := range matchesIP {
			if len(match) == 0 {
				continue
			}
			ipAddr := net.ParseIP(match[0])
			if ipAddr == nil {
				continue
			}

			ipBuf = binary.BigEndian.Uint32(ipAddr.To4()[:4])
			if _, ok := ips[ipv4range.IPv4(ipBuf)]; !ok {
				ips[ipv4range.IPv4(ipBuf)] = struct{}{}
			}
		}
	}
	return
}
