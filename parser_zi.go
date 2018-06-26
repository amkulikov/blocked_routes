package main

import (
	"net"
	"encoding/binary"
	"github.com/amkulikov/ipv4range"
	"io"
	"bufio"
	"strings"
	"regexp"
	"os"
)

var (
	regexpCIDR = regexp.MustCompile(`(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}`)
	regexpIP   = regexp.MustCompile(`(?:\d{1,3}\.){3}\d{1,3}`)
)

// Парсер для блоклиста от https://github.com/zapret-info/z-i
type ZapretInfoParser struct {
	AllowedDomains   []string // Разрешенные домены для выборки в blocklist
	AllowEmptyDomain bool     // Использование правил с пустыми доменами
	AllDomains       bool     // Использование любых доменов (в т.ч. пустых)
}

// Загрузка списка разрешенных доменов из файла
func (zi *ZapretInfoParser) LoadAllowedDomains(src string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	br := bufio.NewReader(f)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			} else {
				return err
			}
		}

		zi.AllowedDomains = append(zi.AllowedDomains, strings.TrimSpace(line))
	}
	return nil
}

// Разбор содержимого блоклиста
func (zi *ZapretInfoParser) Parse(r io.Reader) (ips map[ipv4range.IPv4]struct{}, nets []*net.IPNet, e error) {
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

		ipPart := line[:]
		if sep := strings.Index(ipPart, ";"); sep >= 0 {
			ipPart = ipPart[:sep]
		} else {
			continue
		}

		if !zi.AllDomains {
			domainPart := line[len(ipPart)+1:]
			if sep := strings.Index(domainPart, ";"); sep >= 0 {
				domainPart = strings.TrimSpace(domainPart[:sep])
			} else {
				continue
			}
			if len(domainPart) == 0 {
				if !zi.AllowEmptyDomain {
					continue
				}
			} else if len(zi.AllowedDomains) > 0 {
				skipLine := true
				for _, d := range zi.AllowedDomains {
					if strings.HasSuffix(domainPart, d) {
						skipLine = false
						break
					}
				}
				if skipLine {
					continue
				}
			}
		}

		matchesCIDR := regexpCIDR.FindAllStringSubmatch(ipPart, -1)
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
		matchesIP := regexpIP.FindAllStringSubmatch(ipPart, -1)
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
