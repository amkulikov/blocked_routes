package main

import (
	"net"
	"os"
	"bufio"
	"strings"
)

// Частные сети
var (
	_, privateNet8, _  = net.ParseCIDR("10.0.0.0/8")
	_, privateNet12, _ = net.ParseCIDR("172.16.0.0/12")
	_, privateNet16, _ = net.ParseCIDR("192.168.0.0/16")
)

// Загрузка списка исключаемых подсетей.
// src может быть путем к файлу с подсетями, разделенными переносом строки, либо строкой, где подсети разделены запятой.
func LoadExcludedNets(src string) ([]*net.IPNet, error) {
	nets := make([]*net.IPNet, 0)
	f, err := os.Open(src)
	// Пробуем открыть файл
	if err == nil {
		defer f.Close()
		br := bufio.NewReader(f)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				break
			}
			_, nt, err := net.ParseCIDR(strings.TrimSpace(line))
			if err == nil {
				nets = append(nets, nt)
			}
		}
	} else {
		// если открыть файл не удалось, пробуем распарсить это как строку с подсетями
		ns := strings.Split(src, ",")
		for _, n := range ns {
			_, nt, err := net.ParseCIDR(strings.TrimSpace(n))
			if err == nil {
				nets = append(nets, nt)
			}
		}
	}
	return nets, nil
}
