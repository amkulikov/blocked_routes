package main

import (
	"net"
	"flag"
	"os"
	"net/url"
)

var (
	flagSrc              = flag.String("src", "", "Location of blocklist file. It may be URL or filepath.")
	flagMaxNets          = flag.Uint("max", uint(^uint32(0)), "Max subnets in output.")
	flagSilent           = flag.Bool("silent", false, "Prevent errors at stderr.")
	flagAllowEmptyDomain = flag.Bool("empty-domains", false, "Use rules with empty domains from blocklist.")
	flagAllowDomains     = flag.String("allowed-domains", "", "Use only allowed domains from blocklist rules. Not contains empty domains.")
	flagExcludeNets      = flag.String("exclude", "", "Comma-separated nets in CIDR that must be excluded from result. Private subnets always excluded.")
	flagOutputFormat     = flag.String("output", "default", "Output format: default, cidr, ovpn, push-ovpn.")
)

func main() {
	var err error
	flag.Parse()

	// Создаем парсер блоклиста (данных о заблокированных ресурсах)
	blParser := &ZapretInfoParser{
		AllowEmptyDomain: *flagAllowEmptyDomain || *flagAllowDomains == "",
	}
	if *flagAllowDomains != "" {
		// Разрешаем парсеру включать в список только перечисленные домены (с поддоменами)
		if err := blParser.LoadAllowedDomains(*flagAllowDomains); err != nil {
			Log("Unable to load allowed domains: %s", err)
			os.Exit(1)
		}
	}

	// Инициализируем блоклист и устанавливаем парсер
	bl := NewBlocklist()
	bl.SetParser(blParser)

	// Выбираем источник данных о заблокированных ресурсах
	if *flagSrc == "" {
		err = bl.Parse(os.Stdin)
	} else if u, err := url.Parse(*flagSrc); err == nil && u.IsAbs() {
		err = bl.LoadFromURL(u)
	} else {
		err = bl.LoadFromFile(*flagSrc)
	}
	if err != nil {
		Log("Unable to load blocklist: %s", err)
		os.Exit(1)
	}

	// Формируем дерево подсетей из блоклиста
	netsTreeRoot := bl.SubnetsTree()

	// Частные сети исключаем всегда
	excludedNets := []*net.IPNet{privateNet8, privateNet12, privateNet16}
	if *flagExcludeNets != "" {
		// Добавляем для исключения указанные дополнительные сети
		en, err := LoadExcludedNets(*flagExcludeNets)
		if err != nil {
			Log("Unable to load excluded nets: %s", err)
			os.Exit(1)
		}
		excludedNets = append(excludedNets, en...)
	}

	ipNets := GetOptimizedNets(netsTreeRoot, excludedNets, *flagMaxNets)

	OutputNets(ipNets)

	Log("Total nets: %d, excluded: %d", len(ipNets), len(excludedNets))
}
