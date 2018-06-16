package main

import (
	"os"
	"bufio"
	"regexp"
	"strconv"
	"fmt"

	"github.com/amkulikov/ipv4range"
)

// Вспомогательная утилита russian_nets читает из файла, путь к которому передан первым аргументом,
// диапазоны IP-адресов и формирует из них подсети в формате CIDR, принадлежащие России.
// В качестве файла с информацией о диапазонах используется geo_ip_ranges.txt, содержимое которого взято с ресурса ipgeobase.ru.
// geo_ip_ranges.txt имеет следующий формат записи:
// <начало блока> <конец блока> <блок адресов> <страна> <идентификатор города>
// <начало блока> - число, полученное из первого ip адреса блока (диапазона) ip-адресов вида a.b.c.d по формуле a*256*256*256+b*256*256+c*256+d
// <конец блока> - число, полученное из второго ip адреса блока (диапазона) ip-адресов вида e.f.g.h по формуле e*256*256*256+f*256*256+g*256+h
// <блок адресов> - блок (диапазон) ip-адресов вида a.b.c.d - e.f.g.h, для кторого определено положение
// <страна> - двухбуквенный код страны, к которой относится блок
// <идентификатор города>

var regexpRussianRange = regexp.MustCompile(`(\d{1,10})\t(\d{1,10})\t.{17,33}\tRU\t.*`)

func main() {
	// Читаем файл, путь к которому должен содержаться в первом аргументе
	f, err := os.Open(os.Args[1])
	if err != nil {
		os.Exit(1)
	}
	defer f.Close()

	var curRange *ipv4range.IPRange
	br := bufio.NewReader(f)
	for {
		// построково читаем файл
		line, err := br.ReadString('\n')
		if err != nil {
			break
		}

		// регуляркой выбираем только строки со страной RU
		matches := regexpRussianRange.FindAllStringSubmatch(line, -1)
		if len(matches) == 0 || len(matches[0]) != 3 {
			continue
		}

		left, err := strconv.ParseUint(matches[0][1], 10, 32)
		if err != nil {
			continue
		}

		right, err := strconv.ParseUint(matches[0][2], 10, 32)
		if err != nil {
			continue
		}

		leftIP := ipv4range.IPv4(left)
		rightIP := ipv4range.IPv4(right)

		// Диапазоны одной страны часто идут вплотную, поэтому дополняем предыдущий диапазон при совпадении
		if curRange != nil && leftIP == curRange.Right+1 {
			curRange.Right = rightIP
		} else {
			if curRange != nil {
				nets := curRange.Subnets()
				for _, n := range nets {
					fmt.Println(n)
				}
			}
			curRange = ipv4range.NewIPRange(leftIP, rightIP)
		}
	}
	if curRange != nil {
		nets := curRange.Subnets()
		for _, n := range nets {
			fmt.Println(n)
		}
	}
}
