package main

import (
	"net"
	"github.com/amkulikov/ipv4range"
	"os"
	"net/url"
	"net/http"
	"io"
	"errors"
)

// Интерфейс парсера списка заблокированных ресурсов
type BlocklistParser interface {
	// Читает содержимое блоклиста и возвращает отдельные IP-адреса в ips,
	// заблокированные сети в nets, err в случае ошибки.
	// nets могут включать адреса из ips, а также содержать в себе другие элементы nets.
	Parse(r io.Reader) (ips map[ipv4range.IPv4]struct{}, nets []*net.IPNet, err error)
}

// Список заблокированных ресурсов
type Blocklist struct {
	nets []*net.IPNet                // заблокированные сети
	ips  map[ipv4range.IPv4]struct{} // заблокированные отдельные IP

	parser BlocklistParser // парсер исходного списка ресурсов
}

// Инициализация нового блоклиста
func NewBlocklist() *Blocklist {
	return &Blocklist{
		ips: make(map[ipv4range.IPv4]struct{}),
	}
}

// Загрузка блоклиста из файла
func (b *Blocklist) LoadFromFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return b.Parse(f)
}

// Загрузка блоклиста по URL
func (b *Blocklist) LoadFromURL(url *url.URL) error {
	res, err := http.Get(url.String())
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK {
		return errors.New(res.Status)
	}
	defer res.Body.Close()

	return b.Parse(res.Body)
}

// Загрузка блоклиста из io.Reader
func (b *Blocklist) Parse(r io.Reader) error {
	ips, nets, err := b.parser.Parse(r)
	if err != nil {
		return err
	}
	b.ips = ips
	b.nets = nets
	return nil
}

// Установка парсера
func (b *Blocklist) SetParser(p BlocklistParser) {
	b.parser = p
}

// Формирование дерева подсетей из блоклиста
func (b *Blocklist) SubnetsTree() (root *IPTreeNode) {
	root = &IPTreeNode{}
	for _, n := range b.nets {
		root.AddSubnet(n)
	}

	for ip := range b.ips {
		root.AddIP(ip)
	}
	return
}
