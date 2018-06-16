package main

import (
	"net"
	"encoding/binary"
	"strings"
	"fmt"
	"github.com/amkulikov/ipv4range"
)

type IPTreeNode struct {
	Parent *IPTreeNode
	One    *IPTreeNode
	Zero   *IPTreeNode

	IsLeaf bool

	Value net.IP

	ForceExpand bool

	SubtreeCapacity   uint32
	SubtreeSize       uint32
	SubtreeLeafsCount uint32
	penalty           uint32
	MaskSize          uint8
}

// Создает и возвращает новый узел IPTreeNode
func NewIPTreeNode(ip ipv4range.IPv4, depth uint8, parent *IPTreeNode) *IPTreeNode {
	ipBuf := make(net.IP, 4)
	binary.BigEndian.PutUint32(ipBuf, uint32(ip))
	node := &IPTreeNode{
		Parent:            parent,
		MaskSize:          depth,
		SubtreeCapacity:   1 << (32 - depth),
		SubtreeSize:       1,
		SubtreeLeafsCount: 1,
		Value:             ipBuf.Mask(net.CIDRMask(int(depth), 32)),
	}

	if depth == 32 {
		node.IsLeaf = true
	}

	return node
}

// Добавление IP-адреса. success будет false, если добавляемый IP адрес уже был добавлен или входит в ранее добавленную подсеть.
func (t *IPTreeNode) AddIP(ip ipv4range.IPv4, depth uint8) (success bool) {
	var child **IPTreeNode
	if ip&(1<<(32-depth)) != 0 {
		child = &t.One
	} else {
		child = &t.Zero
	}

	if t.IsLeaf {
		// Добавляемый IP уже входит в ранее добавленную подсеть
		return false
	}

	if *child == nil {
		*child = NewIPTreeNode(ip, depth, t)
	} else {
		(*child).SubtreeSize++
		(*child).SubtreeLeafsCount++
	}

	if depth < 32 {
		if (*child).AddIP(ip, depth+1) {
			return true
		} else {
			return false
		}
	}
	return true
}

// Добавление подсети.
// success будет false, если добавляемая подсеть уже содержится в ранее добавленной.
// size содержит кол-во фактически добавленных IP-адресов. Например, если при добавлении подсети были поглощёны ранее
// добавленные IP-адреса, вернется вместимость подсети за вычетом кол-ва поглощённых адресов или вместимости поглощенных посетей
func (t *IPTreeNode) AddSubnet(s *net.IPNet, depth uint8) (success bool, size uint32, count int64) {
	var child **IPTreeNode
	ip := binary.BigEndian.Uint32(s.IP)
	if ip&(1<<(32-depth)) != 0 {
		child = &t.One
	} else {
		child = &t.Zero
	}

	// Выходим, так как добавляемая подсеть входит в текущую
	if t.IsLeaf {
		return false, 0, 0
	}

	if *child == nil {
		*child = NewIPTreeNode(ipv4range.IPv4(ip), depth, t)
	}

	maskSize, _ := s.Mask.Size()

	if int(depth) <= maskSize {
		if success, size, count = (*child).AddSubnet(s, depth+1); success {
			t.SubtreeSize += size
			t.SubtreeLeafsCount = uint32(int64(t.SubtreeLeafsCount) + count)
			return true, size, count
		} else {
			return false, 0, 0
		}
	} else {
		// достигнут размер маски добавляемой подсети

		// удаляем всё ниже расположенное поддерево
		t.DeleteSubtree()
		// текущий узел становится листом
		t.IsLeaf = true
		// размер добавленного поддерева считаем как вместимость поддерева за вычетом уже бывших здесь подсетей
		size = t.SubtreeCapacity - t.SubtreeSize
		t.SubtreeSize = t.SubtreeCapacity
		t.SubtreeLeafsCount = 1
		return true, size, int64(1 - t.SubtreeLeafsCount)
	}
	return true, t.SubtreeCapacity, int64(t.SubtreeLeafsCount)
}

// Удаление поддерева
func (t *IPTreeNode) DeleteSubtree() {
	if t.One != nil {
		t.One.DeleteSubtree()
		t.One.Parent = nil
		t.One = nil
	}
	if t.Zero != nil {
		t.Zero.DeleteSubtree()
		t.Zero.Parent = nil
		t.Zero = nil
	}
}

func (t *IPTreeNode) DumpNode(limit int) string {
	if limit < 0 {
		return ""
	}
	if t == nil {
		return "<nil>"
	} else {
		pad := strings.Repeat("-", int(t.MaskSize+1))
		return fmt.Sprintf("IP: %s, Mask: %d, Penalty: %d, Size: %d, Count: %d, Capacity: %d \n%s%s\n%s%s", t.Value, t.MaskSize, t.penalty, t.SubtreeSize, t.SubtreeLeafsCount, t.SubtreeCapacity, pad, t.Zero.DumpNode(limit-1), pad, t.One.DumpNode(limit-1))
	}
}

func (t *IPTreeNode) DumpSubtree() string {
	return t.DumpNode(32)
}

// Получение последнего потомка, имеющего степень отличную от 1
func (t *IPTreeNode) Fallthrough() (leaf *IPTreeNode) {
	if t.One != nil && t.Zero == nil {
		return t.One.Fallthrough()
	} else if t.Zero != nil && t.One == nil {
		return t.Zero.Fallthrough()
	} else {
		return t
	}
}

func (t *IPTreeNode) excludeSubnet(s *net.IPNet, depth uint8) (excludedSize uint32, excludedCount int64) {
	var child **IPTreeNode

	ip := binary.BigEndian.Uint32(s.IP)
	maskedIP := binary.BigEndian.Uint32(s.IP.Mask(net.CIDRMask(int(depth-1), 32)).To4()[:])

	// Если нода крайняя, а глубина исключаемой подсети ещё не достигнута, необходимо углубляться в подсеть
	if t.IsLeaf {
		if t.One == nil {
			t.One = NewIPTreeNode(ipv4range.IPv4(maskedIP|(1<<(32-depth))), depth, t)
			t.One.SubtreeSize = t.One.SubtreeCapacity
		}
		t.One.IsLeaf = true
		if t.Zero == nil {
			t.Zero = NewIPTreeNode(ipv4range.IPv4(maskedIP), depth, t)
			t.Zero.SubtreeSize = t.Zero.SubtreeCapacity
		}
		t.Zero.IsLeaf = true
		t.IsLeaf = false

		if ip&(1<<(32-depth)) != 0 {
			child = &t.One
		} else {
			child = &t.Zero
		}
	} else {
		if ip&(1<<(32-depth)) != 0 {
			child = &t.One
		} else {
			child = &t.Zero
		}

		if *child == nil {
			// Выходим, так как исключаемая подсеть отсутствует
			return 0, 0
		}
	}
	t.ForceExpand = true

	maskSize, _ := s.Mask.Size()
	if maskSize == int(depth) {
		excludedSize = (*child).SubtreeSize
		excludedCount = int64((*child).SubtreeLeafsCount)
		t.SubtreeSize -= excludedSize
		t.SubtreeLeafsCount = uint32(int64(t.SubtreeLeafsCount) - excludedCount)
		*child = nil
		return
	}

	excludedSize, excludedCount = (*child).excludeSubnet(s, depth+1)
	t.SubtreeSize -= excludedSize
	t.SubtreeLeafsCount = uint32(int64(t.SubtreeLeafsCount) - excludedCount)
	return
}

func (t *IPTreeNode) ExcludeSubnet(s *net.IPNet) {
	t.excludeSubnet(s, 1)
}

func (t *IPTreeNode) Network() *net.IPNet {
	return &net.IPNet{IP: t.Value, Mask: net.CIDRMask(int(t.MaskSize), 32)}
}

// Расчёт штрафа за оставление текущей подсети
func (t *IPTreeNode) Penalty() uint32 {
	if t.penalty == 0 {
		if t.IsLeaf {
			t.penalty = 1
		} else if t.ForceExpand {
			t.penalty = 1<<32 - 1
		} else {
			// штраф за оставление подсети = отношение общего кол-ва IP в подсети к кол-ву заблокированных, присутствующих в ней
			t.penalty = t.SubtreeCapacity / t.SubtreeSize * t.SubtreeLeafsCount
		}
	}

	return t.penalty
}

// Получение соседа
func (t *IPTreeNode) Sibling() (*IPTreeNode) {
	if t.Parent.One == t {
		return t.Parent.Zero
	} else {
		return t.Parent.One
	}
}

func (t *IPTreeNode) SetPenalty(penalty uint32) {
	t.penalty = penalty
}
