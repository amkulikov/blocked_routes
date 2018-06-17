package main

import (
	"net"
)

type IPTreeNodesList struct {
	nodes []*IPTreeNode
	m     map[*IPTreeNode]struct{}
}

func NewIPTreeNodesList(max uint32) *IPTreeNodesList {
	return &IPTreeNodesList{
		nodes: make([]*IPTreeNode, 0, max),
		m:     make(map[*IPTreeNode]struct{}),
	}
}

func (l *IPTreeNodesList) Insert(node *IPTreeNode) {
	// список отсортирован по размеру штрафа по убыванию
	inserted := false
	for i := 0; i < len(l.nodes); i++ {
		if node.Penalty() > l.nodes[i].Penalty() {
			l.nodes = append(l.nodes, nil)
			copy(l.nodes[i+1:], l.nodes[i:])
			l.nodes[i] = node

			inserted = true
			break
		}
	}
	if !inserted {
		l.nodes = append(l.nodes, node)
	}
	l.m[node] = struct{}{}
}

func (l *IPTreeNodesList) Nets() (nets []*net.IPNet) {
	nets = make([]*net.IPNet, 0, l.Size())

	for _, leaf := range l.nodes {
		nets = append(nets, leaf.Network())
	}
	return
}

func (l *IPTreeNodesList) Pop() (node *IPTreeNode) {
	if len(l.nodes) == 0 {
		return nil
	}
	node = l.nodes[0]
	delete(l.m, node)
	copy(l.nodes[0:], l.nodes[1:])
	l.nodes[len(l.nodes)-1] = nil
	l.nodes = l.nodes[:len(l.nodes)-1]
	return
}

func (l *IPTreeNodesList) Size() uint {
	return uint(len(l.nodes))
}

func GetOptimizedNets(rootNode *IPTreeNode, excludeNets []*net.IPNet, maxNets uint) (nets []*net.IPNet) {
	l := NewIPTreeNodesList(rootNode.SubtreeLeafsCount)

	l.Insert(rootNode)

	for _, e := range excludeNets {
		rootNode.ExcludeSubnet(e)
	}

	curNode := l.Pop()
	for curNode != nil {
		if curNode.MaskSize == 32 || curNode.IsLeaf {
			l.Insert(curNode)
			break
		}

		if curNode.Zero != nil {
			l.Insert(curNode.Zero.Fallthrough())
		}

		if curNode.One != nil {
			l.Insert(curNode.One.Fallthrough())
		}

		if l.Size() >= maxNets && !curNode.ForceExpand {
			break
		}
		curNode = l.Pop()
	}

	/*if maxNets > 0 {
		for i := 0; i < len(l.nodes); i++ {
			sibl := l.nodes[i].Sibling()
			if _, ok := l.m[sibl]; ok {
				delete(l.m, sibl)
				delete(l.m, l.nodes[i])
				for j := i + 1; j < len(l.nodes); j++ {
					if l.nodes[j] == sibl {
						l.nodes[j] = l.nodes[len(l.nodes)-1]
						l.nodes[len(l.nodes)-1] = nil
						l.nodes = l.nodes[:len(l.nodes)-1]
						break
					}
				}
				l.nodes[i] = l.nodes[i].Parent
				i--
			}
		}
	}*/

	/*for _, n := range l.nodes {
		fmt.Println(n.DumpNode(0))
	}
	fmt.Println(len(l.nodes))*/

	return l.Nets()
}
