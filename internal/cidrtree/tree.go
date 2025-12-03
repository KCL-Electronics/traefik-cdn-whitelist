// Package cidrtree offers a compact prefix tree used to deduplicate CIDR ranges.
package cidrtree

import (
	"net/netip"
)

const (
	ipv4Bits    = 32
	ipv6Bits    = 128
	bitsPerByte = 8
)

// Tree stores CIDR prefixes using a binary trie for fast lookups and deduplication.
type Tree struct {
	root    *node
	maxBits int
}

type node struct {
	children [2]*node
	allow    bool
	cidr     string
}

// New returns an empty tree supporting addresses up to maxBits wide (32 or 128).
func New(maxBits int) *Tree {
	return &Tree{maxBits: maxBits, root: &node{}}
}

// Insert adds a prefix to the trie, removing any contained children and avoiding duplicates.
func (t *Tree) Insert(prefix netip.Prefix) (string, []string, bool) {
	if t == nil || t.root == nil {
		return "", nil, false
	}

	bits := prefix.Bits()
	if bits < 0 || bits > t.maxBits {
		bits = t.maxBits
	}

	addr := prefix.Masked().Addr()
	current := t.root

	for i := 0; i < bits; i++ {
		if current.allow {
			return "", nil, true
		}

		bit := pickBit(addr, i, t.maxBits)
		if current.children[bit] == nil {
			current.children[bit] = &node{}
		}
		current = current.children[bit]
	}

	if current.allow && current.cidr == prefix.String() {
		return "", nil, true
	}

	removed := collectCIDRs(current)

	current.allow = true
	current.cidr = prefix.String()
	current.children[0] = nil
	current.children[1] = nil

	return current.cidr, removed, false
}

// Contains reports whether addr is covered by any prefix in the tree.
func (t *Tree) Contains(addr netip.Addr) bool {
	if t == nil || t.root == nil {
		return false
	}

	current := t.root
	allowed := current.allow

	for i := 0; i < t.maxBits; i++ {
		bit := pickBit(addr, i, t.maxBits)
		next := current.children[bit]
		if next == nil {
			return allowed
		}
		allowed = allowed || next.allow
		current = next
	}

	return allowed
}

// CIDRs returns a flattened list of stored prefixes.
func (t *Tree) CIDRs() []string {
	if t == nil || t.root == nil {
		return nil
	}

	var result []string
	collectAllowed(t.root, &result)
	return result
}

// Reset removes all prefixes from the tree.
func (t *Tree) Reset() {
	if t == nil || t.root == nil {
		return
	}

	t.root.children[0] = nil
	t.root.children[1] = nil
	t.root.allow = false
	t.root.cidr = ""
}

func collectAllowed(n *node, acc *[]string) {
	if n == nil {
		return
	}

	if n.allow && n.cidr != "" {
		*acc = append(*acc, n.cidr)
	}

	collectAllowed(n.children[0], acc)
	collectAllowed(n.children[1], acc)
}

func collectCIDRs(n *node) []string {
	if n == nil {
		return nil
	}

	var result []string
	var stack []*node
	stack = append(stack, n.children[0], n.children[1])

	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if current == nil {
			continue
		}
		if current.allow && current.cidr != "" {
			result = append(result, current.cidr)
		}
		if current.children[0] != nil {
			stack = append(stack, current.children[0])
		}
		if current.children[1] != nil {
			stack = append(stack, current.children[1])
		}
	}

	return result
}

func pickBit(addr netip.Addr, pos int, maxBits int) int {
	if maxBits == ipv4Bits {
		addr = addr.Unmap()
		b := addr.As4()
		byteIdx := pos / bitsPerByte
		shift := uint(7 - (pos % bitsPerByte))
		return int((b[byteIdx] >> shift) & 1)
	}

	b := addr.As16()
	byteIdx := pos / bitsPerByte
	shift := uint(7 - (pos % bitsPerByte))
	return int((b[byteIdx] >> shift) & 1)
}
