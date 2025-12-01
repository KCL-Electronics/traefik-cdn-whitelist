package cidrtree

import (
	"net/netip"
	"testing"
)

func TestInsertAndContains(t *testing.T) {
	tree := New(32)

	inserted, removed, covered := tree.Insert(mustPrefix(t, "10.0.0.0/8"))
	if inserted == "" || covered {
		t.Fatalf("expected new prefix, got inserted=%q covered=%v", inserted, covered)
	}
	if len(removed) != 0 {
		t.Fatalf("expected no removed prefixes, got %v", removed)
	}

	if !tree.Contains(netip.MustParseAddr("10.1.2.3")) {
		t.Fatalf("expected address to be contained")
	}
	if tree.Contains(netip.MustParseAddr("192.168.0.1")) {
		t.Fatalf("expected address outside prefix to be rejected")
	}

	inserted, removed, covered = tree.Insert(mustPrefix(t, "10.0.0.0/16"))
	if inserted != "" || len(removed) != 0 || !covered {
		t.Fatalf("child prefix should be covered, inserted=%q removed=%v covered=%v", inserted, removed, covered)
	}

	inserted, removed, covered = tree.Insert(mustPrefix(t, "11.2.0.0/16"))
	if inserted == "" || covered {
		t.Fatalf("expected new child prefix outside existing range, inserted=%q covered=%v", inserted, covered)
	}
	if len(removed) != 0 {
		t.Fatalf("expected no removals, got %v", removed)
	}

	inserted, removed, covered = tree.Insert(mustPrefix(t, "10.0.0.0/7"))
	if inserted == "" || covered {
		t.Fatalf("expected parent prefix insertion")
	}
	if len(removed) < 2 {
		t.Fatalf("expected child prefixes to be removed, got %v", removed)
	}
}

func TestCIDRs(t *testing.T) {
	tree := New(128)
	tree.Insert(mustPrefix(t, "2001:db8::/32"))
	tree.Insert(mustPrefix(t, "2001:db8:1::/48"))

	cidrs := tree.CIDRs()
	if len(cidrs) != 1 || cidrs[0] != "2001:db8::/32" {
		t.Fatalf("expected collapsed CIDR list, got %v", cidrs)
	}
}

func TestReset(t *testing.T) {
	tree := New(32)
	tree.Insert(mustPrefix(t, "192.0.2.0/24"))
	if !tree.Contains(netip.MustParseAddr("192.0.2.1")) {
		t.Fatalf("expected IP to be contained before reset")
	}

	tree.Reset()

	if tree.Contains(netip.MustParseAddr("192.0.2.1")) {
		t.Fatalf("expected IP to be rejected after reset")
	}
}

func mustPrefix(t *testing.T, cidr string) netip.Prefix {
	t.Helper()

	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		t.Fatalf("parse prefix %s: %v", cidr, err)
	}

	return p
}
