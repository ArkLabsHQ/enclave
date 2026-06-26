package cli

import (
	"strings"
	"testing"
)

func entriesBySelf(es ...lineageEntryV1) map[string]lineageEntryV1 {
	m := map[string]lineageEntryV1{}
	for _, e := range es {
		m[strings.ToLower(e.SelfPCR0)] = e
	}
	return m
}

func link(prev, self, purpose string) lineageEntryV1 {
	return lineageEntryV1{Schema: lineageSchemaV1, Purpose: purpose, PrevPCR0: prev, SelfPCR0: self}
}

func selfs(chain []lineageEntryV1) []string {
	out := make([]string, len(chain))
	for i, e := range chain {
		out[i] = e.SelfPCR0
	}
	return strings.Split(strings.ToLower(strings.Join(out, ",")), ",")
}

func TestWalkLineage(t *testing.T) {
	t.Run("linear chain walks genesis to head", func(t *testing.T) {
		entries := entriesBySelf(
			link("", "aa", lineagePurposeGenesis),
			link("aa", "bb", lineagePurposeMigration),
			link("bb", "cc", lineagePurposeMigration),
		)
		chain, err := walkLineage(entries, "AA") // case-insensitive pin
		if err != nil {
			t.Fatalf("walk: %v", err)
		}
		got := selfs(chain)
		if len(got) != 3 || got[0] != "aa" || got[2] != "cc" {
			t.Fatalf("chain = %v, want [aa bb cc]", got)
		}
	})

	t.Run("single genesis is a one-element chain", func(t *testing.T) {
		entries := entriesBySelf(link("", "aa", lineagePurposeGenesis))
		chain, err := walkLineage(entries, "aa")
		if err != nil || len(chain) != 1 || chain[0].SelfPCR0 != "aa" {
			t.Fatalf("chain = %v, err = %v", chain, err)
		}
	})

	t.Run("missing pinned genesis fails", func(t *testing.T) {
		entries := entriesBySelf(link("", "aa", lineagePurposeGenesis))
		if _, err := walkLineage(entries, "zz"); err == nil {
			t.Fatal("expected error for absent genesis")
		}
	})

	t.Run("fork (two successors) is rejected", func(t *testing.T) {
		entries := entriesBySelf(
			link("", "aa", lineagePurposeGenesis),
			link("aa", "bb", lineagePurposeMigration),
			link("aa", "cc", lineagePurposeMigration),
		)
		_, err := walkLineage(entries, "aa")
		if err == nil || !strings.Contains(err.Error(), "fork") {
			t.Fatalf("expected fork error, got %v", err)
		}
	})

	t.Run("cycle is rejected", func(t *testing.T) {
		entries := entriesBySelf(
			link("", "aa", lineagePurposeGenesis),
			link("aa", "bb", lineagePurposeMigration),
			link("bb", "aa", lineagePurposeMigration),
		)
		_, err := walkLineage(entries, "aa")
		if err == nil || !strings.Contains(err.Error(), "cycle") {
			t.Fatalf("expected cycle error, got %v", err)
		}
	})

	t.Run("a missing link truncates before the head", func(t *testing.T) {
		// bb→cc exists but aa→bb is absent: walk from aa stops at aa (cc unreachable).
		entries := entriesBySelf(
			link("", "aa", lineagePurposeGenesis),
			link("bb", "cc", lineagePurposeMigration),
		)
		chain, err := walkLineage(entries, "aa")
		if err != nil || len(chain) != 1 {
			t.Fatalf("chain = %v, err = %v; want just [aa] (cc unreachable)", chain, err)
		}
	})
}

func TestPCR31Commitment(t *testing.T) {
	c, err := pcr31Commitment("abcd")
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if len(c) != 48 {
		t.Fatalf("commitment len = %d, want 48 (SHA-384)", len(c))
	}
	if _, err := pcr31Commitment("nothex!"); err == nil {
		t.Fatal("expected error for non-hex PCR0")
	}
}
