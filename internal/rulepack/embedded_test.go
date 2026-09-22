package rulepack

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestEmbeddedPacksMatchRulesDir keeps internal/rulepack/packs byte-identical
// to rules/. rules/ is the authoring location and what the community mirror
// publishes; packs/ is what users actually execute. If they drift, the repo
// advertises one rule set and ships another — which is exactly the bug this
// embedding was added to fix.
func TestEmbeddedPacksMatchRulesDir(t *testing.T) {
	names, err := EmbeddedNames()
	if err != nil {
		t.Fatal(err)
	}
	if len(names) == 0 {
		t.Fatal("no packs embedded; a released binary would ship zero pack rules")
	}
	srcDir := filepath.Join("..", "..", "rules")
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			want = append(want, e.Name())
		}
	}
	if len(want) != len(names) {
		t.Fatalf("rules/ has %d packs, embedded has %d — run scripts/sync-packs.sh", len(want), len(names))
	}
	for _, name := range names {
		onDisk, err := os.ReadFile(filepath.Join(srcDir, name))
		if err != nil {
			t.Fatalf("%s embedded but missing from rules/: %v", name, err)
		}
		embedded, err := EmbeddedBytes(name)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(onDisk, embedded) {
			t.Errorf("%s differs between rules/ and the embedded copy — run scripts/sync-packs.sh", name)
		}
	}
}

// TestEmbeddedPacksLoadAndCarryProvenance: the packs must parse under the
// same validation as a --rules directory, andeach pack must be identifiable
// afterwards.
func TestEmbeddedPacksLoadAndCarryProvenance(t *testing.T) {
	packs, srcs, err := Embedded()
	if err != nil {
		t.Fatalf("embedded packs do not load: %v", err)
	}
	if len(packs) == 0 {
		t.Fatal("no embedded packs")
	}
	total := 0
	for i, p := range packs {
		if p.Pack == "" || p.Version == "" {
			t.Errorf("pack %d has no name or version", i)
		}
		if srcs[i].SHA256 == "" || len(srcs[i].SHA256) != 64 {
			t.Errorf("pack %s has no usable content hash", p.Pack)
		}
		if srcs[i].Origin != "embedded" {
			t.Errorf("pack %s origin = %q", p.Pack, srcs[i].Origin)
		}
		total += len(p.Rules)
	}
	if total < 50 {
		t.Fatalf("only %d embedded pack rules; expected the full shipped set", total)
	}
}

// TestDedupeDropsRepeatedRuleIDs: CURL_PIPE_SHELL shipped in both the
// starter and community packs, so loading both fired it twice on the same
// evidence.
func TestDedupeDropsRepeatedRuleIDs(t *testing.T) {
	packs, _, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	deduped, dropped := Dedupe(packs)
	seen := map[string]bool{}
	for _, p := range deduped {
		for _, r := range p.Rules {
			if seen[r.ID] {
				t.Errorf("rule %s still duplicated after Dedupe", r.ID)
			}
			seen[r.ID] = true
		}
	}
	_ = dropped
}
