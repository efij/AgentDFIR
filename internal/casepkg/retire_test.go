package casepkg

import "testing"

// Artifacts a v1.0.0 collector took from node_modules stay in the manifest
// as evidence, but the current collector would not collect them, so they
// leave the scan set — until a later round collects the path on purpose.
func TestCurrentOmitsRetiredPathsUntilRecollected(t *testing.T) {
	junk := "/h/.claude/plugins/cache/x/node_modules/tree-sitter/parser.c"
	keep := "/h/.claude/plugins/cache/x/SKILL.md"
	man := &Manifest{Artifacts: []ArtifactRecord{
		{SourcePath: junk, Round: 1, Status: StatusOK},
		{SourcePath: keep, Round: 1, Status: StatusOK},
	}}
	if n := man.RetireExcluded(); n != 1 {
		t.Fatalf("retired %d records, want 1 (the node_modules path)", n)
	}
	cur := man.Current()
	if len(cur) != 1 || cur[0].SourcePath != keep {
		t.Fatalf("current = %+v, want only %s", cur, keep)
	}
	if len(man.Artifacts) != 2 {
		t.Fatal("retiring must not delete evidence records")
	}
	// A later round that collects the path again (run --full-plugins) wins.
	man.Artifacts = append(man.Artifacts, ArtifactRecord{SourcePath: junk, Round: 2, Status: StatusOK})
	if cur := man.Current(); len(cur) != 2 {
		t.Fatalf("re-collected path still retired: %+v", cur)
	}
}

func TestRetiredListPersistsAcrossReadManifest(t *testing.T) {
	pkg := t.TempDir() + "/r.adfir"
	b, err := New(pkg, "R-1", CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	a := root + "/node_modules/a.js"
	k := root + "/SKILL.md"
	writeFile(t, a, "x")
	writeFile(t, k, "y")
	ingest(t, b, a, "node_modules/a.js")
	ingest(t, b, k, "SKILL.md")
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	man, err := ReadManifest(pkg)
	if err != nil {
		t.Fatal(err)
	}
	man.RetireExcluded()
	if err := WriteRetired(pkg, man); err != nil {
		t.Fatal(err)
	}
	again, err := ReadManifest(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if cur := again.Current(); len(cur) != 1 || cur[0].LogicalPath != "SKILL.md" {
		t.Fatalf("after reopen current = %+v, want only SKILL.md", cur)
	}
}
