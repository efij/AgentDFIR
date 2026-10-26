package mitre

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestEmbeddedDataLoads(t *testing.T) {
	if err := Err(); err != nil {
		t.Fatal(err)
	}
}

// TestPinnedVersions keeps the exported constants equal to the embedded
// data and the data equal to the pins the generator enforces.
func TestPinnedVersions(t *testing.T) {
	a := ATLAS()
	if a.Version != ATLASVersion || a.FormatVersion != "6.0.0" {
		t.Errorf("ATLAS data %s (format %s), constant %s", a.Version, a.FormatVersion, ATLASVersion)
	}
	if a.SHA256 != "935efa93e28294432d3e2f537eb94991ef8d1f8c58341cd360ea3321ddb66688" ||
		a.SourceURL != "https://github.com/mitre-atlas/atlas-data/releases/download/v2026.09/ATLAS-2026.09.yaml" {
		t.Errorf("ATLAS pin changed: %s %s", a.SourceURL, a.SHA256)
	}
	k := ATTACK()
	if k.Version != ATTACKVersion {
		t.Errorf("ATT&CK data %s, constant %s", k.Version, ATTACKVersion)
	}
	if k.SHA256 != "81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352" ||
		!strings.HasSuffix(k.SourceURL, "/enterprise-attack-20.0.json") {
		t.Errorf("ATT&CK pin changed: %s %s", k.SourceURL, k.SHA256)
	}
}

// TestATLASCatalogShape: ATLAS 2026.09 is 120 techniques + 88
// sub-techniques, and every one belongs to at least one tactic.
func TestATLASCatalogShape(t *testing.T) {
	var top, sub int
	for _, tc := range ATLAS().Techniques {
		if strings.Count(tc.ID, ".") == 2 {
			sub++
			if _, ok := ATLASTechnique(tc.ID[:len("AML.T0000")]); !ok {
				t.Errorf("%s: parent technique missing", tc.ID)
			}
		} else {
			top++
		}
		if len(tc.Tactics) == 0 {
			t.Errorf("%s: no tactic", tc.ID)
		}
		for _, ta := range tc.Tactics {
			if ATLASTacticName(ta) == "" {
				t.Errorf("%s: unknown tactic %s", tc.ID, ta)
			}
		}
	}
	if top != 120 || sub != 88 {
		t.Errorf("ATLAS %s: %d techniques + %d sub-techniques, want 120 + 88", ATLASVersion, top, sub)
	}
	for id, name := range map[string]string{
		"AML.T0051":     "LLM Prompt Injection",
		"AML.T0072":     "Cyber Communication Channel",
		"AML.T0075":     "Enterprise Resource Discovery",
		"AML.T0110.001": "Implementation",
	} {
		if ATLASName(id) != name {
			t.Errorf("%s: name %q, want %q", id, ATLASName(id), name)
		}
	}
}

func TestATTACKCatalogShape(t *testing.T) {
	k := ATTACK()
	if len(k.Techniques) != 706 || len(k.Revoked) != 149 || len(k.Deprecated) != 12 {
		t.Errorf("ATT&CK %s: %d active, %d revoked, %d deprecated", k.Version, len(k.Techniques), len(k.Revoked), len(k.Deprecated))
	}
	for _, r := range k.Revoked {
		if r.RevokedBy != "" && ATTACKStatus(r.RevokedBy) == StatusUnknown {
			t.Errorf("%s revoked by unknown %s", r.ID, r.RevokedBy)
		}
	}
	if ATTACKStatus("T1059") != StatusActive || ATTACKStatus("T1562.001") != StatusRevoked || ATTACKStatus("T9999") != StatusUnknown {
		t.Error("status lookups wrong")
	}
}

// TestMigrationsMatchCatalogs: every recorded migration is what the pinned
// catalog itself says. For ATT&CK the old ID must be revoked with a
// revoked-by pointing at the new one; for ATLAS the old ID must be gone.
func TestMigrationsMatchCatalogs(t *testing.T) {
	ms := Migrations()
	if len(ms) == 0 {
		t.Fatal("no migrations")
	}
	seen := map[string]bool{}
	for _, m := range ms {
		if seen[m.Old] {
			t.Errorf("%s migrated twice", m.Old)
		}
		seen[m.Old] = true
		if m.Reason == "" {
			t.Errorf("%s: no reason", m.Old)
		}
		switch m.Catalog {
		case "ATT&CK Enterprise":
			if m.Version != ATTACKVersion {
				t.Errorf("%s: version %s", m.Old, m.Version)
			}
			by, ok := ATTACKRevokedBy(m.Old)
			if !ok || by != m.New {
				t.Errorf("%s: catalog says revoked-by %q (revoked=%v), migration says %s", m.Old, by, ok, m.New)
			}
			if !ValidATTACK(m.New) {
				t.Errorf("%s: target %s not active", m.Old, m.New)
			}
		case "ATLAS":
			if m.Version != ATLASVersion || ValidATLAS(m.Old) || !ValidATLAS(m.New) {
				t.Errorf("%s → %s: not a removal to a valid technique in ATLAS %s", m.Old, m.New, ATLASVersion)
			}
		default:
			t.Errorf("%s: unknown catalog %q", m.Old, m.Catalog)
		}
	}
	// The six ATT&CK IDs v4.5 cited that v20.0 revokes.
	for old, want := range map[string]string{"T1562": "T1685", "T1562.001": "T1685", "T1562.004": "T1686",
		"T1562.008": "T1685.002", "T1070.001": "T1685.005", "T1070.002": "T1685.006"} {
		found := false
		for _, m := range ms {
			found = found || (m.Old == old && m.New == want)
		}
		if !found {
			t.Errorf("missing migration %s → %s", old, want)
		}
	}
}

func TestOWASPLists(t *testing.T) {
	ls := OWASP()
	if len(ls) != 2 {
		t.Fatalf("%d OWASP lists", len(ls))
	}
	n := 0
	for _, l := range ls {
		if l.SourceURL == "" || l.Version == "" || len(l.Items) != 10 {
			t.Errorf("%s: incomplete", l.Name)
		}
		n += len(l.Items)
	}
	if n != 20 || OWASPName("LLM01") != "Prompt Injection" || OWASPName("ASI10") != "Rogue Agents" || ValidOWASP("LLM11") {
		t.Error("OWASP table wrong")
	}
}

// attackTokenRe finds ATT&CK technique IDs in text, including the
// attack.mitre.org URL form (T1562/001).
var attackTokenRe = regexp.MustCompile(`\bT(\d{4})(?:[./](\d{3}))?\b`)

// atlasTokenRe finds ATLAS technique IDs; the ones 2026.09 removed are
// the ATLAS migrations' `old` values.
var atlasTokenRe = regexp.MustCompile(`\bAML\.T\d{4}(?:\.\d{3})?\b`)

// revokedAllowed lists the only files that may still name a revoked or
// removed ID, and only one that is a migration's `old`: history, the
// catalog data itself, and a backward-compatibility table.
var revokedAllowed = map[string]string{
	"CHANGELOG.md":                   "release history",
	"internal/mitre/data":            "the pinned catalogs and the migration record",
	"internal/mitre/mitre_test.go":   "this test",
	"internal/reconstruct/stages.go": "stages findings stored by earlier releases",
	"docs/reconstruct.md":            "documents that backward-compatible mapping",
	"docs/index.html":                "site page owned by the release workstream; migrate there, then drop this line",
}

func repoRoot(t *testing.T) string {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func allowed(rel string) bool {
	for p := range revokedAllowed {
		if rel == p || strings.HasPrefix(rel, p+"/") {
			return true
		}
	}
	return false
}

// TestNoRevokedIDsInRepo: no Go source, rule pack, chain or doc cites a
// revoked or deprecated ATT&CK technique or a removed ATLAS technique,
// except the allowlisted history files — and even there only IDs that a
// recorded migration covers.
func TestNoRevokedIDsInRepo(t *testing.T) {
	root := repoRoot(t)
	migrated := map[string]bool{}
	atlasRemoved := map[string]bool{}
	for _, m := range Migrations() {
		migrated[m.Old] = true
		if m.Catalog == "ATLAS" {
			atlasRemoved[m.Old] = true
		}
	}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if name == ".git" || name == "node_modules" || name == "marketing" || name == "dist" {
				return filepath.SkipDir
			}
			return nil
		}
		switch filepath.Ext(name) {
		case ".go", ".json", ".md", ".html", ".yaml", ".yml", ".txt", ".sh":
		default:
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if rel == "internal/mitre/data/attack-enterprise.json" || rel == "internal/mitre/data/atlas.json" {
			return nil // the catalogs themselves list every revoked ID
		}
		info, err := d.Info()
		if err != nil || info.Size() > 8<<20 {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(data), "\n") {
			var bad []string
			for _, m := range attackTokenRe.FindAllStringSubmatch(line, -1) {
				id := "T" + m[1]
				if m[2] != "" {
					id += "." + m[2]
				}
				if s := ATTACKStatus(id); s == StatusRevoked || s == StatusDeprecated {
					bad = append(bad, id)
				}
			}
			for _, id := range atlasTokenRe.FindAllString(line, -1) {
				if atlasRemoved[id] {
					bad = append(bad, id)
				}
			}
			for _, id := range bad {
				if allowed(rel) && migrated[id] {
					continue
				}
				t.Errorf("%s:%d cites %s, which is revoked/deprecated/removed in the pinned catalogs; migrate it (internal/mitre/data/migrations.json)", rel, i+1, id)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// sourceAttackRe finds ATT&CK IDs written as string literals in Go source:
// MitreATTACK fields, and the `sev, attack := "HIGH", "T…"` form.
var sourceAttackRe = regexp.MustCompile(`"(T\d{4}(?:\.\d{3})?)"`)

// TestSourceATTACKLiteralsActive: every ATT&CK technique a Go rule can
// emit is active in ATT&CK Enterprise v20.0. Built-in findings set
// MitreATTACK in code, not only in the catalog, so the catalog test alone
// would miss a revoked ID in an emitting literal.
func TestSourceATTACKLiteralsActive(t *testing.T) {
	root := repoRoot(t)
	files, err := filepath.Glob(filepath.Join(root, "internal", "*", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, f := range files {
		rel, _ := filepath.Rel(root, f)
		rel = filepath.ToSlash(rel)
		if strings.HasSuffix(f, "_test.go") || allowed(rel) {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			for _, m := range sourceAttackRe.FindAllStringSubmatch(line, -1) {
				n++
				if !ValidATTACK(m[1]) {
					t.Errorf("%s:%d: %s is %s in ATT&CK Enterprise %s", rel, i+1, m[1], ATTACKStatus(m[1]), ATTACKVersion)
				}
			}
		}
	}
	if n < 50 {
		t.Errorf("only %d ATT&CK literals found; the scan is not reaching the rule code", n)
	}
}
