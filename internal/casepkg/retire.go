package casepkg

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// ExcludedByPolicy reports whether the default collection policy would skip
// path: third-party dependency trees and git object storage, wherever they
// sit. The collector consults it while walking; RetireExcluded applies the
// same policy to records an older collector (or --full-plugins) already
// took, so the scan set and the walk agree on what is agent-facing content.
func ExcludedByPolicy(path string) bool {
	p := filepath.ToSlash(path)
	for _, seg := range strings.Split(p, "/") {
		if seg == "node_modules" {
			return true
		}
	}
	for _, suffix := range []string{"/.git/objects", "/.git/lfs", "/.git/modules"} {
		if strings.HasSuffix(p, suffix) || strings.Contains(p, suffix+"/") {
			return true
		}
	}
	return false
}

// retiredFile lists source paths the current policy excludes and the last
// round that collected each. Derived data: outside the sealed zone, never
// removes a record, and a later round that collects the path again wins.
const retiredFile = "retired.json"

// RetireExcluded marks every current record ExcludedByPolicy would have
// skipped. Returns how many records left the scan set. Evidence records
// stay in Artifacts; only Current() changes.
func (m *Manifest) RetireExcluded() int {
	if m.retired == nil {
		m.retired = map[string]int{}
	}
	n := 0
	for _, a := range m.Artifacts {
		if !ExcludedByPolicy(a.SourcePath) {
			continue
		}
		if r, ok := m.retired[a.SourcePath]; !ok || a.Round > r {
			m.retired[a.SourcePath] = a.Round
		}
		n++
	}
	return n
}

func (m *Manifest) isRetired(a ArtifactRecord) bool {
	r, ok := m.retired[a.SourcePath]
	return ok && a.Round <= r
}

// WriteRetired persists the retired list next to the normalized overlay.
func WriteRetired(pkgDir string, m *Manifest) error {
	dir := filepath.Join(pkgDir, "normalized")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(m.retired)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, retiredFile), data, 0o600)
}

func readRetired(pkgDir string, m *Manifest) {
	data, err := os.ReadFile(filepath.Join(pkgDir, "normalized", retiredFile))
	if errors.Is(err, os.ErrNotExist) || err != nil {
		return
	}
	var r map[string]int
	if json.Unmarshal(data, &r) == nil {
		m.retired = r
	}
}
