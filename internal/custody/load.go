package custody

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// All is the case's whole custody record: the sealed log and the
// post-seal activity log, each with its chain state.
type All struct {
	Sealed           []Record
	SealedChainErr   string
	Activity         []Record
	ActivityChainErr string
}

// Load reads both logs of a package.
func Load(pkg string) (*All, error) {
	f, err := os.Open(filepath.Join(pkg, "chain-of-custody.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("%s is not an evidence package: %w", pkg, err)
	}
	all := &All{}
	all.Sealed, all.SealedChainErr, err = decode(f)
	f.Close()
	if err != nil {
		return nil, err
	}
	all.Activity, all.ActivityChainErr, err = Read(pkg)
	if err != nil {
		return nil, err
	}
	return all, nil
}

// Describe renders a record's event-specific fields on one line.
func Describe(r Record) string {
	var parts []string
	for _, k := range r.SortedFieldKeys() {
		v := r.FieldString(k)
		if v == "" || v == "null" || v == "0" || v == "[]" {
			continue
		}
		if len(v) > 80 {
			v = v[:77] + "…"
		}
		parts = append(parts, k+"="+v)
	}
	sort.Strings(parts)
	return strings.Join(parts, " ")
}
