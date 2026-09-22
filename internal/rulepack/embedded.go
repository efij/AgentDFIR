package rulepack

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// The shipped rule packs travel inside the binary.
//
// They used to live only in rules/ at the repository root, loadable with
// `analyze --rules <dir>`. Nothing set that flag by default, `run` did not
// have it at all, and the release archives contain only the binary — so on
// any installed copy the packs never ran. A machine that reported 1,519
// findings had produced every one of them from the built-in Go rules, with
// 80 declared pack rules sitting inert.
//
// Embedding keeps the single static portable binary and the one-file
// installer, works air-gapped, and locks the rule set to the binary
// version, which is what makes a finding reproducible years later. Packs
// that need to ship between releases still go through the signed override
// mechanism (`packs` / `update-packs` / `sign --file`).
//
// packs/ is a byte-for-byte copy of rules/, refreshed by
// scripts/sync-packs.sh. //go:embed cannot reach outside its own package
// directory, and rules/ has to stay where it is because
// github.com/efij/agentdfir-rules mirrors it. TestEmbeddedPacksMatchRulesDir
// fails the build if the two drift.
//
//go:embed packs/*.json
var packFS embed.FS

// PackSource records which rule set produced a finding: name, version and
// the SHA-256 of the exact bytes that were evaluated. It is written into
// the analysis results so "which rules decided this" stays answerable long
// after the binary that ran them has been replaced.
type PackSource struct {
	Pack    string `json:"pack"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	Rules   int    `json:"rules"`
	Origin  string `json:"origin"` // "embedded" or the directory it was read from
}

// Embedded returns the packs compiled into this binary, with their
// provenance, sorted by pack name so results are deterministic.
func Embedded() ([]Pack, []PackSource, error) {
	entries, err := fs.ReadDir(packFS, "packs")
	if err != nil {
		return nil, nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	var packs []Pack
	var srcs []PackSource
	for _, name := range names {
		data, err := packFS.ReadFile(path.Join("packs", name))
		if err != nil {
			return nil, nil, err
		}
		p, err := parsePack(data)
		if err != nil {
			return nil, nil, fmt.Errorf("embedded pack %s: %w", name, err)
		}
		sum := sha256.Sum256(data)
		packs = append(packs, *p)
		srcs = append(srcs, PackSource{
			Pack: p.Pack, Version: p.Version, SHA256: hex.EncodeToString(sum[:]),
			Rules: len(p.Rules), Origin: "embedded",
		})
	}
	return packs, srcs, nil
}

// EmbeddedBytes exposes one embedded pack's raw bytes, for the parity test
// and for `rules export`.
func EmbeddedBytes(name string) ([]byte, error) {
	return packFS.ReadFile(path.Join("packs", name))
}

// EmbeddedNames lists the embedded pack file names.
func EmbeddedNames() ([]string, error) {
	entries, err := fs.ReadDir(packFS, "packs")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

// Dedupe drops rules whose ID was already seen in an earlier pack and
// reports what it dropped.
//
// Packs overlap: a rule may be promoted from the starter pack into the
// community pack and left in both. Without this, both fire and the analyst
// sees the same finding twice from the same evidence. First pack wins, so
// load order decides, and load order is deterministic.
func Dedupe(packs []Pack) ([]Pack, []string) {
	seen := map[string]string{}
	var dropped []string
	out := make([]Pack, 0, len(packs))
	for _, p := range packs {
		kept := make([]Rule, 0, len(p.Rules))
		for _, r := range p.Rules {
			if first, ok := seen[r.ID]; ok {
				dropped = append(dropped, fmt.Sprintf("%s (already in %s, ignored in %s)", r.ID, first, p.Pack))
				continue
			}
			seen[r.ID] = p.Pack
			kept = append(kept, r)
		}
		p.Rules = kept
		out = append(out, p)
	}
	return out, dropped
}

// parsePack unmarshals and validates one pack from bytes. LoadFile wraps it
// for the filesystem case.
func parsePack(data []byte) (*Pack, error) {
	var p Pack
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("invalid pack JSON: %w", err)
	}
	if err := validatePack(&p); err != nil {
		return nil, err
	}
	return &p, nil
}
