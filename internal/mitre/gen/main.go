// Command gen regenerates the pinned MITRE catalog tables embedded by
// internal/mitre (and the ATLAS ID table internal/rulepack keeps for the
// analysis path) from exact upstream releases.
//
//	go run ./internal/mitre/gen [-atlas ATLAS-2026.09.yaml] [-attack enterprise-attack-20.0.json] [-only atlas|attack]
//
// Each source is a pinned release with a pinned SHA-256. A local file is
// used when given (flag, or $ATLAS_YAML / $ATTACK_JSON); otherwise the
// pinned URL is downloaded. Either way the bytes are hashed and rejected
// unless they match the pin, before anything is parsed. Nothing here ever
// reads a floating "latest": moving to a new release means changing the
// pin below, which is a reviewed code change.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Pinned upstream releases.
const (
	atlasVersion = "2026.09"
	atlasURL     = "https://github.com/mitre-atlas/atlas-data/releases/download/v2026.09/ATLAS-2026.09.yaml"
	atlasSHA256  = "935efa93e28294432d3e2f537eb94991ef8d1f8c58341cd360ea3321ddb66688"
	atlasCount   = 208 // 120 techniques + 88 sub-techniques

	attackVersion = "20.0"
	attackURL     = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-20.0.json"
	attackSHA256  = "81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352"
)

// maxSource bounds a download or local read; the ATT&CK bundle is ~55 MB.
const maxSource = 256 << 20

func main() {
	atlasPath := flag.String("atlas", os.Getenv("ATLAS_YAML"), "local ATLAS-"+atlasVersion+".yaml (default: download the pinned release)")
	attackPath := flag.String("attack", os.Getenv("ATTACK_JSON"), "local enterprise-attack-"+attackVersion+".json (default: download the pinned release)")
	only := flag.String("only", "", "regenerate only one catalog: atlas | attack")
	out := flag.String("out", "data", "output directory for the embedded tables")
	rulepackOut := flag.String("rulepack", filepath.Join("..", "rulepack", "atlas_ids.go"), "rulepack ATLAS table to regenerate (empty to skip)")
	flag.Parse()

	if *only == "" || *only == "atlas" {
		if err := genATLAS(*atlasPath, *out, *rulepackOut); err != nil {
			fmt.Fprintln(os.Stderr, "atlas:", err)
			os.Exit(1)
		}
	}
	if *only == "" || *only == "attack" {
		if err := genATTACK(*attackPath, *out); err != nil {
			fmt.Fprintln(os.Stderr, "attack:", err)
			os.Exit(1)
		}
	}
}

// fetchPinned returns the source bytes after checking them against the pin.
func fetchPinned(local, url, sum string) ([]byte, error) {
	var data []byte
	if local != "" {
		f, err := os.Open(local)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		data, err = io.ReadAll(io.LimitReader(f, maxSource+1))
		if err != nil {
			return nil, err
		}
	} else {
		c := &http.Client{Timeout: 5 * time.Minute}
		resp, err := c.Get(url)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
		}
		data, err = io.ReadAll(io.LimitReader(resp.Body, maxSource+1))
		if err != nil {
			return nil, err
		}
	}
	if len(data) > maxSource {
		return nil, fmt.Errorf("source larger than %d bytes", maxSource)
	}
	got := sha256.Sum256(data)
	if hex.EncodeToString(got[:]) != sum {
		return nil, fmt.Errorf("sha256 %x does not match the pinned %s; refusing to use it", got, sum)
	}
	return data, nil
}

type tactic struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type atlasTechnique struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Tactics []string `json:"tactics"`
}

var (
	reTacticKey    = regexp.MustCompile(`^  (AML\.TA\d{4}):\s*$`)
	reTechniqueKey = regexp.MustCompile(`^  (AML\.T\d{4}(?:\.\d{3})?):\s*$`)
	reAnyKey       = regexp.MustCompile(`^  (\S+):\s*$`)
	reName         = regexp.MustCompile(`^    name: (.+)$`)
	reKind         = regexp.MustCompile(`^    ([a-z-]+):\s*$`)
	reTarget       = regexp.MustCompile(`^      target: (\S+)\s*$`)
	reSection      = regexp.MustCompile(`^([a-z-]+):`)
	reCollVersion  = regexp.MustCompile(`^  version: (.+)$`)
	reFormat       = regexp.MustCompile(`^format-version: (.+)$`)
)

// parseATLAS reads the format-6.0.0 release: techniques are a map under
// `techniques:` keyed by ID, tactic membership is the `achieves`
// relationship under `relationships:`.
func parseATLAS(data []byte) (format, version string, tactics []tactic, techs []atlasTechnique, err error) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	section, cur, kind := "", "", ""
	byID := map[string]*atlasTechnique{}
	tacticNames := map[string]string{}
	var order []string
	for sc.Scan() {
		line := sc.Text()
		if m := reSection.FindStringSubmatch(line); m != nil {
			section, cur, kind = m[1], "", ""
			if m := reFormat.FindStringSubmatch(line); m != nil {
				format = unquote(m[1])
			}
			continue
		}
		switch section {
		case "collection":
			if m := reCollVersion.FindStringSubmatch(line); m != nil {
				version = unquote(m[1])
			}
		case "tactics":
			if m := reTacticKey.FindStringSubmatch(line); m != nil {
				cur = m[1]
			} else if m := reName.FindStringSubmatch(line); m != nil && cur != "" && tacticNames[cur] == "" {
				tacticNames[cur] = unquote(m[1])
			}
		case "techniques":
			if m := reTechniqueKey.FindStringSubmatch(line); m != nil {
				cur = m[1]
				if byID[cur] != nil {
					return "", "", nil, nil, fmt.Errorf("duplicate technique %s", cur)
				}
				byID[cur] = &atlasTechnique{ID: cur}
				order = append(order, cur)
			} else if reAnyKey.MatchString(line) {
				cur = ""
			} else if m := reName.FindStringSubmatch(line); m != nil && cur != "" && byID[cur].Name == "" {
				byID[cur].Name = unquote(m[1])
			}
		case "relationships":
			if m := reAnyKey.FindStringSubmatch(line); m != nil {
				cur, kind = m[1], ""
			} else if m := reKind.FindStringSubmatch(line); m != nil {
				kind = m[1]
			} else if m := reTarget.FindStringSubmatch(line); m != nil && kind == "achieves" {
				if t := byID[cur]; t != nil && strings.HasPrefix(m[1], "AML.TA") {
					t.Tactics = append(t.Tactics, m[1])
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		return "", "", nil, nil, err
	}
	for id, n := range tacticNames {
		tactics = append(tactics, tactic{ID: id, Name: n})
	}
	sort.Slice(tactics, func(i, j int) bool { return tactics[i].ID < tactics[j].ID })
	sort.Strings(order)
	for _, id := range order {
		t := byID[id]
		if t.Name == "" {
			return "", "", nil, nil, fmt.Errorf("technique %s has no name", id)
		}
		sort.Strings(t.Tactics)
		t.Tactics = dedupe(t.Tactics)
		for _, ta := range t.Tactics {
			if tacticNames[ta] == "" {
				return "", "", nil, nil, fmt.Errorf("technique %s achieves unknown tactic %s", id, ta)
			}
		}
		techs = append(techs, *t)
	}
	return format, version, tactics, techs, nil
}

func genATLAS(local, out, rulepackOut string) error {
	data, err := fetchPinned(local, atlasURL, atlasSHA256)
	if err != nil {
		return err
	}
	format, version, tactics, techs, err := parseATLAS(data)
	if err != nil {
		return err
	}
	if version != atlasVersion {
		return fmt.Errorf("collection version %q, pinned %q", version, atlasVersion)
	}
	if format != "6.0.0" {
		return fmt.Errorf("format-version %q, parser expects 6.0.0", format)
	}
	if len(techs) != atlasCount {
		return fmt.Errorf("%d techniques, the pinned release has %d", len(techs), atlasCount)
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "{\n  \"catalog\": \"MITRE ATLAS\",\n  \"version\": %q,\n  \"format_version\": %q,\n  \"source_url\": %q,\n  \"sha256\": %q,\n",
		version, format, atlasURL, atlasSHA256)
	writeList(&b, "tactics", len(tactics), func(i int) any { return tactics[i] }, false)
	writeList(&b, "techniques", len(techs), func(i int) any { return techs[i] }, true)
	b.WriteString("}\n")
	path := filepath.Join(out, "atlas.json")
	if err := os.WriteFile(path, b.Bytes(), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s: ATLAS %s, %d techniques, %d tactics\n", path, version, len(techs), len(tactics))
	if rulepackOut == "" {
		return nil
	}
	return writeRulepackTable(rulepackOut, version, techs)
}

// writeRulepackTable keeps internal/rulepack's own ATLAS table. The
// analysis path validates chain and pack ATLAS IDs at load time; keeping
// that table in rulepack (rather than importing internal/mitre) keeps the
// relevance inventory out of the analysis fingerprint.
func writeRulepackTable(path, version string, techs []atlasTechnique) error {
	var b bytes.Buffer
	fmt.Fprintf(&b, "// Code generated from MITRE ATLAS %s (%s, sha256 %s); DO NOT EDIT.\n", version, filepath.Base(atlasURL), atlasSHA256)
	b.WriteString("// Regenerate: scripts/gen-atlas-ids.sh (go run ./internal/mitre/gen).\n\npackage rulepack\n\n")
	b.WriteString("// ATLASVersion is the ATLAS release the technique table was generated from.\n")
	fmt.Fprintf(&b, "const ATLASVersion = %q\n\n", version)
	b.WriteString("// atlasTechniques lists every technique and sub-technique ID in that release.\nvar atlasTechniques = map[string]string{\n")
	for _, t := range techs {
		fmt.Fprintf(&b, "\t%q: %q,\n", t.ID, t.Name)
	}
	b.WriteString("}\n")
	if err := os.WriteFile(path, b.Bytes(), 0o644); err != nil {
		return err
	}
	if gofmt, err := exec.LookPath("gofmt"); err == nil {
		if err := exec.Command(gofmt, "-w", path).Run(); err != nil {
			return err
		}
	}
	fmt.Printf("wrote %s\n", path)
	return nil
}

// stixObject is the subset of a STIX 2.1 object the ATT&CK table needs.
type stixObject struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
	Name       string `json:"name"`
	Revoked    bool   `json:"revoked"`
	Deprecated bool   `json:"x_mitre_deprecated"`
	ExtRefs    []struct {
		SourceName string `json:"source_name"`
		ExternalID string `json:"external_id"`
	} `json:"external_references"`
	RelType   string `json:"relationship_type"`
	SourceRef string `json:"source_ref"`
	TargetRef string `json:"target_ref"`
	Version   string `json:"x_mitre_version"`
}

type attackTechnique struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type attackRevoked struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	RevokedBy string `json:"revoked_by"`
}

var reAttackID = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)

func genATTACK(local, out string) error {
	data, err := fetchPinned(local, attackURL, attackSHA256)
	if err != nil {
		return err
	}
	var bundle struct {
		Objects []stixObject `json:"objects"`
	}
	if err := json.Unmarshal(data, &bundle); err != nil {
		return err
	}
	ext := func(o *stixObject) string {
		for _, r := range o.ExtRefs {
			if r.SourceName == "mitre-attack" {
				return r.ExternalID
			}
		}
		return ""
	}
	patterns := map[string]*stixObject{}
	version := ""
	for i := range bundle.Objects {
		o := &bundle.Objects[i]
		switch o.Type {
		case "attack-pattern":
			patterns[o.ID] = o
		case "x-mitre-collection":
			version = o.Version
		}
	}
	if version != attackVersion {
		return fmt.Errorf("collection version %q, pinned %q", version, attackVersion)
	}
	revokedBy := map[string]string{}
	for i := range bundle.Objects {
		o := &bundle.Objects[i]
		if o.Type != "relationship" || o.RelType != "revoked-by" {
			continue
		}
		s, t := patterns[o.SourceRef], patterns[o.TargetRef]
		if s != nil && t != nil {
			revokedBy[s.ID] = ext(t)
		}
	}
	var active []attackTechnique
	var revoked []attackRevoked
	var deprecated []attackTechnique
	seen := map[string]bool{}
	for _, o := range patterns {
		id := ext(o)
		if !reAttackID.MatchString(id) {
			continue
		}
		if seen[id] {
			return fmt.Errorf("technique %s appears twice", id)
		}
		seen[id] = true
		switch {
		case o.Revoked:
			revoked = append(revoked, attackRevoked{ID: id, Name: o.Name, RevokedBy: revokedBy[o.ID]})
		case o.Deprecated:
			deprecated = append(deprecated, attackTechnique{ID: id, Name: o.Name})
		default:
			active = append(active, attackTechnique{ID: id, Name: o.Name})
		}
	}
	sort.Slice(active, func(i, j int) bool { return active[i].ID < active[j].ID })
	sort.Slice(revoked, func(i, j int) bool { return revoked[i].ID < revoked[j].ID })
	sort.Slice(deprecated, func(i, j int) bool { return deprecated[i].ID < deprecated[j].ID })
	if len(active) < 500 {
		return fmt.Errorf("suspiciously few active techniques (%d)", len(active))
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "{\n  \"catalog\": \"MITRE ATT&CK Enterprise\",\n  \"version\": %q,\n  \"source_url\": %q,\n  \"sha256\": %q,\n",
		version, attackURL, attackSHA256)
	writeList(&b, "techniques", len(active), func(i int) any { return active[i] }, false)
	writeList(&b, "revoked", len(revoked), func(i int) any { return revoked[i] }, false)
	writeList(&b, "deprecated", len(deprecated), func(i int) any { return deprecated[i] }, true)
	b.WriteString("}\n")
	path := filepath.Join(out, "attack-enterprise.json")
	if err := os.WriteFile(path, b.Bytes(), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s: ATT&CK Enterprise %s, %d active, %d revoked, %d deprecated\n", path, version, len(active), len(revoked), len(deprecated))
	return nil
}

// writeList writes one JSON array member per line so table diffs stay
// readable across catalog upgrades.
func writeList(b *bytes.Buffer, key string, n int, at func(int) any, last bool) {
	fmt.Fprintf(b, "  %q: [", key)
	for i := 0; i < n; i++ {
		j, _ := json.Marshal(at(i))
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString("\n    ")
		b.Write(j)
	}
	if n > 0 {
		b.WriteString("\n  ")
	}
	b.WriteString("]")
	if !last {
		b.WriteString(",")
	}
	b.WriteString("\n")
}

// unquote handles the YAML scalar forms the ATLAS release uses for names.
func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		var v string
		if json.Unmarshal([]byte(s), &v) == nil {
			return v
		}
		return s[1 : len(s)-1]
	}
	return s
}

func dedupe(in []string) []string {
	out := in[:0]
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}
