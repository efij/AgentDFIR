// Package mitre holds the pinned threat catalogs AgentDFIR maps its
// detections to, and the ATLAS relevance inventory that says, for every
// ATLAS technique, whether an endpoint and agent forensic tool can observe
// it and which rules and chains answer it.
//
// Everything here is embedded data, regenerated from exact upstream
// releases (go generate ./internal/mitre, pins in gen/main.go):
//
//   - data/atlas.json             MITRE ATLAS 2026.09: technique IDs, names, tactic membership
//   - data/attack-enterprise.json MITRE ATT&CK Enterprise v20.0: active techniques, revoked → replacement, deprecated
//   - data/owasp.json             OWASP Top 10 for LLM Applications 2025 and for Agentic Applications 2026 (hand-maintained)
//   - data/migrations.json        every catalog ID AgentDFIR stopped citing, and what replaced it
//   - data/atlas-relevance.json   one record per ATLAS technique (hand-maintained, CI-checked)
//
// The analysis path does not import this package: internal/rulepack keeps
// its own generated ATLAS table, so editing the relevance inventory never
// changes the analysis fingerprint.
package mitre

import (
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
)

//go:generate go run ./gen -out data

// Pinned catalog versions. TestPinnedVersions keeps them equal to the data.
const (
	ATLASVersion  = "2026.09"
	ATTACKVersion = "20.0"
)

//go:embed data/*.json
var dataFS embed.FS

// Tactic is an ATLAS tactic.
type Tactic struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Technique is an ATLAS technique or sub-technique.
type Technique struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Tactics []string `json:"tactics"`
}

// ATLASCatalog is the embedded ATLAS release.
type ATLASCatalog struct {
	Catalog       string      `json:"catalog"`
	Version       string      `json:"version"`
	FormatVersion string      `json:"format_version"`
	SourceURL     string      `json:"source_url"`
	SHA256        string      `json:"sha256"`
	Tactics       []Tactic    `json:"tactics"`
	Techniques    []Technique `json:"techniques"`
}

// AttackTechnique is an ATT&CK Enterprise technique; RevokedBy is set for
// revoked ones and names the technique that replaced it.
type AttackTechnique struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	RevokedBy string `json:"revoked_by,omitempty"`
}

// ATTACKCatalog is the embedded ATT&CK Enterprise release.
type ATTACKCatalog struct {
	Catalog    string            `json:"catalog"`
	Version    string            `json:"version"`
	SourceURL  string            `json:"source_url"`
	SHA256     string            `json:"sha256"`
	Techniques []AttackTechnique `json:"techniques"`
	Revoked    []AttackTechnique `json:"revoked"`
	Deprecated []AttackTechnique `json:"deprecated"`
}

// OWASPItem is one entry of an OWASP Top 10 list.
type OWASPItem struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// OWASPList is one pinned OWASP Top 10.
type OWASPList struct {
	Name      string      `json:"name"`
	Version   string      `json:"version"`
	SourceURL string      `json:"source_url"`
	Items     []OWASPItem `json:"items"`
}

// Migration records an ID AgentDFIR used to cite and what replaced it.
type Migration struct {
	Old     string `json:"old"`
	New     string `json:"new"`
	Catalog string `json:"catalog"` // "ATT&CK Enterprise" | "ATLAS"
	Version string `json:"version"` // catalog release that forced the change
	Reason  string `json:"reason"`
}

// Relevance classes.
const (
	ClassDirect       = "direct"       // the technique itself leaves agent/endpoint evidence AgentDFIR reads
	ClassSupporting   = "supporting"   // only its precursors or effects are observable
	ClassOutOfScope   = "out_of_scope" // happens outside the systems AgentDFIR examines
	ClassUnobservable = "unobservable" // in scope, but leaves no evidence AgentDFIR can read
)

// Entry is one record of the ATLAS relevance inventory.
type Entry struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Class           string   `json:"class"`
	Priority        string   `json:"priority"` // P0 | P1 | P2; empty for out_of_scope
	Rationale       string   `json:"rationale"`
	EvidenceSources []string `json:"evidence_sources"`
	Rules           []string `json:"rules"`
	Chains          []string `json:"chains"`
	OWASP           []string `json:"owasp"`
	Tests           []string `json:"tests"`
	Exception       string   `json:"exception,omitempty"`
	Planned         []string `json:"planned"`
}

// Observable reports whether the class is one AgentDFIR can see evidence of.
func (e Entry) Observable() bool {
	return e.Class == ClassDirect || e.Class == ClassSupporting
}

type db struct {
	atlas      ATLASCatalog
	attack     ATTACKCatalog
	owasp      []OWASPList
	migrations []Migration
	relevance  []Entry

	atlasByID  map[string]Technique
	tacticName map[string]string
	active     map[string]string
	revoked    map[string]AttackTechnique
	deprecated map[string]string
	owaspByID  map[string]OWASPItem
}

var (
	loadOnce sync.Once
	loaded   *db
	loadErr  error
)

func get() *db {
	loadOnce.Do(func() {
		loaded, loadErr = load()
		if loadErr != nil {
			loaded = &db{}
		}
	})
	return loaded
}

// Err reports whether the embedded tables failed to parse. Every lookup
// answers "unknown" in that case; TestEmbeddedDataLoads keeps it nil.
func Err() error {
	get()
	return loadErr
}

func load() (*db, error) {
	d := &db{}
	var owasp struct {
		Lists []OWASPList `json:"lists"`
	}
	var migrations struct {
		Migrations []Migration `json:"migrations"`
	}
	var relevance struct {
		Entries []Entry `json:"entries"`
	}
	for name, v := range map[string]any{
		"data/atlas.json":             &d.atlas,
		"data/attack-enterprise.json": &d.attack,
		"data/owasp.json":             &owasp,
		"data/migrations.json":        &migrations,
		"data/atlas-relevance.json":   &relevance,
	} {
		b, err := dataFS.ReadFile(name)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, v); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
	}
	d.owasp, d.migrations, d.relevance = owasp.Lists, migrations.Migrations, relevance.Entries

	d.atlasByID = map[string]Technique{}
	for _, t := range d.atlas.Techniques {
		d.atlasByID[t.ID] = t
	}
	d.tacticName = map[string]string{}
	for _, t := range d.atlas.Tactics {
		d.tacticName[t.ID] = t.Name
	}
	d.active = map[string]string{}
	for _, t := range d.attack.Techniques {
		d.active[t.ID] = t.Name
	}
	d.revoked = map[string]AttackTechnique{}
	for _, t := range d.attack.Revoked {
		d.revoked[t.ID] = t
	}
	d.deprecated = map[string]string{}
	for _, t := range d.attack.Deprecated {
		d.deprecated[t.ID] = t.Name
	}
	d.owaspByID = map[string]OWASPItem{}
	for _, l := range d.owasp {
		for _, it := range l.Items {
			d.owaspByID[it.ID] = it
		}
	}
	return d, nil
}

// ATLAS returns the embedded ATLAS catalog.
func ATLAS() ATLASCatalog { return get().atlas }

// ValidATLAS reports whether id is a technique or sub-technique in ATLAS 2026.09.
func ValidATLAS(id string) bool {
	_, ok := get().atlasByID[id]
	return ok
}

// ATLASTechnique looks up an ATLAS technique.
func ATLASTechnique(id string) (Technique, bool) {
	t, ok := get().atlasByID[id]
	return t, ok
}

// ATLASName returns the ATLAS technique name, or "" when unknown.
func ATLASName(id string) string { return get().atlasByID[id].Name }

// ATLASTacticName returns the ATLAS tactic name, or "" when unknown.
func ATLASTacticName(id string) string { return get().tacticName[id] }

// ATTACK returns the embedded ATT&CK Enterprise catalog.
func ATTACK() ATTACKCatalog { return get().attack }

// ATT&CK technique status values.
const (
	StatusActive     = "active"
	StatusRevoked    = "revoked"
	StatusDeprecated = "deprecated"
	StatusUnknown    = "unknown"
)

// ATTACKStatus classifies an ATT&CK Enterprise technique ID in v20.0.
func ATTACKStatus(id string) string {
	d := get()
	switch {
	case d.active[id] != "":
		return StatusActive
	case d.revoked[id].ID != "":
		return StatusRevoked
	case d.deprecated[id] != "":
		return StatusDeprecated
	}
	return StatusUnknown
}

// ValidATTACK reports whether id is an active (not revoked, not
// deprecated) ATT&CK Enterprise v20.0 technique or sub-technique.
func ValidATTACK(id string) bool { return get().active[id] != "" }

// ATTACKName returns the name of an active technique, or "".
func ATTACKName(id string) string { return get().active[id] }

// ATTACKRevokedBy returns the technique that replaced a revoked ID.
func ATTACKRevokedBy(id string) (string, bool) {
	t, ok := get().revoked[id]
	return t.RevokedBy, ok
}

// OWASP returns the pinned OWASP Top 10 lists.
func OWASP() []OWASPList { return get().owasp }

// ValidOWASP reports whether id (LLM01…LLM10, ASI01…ASI10) is in a pinned list.
func ValidOWASP(id string) bool {
	_, ok := get().owaspByID[id]
	return ok
}

// OWASPName returns the OWASP entry name, or "".
func OWASPName(id string) string { return get().owaspByID[id].Name }

// Migrations returns every recorded ID migration.
func Migrations() []Migration { return append([]Migration(nil), get().migrations...) }

// Relevance returns the ATLAS relevance inventory sorted by technique ID.
func Relevance() []Entry {
	out := append([]Entry(nil), get().relevance...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
