// Package crosscase reports what two or more cases have in common: the
// same outbound destinations, incident indicators, credentials (by
// fingerprint, never by value), instruction files, MCP servers and tool
// definitions, reused session and agent ids, and AI logins.
//
// It reads only analyzed, verified packages. Each package's seal is
// checked first; one that fails is refused unless the analyst asks for
// it, and then every result says it includes an unverified case. Results
// are computed from the stored analysis overlay; a package whose analysis
// is missing or was produced by different analysis code is refused with
// the command that brings it up to date, so two cases are never compared
// through two different rule sets.
//
// Identity is never inferred. Hosts and OS users are listed per case and
// stay separate entities. Two cases' identities are linked only when the
// evidence carries the same exact identifier — an AI account email or an
// account uuid read from the login files — and the link names that
// identifier. A shared host name is reported as a shared name, not as the
// same machine.
package crosscase

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/accounts"
	"github.com/efij/AgentDFIR/v4/internal/analysis"
	"github.com/efij/AgentDFIR/v4/internal/casepkg"
	"github.com/efij/AgentDFIR/v4/internal/detect"
	"github.com/efij/AgentDFIR/v4/internal/ioc"
	"github.com/efij/AgentDFIR/v4/internal/mcpaudit"
	"github.com/efij/AgentDFIR/v4/internal/netdest"
	"github.com/efij/AgentDFIR/v4/internal/overlay"
	"github.com/efij/AgentDFIR/v4/internal/schema"
	"github.com/efij/AgentDFIR/v4/internal/seal"
)

// Schema identifies the document this package writes.
const Schema = "agentdfir.crosscase/1"

// Shared-item kinds, in reporting order.
const (
	KindAccount     = "account"
	KindIOC         = "ioc"
	KindSecret      = "secret_fingerprint"
	KindNetwork     = "network_destination"
	KindMCP         = "mcp_server"
	KindToolDef     = "tool_definition"
	KindInstruction = "instruction_file"
	KindSession     = "session_id"
	KindAgent       = "agent_id"
	KindHostName    = "host_name"
)

var kindRank = map[string]int{KindAccount: 0, KindIOC: 1, KindSecret: 2, KindNetwork: 3, KindMCP: 4, KindToolDef: 5,
	KindInstruction: 6, KindSession: 7, KindAgent: 8, KindHostName: 9}

// Options control loading and output.
type Options struct {
	AllowUnverified bool // compare packages whose seal does not verify, marking every result
	IncludeCommon   bool // also list allowlisted destinations (model providers, package registries)
	MaxTimeline     int  // default 2000
	MaxSecretBytes  int64
	// Verify checks one package; nil uses the full seal check (casepkg.Verify
	// and the signature). Tests substitute a cheaper or failing one.
	Verify func(pkg string) Integrity
}

// Report is the whole result.
type Report struct {
	Schema     string          `json:"schema"`
	Unverified bool            `json:"includes_unverified_cases"`
	Cases      []Case          `json:"cases"`
	Shared     []Shared        `json:"shared"`
	Links      []IdentityLink  `json:"identity_links"`
	Timeline   []TimelineEntry `json:"timeline"`
	Omitted    map[string]int  `json:"omitted,omitempty"`
	Notes      []string        `json:"notes"`
	Limits     []string        `json:"limits"`
}

// Case is one input package.
type Case struct {
	Label     string        `json:"label"` // C1, C2, … in argument order
	Path      string        `json:"path"`
	CaseID    string        `json:"case_id"`
	Host      string        `json:"host"`
	OS        string        `json:"os,omitempty"`
	OSUsers   []string      `json:"os_users"`
	Integrity Integrity     `json:"integrity"`
	Accounts  []AccountInfo `json:"accounts"`
	Events    int           `json:"events"`
	Findings  int           `json:"findings"`
}

// Integrity is the outcome of checking a package's seal.
type Integrity struct {
	Result    string   `json:"result"` // VERIFIED | FAILED
	Signature string   `json:"signature"`
	Problems  []string `json:"problems,omitempty"`
}

// AccountInfo is one AI login in a case, by the identifiers that can link
// it to another case.
type AccountInfo struct {
	Profile     string `json:"profile"`
	Product     string `json:"product"`
	Email       string `json:"email,omitempty"`
	AccountUUID string `json:"account_uuid,omitempty"`
	Source      string `json:"login_source,omitempty"`
}

// Shared is one item seen in at least two cases.
type Shared struct {
	Kind    string       `json:"kind"`
	Key     string       `json:"key"`
	Display string       `json:"display"`
	Note    string       `json:"note,omitempty"`
	Cases   []Occurrence `json:"cases"`
}

// Occurrence is the item in one case.
type Occurrence struct {
	Case       string   `json:"case"`
	Count      int      `json:"count"`
	FirstSeen  string   `json:"first_seen,omitempty"`
	LastSeen   string   `json:"last_seen,omitempty"`
	TimeSource string   `json:"time_source,omitempty"` // transcript | file_mtime | ioc_hunt
	Where      []string `json:"where,omitempty"`
	Refs       []string `json:"evidence_refs,omitempty"`
	Unverified bool     `json:"from_unverified_case,omitempty"`
}

// IdentityLink is two or more cases' entities tied by one exact identifier.
type IdentityLink struct {
	Identifier string   `json:"identifier"` // email | account_uuid
	Value      string   `json:"value"`
	Entities   []string `json:"entities"`
}

// TimelineEntry places one shared item in one case in time.
type TimelineEntry struct {
	Time       string `json:"time"`
	TimeSource string `json:"time_source"`
	Case       string `json:"case"`
	Kind       string `json:"kind"`
	Key        string `json:"key"`
	Display    string `json:"display"`
	Event      string `json:"event"` // first_seen | last_seen
}

const (
	maxRefs  = 3
	maxWhere = 5
)

// Run loads, verifies and compares the packages.
func Run(pkgs []string, o Options) (*Report, error) {
	if len(pkgs) < 2 {
		return nil, errors.New("need at least two packages")
	}
	if o.MaxTimeline <= 0 {
		o.MaxTimeline = 2000
	}
	if o.MaxSecretBytes <= 0 {
		o.MaxSecretBytes = 512 << 20
	}
	if o.Verify == nil {
		o.Verify = VerifyPackage
	}
	seen := map[string]bool{}
	for _, p := range pkgs {
		abs, err := filepath.Abs(p)
		if err != nil {
			return nil, err
		}
		if seen[abs] {
			return nil, fmt.Errorf("%s is listed twice", p)
		}
		seen[abs] = true
	}
	rep := &Report{Schema: Schema, Shared: []Shared{}, Links: []IdentityLink{}, Timeline: []TimelineEntry{}, Notes: []string{}}
	var loaded []*caseData
	var refused []string
	for i, p := range pkgs {
		label := fmt.Sprintf("C%d", i+1)
		if why := analysis.StaleReason(p); why != "" {
			refused = append(refused, fmt.Sprintf("%s (%s): analysis is not current (%s). Run: agentdfir analyze %s", label, p, why, p))
			continue
		}
		integ := o.Verify(p)
		if integ.Result != "VERIFIED" && !o.AllowUnverified {
			refused = append(refused, fmt.Sprintf("%s (%s): seal does not verify (%s). Pass --allow-unverified to compare it anyway; every result is then marked.",
				label, p, strings.Join(integ.Problems, "; ")))
			continue
		}
		cd, err := load(label, p, integ, o)
		if err != nil {
			refused = append(refused, fmt.Sprintf("%s (%s): %v", label, p, err))
			continue
		}
		loaded = append(loaded, cd)
	}
	if len(refused) > 0 {
		return nil, &RefusedError{Problems: refused}
	}
	for _, cd := range loaded {
		rep.Cases = append(rep.Cases, cd.info)
		if cd.info.Integrity.Result != "VERIFIED" {
			rep.Unverified = true
		}
		rep.Notes = append(rep.Notes, cd.notes...)
	}
	compare(rep, loaded, o)
	rep.Limits = []string{
		"Only exact identifiers link identities: an account email or account uuid read from collected login files. Hosts, OS users and profile names are never merged.",
		"A shared host name or session id can be two copies of the same machine's evidence; the cases' paths, case ids and collection times tell which.",
		"Secrets are compared by a truncated SHA-256 fingerprint of the value; the value itself is never read into the report.",
		"Allowlisted destinations (model providers, package registries) are left out unless --include-common is given: nearly every case shares them.",
		"Only what each package's stored analysis and sealed evidence hold is compared; indicators not collected in a case cannot be shared by it.",
	}
	return rep, nil
}

// RefusedError lists every package that could not be compared and why.
type RefusedError struct{ Problems []string }

func (e *RefusedError) Error() string {
	return "cannot compare:\n  " + strings.Join(e.Problems, "\n  ")
}

// VerifyPackage is the full seal check `agentdfir verify` runs: every blob
// re-hashed, both hash chains, and the signature when one is present.
func VerifyPackage(pkg string) Integrity {
	in := Integrity{Result: "VERIFIED", Signature: "none"}
	res, err := casepkg.Verify(pkg)
	if err != nil {
		return Integrity{Result: "FAILED", Signature: "unknown", Problems: []string{err.Error()}}
	}
	in.Problems = append(in.Problems, res.Problems...)
	sig, err := seal.Verify(pkg, "")
	switch {
	case err != nil:
		in.Signature = "error"
		in.Problems = append(in.Problems, "SEAL.sig: "+err.Error())
	case !sig.Present:
	case sig.Valid:
		in.Signature = "valid"
	default:
		in.Signature = "INVALID"
		in.Problems = append(in.Problems, "SEAL.sig: "+sig.Reason)
	}
	if len(in.Problems) > 0 {
		in.Result = "FAILED"
	}
	return in
}

// ---- loading

type occ struct {
	count       int
	first, last time.Time
	timeSource  string
	where       map[string]bool
	refs        []string
	display     string
	note        string
}

type caseData struct {
	info  Case
	items map[string]map[string]*occ // kind → key → occurrence
	notes []string
}

func (cd *caseData) add(kind, key, display string, t time.Time, src, where, ref string) *occ {
	if key == "" {
		return nil
	}
	// Everything here is printed and written out. Credential-format values
	// are masked to their type and fingerprint in every field, the key
	// included (the fingerprint keeps distinct values distinct).
	key, display, where, ref = detect.MaskSecrets(key), detect.MaskSecrets(display), detect.MaskSecrets(where), detect.MaskSecrets(ref)
	m := cd.items[kind]
	if m == nil {
		m = map[string]*occ{}
		cd.items[kind] = m
	}
	o := m[key]
	if o == nil {
		o = &occ{display: display, where: map[string]bool{}}
		m[key] = o
	}
	o.count++
	if !t.IsZero() {
		if o.first.IsZero() || t.Before(o.first) {
			o.first = t
		}
		if t.After(o.last) {
			o.last = t
		}
		o.timeSource = src
	}
	if where != "" {
		o.where[where] = true
	}
	if ref != "" && len(o.refs) < maxRefs {
		o.refs = append(o.refs, ref)
	}
	return o
}

func load(label, pkg string, integ Integrity, o Options) (*caseData, error) {
	man, err := casepkg.ReadManifest(pkg)
	if err != nil {
		return nil, err
	}
	cd := &caseData{items: map[string]map[string]*occ{}}
	cd.info = Case{Label: label, Path: pkg, CaseID: man.CaseID, Host: man.Host, OS: man.OS, Integrity: integ, OSUsers: []string{}, Accounts: []AccountInfo{}}
	users := map[string]bool{}
	for _, a := range man.Current() {
		if a.User != "" {
			users[a.User] = true
		}
	}
	for u := range users {
		cd.info.OSUsers = append(cd.info.OSUsers, u)
	}
	sort.Strings(cd.info.OSUsers)
	events := analysis.LoadEvents(pkg)
	findings := analysis.LoadFindings(pkg)
	cd.info.Events, cd.info.Findings = len(events), len(findings)
	store := casepkg.NewStore(pkg, man)

	cd.add(KindHostName, strings.ToLower(man.Host), man.Host, time.Time{}, "", "", "")
	if o := cd.items[KindHostName][strings.ToLower(man.Host)]; o != nil {
		o.note = "a host name is not a unique machine identifier"
	}
	cd.loadAccounts(store, man)
	cd.loadEvents(events, o)
	cd.loadCorrelation(pkg, o)
	cd.loadHunt(pkg)
	cd.loadMCP(pkg)
	cd.loadInstructions(man)
	cd.loadSecrets(store, man, findings, o)
	return cd, nil
}

func (cd *caseData) loadAccounts(store *casepkg.Store, man *casepkg.Manifest) {
	accts, uuids := accounts.Identities(store, man.Current())
	for _, k := range sortedKeys(accts) {
		a := accts[k]
		ai := AccountInfo{Profile: a.Key, Product: a.Product, Email: a.Email, AccountUUID: uuids[k], Source: a.Source}
		cd.info.Accounts = append(cd.info.Accounts, ai)
		who := fmt.Sprintf("%s profile %s", accounts.ProductName(a.Product), a.Key)
		if a.Email != "" {
			cd.add(KindAccount, "email:"+strings.ToLower(a.Email), "account email "+a.Email, time.Time{}, "", who, a.Source)
		}
		if u := uuids[k]; u != "" {
			cd.add(KindAccount, "account_uuid:"+strings.ToLower(u), "account uuid "+u, time.Time{}, "", who, a.Source)
		}
	}
}

func (cd *caseData) loadEvents(events []schema.Event, o Options) {
	common := 0
	for _, ev := range events {
		t, _ := parseTS(ev.Timestamp)
		ref := evRef(ev)
		if ev.SessionID != "" {
			cd.add(KindSession, ev.SessionID, "session "+ev.SessionID, t, "transcript", ev.Product, "")
		}
		if ev.AgentID != "" && !strings.HasPrefix(ev.AgentID, "main:") {
			cd.add(KindAgent, ev.AgentID, "agent "+ev.AgentID, t, "transcript", ev.Product, "")
		}
		if ev.EventType != schema.EventToolCall {
			continue
		}
		dests := netdest.Extract(ev.FullCommand())
		if ev.NetworkDest != "" {
			dests = append(dests, ev.NetworkDest)
		}
		seen := map[string]bool{}
		for _, d := range dests {
			h := strings.ToLower(netdest.Host(d))
			if h == "" || seen[h] || isLoopback(h) {
				continue
			}
			seen[h] = true
			if !o.IncludeCommon && netdest.IsAllowed(h, nil) {
				common++
				continue
			}
			cd.add(KindNetwork, h, h, t, "transcript", "named in an agent command", ref)
		}
	}
	if common > 0 {
		cd.notes = append(cd.notes, fmt.Sprintf("%s: %d reference(s) to allowlisted destinations not compared (use --include-common)", cd.info.Label, common))
	}
}

func (cd *caseData) loadCorrelation(pkg string, o Options) {
	c := analysis.LoadCorrelation(pkg)
	if c == nil {
		return
	}
	for _, m := range c.Matches {
		recs := []struct {
			kind, host string
			t          time.Time
			ref        string
		}{{m.Record.Kind, destHost(m.Record.DestHost, m.Record.DestIP), m.Record.Time, m.Record.Source + " " + m.Record.Ref}}
		for _, r := range m.Related {
			recs = append(recs, struct {
				kind, host string
				t          time.Time
				ref        string
			}{r.Record.Kind, destHost(r.Record.DestHost, r.Record.DestIP), r.Record.Time, r.Record.Source + " " + r.Record.Ref})
		}
		for _, r := range recs {
			if r.kind != "network" || r.host == "" || isLoopback(r.host) || (!o.IncludeCommon && netdest.IsAllowed(r.host, nil)) {
				continue
			}
			cd.add(KindNetwork, r.host, r.host, r.t.UTC(), "endpoint_telemetry", "connected to (endpoint telemetry)", "telemetry "+r.ref)
		}
	}
}

func (cd *caseData) loadHunt(pkg string) {
	data, err := overlay.ReadFile(filepath.Join(pkg, "detections", "hunt.json"))
	if err != nil {
		return
	}
	var verdicts []ioc.Verdict
	if json.Unmarshal(data, &verdicts) != nil {
		cd.notes = append(cd.notes, cd.info.Label+": hunt.json unreadable; incident indicators not compared")
		return
	}
	for _, v := range verdicts {
		if v.Status != "HIT" {
			continue
		}
		for _, h := range v.Hits {
			key := v.Incident.ID + "|" + h.Indicator.Kind + ":" + strings.ToLower(h.Indicator.Value)
			disp := fmt.Sprintf("%s: %s %s", v.Incident.ID, h.Indicator.Kind, h.Indicator.Value)
			t, _ := parseTS(h.FirstSeen)
			o := cd.add(KindIOC, key, disp, t, "ioc_hunt", h.Surface, h.Evidence)
			if o != nil && h.Count > 1 {
				o.count += h.Count - 1
			}
			if lt, ok := parseTS(h.LastSeen); ok && o != nil && lt.After(o.last) {
				o.last = lt
			}
		}
	}
}

func (cd *caseData) loadMCP(pkg string) {
	data, err := overlay.ReadFile(filepath.Join(pkg, "detections", "mcp-audit.json"))
	if err != nil {
		return
	}
	var v struct {
		Inventory *mcpaudit.Inventory `json:"inventory"`
	}
	if json.Unmarshal(data, &v) != nil || v.Inventory == nil {
		cd.notes = append(cd.notes, cd.info.Label+": mcp-audit.json unreadable; MCP servers not compared")
		return
	}
	for _, s := range v.Inventory.Servers {
		where := s.Name + " in " + s.ConfigPath
		if s.Package != "" {
			if strings.Contains(s.Package, "://") {
				// git+https://user:token@host/… package refs carry URLs too.
				k, d := urlIdentity(s.Package)
				cd.add(KindMCP, "package_url:"+k, "MCP package "+d, time.Time{}, "", where, "")
			} else {
				cd.add(KindMCP, "package:"+strings.ToLower(s.Package), "MCP package "+s.Package, time.Time{}, "", where, "")
			}
		}
		if s.URL != "" {
			k, d := urlIdentity(s.URL)
			cd.add(KindMCP, "url:"+k, "MCP server URL "+d, time.Time{}, "", where, "")
		}
		if s.SHA256 != "" {
			cd.add(KindMCP, "binary:"+s.SHA256, "MCP server binary sha256:"+short(s.SHA256), time.Time{}, "", where, "")
		}
		for _, tl := range s.Tools {
			if tl.DefSHA256 != "" {
				cd.add(KindToolDef, tl.DefSHA256, fmt.Sprintf("tool definition %s (sha256:%s)", tl.Name, short(tl.DefSHA256)), time.Time{}, "", s.Name+"/"+tl.Name, "")
			}
		}
	}
}

// instructionRe names the standing-instruction files agents load into
// every session: the files whose content, shared across cases, means the
// same instructions reached both.
var instructionRe = regexp.MustCompile(`(?i)(^|/)(CLAUDE(\.local)?\.md|AGENTS?\.md|GEMINI\.md|\.cursorrules|\.windsurfrules|\.clinerules|copilot-instructions\.md|instructions\.md|memory\.md)$|(^|/)\.cursor/rules/|(^|/)\.github/instructions/|(^|/)\.claude/(agents|commands|skills)/`)

func (cd *caseData) loadInstructions(man *casepkg.Manifest) {
	for _, a := range man.Current() {
		if a.Status != casepkg.StatusOK || a.ArtifactID == "" || !instructionRe.MatchString(a.LogicalPath) {
			continue
		}
		t, _ := parseTS(a.ModTimeUTC)
		cd.add(KindInstruction, a.ArtifactID, fmt.Sprintf("%s (sha256:%s)", path.Base(a.LogicalPath), short(a.ArtifactID)), t, "file_mtime", a.LogicalPath, "")
	}
}

// secretRules are the findings whose cited artifacts hold credential
// material worth fingerprinting.
var secretRules = map[string]bool{"POTENTIAL_SECRET_EXPOSURE": true, "MCP_SECRET_IN_CONFIG": true}

func (cd *caseData) loadSecrets(store *casepkg.Store, man *casepkg.Manifest, findings []schema.Finding, o Options) {
	byPrefix := map[string]casepkg.ArtifactRecord{}
	for _, a := range man.Current() {
		if a.ArtifactID != "" && a.Status == casepkg.StatusOK {
			byPrefix[a.LogicalPath+"\x00"+short12(a.ArtifactID)] = a
		}
	}
	want := map[string]casepkg.ArtifactRecord{}
	for _, f := range findings {
		if !secretRules[f.RuleID] {
			continue
		}
		for _, r := range f.EvidenceRefs {
			p, id := splitRef(r)
			if a, ok := byPrefix[p+"\x00"+id]; ok {
				want[a.ArtifactID] = a
			}
		}
	}
	var budget int64
	for _, id := range sortedKeys(want) {
		a := want[id]
		if budget+a.Size > o.MaxSecretBytes {
			cd.notes = append(cd.notes, fmt.Sprintf("%s: secret fingerprinting stopped at %d MiB of evidence; remaining artifacts not fingerprinted", cd.info.Label, o.MaxSecretBytes>>20))
			break
		}
		budget += a.Size
		data, err := store.ReadAll(id, 64<<20)
		if err != nil {
			cd.notes = append(cd.notes, fmt.Sprintf("%s: %s not fingerprinted: %v", cd.info.Label, a.LogicalPath, err))
			continue
		}
		t, _ := parseTS(a.ModTimeUTC)
		for _, fp := range detect.SecretFingerprints(data) {
			o := cd.add(KindSecret, fp.Type+"|"+fp.Fingerprint, fmt.Sprintf("%s %s… %s", fp.Type, fp.Prefix, fp.Fingerprint), t, "file_mtime", a.LogicalPath,
				fmt.Sprintf("%s (artifact %s, byte offset %d)", a.LogicalPath, short12(a.ArtifactID), fp.FirstOffset))
			if o != nil && fp.Count > 1 {
				o.count += fp.Count - 1
			}
		}
	}
}

// ---- comparison

func compare(rep *Report, cases []*caseData, o Options) {
	type itemKey struct{ kind, key string }
	var keys []itemKey
	seen := map[itemKey]bool{}
	for _, cd := range cases {
		for kind, m := range cd.items {
			for key := range m {
				k := itemKey{kind, key}
				if !seen[k] {
					seen[k] = true
					keys = append(keys, k)
				}
			}
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if kindRank[keys[i].kind] != kindRank[keys[j].kind] {
			return kindRank[keys[i].kind] < kindRank[keys[j].kind]
		}
		return keys[i].key < keys[j].key
	})
	var timeline []TimelineEntry
	for _, k := range keys {
		var occs []Occurrence
		var display, note string
		for _, cd := range cases {
			oc := cd.items[k.kind][k.key]
			if oc == nil {
				continue
			}
			if display == "" {
				display, note = oc.display, oc.note
			}
			occ := Occurrence{Case: cd.info.Label, Count: oc.count, TimeSource: oc.timeSource, Refs: oc.refs,
				Unverified: cd.info.Integrity.Result != "VERIFIED"}
			if !oc.first.IsZero() {
				occ.FirstSeen, occ.LastSeen = rfc(oc.first), rfc(oc.last)
			}
			for _, w := range sortedKeys(oc.where) {
				if len(occ.Where) >= maxWhere {
					break
				}
				occ.Where = append(occ.Where, w)
			}
			occs = append(occs, occ)
		}
		if len(occs) < 2 {
			continue
		}
		rep.Shared = append(rep.Shared, Shared{Kind: k.kind, Key: k.key, Display: display, Note: note, Cases: occs})
		for _, oc := range occs {
			if oc.FirstSeen == "" {
				continue
			}
			timeline = append(timeline, TimelineEntry{Time: oc.FirstSeen, TimeSource: oc.TimeSource, Case: oc.Case, Kind: k.kind, Key: k.key, Display: display, Event: "first_seen"})
			if oc.LastSeen != oc.FirstSeen {
				timeline = append(timeline, TimelineEntry{Time: oc.LastSeen, TimeSource: oc.TimeSource, Case: oc.Case, Kind: k.kind, Key: k.key, Display: display, Event: "last_seen"})
			}
		}
		if k.kind == KindAccount {
			id, val, _ := strings.Cut(k.key, ":")
			link := IdentityLink{Identifier: id, Value: val}
			for _, oc := range occs {
				for _, w := range oc.Where {
					link.Entities = append(link.Entities, oc.Case+": "+w)
				}
			}
			rep.Links = append(rep.Links, link)
		}
	}
	sort.SliceStable(timeline, func(i, j int) bool {
		a, b := timeline[i], timeline[j]
		if a.Time != b.Time {
			return a.Time < b.Time
		}
		if a.Case != b.Case {
			return a.Case < b.Case
		}
		if kindRank[a.Kind] != kindRank[b.Kind] {
			return kindRank[a.Kind] < kindRank[b.Kind]
		}
		if a.Key != b.Key {
			return a.Key < b.Key
		}
		return a.Event < b.Event
	})
	if len(timeline) > o.MaxTimeline {
		if rep.Omitted == nil {
			rep.Omitted = map[string]int{}
		}
		rep.Omitted["timeline"] = len(timeline) - o.MaxTimeline
		timeline = timeline[:o.MaxTimeline]
	}
	rep.Timeline = append(rep.Timeline, timeline...)
}

// ---- helpers

func parseTS(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000Z", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func rfc(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func evRef(ev schema.Event) string {
	return fmt.Sprintf("%s:%d (artifact %s, offset %d)", ev.SourcePath, ev.SourceLine, short12(ev.SourceArtifact), ev.SourceOffset)
}

// splitRef pulls the logical path and the 12-character artifact id prefix
// out of "path[:line] (artifact <id>, …)".
func splitRef(ref string) (string, string) {
	i := strings.Index(ref, " (artifact ")
	if i < 0 {
		return "", ""
	}
	p, rest := ref[:i], ref[i+len(" (artifact "):]
	id := rest
	if j := strings.IndexAny(rest, ",)"); j >= 0 {
		id = rest[:j]
	}
	// An event reference carries ":<line>" after the path; an artifact
	// reference does not. Paths can contain ':' (C:/…), so only a numeric
	// suffix is stripped.
	if j := strings.LastIndexByte(p, ':'); j > 0 && isDigits(p[j+1:]) {
		p = p[:j]
	}
	return p, short12(strings.TrimSpace(id))
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func short(s string) string {
	if len(s) > 16 {
		return s[:16]
	}
	return s
}

func short12(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func destHost(host, ip string) string {
	if host != "" {
		return strings.ToLower(host)
	}
	return strings.ToLower(ip)
}

func isLoopback(h string) bool {
	return h == "localhost" || strings.HasPrefix(h, "127.") || h == "::1" || h == "0.0.0.0"
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
