// Package suite reads the exports of commercial and open-source forensic
// suites — Cellebrite UFDR report.xml and .ufd/.ufdx descriptors, Magnet
// AXIOM CSV exports (and Case.mfdb, which is inventoried only), Plaso
// psort timelines and Autopsy "Files - Text" reports — out of a sealed
// package and normalizes the records that concern AI applications and
// AI-service URLs.
//
// Evidence class "forensic-suite": every record here is another tool's
// decoding of the original evidence. An event says the suite reported a
// record, at the place in its export the event names; it is not the
// device's own record and never proof of execution. The originals stay
// sealed byte for byte, and only documented, generic structure is read:
//
//   - every format is read for a small set of supported fields;
//   - every other record or column is counted and left in the sealed file;
//   - a structure the reader does not know is reported UNSUPPORTED with a
//     reason (a trace_gap event with result "unsupported");
//   - device identifiers are masked in normalized output (mask.go).
//
// Events carry the timestamp source prefix "forensic_suite" so the
// per-artifact integrity rules treat an export as the multi-record store
// it is, not as a spliced transcript.
package suite

import (
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v5/internal/casepkg"
	"github.com/efij/AgentDFIR/v5/internal/parsers/segment"
	"github.com/efij/AgentDFIR/v5/internal/schema"
	"github.com/efij/AgentDFIR/v5/internal/version"
)

// IDFormat renders an event id from its sequence number.
const IDFormat = "evt-fs-%06d"

// EvidenceClass names what these events can prove; TimestampPrefix
// starts every event's timestamp source.
const (
	EvidenceClass   = "forensic-suite"
	TimestampPrefix = "forensic_suite"
)

// Results and actions.
const (
	actionRecord    = "suite_record"
	actionMeta      = "suite_metadata"
	actionInventory = "suite_inventory"
	resultUnsup     = "unsupported"
	resultUnparsed  = "unparsed"
	maxSummary      = 500
	maxEntityAttrs  = 160
)

// CaseDBUnsupported is the reason reported for every AXIOM Case.mfdb.
const CaseDBUnsupported = "AXIOM_CASE_DB_UNSUPPORTED: AXIOM Case.mfdb schema is undocumented; export to CSV/Portable Case from AXIOM and import that"

// ParsePackage parses every suite artifact in a sealed package.
func ParsePackage(pkgDir string) (*schema.Normalized, error) { return parseWith(pkgDir, nil, nil) }

// StreamPackage emits every event to sink instead of accumulating them.
func StreamPackage(pkgDir string, sink func(schema.Event)) (*schema.Normalized, error) {
	return parseWith(pkgDir, sink, nil)
}

// StreamPackageCached is StreamPackage with an overlay cache.
func StreamPackageCached(pkgDir string, sink func(schema.Event), cache segment.Cache) (*schema.Normalized, error) {
	return parseWith(pkgDir, sink, cache)
}

var parsedRules = map[string]bool{
	RuleUFDRReport: true, RuleUFD: true, RuleAxiomCSV: true, RuleAxiomCaseDB: true, RulePlaso: true, RuleAutopsy: true,
}

// Parses reports whether an artifact is one this parser reads. A Case.mfdb
// that was not sealed (over the size bound) is still reported, so the
// UNSUPPORTED notice is never lost.
func Parses(a casepkg.ArtifactRecord) bool {
	if a.CollectorRule == RuleAxiomCaseDB && a.Status != "" {
		return true
	}
	return a.Status == casepkg.StatusOK && parsedRules[a.CollectorRule]
}

func parseWith(pkgDir string, sink func(schema.Event), cache segment.Cache) (*schema.Normalized, error) {
	man, err := casepkg.ReadManifest(pkgDir)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	store := casepkg.NewStore(pkgDir, man)
	p := &parser{res: &schema.Normalized{}, sink: sink, caseID: man.CaseID, host: man.Host,
		entities: map[string]schema.Entity{}, relSeen: map[string]bool{}}
	for _, a := range man.Current() {
		if !Parses(a) {
			continue
		}
		base := p.seq
		if cache != nil {
			rp, err := cache.Begin(a, base)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", a.LogicalPath, err)
			}
			if rp != nil {
				p.seq = base + rp.Events
				for _, e := range rp.Entities {
					p.addEntity(e)
				}
				for _, r := range rp.Relationships {
					p.addRel(r)
				}
				continue
			}
			p.rec = &segment.Recorder{}
		}
		if err := p.parseArtifact(store, a); err != nil {
			return nil, fmt.Errorf("%s: %w", a.LogicalPath, err)
		}
		if cache != nil {
			if err := cache.End(a, base, p.seq-base, p.rec.Entities, p.rec.Relationships); err != nil {
				return nil, fmt.Errorf("%s: %w", a.LogicalPath, err)
			}
			p.rec = nil
		}
	}
	p.finishEntities()
	return p.res, nil
}

type parser struct {
	sink     func(schema.Event)
	res      *schema.Normalized
	caseID   string
	host     string
	seq      int
	entities map[string]schema.Entity
	relSeen  map[string]bool
	rec      *segment.Recorder

	// per artifact
	art     casepkg.ArtifactRecord
	product string
	tool    string // vendor of the suite (cellebrite, magnet, plaso, autopsy)
	session string // the artifact's own session (metadata, inventory, gaps)
}

var tools = map[string]string{ProductUFDR: "cellebrite", ProductAxiom: "magnet", ProductPlaso: "plaso", ProductAutopsy: "autopsy"}

func productOf(rule string) string {
	switch rule {
	case RuleUFDRReport, RuleUFD:
		return ProductUFDR
	case RuleAxiomCSV, RuleAxiomCaseDB:
		return ProductAxiom
	case RulePlaso:
		return ProductPlaso
	}
	return ProductAutopsy
}

func (p *parser) parseArtifact(store *casepkg.Store, art casepkg.ArtifactRecord) error {
	p.art = art
	p.product = productOf(art.CollectorRule)
	p.tool = tools[p.product]
	short := art.ArtifactID
	if len(short) > 12 {
		short = short[:12]
	}
	if short == "" {
		short = "unsealed"
	}
	p.session = "suite:" + p.product + ":" + short
	p.describe(p.session, path.Base(art.LogicalPath), map[string]string{"logical_path": art.LogicalPath})
	if art.CollectorRule == RuleAxiomCaseDB {
		return p.parseCaseDB(store)
	}
	rc, err := store.Open(art.ArtifactID)
	if err != nil {
		return err
	}
	defer rc.Close()
	switch art.CollectorRule {
	case RuleUFDRReport:
		return p.parseUFDR(rc)
	case RuleUFD:
		return p.parseDescriptor(rc)
	case RuleAxiomCSV:
		return p.parseAxiom(rc)
	case RulePlaso:
		return p.parsePlaso(rc)
	case RuleAutopsy:
		return p.parseAutopsy(rc)
	}
	return nil
}

// ---- events ----

func (p *parser) emit(ev schema.Event) {
	ev.EventID = fmt.Sprintf(IDFormat, p.seq)
	ev.CaseID = p.caseID
	ev.SchemaVersion = version.SchemaVersion
	ev.Sequence = p.seq
	ev.Host = p.host
	ev.User = p.art.User
	ev.Product = p.product
	ev.SourceArtifact = p.art.ArtifactID
	ev.SourcePath = p.art.LogicalPath
	if ev.TimestampSrc == "" {
		ev.TimestampSrc = TimestampPrefix + ":" + p.product
	}
	if ev.Vendor == "" {
		ev.Vendor = p.tool
	}
	if ev.SessionID == "" {
		ev.SessionID = p.session
	}
	if ev.Corroboration == "" {
		ev.Corroboration = schema.StateUnknown
	}
	p.touchSession(ev.SessionID)
	p.seq++
	if p.sink != nil {
		p.sink(ev)
	} else {
		p.res.Events = append(p.res.Events, ev)
	}
}

// meta emits a metadata or inventory event of the artifact.
func (p *parser) meta(action, result, summary string) {
	p.emit(schema.Event{EventType: schema.EventSessionMeta, ActorType: schema.ActorSystem,
		Action: action, Result: result, Summary: clip(summary, 1200), Corroboration: schema.StateObserved, SourceLine: 1})
}

// record emits one normalized suite record.
func (p *parser) record(ev schema.Event) {
	ev.EventType, ev.ActorType, ev.Action = schema.EventSessionMeta, schema.ActorSystem, actionRecord
	ev.Corroboration = schema.StateObserved
	ev.Summary = clip(ev.Summary, maxSummary)
	p.emit(ev)
}

// unsupported records a structure this package does not read.
func (p *parser) unsupported(why string) {
	p.emit(schema.Event{EventType: schema.EventTraceGap, ActorType: schema.ActorSystem, Result: resultUnsup,
		Summary:       clip(fmt.Sprintf("UNSUPPORTED %s (%s): %s", p.art.LogicalPath, p.product, why), 900),
		Corroboration: schema.StateObserved, SourceLine: 1})
}

// gap records a malformed or truncated region.
func (p *parser) gap(off int64, line int, why string) {
	p.emit(schema.Event{EventType: schema.EventTraceGap, ActorType: schema.ActorSystem, Result: resultUnparsed,
		Summary: clip(why, 600), Corroboration: schema.StateObserved, SourceOffset: off, SourceLine: line})
}

// setTime normalizes an event's time and names the original value.
func (p *parser) setTime(ev *schema.Event, field, raw string, t time.Time) {
	raw = clip(strings.TrimSpace(raw), 64)
	src := TimestampPrefix + ":" + p.product
	switch {
	case !t.IsZero():
		ev.Timestamp = t.UTC().Format(time.RFC3339Nano)
		ev.TimestampSrc = src + ":" + field + "=" + raw
	case raw != "":
		ev.TimestampSrc = src + ":" + field + "=" + raw + " (not normalized)"
	default:
		ev.TimestampSrc = src
	}
}

// ---- graph ----

func (p *parser) touchSession(id string) {
	p.addEntity(schema.Entity{EntityID: "session:" + id, Kind: "session", Label: id, Product: p.product})
}

// describe attaches attributes to a session entity.
func (p *parser) describe(id, label string, attrs map[string]string) {
	a := map[string]string{"evidence_class": EvidenceClass, "suite": p.tool}
	for k, v := range attrs {
		if v != "" && len(a) < maxEntityAttrs {
			a[k] = clip(v, 256)
		}
	}
	if label == "" {
		label = id
	}
	if prev, ok := p.entities["session:"+id]; ok && len(prev.Attributes) > 0 {
		for k, v := range prev.Attributes {
			if _, set := a[k]; !set && len(a) < maxEntityAttrs {
				a[k] = v
			}
		}
		if prev.Label != id {
			label = prev.Label
		}
	}
	e := schema.Entity{EntityID: "session:" + id, Kind: "session", Label: clip(label, 200), Product: p.product, Attributes: a}
	if p.rec != nil {
		p.rec.Entity(e)
	}
	p.entities[e.EntityID] = e
}

func (p *parser) addEntity(e schema.Entity) {
	if p.rec != nil {
		p.rec.Entity(e)
	}
	prev, ok := p.entities[e.EntityID]
	if !ok || (len(prev.Attributes) == 0 && len(e.Attributes) > 0) {
		p.entities[e.EntityID] = e
	}
}

func (p *parser) addRel(r schema.Relationship) {
	if p.rec != nil {
		p.rec.Rel(r)
	}
	k := r.From + "\x00" + r.To + "\x00" + r.Type
	if p.relSeen[k] {
		return
	}
	p.relSeen[k] = true
	p.res.Relationships = append(p.res.Relationships, r)
}

func (p *parser) finishEntities() {
	keys := make([]string, 0, len(p.entities))
	for k := range p.entities {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p.res.Entities = append(p.res.Entities, p.entities[k])
	}
}

// ---- helpers ----

// counts renders a type → count map, largest first, at most n entries.
func counts(m map[string]int, n int) string {
	type kv struct {
		k string
		v int
	}
	var l []kv
	for k, v := range m {
		l = append(l, kv{k, v})
	}
	sort.Slice(l, func(i, j int) bool {
		if l[i].v != l[j].v {
			return l[i].v > l[j].v
		}
		return l[i].k < l[j].k
	})
	var parts []string
	for i, e := range l {
		if i == n {
			parts = append(parts, fmt.Sprintf("… %d more types", len(l)-n))
			break
		}
		parts = append(parts, fmt.Sprintf("%s=%d", e.k, e.v))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

func sum(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

// readHead reads the first n bytes of r and returns them plus a reader
// that replays them.
func readHead(r io.Reader, n int) ([]byte, io.Reader) {
	head := make([]byte, n)
	k, _ := io.ReadFull(r, head)
	head = head[:k]
	return head, io.MultiReader(strings.NewReader(string(head)), r)
}
