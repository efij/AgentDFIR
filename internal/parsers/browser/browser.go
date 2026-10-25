// Package browser recovers AI-service sessions from browser history
// databases collected with --include-browser (or `collect --product
// browser`):
//
//	Chromium family  History        urls + visits         (Chrome, Edge, Brave, Arc, Vivaldi, Opera, Chromium)
//	Firefox          places.sqlite  moz_places + moz_historyvisits
//	Safari           History.db     history_items + history_visits
//
// Evidence class "browser-history": a row proves the browser recorded a
// visit to a URL at a time, nothing more. It is never conversation
// content. No prompt or response text is produced from history; the page
// title is reported as the title the browser stored, which for most AI
// services is the conversation title.
//
// Privacy: history is broad personal data. Only rows whose URL belongs to
// a service in the Services table are read into events; every other URL
// and title is dropped as soon as it is classified and never leaves this
// package. The raw database stays sealed, losslessly, like any artifact.
//
// The databases are read with sqlitero (stdlib only, read-only, WAL
// aware) out of the sealed package, never from the live profile.
package browser

import (
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/casepkg"
	"github.com/efij/AgentDFIR/v4/internal/parsers/segment"
	"github.com/efij/AgentDFIR/v4/internal/parsers/sqlitero"
	"github.com/efij/AgentDFIR/v4/internal/schema"
	"github.com/efij/AgentDFIR/v4/internal/version"
)

// Category is the artifact type the browser collector writes. It is not
// agent_session on purpose: transcript rules and secret scans must not
// read a whole history database.
const Category = "browser_history"

// Product is the product id events carry.
const Product = "browser"

// EvidenceClass names what these events can prove.
const EvidenceClass = "browser-history"

// IDFormat renders an event id from its sequence number.
const IDFormat = "evt-br-%06d"

// Bounds on what one database may ask of the parser.
const (
	MaxDBBytes     = 512 << 20
	MaxVisitsPerDB = 200_000 // AI-service visit rows emitted from one database
	maxTitle       = 160
)

// ParsePackage parses every browser history artifact in a sealed package.
func ParsePackage(pkgDir string) (*schema.Normalized, error) { return parseWith(pkgDir, nil) }

// StreamPackageCached has the signature the overlay expects. The cache is
// not used: visits are grouped into sessions across databases (the same
// conversation opened in two browsers is one session), so an artifact's
// events depend on the other artifacts in the package.
func StreamPackageCached(pkgDir string, sink func(schema.Event), _ segment.Cache) (*schema.Normalized, error) {
	return parseWith(pkgDir, sink)
}

func parseWith(pkgDir string, sink func(schema.Event)) (*schema.Normalized, error) {
	man, err := casepkg.ReadManifest(pkgDir)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	store := casepkg.NewStore(pkgDir, man)
	p := &parser{res: &schema.Normalized{}, sink: sink, caseID: man.CaseID, host: man.Host,
		groups: map[string]*group{}}
	current := man.Current()
	byPath := map[string]casepkg.ArtifactRecord{}
	for _, a := range current {
		if a.Status == casepkg.StatusOK && a.ArtifactType == Category {
			byPath[a.LogicalPath] = a
		}
	}
	for _, a := range current {
		if a.Status != casepkg.StatusOK || a.ArtifactType != Category || isSidecar(a.LogicalPath) {
			continue
		}
		var wal, journal *casepkg.ArtifactRecord
		if w, ok := byPath[a.LogicalPath+"-wal"]; ok {
			wal = &w
		}
		if j, ok := byPath[a.LogicalPath+"-journal"]; ok && j.Size > 0 {
			journal = &j
		}
		p.parseDB(store, a, wal, journal)
	}
	p.flush()
	return p.res, nil
}

// isSidecar reports SQLite companion files, which are read with their
// database rather than on their own.
func isSidecar(logical string) bool {
	for _, s := range []string{"-wal", "-journal", "-shm", "-lock"} {
		if strings.HasSuffix(logical, s) {
			return true
		}
	}
	return false
}

// dbSource describes where one database came from.
type dbSource struct {
	art     casepkg.ArtifactRecord
	browser string // chrome, firefox, safari, …
	profile string // Default, Profile 1, abcd.default-release, …
}

// visit is one AI-service visit row, kept until all databases are read.
type visit struct {
	src        *dbSource
	match      Match
	url        string
	title      string
	at         time.Time
	raw        string // raw time value as stored
	clock      string
	table      string // table the visit row came from
	rowid      int64
	urlTable   string
	urlRow     int64
	transition string // how the visit happened, when recorded (typed, link, reload, …)
	typed      bool
	urlVisits  int64 // the browser's own visit counter for the URL
}

// group is one per-service browser session.
type group struct {
	key        string
	match      Match
	title      string
	titleAt    time.Time
	visits     []visit
	browsers   map[string]bool
	urlCounter map[string]int64 // per browser/profile+url: highest visit counter seen
}

type parser struct {
	sink   func(schema.Event)
	res    *schema.Normalized
	caseID string
	host   string
	seq    int
	groups map[string]*group
}

func (p *parser) readAll(store *casepkg.Store, art casepkg.ArtifactRecord) ([]byte, error) {
	if art.Size > MaxDBBytes {
		return nil, fmt.Errorf("%d bytes, over the %d-byte parse bound", art.Size, MaxDBBytes)
	}
	f, err := store.Open(art.ArtifactID)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, MaxDBBytes+1))
}

func (p *parser) parseDB(store *casepkg.Store, art casepkg.ArtifactRecord, walArt, journal *casepkg.ArtifactRecord) {
	src := &dbSource{art: art, browser: browserName(art), profile: path.Base(path.Dir(art.LogicalPath))}
	data, err := p.readAll(store, art)
	if err != nil {
		p.gap(src, "read_failed", "history database not readable: "+err.Error())
		return
	}
	var wal []byte
	if walArt != nil {
		if wal, err = p.readAll(store, *walArt); err != nil {
			p.note(src, "wal_unreadable", "write-ahead log not readable; database read as last checkpointed: "+err.Error())
			wal = nil
		}
	}
	db, err := sqlitero.Open(data, wal)
	if err != nil {
		p.gap(src, "malformed_database", "history database not parseable: "+err.Error())
		return
	}
	if journal != nil {
		p.note(src, "journal_not_applied", fmt.Sprintf("rollback journal (%d bytes) preserved but not applied: the database was read as written, which may include pages of an unfinished transaction", journal.Size))
	}
	var st readStats
	switch {
	case hasTable(db, "urls") && hasTable(db, "visits"):
		st = p.chromium(db, src)
	case hasTable(db, "moz_places"):
		st = p.firefox(db, src)
	case hasTable(db, "history_items"):
		st = p.safari(db, src)
	default:
		p.unsupported(src, "no recognized history schema (expected Chromium urls/visits, Firefox moz_places or Safari history_items); preserved unparsed")
		return
	}
	summary := fmt.Sprintf("%s/%s history read: %d URL row(s), %d AI-service URL(s) kept, %d other URL(s) not extracted; %d AI-service visit row(s)",
		src.browser, src.profile, st.urls, st.aiURLs, st.urls-st.aiURLs, st.aiVisits)
	if wal != nil {
		summary += "; write-ahead log applied"
	}
	if st.truncated {
		summary += fmt.Sprintf("; visit rows past %d not emitted (bound)", MaxVisitsPerDB)
	}
	if st.noVisits {
		summary += "; visit table missing or unreadable, last-visit time from the URL row used"
	}
	p.emitNow(schema.Event{
		EventType: schema.EventSessionMeta, ActorType: schema.ActorSystem,
		SessionID: "web:db:" + src.browser + "/" + src.profile,
		Action:    "browser_db", Result: "browser_db_read", Summary: summary,
		Corroboration: schema.StateObserved,
	}, art, 0)
}

type readStats struct {
	urls, aiURLs, aiVisits int
	truncated, noVisits    bool
}

func hasTable(db *sqlitero.DB, name string) bool {
	_, err := db.Table(name)
	return err == nil
}

// col reads a named column of a row, or nil.
func col(t *sqlitero.Table, row []any, name string) any {
	if i := t.Index(name); i >= 0 && i < len(row) {
		return row[i]
	}
	return nil
}

// urlRow is a kept (AI-service) URL row.
type urlRow struct {
	url    string
	title  string
	count  int64
	typed  int64
	last   int64
	rowid  int64
	match  Match
	visits int
}

// readURLs walks a URL table and keeps only AI-service rows.
func readURLs(db *sqlitero.DB, table string, st *readStats, fields func(t *sqlitero.Table, row []any) urlRow) (map[int64]*urlRow, error) {
	t, err := db.Table(table)
	if err != nil {
		return nil, err
	}
	kept := map[int64]*urlRow{}
	err = db.Each(t, func(rowid int64, row []any) error {
		st.urls++
		u := sqlitero.Str(col(t, row, "url"))
		m := Classify(u)
		if m == nil {
			return nil // not an AI service: never read further
		}
		r := fields(t, row)
		r.url, r.rowid, r.match = u, rowid, *m
		st.aiURLs++
		kept[rowid] = &r
		return nil
	})
	return kept, err
}

// chromium reads Chrome-family History: urls(id, url, title, visit_count,
// typed_count, last_visit_time) and visits(id, url, visit_time,
// transition, from_visit).
func (p *parser) chromium(db *sqlitero.DB, src *dbSource) readStats {
	var st readStats
	urls, err := readURLs(db, "urls", &st, func(t *sqlitero.Table, row []any) urlRow {
		return urlRow{title: sqlitero.Str(col(t, row, "title")), count: sqlitero.Int(col(t, row, "visit_count")),
			typed: sqlitero.Int(col(t, row, "typed_count")), last: sqlitero.Int(col(t, row, "last_visit_time"))}
	})
	if err != nil {
		p.gap(src, "malformed_table", "urls table not readable: "+err.Error())
		return st
	}
	t, terr := db.Table("visits")
	if terr == nil {
		terr = db.Each(t, func(rowid int64, row []any) error {
			u, ok := urls[sqlitero.Int(col(t, row, "url"))]
			if !ok {
				return nil
			}
			if st.aiVisits >= MaxVisitsPerDB {
				st.truncated = true
				return errStop
			}
			st.aiVisits++
			u.visits++
			raw := sqlitero.Int(col(t, row, "visit_time"))
			at, _ := webkitTime(raw)
			tr := sqlitero.Int(col(t, row, "transition"))
			name := chromeTransition(tr)
			p.add(visit{src: src, match: u.match, url: u.url, title: u.title, at: at,
				raw: fmt.Sprint(raw), clock: ClockWebKit, table: "visits", rowid: rowid, urlTable: "urls", urlRow: u.rowid,
				transition: name, typed: name == "typed" || name == "keyword", urlVisits: u.count})
			return nil
		})
		if terr == errStop {
			terr = nil
		}
	}
	if terr != nil {
		st.noVisits = true
	}
	p.urlOnly(src, urls, "urls", ClockWebKit, terr != nil, func(u *urlRow) (time.Time, string) {
		at, _ := webkitTime(u.last)
		return at, fmt.Sprint(u.last)
	})
	return st
}

// firefox reads places.sqlite: moz_places(id, url, title, visit_count,
// typed, last_visit_date) and moz_historyvisits(id, place_id,
// visit_date, visit_type, from_visit).
func (p *parser) firefox(db *sqlitero.DB, src *dbSource) readStats {
	var st readStats
	urls, err := readURLs(db, "moz_places", &st, func(t *sqlitero.Table, row []any) urlRow {
		return urlRow{title: sqlitero.Str(col(t, row, "title")), count: sqlitero.Int(col(t, row, "visit_count")),
			typed: sqlitero.Int(col(t, row, "typed")), last: sqlitero.Int(col(t, row, "last_visit_date"))}
	})
	if err != nil {
		p.gap(src, "malformed_table", "moz_places table not readable: "+err.Error())
		return st
	}
	t, terr := db.Table("moz_historyvisits")
	if terr == nil {
		terr = db.Each(t, func(rowid int64, row []any) error {
			u, ok := urls[sqlitero.Int(col(t, row, "place_id"))]
			if !ok {
				return nil
			}
			if st.aiVisits >= MaxVisitsPerDB {
				st.truncated = true
				return errStop
			}
			st.aiVisits++
			u.visits++
			raw := sqlitero.Int(col(t, row, "visit_date"))
			at, _ := prTime(raw)
			name := firefoxVisitType(sqlitero.Int(col(t, row, "visit_type")))
			p.add(visit{src: src, match: u.match, url: u.url, title: u.title, at: at,
				raw: fmt.Sprint(raw), clock: ClockPRTime, table: "moz_historyvisits", rowid: rowid, urlTable: "moz_places", urlRow: u.rowid,
				transition: name, typed: name == "typed", urlVisits: u.count})
			return nil
		})
		if terr == errStop {
			terr = nil
		}
	}
	if terr != nil {
		st.noVisits = true
	}
	p.urlOnly(src, urls, "moz_places", ClockPRTime, terr != nil, func(u *urlRow) (time.Time, string) {
		at, _ := prTime(u.last)
		return at, fmt.Sprint(u.last)
	})
	return st
}

// safari reads History.db: history_items(id, url, visit_count) and
// history_visits(id, history_item, visit_time, title, synthesized).
// Safari stores the title on the visit, not the URL.
func (p *parser) safari(db *sqlitero.DB, src *dbSource) readStats {
	var st readStats
	urls, err := readURLs(db, "history_items", &st, func(t *sqlitero.Table, row []any) urlRow {
		return urlRow{count: sqlitero.Int(col(t, row, "visit_count"))}
	})
	if err != nil {
		p.gap(src, "malformed_table", "history_items table not readable: "+err.Error())
		return st
	}
	t, terr := db.Table("history_visits")
	if terr == nil {
		terr = db.Each(t, func(rowid int64, row []any) error {
			u, ok := urls[sqlitero.Int(col(t, row, "history_item"))]
			if !ok {
				return nil
			}
			if st.aiVisits >= MaxVisitsPerDB {
				st.truncated = true
				return errStop
			}
			st.aiVisits++
			u.visits++
			rawV := col(t, row, "visit_time")
			at, _ := cocoaTime(rawV)
			v := visit{src: src, match: u.match, url: u.url, title: sqlitero.Str(col(t, row, "title")), at: at,
				raw: sqlitero.Str(rawV), clock: ClockCocoa, table: "history_visits", rowid: rowid, urlTable: "history_items", urlRow: u.rowid,
				urlVisits: u.count}
			if sqlitero.Int(col(t, row, "synthesized")) != 0 {
				v.transition = "synthesized"
			}
			p.add(v)
			return nil
		})
		if terr == errStop {
			terr = nil
		}
	}
	if terr != nil {
		st.noVisits = true
	}
	// Safari keeps no last-visit time on the URL row; without visit rows
	// there is no time to report, and the URL rows are reported undated.
	p.urlOnly(src, urls, "history_items", ClockCocoa, terr != nil, func(*urlRow) (time.Time, string) { return time.Time{}, "" })
	return st
}

// urlOnly reports kept URL rows that have no visit row: Chromium expires
// visits after ~90 days but keeps the URL with its counter and last-visit
// time, and a database whose visit table is unreadable still has URLs.
func (p *parser) urlOnly(src *dbSource, urls map[int64]*urlRow, table, clock string, visitsUnreadable bool, last func(*urlRow) (time.Time, string)) {
	ids := make([]int64, 0, len(urls))
	for id, u := range urls {
		if u.visits == 0 {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		u := urls[id]
		at, raw := last(u)
		tr := "url-row-only"
		if visitsUnreadable {
			tr = "url-row (visit table unreadable)"
		}
		p.add(visit{src: src, match: u.match, url: u.url, title: u.title, at: at, raw: raw, clock: clock,
			table: table, rowid: u.rowid, urlTable: table, urlRow: u.rowid, transition: tr, typed: u.typed > 0, urlVisits: u.count})
	}
}

var errStop = fmt.Errorf("stop")

// add files a visit under its session group.
func (p *parser) add(v visit) {
	key := groupKey(v)
	g, ok := p.groups[key]
	if !ok {
		g = &group{key: key, match: v.match, browsers: map[string]bool{}, urlCounter: map[string]int64{}}
		p.groups[key] = g
	}
	g.visits = append(g.visits, v)
	g.browsers[v.src.browser+"/"+v.src.profile] = true
	ck := v.src.browser + "/" + v.src.profile + "\x00" + v.url
	if v.urlVisits > g.urlCounter[ck] {
		g.urlCounter[ck] = v.urlVisits
	}
	if t := strings.TrimSpace(v.title); t != "" && (g.title == "" || !v.at.Before(g.titleAt)) {
		g.title, g.titleAt = t, v.at
	}
}

// groupKey: one session per conversation / share / project id across
// browsers; pages without an id are one session per service, kind and
// browser profile.
func groupKey(v visit) string {
	if v.match.ID != "" {
		return "web:" + v.match.Service.Key + ":" + v.match.Kind + ":" + sanitizeID(v.match.ID)
	}
	return "web:" + v.match.Service.Key + ":" + v.match.Kind + ":" + v.src.browser + "/" + v.src.profile
}

func sanitizeID(s string) string {
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < 128; i++ {
		c := s[i]
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-' || c == '_' || c == '.' {
			b.WriteByte(c)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

// flush emits every group: one browser_session summary, then its visits
// in time order. Groups are ordered by first visit, so the timeline reads
// in the order the services were used.
func (p *parser) flush() {
	gs := make([]*group, 0, len(p.groups))
	for _, g := range p.groups {
		sort.SliceStable(g.visits, func(i, j int) bool {
			a, b := g.visits[i], g.visits[j]
			if !a.at.Equal(b.at) {
				if a.at.IsZero() || b.at.IsZero() {
					return b.at.IsZero() && !a.at.IsZero()
				}
				return a.at.Before(b.at)
			}
			if a.src.art.LogicalPath != b.src.art.LogicalPath {
				return a.src.art.LogicalPath < b.src.art.LogicalPath
			}
			return a.rowid < b.rowid
		})
		gs = append(gs, g)
	}
	sort.Slice(gs, func(i, j int) bool {
		a, b := gs[i].visits[0].at, gs[j].visits[0].at
		if !a.Equal(b) {
			if a.IsZero() || b.IsZero() {
				return b.IsZero() && !a.IsZero()
			}
			return a.Before(b)
		}
		return gs[i].key < gs[j].key
	})
	for _, g := range gs {
		p.emitGroup(g)
	}
}

// label renders `ChatGPT conversation "title"`.
func label(m Match, title string) string {
	s := m.Service.Name + " " + kindLabel(m.Kind)
	if title != "" {
		s += fmt.Sprintf(" %q", trim(title, maxTitle))
	}
	return s
}

func kindLabel(k string) string {
	switch k {
	case KindGPT:
		return "custom assistant"
	case KindApp:
		return "(no conversation id in URL)"
	}
	return k
}

func (p *parser) emitGroup(g *group) {
	first, last := g.visits[0].at, time.Time{}
	dated := 0
	for _, v := range g.visits {
		if !v.at.IsZero() {
			dated++
			if v.at.After(last) {
				last = v.at
			}
		}
	}
	browsers := make([]string, 0, len(g.browsers))
	for b := range g.browsers {
		browsers = append(browsers, b)
	}
	sort.Strings(browsers)
	var counter int64
	for _, n := range g.urlCounter {
		counter += n
	}
	lbl := label(g.match, g.title)
	times := "undated"
	if dated > 0 {
		times = "between " + rfc3339(first) + " and " + rfc3339(last)
		if first.Equal(last) {
			times = "at " + rfc3339(first)
		}
	}
	summary := fmt.Sprintf("%s visited %d time(s) %s (%s)", lbl, len(g.visits), times, strings.Join(browsers, ", "))
	if g.match.ID != "" {
		summary += " id=" + g.match.ID
	}
	summary += " — browser history proves visits, not conversation content"

	attrs := map[string]string{
		"evidence_class": EvidenceClass,
		"service":        g.match.Service.Key,
		"service_name":   g.match.Service.Name,
		"page_kind":      g.match.Kind,
		"visit_rows":     fmt.Sprint(len(g.visits)),
		"browsers":       strings.Join(browsers, ","),
	}
	if g.match.ID != "" {
		attrs["conversation_id"] = g.match.ID
	}
	if g.title != "" {
		attrs["title"] = trim(g.title, maxTitle)
	}
	if counter > 0 {
		attrs["browser_visit_count"] = fmt.Sprint(counter)
	}
	if dated > 0 {
		attrs["first_visit"], attrs["last_visit"] = rfc3339(first), rfc3339(last)
	}
	p.addEntity(schema.Entity{EntityID: "session:" + g.key, Kind: "session", Label: trim(lbl, 200),
		Product: Product, Attributes: attrs})

	v0 := g.visits[0]
	p.emitNow(schema.Event{
		Timestamp: rfc3339(first), SessionID: g.key,
		EventType: schema.EventSessionMeta, ActorType: schema.ActorHuman,
		Vendor: g.match.Service.Key, Action: "browser_session", Result: g.match.Kind,
		Summary: trim(summary, 400), Corroboration: schema.StateObserved,
	}, v0.src.art, v0.rowid)
	for _, v := range g.visits {
		p.emitVisit(g, v)
	}
}

func (p *parser) emitVisit(g *group, v visit) {
	parts := []string{label(v.match, v.title)}
	if v.match.ID != "" {
		parts = append(parts, "id="+v.match.ID)
	}
	parts = append(parts, v.src.browser+"/"+v.src.profile)
	if v.transition != "" {
		parts = append(parts, "transition="+v.transition)
	}
	if v.typed {
		parts = append(parts, "typed")
	}
	if v.urlVisits > 0 {
		parts = append(parts, fmt.Sprintf("url_visit_count=%d", v.urlVisits))
	}
	if v.raw != "" {
		parts = append(parts, fmt.Sprintf("raw_time=%s (%s)", v.raw, v.clock))
	}
	if v.table == v.urlTable {
		parts = append(parts, fmt.Sprintf("row %s:%d", v.table, v.rowid))
	} else {
		parts = append(parts, fmt.Sprintf("row %s:%d → %s:%d", v.table, v.rowid, v.urlTable, v.urlRow))
	}
	p.emitNow(schema.Event{
		Timestamp: rfc3339(v.at), SessionID: g.key,
		EventType: schema.EventSessionMeta, ActorType: schema.ActorHuman,
		Vendor: v.match.Service.Key, Action: "browser_visit", Result: v.match.Kind,
		Summary: trim(strings.Join(parts, " · "), 500), Corroboration: schema.StateObserved,
	}, v.src.art, v.rowid)
}

func (p *parser) gap(src *dbSource, result, summary string) {
	p.emitNow(schema.Event{EventType: schema.EventTraceGap, ActorType: schema.ActorSystem,
		SessionID: "web:db:" + src.browser + "/" + src.profile,
		Result:    result, Summary: trim(summary, 300), Corroboration: schema.StateObserved}, src.art, 0)
}

func (p *parser) note(src *dbSource, result, summary string) {
	p.emitNow(schema.Event{EventType: schema.EventSessionMeta, ActorType: schema.ActorSystem,
		SessionID: "web:db:" + src.browser + "/" + src.profile, Action: "browser_db",
		Result: result, Summary: trim(summary, 300), Corroboration: schema.StateObserved}, src.art, 0)
}

func (p *parser) unsupported(src *dbSource, why string) {
	p.note(src, "unsupported", "UNSUPPORTED: "+why)
}

func (p *parser) emitNow(ev schema.Event, art casepkg.ArtifactRecord, rowid int64) {
	ev.EventID = fmt.Sprintf(IDFormat, p.seq)
	ev.CaseID = p.caseID
	ev.SchemaVersion = version.SchemaVersion
	ev.Sequence = p.seq
	ev.Host = p.host
	ev.User = art.User
	ev.Product = Product
	ev.SourceArtifact = art.ArtifactID
	ev.SourcePath = art.LogicalPath
	ev.SourceOffset = rowid // the row, not a byte offset
	if ev.Timestamp != "" {
		ev.TimestampSrc = "browser_history"
	}
	if ev.Corroboration == "" {
		ev.Corroboration = schema.StateUnknown
	}
	p.seq++
	if p.sink != nil {
		p.sink(ev)
	} else {
		p.res.Events = append(p.res.Events, ev)
	}
}

func (p *parser) addEntity(e schema.Entity) {
	for _, ex := range p.res.Entities {
		if ex.EntityID == e.EntityID {
			return
		}
	}
	p.res.Entities = append(p.res.Entities, e)
}

// browserName reads the browser from the collector rule
// (browser.<name>_<platform>), falling back to the file name.
func browserName(a casepkg.ArtifactRecord) string {
	if rule := strings.TrimPrefix(a.CollectorRule, "browser."); rule != a.CollectorRule {
		if i := strings.LastIndexByte(rule, '_'); i > 0 {
			return rule[:i]
		}
		if rule != "" {
			return rule
		}
	}
	switch path.Base(a.LogicalPath) {
	case "places.sqlite":
		return "firefox"
	case "History.db":
		return "safari"
	}
	return "chromium-family"
}

// chromeTransition names the core type of a Chromium page transition
// (the low byte; the high bits are qualifiers).
func chromeTransition(t int64) string {
	names := []string{"link", "typed", "auto_bookmark", "auto_subframe", "manual_subframe",
		"generated", "auto_toplevel", "form_submit", "reload", "keyword", "keyword_generated"}
	core := t & 0xff
	if core >= 0 && int(core) < len(names) {
		return names[core]
	}
	return fmt.Sprintf("core_%d", core)
}

// firefoxVisitType names a moz_historyvisits.visit_type.
func firefoxVisitType(t int64) string {
	switch t {
	case 1:
		return "link"
	case 2:
		return "typed"
	case 3:
		return "bookmark"
	case 4:
		return "embed"
	case 5:
		return "redirect_permanent"
	case 6:
		return "redirect_temporary"
	case 7:
		return "download"
	case 8:
		return "framed_link"
	case 9:
		return "reload"
	}
	return fmt.Sprintf("type_%d", t)
}

func trim(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut] + "…"
}
