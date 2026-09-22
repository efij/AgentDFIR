package normalize

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/efij/AgentDFIR/v2/internal/casepkg"
	"github.com/efij/AgentDFIR/v2/internal/overlay"
	"github.com/efij/AgentDFIR/v2/internal/parsers/segment"
	"github.com/efij/AgentDFIR/v2/internal/schema"
	"github.com/efij/AgentDFIR/v2/internal/version"
)

// The incremental events overlay.
//
// Collection became incremental in v1.5.0: a second `agentdfir run`
// against the same machine re-read 10 files and carried 8,269 forward for
// 157 KB. Analysis did not follow. Any round appended to the manifest,
// the manifest was then newer than normalized/events.jsonl, and the whole
// overlay was thrown away — 7 minutes 27 seconds to re-parse 206,896
// events out of transcripts that had not changed a byte.
//
// The overlay is now segmented. Every source artifact a parser reads gets
// its own file under normalized/events/<parser>/<key>.jsonl.gz, and
// normalized/events.jsonl is the concatenation of those segments in parse
// order — the same flat, uncompressed file every reader already knows.
// Rebuilding it after a round decompresses the segments of the artifacts
// that did not change straight into it, and re-parses only the ones that
// did. On the benchmark fixture, 32,080 events across 80 transcripts, a
// round that changed nothing costs 48ms against 462ms for a full parse.
//
// What makes an artifact "changed" is its artifact_id, the sha256 of its
// plaintext. A transcript that grew is stored as a new artifact_id, so its
// segment is replaced whole rather than appended to — which is right,
// because a chunked artifact's plaintext is the entire file, not the tail.
//
// The hard part was never the files; it was that the parsers carry state
// across artifacts. See internal/parsers/segment for how a per-artifact
// contribution is made replayable, and why replaying it through the
// parser's own merge produces the same entity graph and the same agent
// lineage a full parse would have.
//
// The price is disk: the segments hold the same events as events.jsonl, so
// a plaintext cache would about double the overlay and undo most of what
// v2.1.0 reclaimed. The segments are therefore gzipped, the way every
// overlay file except events.jsonl already is. They are only ever read
// whole and sequentially, so nothing here needs to seek them, and at the
// ~10:1 this JSON compresses at the cache costs roughly a tenth of the
// events it replaces instead of all of them. The overlay is derived and
// rebuildable in any case — nothing in the sealed evidence zone changes —
// and `--renormalize` rewrites all of it.

// overlayDirName is the segment directory inside normalized/.
const overlayDirName = "events"

// stateFileName records which artifacts have been normalized and by what.
const stateFileName = "state.json"

// OverlayOptions controls a rebuild.
type OverlayOptions struct {
	// Full forces every artifact to be re-parsed, ignoring (and then
	// replacing) any cached segments. This is what --renormalize sets.
	Full bool
}

// segState is one artifact's cached contribution, as persisted.
type segState struct {
	Key           string                `json:"key"`
	ArtifactID    string                `json:"artifact_id"`
	LogicalPath   string                `json:"logical_path"`
	Base          int                   `json:"base"`   // sequence number of its first event when written
	Events        int                   `json:"events"` // events in the segment file
	Entities      []schema.Entity       `json:"entities,omitempty"`
	Relationships []schema.Relationship `json:"relationships,omitempty"`
}

type parserState struct {
	Name     string     `json:"parser"`
	IDFormat string     `json:"event_id_format"`
	Segments []segState `json:"segments"`
}

// overlayState is normalized/state.json.
//
// Every field outside Parsers is an invalidation key. The binary's own
// version is one of them on purpose: a parser change between releases
// would silently keep producing the old events for every unchanged
// artifact, and a cached wrong answer is worse than a slow right one. The
// cost is one full re-analysis after an upgrade, which is what an analyst
// wants anyway.
type overlayState struct {
	SchemaVersion string        `json:"schema_version"`
	ToolVersion   string        `json:"agentdfir_version"`
	CaseID        string        `json:"case_id"`
	Host          string        `json:"host"`
	Parsers       []parserState `json:"parsers"`
}

// errNoSegment means the cache entry exists but its file cannot be opened —
// deleted, truncated, or no longer a readable gzip stream. The artifact is
// parsed fresh instead of failing the analysis.
var errNoSegment = errors.New("segment file missing")

// BuildOverlay writes normalized/events.jsonl and its segments, re-parsing
// only the artifacts whose content is new to the overlay, and returns the
// entities and relationships for the whole package.
//
// events.jsonl is built under a temporary name and renamed into place, so
// a build that dies half way cannot leave a truncated overlay looking
// newer than the manifest that invalidates it.
func BuildOverlay(pkgDir, dir string, opt OverlayOptions) (*StreamResult, error) {
	res, err := buildOverlay(pkgDir, dir, opt)
	if err != nil && !opt.Full {
		// A damaged or half-written overlay must not make the package
		// un-analyzable: fall back to the full parse once, which also
		// rewrites every segment.
		opt.Full = true
		return buildOverlay(pkgDir, dir, opt)
	}
	return res, err
}

func buildOverlay(pkgDir, dir string, opt OverlayOptions) (*StreamResult, error) {
	man, err := casepkg.ReadManifest(pkgDir)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	segDir := filepath.Join(dir, overlayDirName)
	if err := os.MkdirAll(segDir, 0o700); err != nil {
		return nil, err
	}

	evPath := filepath.Join(dir, "events.jsonl")
	tmp, err := os.CreateTemp(dir, "events-*.jsonl.tmp")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpName) // no-op once renamed
	}()

	ov := &segCache{
		segDir: segDir,
		buf:    bufio.NewWriterSize(tmp, 256<<10),
		prev:   map[string]*segState{},
		live:   map[string]bool{},
		taken:  map[string]bool{},
	}
	ov.enc = json.NewEncoder(ov.buf)
	if !opt.Full {
		ov.load(dir, man)
	}

	merged := &schema.Normalized{}
	seenEnt := map[string]bool{}
	for _, pe := range parsers {
		ov.begin(pe)
		pres, err := pe.cached(pkgDir, ov.write, ov)
		if err != nil {
			return nil, err
		}
		if ov.err != nil {
			return nil, ov.err
		}
		for _, e := range pres.Entities {
			if !seenEnt[e.EntityID] {
				seenEnt[e.EntityID] = true
				merged.Entities = append(merged.Entities, e)
			}
		}
		merged.Relationships = append(merged.Relationships, pres.Relationships...)
	}
	if err := ov.buf.Flush(); err != nil {
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(tmpName, evPath); err != nil {
		return nil, err
	}
	// events.jsonl is the one overlay file that stays uncompressed, because
	// internal/index addresses it by byte offset. A .gz left by an older
	// binary would otherwise be preferred by every reader over the file we
	// just wrote.
	if err := os.Remove(evPath + overlay.Suffix); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err := ov.save(dir, man); err != nil {
		return nil, err
	}
	ov.prune()

	return &StreamResult{
		Entities:      merged.Entities,
		Relationships: merged.Relationships,
		EventCount:    ov.count,
		Reused:        ov.reused,
		Reparsed:      ov.parsed,
	}, nil
}

// segCache is the segment.Cache the parsers talk to while a rebuild runs.
type segCache struct {
	segDir string
	buf    *bufio.Writer
	enc    *json.Encoder
	err    error

	prev  map[string]*segState // parser\x00key -> cached segment
	live  map[string]bool      // parser/file.jsonl that survive this build
	taken map[string]bool      // keys already used in this build

	// current parser
	name     string
	idFormat string
	out      []parserState

	// current fresh segment
	curKey     string
	curFile    *os.File
	curZW      *gzip.Writer
	curEnc     *json.Encoder
	curTmp     string
	curWritten int

	count  int
	reused int
	parsed int
}

func (o *segCache) load(dir string, man *casepkg.Manifest) {
	data, err := os.ReadFile(filepath.Join(dir, stateFileName))
	if err != nil {
		return
	}
	var st overlayState
	if json.Unmarshal(data, &st) != nil {
		return
	}
	if st.SchemaVersion != version.SchemaVersion || st.ToolVersion != version.Version ||
		st.CaseID != man.CaseID || st.Host != man.Host {
		return
	}
	for i := range st.Parsers {
		ps := &st.Parsers[i]
		for j := range ps.Segments {
			s := &ps.Segments[j]
			o.prev[ps.Name+"\x00"+s.Key] = s
		}
	}
}

func (o *segCache) begin(pe parserEntry) {
	o.name, o.idFormat = pe.name, pe.idFormat
	o.out = append(o.out, parserState{Name: pe.name, IDFormat: pe.idFormat})
}

// write is the sink every parser emits through. Enrichment happens here,
// before the event reaches either file, so a segment holds exactly what a
// full parse would have put in events.jsonl and a replay needs no further
// processing.
func (o *segCache) write(ev schema.Event) {
	if o.err != nil {
		return
	}
	enrichEvent(&ev)
	if err := o.enc.Encode(ev); err != nil {
		o.err = err
		return
	}
	if o.curEnc != nil {
		if err := o.curEnc.Encode(ev); err != nil {
			o.err = err
			return
		}
		o.curWritten++
	}
	o.count++
}

// Begin implements segment.Cache.
func (o *segCache) Begin(art casepkg.ArtifactRecord, base int) (*segment.Replay, error) {
	key := segKey(art)
	if o.taken[key] {
		// Two current artifacts fingerprinting the same is not something a
		// collector produces, but if it ever happened the second would
		// overwrite the first's segment. Parse it and cache nothing.
		o.curKey = ""
		return nil, nil
	}
	o.curKey = ""
	if st, ok := o.prev[o.name+"\x00"+key]; ok {
		rp, err := o.replay(st, base)
		if err == nil {
			o.taken[key] = true
			o.live[o.segRel(key)] = true
			o.record(*st)
			o.reused++
			return rp, nil
		}
		if !errors.Is(err, errNoSegment) {
			return nil, err
		}
		// Cache entry without a readable file: fall through and re-parse.
	}
	if err := o.fresh(key); err != nil {
		return nil, err
	}
	return nil, nil
}

// End implements segment.Cache.
func (o *segCache) End(art casepkg.ArtifactRecord, base, count int, ents []schema.Entity, rels []schema.Relationship) error {
	if o.err != nil {
		return o.err
	}
	if o.curKey == "" {
		return nil // uncacheable artifact; nothing was captured
	}
	if count != o.curWritten {
		// The parser's sequence counter and the events that reached the
		// overlay have to agree, or a replay would emit the wrong number
		// of events and shift every id after it.
		_ = o.closeFresh(false)
		o.curKey = ""
		return fmt.Errorf("%s: parser advanced %d event(s) but wrote %d", art.LogicalPath, count, o.curWritten)
	}
	if err := o.closeFresh(true); err != nil {
		return err
	}
	o.record(segState{
		Key: o.curKey, ArtifactID: art.ArtifactID, LogicalPath: art.LogicalPath,
		Base: base, Events: count, Entities: ents, Relationships: rels,
	})
	o.live[o.segRel(o.curKey)] = true
	o.taken[o.curKey] = true
	o.parsed++
	o.curKey = ""
	return nil
}

// record appends a segment to the state being built.
//
// Base is the sequence number the segment's *file* was written at, and it
// is never updated to the position the segment happens to occupy in this
// build. Renumbering is done on the way out, in replay, and is deliberately
// not written back: a rewritten segment file and the state that describes
// it are two writes, and a crash between them would leave a segment whose
// numbering the state disagrees with — which would shift every event id
// after it on the next round, silently.
func (o *segCache) record(st segState) {
	ps := &o.out[len(o.out)-1]
	ps.Segments = append(ps.Segments, st)
}

// replay copies a cached artifact's events into the overlay.
//
// When the segment still starts at the sequence number it was written at —
// the common case, because a round appends new sources at the end — this
// decompresses the segment straight into the overlay and parses nothing.
// When an earlier artifact grew or was added, every following segment
// shifts and the events have to be renumbered; that still only re-encodes
// JSON instead of re-reading evidence.
func (o *segCache) replay(st *segState, base int) (*segment.Replay, error) {
	f, err := overlay.Open(o.segPath(st.Key))
	if err != nil {
		return nil, errNoSegment
	}
	defer f.Close()

	delta := base - st.Base
	n := 0
	if delta == 0 {
		cw := &lineCounter{w: o.buf}
		if _, err := io.Copy(cw, f); err != nil {
			return nil, fmt.Errorf("segment %s: %w", st.LogicalPath, err)
		}
		n = cw.lines
	} else {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64<<10), 16<<20)
		for sc.Scan() {
			var ev schema.Event
			if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
				return nil, fmt.Errorf("segment %s: %w", st.LogicalPath, err)
			}
			segment.Rebase(&ev, o.idFormat, delta)
			if err := o.enc.Encode(ev); err != nil {
				return nil, err
			}
			n++
		}
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("segment %s: %w", st.LogicalPath, err)
		}
	}
	if n != st.Events {
		return nil, fmt.Errorf("segment %s: holds %d event(s), state says %d", st.LogicalPath, n, st.Events)
	}
	o.count += n

	rels := st.Relationships
	if delta != 0 && len(rels) > 0 {
		rels = make([]schema.Relationship, len(st.Relationships))
		copy(rels, st.Relationships)
		for i := range rels {
			rels[i].DerivedFrom = segment.RebaseRefs(rels[i].DerivedFrom, o.idFormat, delta)
		}
	}
	return &segment.Replay{Events: n, Entities: segment.CloneEntities(st.Entities), Relationships: rels}, nil
}

// fresh opens the segment file an artifact about to be parsed writes into.
// It is written under a temporary name and renamed on success, so a failed
// parse cannot leave a partial segment that a later round would trust.
func (o *segCache) fresh(key string) error {
	if err := os.MkdirAll(filepath.Join(o.segDir, o.name), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Join(o.segDir, o.name), "seg-*.tmp")
	if err != nil {
		return err
	}
	o.curKey, o.curFile, o.curTmp = key, f, f.Name()
	o.curZW = gzip.NewWriter(f)
	o.curEnc = json.NewEncoder(o.curZW)
	o.curWritten = 0
	return nil
}

func (o *segCache) closeFresh(keep bool) error {
	f, zw, tmp := o.curFile, o.curZW, o.curTmp
	o.curFile, o.curZW, o.curEnc, o.curTmp = nil, nil, nil, ""
	if f == nil {
		return nil
	}
	if err := zw.Close(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if !keep {
		return os.Remove(tmp)
	}
	return os.Rename(tmp, o.segPath(o.curKey)+overlay.Suffix)
}

// segRel and segPath name a segment. The logical name ends in .jsonl; what
// is on disk is its compressed form, which overlay.Open resolves — so a
// segment written by a build that predates compression still reads.
func (o *segCache) segRel(key string) string {
	return o.name + "/" + key + ".jsonl" + overlay.Suffix
}

func (o *segCache) segPath(key string) string {
	return filepath.Join(o.segDir, o.name, key+".jsonl")
}

func (o *segCache) save(dir string, man *casepkg.Manifest) error {
	st := overlayState{
		SchemaVersion: version.SchemaVersion, ToolVersion: version.Version,
		CaseID: man.CaseID, Host: man.Host, Parsers: o.out,
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, stateFileName), append(data, '\n'), 0o600)
}

// prune deletes segments no artifact in the package refers to any more —
// a transcript that grew leaves its previous content address behind, and
// without this the overlay would keep every version of every session
// forever.
func (o *segCache) prune() {
	entries, err := os.ReadDir(o.segDir)
	if err != nil {
		return
	}
	for _, d := range entries {
		if !d.IsDir() {
			continue
		}
		files, err := os.ReadDir(filepath.Join(o.segDir, d.Name()))
		if err != nil {
			continue
		}
		for _, f := range files {
			if f.IsDir() {
				continue
			}
			rel := d.Name() + "/" + f.Name()
			if o.live[rel] {
				continue
			}
			if !strings.HasSuffix(f.Name(), ".jsonl") && !strings.HasSuffix(f.Name(), ".jsonl"+overlay.Suffix) &&
				!strings.HasSuffix(f.Name(), ".tmp") {
				continue
			}
			_ = os.Remove(filepath.Join(o.segDir, d.Name(), f.Name()))
		}
	}
}

// segKey names an artifact's segment.
//
// The artifact id alone would nearly do — it is the sha256 of the
// plaintext, so new content means a new id and a replaced segment. It is
// not quite enough, because a parser stamps fields on every event that
// come from the manifest record rather than from the bytes: the logical
// path, the user the file belonged to, the collector rule that claimed it.
// Two records can share content and differ in those. The key covers
// everything a parser reads off the record, so a segment can only be
// reused for an artifact that would produce identical events.
func segKey(a casepkg.ArtifactRecord) string {
	h := sha256.New()
	for _, f := range []string{a.ArtifactID, a.LogicalPath, a.User, a.CollectorRule, a.Product, a.ArtifactType} {
		h.Write([]byte(f))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// lineCounter counts the records a byte copy carried, so a segment whose
// file no longer matches the state it is described by is caught rather
// than silently shifting every event id after it.
type lineCounter struct {
	w     io.Writer
	lines int
}

func (c *lineCounter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	for i := 0; i < n; i++ {
		if p[i] == '\n' {
			c.lines++
		}
	}
	return n, err
}
