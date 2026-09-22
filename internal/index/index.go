// Package index is a derived, rebuildable index over a package's normalized
// event overlay (normalized/events.jsonl).
//
// Why it exists: the case explorer used to read the whole overlay into
// []schema.Event and keep it there. One real package is 206,896 events, a
// few hundred MB of resident memory, and the 500,000-event cap that was
// supposed to protect the process silently dropped the tail of a larger
// case — the analyst was told the case was truncated, but the evidence was
// simply not there to look at. This package inverts that: every event's
// byte offset and length in the overlay are recorded once, together with a
// compact summary of the few fields the explorer filters and groups on,
// and the full event is read back from disk by offset only when a detail
// view asks for it. At 206,896 events the resident cost is roughly 35 MB
// instead of hundreds, and it scales linearly: a million events is around
// 170 MB of summary, with no cap and nothing dropped.
//
// The index lives at <pkg>/index/events.idx. It is derived data, not
// evidence: it is deliberately outside the sealed zone and is not covered
// by SHA256SUMS, so deleting it (or copying a package without it) is
// always safe — Open rebuilds it from the overlay and rewrites it when it
// can. A stale index (the overlay changed size or mtime under it, e.g. the
// second witness rewrote the corroboration states) is treated exactly like
// a missing one.
//
// The on-disk form is little-endian and fixed width per event so it can be
// read with a handful of ReadFulls and no parsing at all; the strings are
// interned into one blob that the in-memory rows point into, which is why
// loading 206,896 events costs milliseconds rather than the seconds a JSON
// re-parse of the overlay takes.
package index

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/efij/AgentDFIR/v2/internal/overlay"
	"github.com/efij/AgentDFIR/v2/internal/schema"
)

// Dir and File locate the index inside a package. Nothing outside this
// directory is ever written, and nothing here is ever read as evidence.
const (
	Dir  = "index"
	File = "events.idx"

	magic    = "ADFIRIX1"
	version  = 1
	headSize = 64
	recSize  = 84 // 2×int64 + 2×uint32 + 15×uint32 symbol ids
)

// Sym is an index into the string table. Sym 0 is always the empty string,
// so a zero Row reads as a fully empty event rather than a panic.
type Sym uint32

// Row is one event as the explorer holds it: where the full JSON line is,
// and the low-cardinality fields every list, filter and graph view needs.
// Everything else (command, summary, result, the raw transcript pointer's
// artifact id) is read from the overlay on demand.
type Row struct {
	Offset       int64  // byte offset of the JSON line in events.jsonl
	SourceOffset int64  // the event's own pointer into the raw artifact
	Length       uint32 // length of the JSON line, excluding the newline
	SourceLine   uint32

	ID, TS, Type, Actor, Session, Agent, Parent, Task Sym
	Product, State, Tool, MCP, Dest, File, Path       Sym
}

// Summary is Row with its symbols resolved, named after the schema.Event
// fields it mirrors so call sites read the same as they did when they held
// whole events. Resolving costs nothing: the strings are slices of the one
// interned blob, so a Summary copies headers, never bytes.
type Summary struct {
	EventID       string
	Timestamp     string
	EventType     string
	ActorType     string
	SessionID     string
	AgentID       string
	ParentAgentID string
	TaskID        string
	Product       string
	Corroboration string
	Tool          string
	MCPServer     string
	NetworkDest   string
	File          string
	SourcePath    string
	SourceLine    int
	SourceOffset  int64
}

// Index is read-only once opened and safe for concurrent use: the rows and
// the string table are never mutated, and reads of the overlay go through
// ReadAt, which does not share a file offset.
type Index struct {
	src     string
	f       *os.File
	rows    []Row
	syms    []string
	byID    map[string]int
	rebuilt bool
}

// SourcePath returns the overlay this index was built over.
func (x *Index) SourcePath() string { return x.src }

// Rebuilt reports whether Open had to rebuild the index because the file
// was missing, unreadable or stale. Callers use it for a progress line.
func (x *Index) Rebuilt() bool { return x.rebuilt }

// Len is the number of indexed events: every event in the overlay, with no
// cap of any kind.
func (x *Index) Len() int { return len(x.rows) }

// Rows exposes the compact rows for a caller that wants to scan them
// itself. The slice must not be modified.
func (x *Index) Rows() []Row { return x.rows }

// Sym resolves one interned string.
func (x *Index) Sym(s Sym) string {
	if int(s) >= len(x.syms) {
		return ""
	}
	return x.syms[s]
}

// At returns the summary of event i.
func (x *Index) At(i int) Summary {
	r := &x.rows[i]
	return Summary{
		EventID: x.Sym(r.ID), Timestamp: x.Sym(r.TS), EventType: x.Sym(r.Type), ActorType: x.Sym(r.Actor),
		SessionID: x.Sym(r.Session), AgentID: x.Sym(r.Agent), ParentAgentID: x.Sym(r.Parent), TaskID: x.Sym(r.Task),
		Product: x.Sym(r.Product), Corroboration: x.Sym(r.State), Tool: x.Sym(r.Tool), MCPServer: x.Sym(r.MCP),
		NetworkDest: x.Sym(r.Dest), File: x.Sym(r.File), SourcePath: x.Sym(r.Path),
		SourceLine: int(r.SourceLine), SourceOffset: r.SourceOffset,
	}
}

// Lookup resolves an event id to its position.
func (x *Index) Lookup(id string) (int, bool) {
	i, ok := x.byID[id]
	return i, ok
}

// Line returns the raw JSON line of event i, reusing buf when it is big
// enough. The returned slice is only valid until the next call with the
// same buffer.
func (x *Index) Line(i int, buf []byte) ([]byte, error) {
	if i < 0 || i >= len(x.rows) {
		return nil, fmt.Errorf("index: event %d out of range", i)
	}
	r := x.rows[i]
	if cap(buf) < int(r.Length) {
		buf = make([]byte, r.Length)
	}
	buf = buf[:r.Length]
	n, err := x.f.ReadAt(buf, r.Offset)
	if err != nil && !(errors.Is(err, io.EOF) && n == len(buf)) {
		return nil, err
	}
	return buf, nil
}

// Event reads one full event back from the overlay. This is the only path
// that materializes a whole schema.Event, and it is taken for the handful
// of events a detail view, a timeline page or a tree node actually shows.
func (x *Index) Event(i int) (schema.Event, error) {
	var ev schema.Event
	b, err := x.Line(i, nil)
	if err != nil {
		return ev, err
	}
	if err := json.Unmarshal(b, &ev); err != nil {
		return ev, err
	}
	return ev, nil
}

// EventByID is Event keyed by event id.
func (x *Index) EventByID(id string) (schema.Event, bool) {
	i, ok := x.Lookup(id)
	if !ok {
		return schema.Event{}, false
	}
	ev, err := x.Event(i)
	if err != nil {
		return schema.Event{}, false
	}
	return ev, true
}

// Each streams every full event in overlay order, holding one at a time,
// for the rare scan that genuinely needs every field (a case-wide search).
// fn returning false stops the walk. Positions match Len/At: lines the
// index skipped (malformed JSON) are skipped here too, which is why the
// walk matches on byte offset rather than trusting a second parse.
func (x *Index) Each(fn func(i int, e *schema.Event) bool) error {
	f, err := os.Open(x.src)
	if err != nil {
		return err
	}
	defer f.Close()
	rd := bufio.NewReaderSize(f, 1<<20)
	var off int64
	k := 0
	for k < len(x.rows) {
		line, err := rd.ReadBytes('\n')
		if len(line) == 0 && err != nil {
			break
		}
		start := off
		off += int64(len(line))
		if start != x.rows[k].Offset {
			if err != nil {
				break
			}
			continue // a line the index skipped
		}
		var ev schema.Event
		if json.Unmarshal(trimEOL(line), &ev) == nil {
			if !fn(k, &ev) {
				return nil
			}
		}
		k++
		if err != nil {
			break
		}
	}
	return nil
}

// Close releases the overlay handle.
func (x *Index) Close() error {
	if x.f != nil {
		return x.f.Close()
	}
	return nil
}

// Open returns the index for a package, reading <pkg>/index/events.idx when
// it is present and current and rebuilding it from the overlay otherwise —
// so a package written by a version that predates the index, or one whose
// index was deleted, opens exactly the same, just slower the first time.
// A rebuild tries to write the file back; failing to (a read-only case
// directory, an evidence share mounted noexec/ro) is not an error, because
// the index is derived and the in-memory one is already complete.
func Open(pkg string) (*Index, error) {
	src, fi, err := source(pkg)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(pkg, Dir, File)
	if x, err := read(path, src, fi); err == nil {
		return x, nil
	}
	x, err := Build(src)
	if err != nil {
		return nil, err
	}
	x.rebuilt = true
	_ = write(path, x, fi)
	return x, nil
}

// Refresh writes the index for a package, skipping the work when the file
// on disk already covers the current overlay. analysis.Run calls this after
// the overlay is final so the explorer never pays for the first build.
func Refresh(pkg string) error {
	src, fi, err := source(pkg)
	if err != nil {
		return err
	}
	path := filepath.Join(pkg, Dir, File)
	if x, err := read(path, src, fi); err == nil {
		return x.Close()
	}
	x, err := Build(src)
	if err != nil {
		return err
	}
	defer x.Close()
	return write(path, x, fi)
}

// source locates events.jsonl and makes sure it is in the one form an
// index can be built over.
//
// Everything else in the overlay is stored gzipped; events.jsonl is not,
// because a row here is a byte offset into it and a gzip stream cannot be
// seeked. Versions 2.1.0 through 2.2.1 nevertheless rewrote it with the
// compressing writer once the second witness or endpoint correlation had
// stamped corroboration states onto the events — which left a case holding
// only events.jsonl.gz. Nothing treated that as stale, so the index could
// not be rebuilt and serve refused to open the package at all. Restoring
// the plaintext form here fixes such a case the next time anything reads
// it, without a re-parse.
func source(pkg string) (string, os.FileInfo, error) {
	src := filepath.Join(pkg, "normalized", "events.jsonl")
	if err := overlay.Decompress(src); err != nil {
		return src, nil, err
	}
	fi, err := os.Stat(src)
	return src, fi, err
}

// Build scans the overlay once and returns the in-memory index. The scan
// uses a bufio.Reader rather than a Scanner on purpose: offsets have to be
// exact, and Scanner both strips a trailing CR (which would put every
// later offset one byte out) and refuses lines past its buffer cap.
func Build(src string) (*Index, error) {
	f, err := os.Open(src)
	if err != nil {
		return nil, err
	}
	x := &Index{src: src, byID: map[string]int{}}
	defer func() {
		if x.f == nil {
			f.Close()
		}
	}()
	rd := bufio.NewReaderSize(f, 1<<20)
	tbl := map[string]Sym{"": 0}
	x.syms = []string{""}
	intern := func(s string) Sym {
		if id, ok := tbl[s]; ok {
			return id
		}
		id := Sym(len(x.syms))
		x.syms = append(x.syms, s)
		tbl[s] = id
		return id
	}
	var off int64
	for {
		line, rerr := rd.ReadBytes('\n')
		body := trimEOL(line)
		start := off
		off += int64(len(line))
		if len(body) > 0 {
			var lt lite
			if json.Unmarshal(body, &lt) == nil {
				x.byID[lt.EventID] = len(x.rows)
				x.rows = append(x.rows, Row{
					Offset: start, Length: uint32(len(body)),
					SourceOffset: lt.SourceOffset, SourceLine: uint32(lt.SourceLine),
					ID: intern(lt.EventID), TS: intern(lt.Timestamp), Type: intern(lt.EventType),
					Actor: intern(lt.ActorType), Session: intern(lt.SessionID), Agent: intern(lt.AgentID),
					Parent: intern(lt.ParentAgentID), Task: intern(lt.TaskID), Product: intern(lt.Product),
					State: intern(lt.Corroboration), Tool: intern(lt.Tool), MCP: intern(lt.MCPServer),
					Dest: intern(lt.NetworkDest), File: intern(lt.File), Path: intern(lt.SourcePath),
				})
			}
		}
		if rerr != nil {
			break
		}
	}
	// One handle stays open for the by-offset reads; ReadAt needs no seek
	// of its own, so concurrent HTTP handlers can share it.
	x.f = f
	return x, nil
}

// lite is the subset Build parses. Unmarshalling the full schema.Event here
// would allocate every command, summary and result string in the case just
// to throw them away.
type lite struct {
	EventID       string `json:"event_id"`
	Timestamp     string `json:"timestamp"`
	Product       string `json:"product"`
	SessionID     string `json:"session_id"`
	AgentID       string `json:"agent_id"`
	ParentAgentID string `json:"parent_agent_id"`
	TaskID        string `json:"task_id"`
	ActorType     string `json:"actor_type"`
	EventType     string `json:"event_type"`
	Tool          string `json:"tool"`
	MCPServer     string `json:"mcp_server"`
	File          string `json:"file"`
	NetworkDest   string `json:"network_destination"`
	SourcePath    string `json:"source_logical_path"`
	SourceOffset  int64  `json:"source_offset"`
	SourceLine    int    `json:"source_line"`
	Corroboration string `json:"corroboration_state"`
}

func trimEOL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

// ---- on-disk form ----
//
// header (64 B) | symbol offsets ((n+1)×uint32) | symbol blob | rows (84 B each)
//
// The symbol blob is read as one Go string and every symbol is a slice of
// it, so the whole table costs one allocation plus a header per entry.

func write(path string, x *Index, fi os.FileInfo) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	var blob []byte
	offs := make([]byte, 0, (len(x.syms)+1)*4)
	for _, s := range x.syms {
		offs = binary.LittleEndian.AppendUint32(offs, uint32(len(blob)))
		blob = append(blob, s...)
	}
	offs = binary.LittleEndian.AppendUint32(offs, uint32(len(blob)))

	head := make([]byte, headSize)
	copy(head, magic)
	binary.LittleEndian.PutUint32(head[8:], version)
	binary.LittleEndian.PutUint32(head[12:], recSize)
	binary.LittleEndian.PutUint64(head[16:], uint64(len(x.rows)))
	binary.LittleEndian.PutUint64(head[24:], uint64(fi.Size()))
	binary.LittleEndian.PutUint64(head[32:], uint64(fi.ModTime().UnixNano()))
	binary.LittleEndian.PutUint32(head[40:], uint32(len(x.syms)))
	binary.LittleEndian.PutUint32(head[44:], uint32(len(blob)))

	// Written to a temp file and renamed: a half-written index that still
	// had a valid header would be read back as a complete one.
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	w := bufio.NewWriterSize(f, 1<<20)
	rec := make([]byte, recSize)
	err = func() error {
		for _, b := range [][]byte{head, offs, blob} {
			if _, err := w.Write(b); err != nil {
				return err
			}
		}
		for i := range x.rows {
			putRow(rec, &x.rows[i])
			if _, err := w.Write(rec); err != nil {
				return err
			}
		}
		return w.Flush()
	}()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func read(path, src string, fi os.FileInfo) (*Index, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) < headSize || string(data[:8]) != magic {
		return nil, errors.New("index: bad magic")
	}
	if binary.LittleEndian.Uint32(data[8:]) != version || binary.LittleEndian.Uint32(data[12:]) != recSize {
		return nil, errors.New("index: wrong version")
	}
	count := int(binary.LittleEndian.Uint64(data[16:]))
	// Staleness is size plus mtime of the overlay. The second witness and
	// endpoint correlation rewrite events.jsonl in place with the same
	// event count, so counting events would not notice; the file's identity
	// is what has to match.
	if int64(binary.LittleEndian.Uint64(data[24:])) != fi.Size() ||
		int64(binary.LittleEndian.Uint64(data[32:])) != fi.ModTime().UnixNano() {
		return nil, errors.New("index: stale")
	}
	nsym := int(binary.LittleEndian.Uint32(data[40:]))
	blobLen := int(binary.LittleEndian.Uint32(data[44:]))
	offEnd := headSize + (nsym+1)*4
	blobEnd := offEnd + blobLen
	if nsym < 1 || offEnd < headSize || blobEnd < offEnd || blobEnd > len(data) {
		return nil, errors.New("index: truncated")
	}
	// Computed rather than trusted: a corrupt count must not be able to
	// turn into an out-of-range slice or an overflowing multiplication.
	rem := len(data) - blobEnd
	if rem%recSize != 0 || count < 0 || count != rem/recSize {
		return nil, errors.New("index: truncated")
	}
	blob := string(data[offEnd:blobEnd])
	syms := make([]string, nsym)
	for i := 0; i < nsym; i++ {
		a := int(binary.LittleEndian.Uint32(data[headSize+i*4:]))
		b := int(binary.LittleEndian.Uint32(data[headSize+(i+1)*4:]))
		if a > b || b > len(blob) {
			return nil, errors.New("index: bad string table")
		}
		syms[i] = blob[a:b]
	}
	x := &Index{src: src, syms: syms, rows: make([]Row, count), byID: make(map[string]int, count)}
	for i := 0; i < count; i++ {
		getRow(data[blobEnd+i*recSize:], &x.rows[i])
		if int(x.rows[i].ID) >= nsym {
			return nil, errors.New("index: bad symbol reference")
		}
		x.byID[syms[x.rows[i].ID]] = i
	}
	f, err := os.Open(src)
	if err != nil {
		return nil, err
	}
	x.f = f
	return x, nil
}

func putRow(b []byte, r *Row) {
	binary.LittleEndian.PutUint64(b[0:], uint64(r.Offset))
	binary.LittleEndian.PutUint64(b[8:], uint64(r.SourceOffset))
	binary.LittleEndian.PutUint32(b[16:], r.Length)
	binary.LittleEndian.PutUint32(b[20:], r.SourceLine)
	for i, s := range [...]Sym{r.ID, r.TS, r.Type, r.Actor, r.Session, r.Agent, r.Parent, r.Task,
		r.Product, r.State, r.Tool, r.MCP, r.Dest, r.File, r.Path} {
		binary.LittleEndian.PutUint32(b[24+i*4:], uint32(s))
	}
}

func getRow(b []byte, r *Row) {
	r.Offset = int64(binary.LittleEndian.Uint64(b[0:]))
	r.SourceOffset = int64(binary.LittleEndian.Uint64(b[8:]))
	r.Length = binary.LittleEndian.Uint32(b[16:])
	r.SourceLine = binary.LittleEndian.Uint32(b[20:])
	for i, p := range [...]*Sym{&r.ID, &r.TS, &r.Type, &r.Actor, &r.Session, &r.Agent, &r.Parent, &r.Task,
		&r.Product, &r.State, &r.Tool, &r.MCP, &r.Dest, &r.File, &r.Path} {
		*p = Sym(binary.LittleEndian.Uint32(b[24+i*4:]))
	}
}
