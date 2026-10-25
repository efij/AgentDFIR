package benchmark

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/efij/AgentDFIR/v4/internal/casepkg"
	"github.com/efij/AgentDFIR/v4/internal/catalog"
	"github.com/efij/AgentDFIR/v4/internal/schema"
)

// Provenance is the provenance section: whether every event and finding
// can be traced back to a byte in the sealed zone.
//
// An event is traced by its source_artifact (must be an acquired artifact
// in the manifest), source_line (must exist in that artifact) and
// source_offset (must be where that line starts). A finding is traced by
// its evidence references, which take a few forms ("path:line (artifact
// <id>, offset n)", "path (artifact <id>)", "path:line", "path"); each must
// resolve to an artifact in the package and, when it names a line, to a
// line that exists. Endpoint-witness findings may cite the external log
// they came from, which is not sealed; those are counted apart.
type Provenance struct {
	Packages               int      `json:"packages"`
	Events                 int      `json:"events"`
	EventsResolved         int      `json:"events_resolved"`
	EventsDanglingArtifact int      `json:"events_dangling_artifact"`
	EventsLineOutOfRange   int      `json:"events_line_out_of_range"`
	EventsOffsetMismatch   int      `json:"events_offset_mismatch"`
	EventsWholeArtifact    int      `json:"events_whole_artifact"` // line 0: the event describes the artifact, not a line
	Findings               int      `json:"findings"`
	Refs                   int      `json:"refs"`
	RefsResolved           int      `json:"refs_resolved"`
	RefsDangling           int      `json:"refs_dangling"`
	RefsExternal           int      `json:"refs_external"` // endpoint-witness logs, outside the package by design
	FindingsUnreferenced   int      `json:"findings_unreferenced"`
	ChainStepsDangling     int      `json:"chain_steps_dangling"`
	Examples               []string `json:"examples"` // the first dangling references, for an analyst
}

// Dangling is the number that must be zero.
func (p Provenance) Dangling() int {
	return p.EventsDanglingArtifact + p.EventsLineOutOfRange + p.EventsOffsetMismatch +
		p.RefsDangling + p.FindingsUnreferenced + p.ChainStepsDangling
}

type provenanceChecker struct{ p Provenance }

func newProvenanceChecker() *provenanceChecker {
	return &provenanceChecker{p: Provenance{Examples: []string{}}}
}

func (c *provenanceChecker) result() Provenance { return c.p }

func (c *provenanceChecker) example(format string, a ...any) {
	if len(c.p.Examples) < 20 {
		c.p.Examples = append(c.p.Examples, fmt.Sprintf(format, a...))
	}
}

// maxLineIndex bounds how much of one artifact is read to index its lines.
const maxLineIndex = 256 << 20

// pkgIndex resolves references within one package.
type pkgIndex struct {
	store  *casepkg.Store
	byID   map[string]casepkg.ArtifactRecord
	byPath map[string][]casepkg.ArtifactRecord
	starts map[string][]int64 // artifact → offset of each line start
	err    map[string]error
}

func newPkgIndex(pkg string) (*pkgIndex, error) {
	man, err := casepkg.ReadManifest(pkg)
	if err != nil {
		return nil, err
	}
	ix := &pkgIndex{store: casepkg.NewStore(pkg, man), byID: map[string]casepkg.ArtifactRecord{},
		byPath: map[string][]casepkg.ArtifactRecord{}, starts: map[string][]int64{}, err: map[string]error{}}
	for _, a := range man.Artifacts {
		if a.Status != casepkg.StatusOK || a.ArtifactID == "" {
			continue
		}
		ix.byID[a.ArtifactID] = a
		ix.byPath[a.LogicalPath] = append(ix.byPath[a.LogicalPath], a)
	}
	return ix, nil
}

// lines returns the line-start offsets of an artifact (1-based line n
// starts at starts[n-1]).
func (ix *pkgIndex) lines(id string) ([]int64, error) {
	if s, ok := ix.starts[id]; ok {
		return s, ix.err[id]
	}
	data, err := ix.store.ReadAll(id, maxLineIndex)
	var starts []int64
	if err == nil && len(data) > 0 {
		starts = append(starts, 0)
		for off := 0; ; {
			i := bytes.IndexByte(data[off:], '\n')
			if i < 0 {
				break
			}
			off += i + 1
			if off >= len(data) {
				break
			}
			starts = append(starts, int64(off))
		}
	}
	ix.starts[id], ix.err[id] = starts, err
	return starts, err
}

// byPrefix finds the artifact a short id names, preferring one at path.
func (ix *pkgIndex) byPrefix(prefix, path string) (casepkg.ArtifactRecord, bool) {
	var hit casepkg.ArtifactRecord
	found := false
	for id, a := range ix.byID {
		if !strings.HasPrefix(id, prefix) {
			continue
		}
		if a.LogicalPath == path || !found {
			hit, found = a, true
		}
	}
	return hit, found
}

func (c *provenanceChecker) check(fixture string, a *analyzed) {
	ix, err := newPkgIndex(a.pkg)
	if err != nil {
		c.p.EventsDanglingArtifact += len(a.events)
		c.example("%s: manifest unreadable: %v", fixture, err)
		return
	}
	c.p.Packages++
	eventIDs := map[string]bool{}
	for _, ev := range a.events {
		c.p.Events++
		eventIDs[ev.EventID] = true
		art, ok := ix.byID[ev.SourceArtifact]
		if !ok {
			c.p.EventsDanglingArtifact++
			c.example("%s: event %s cites artifact %.12s, not in the package", fixture, ev.EventID, ev.SourceArtifact)
			continue
		}
		if ev.SourceLine <= 0 {
			c.p.EventsWholeArtifact++
			continue
		}
		starts, err := ix.lines(art.ArtifactID)
		switch {
		case err != nil:
			c.p.EventsLineOutOfRange++
			c.example("%s: event %s: artifact %s unreadable: %v", fixture, ev.EventID, art.LogicalPath, err)
		case ev.SourceLine > len(starts):
			c.p.EventsLineOutOfRange++
			c.example("%s: event %s cites %s:%d, which has %d line(s)", fixture, ev.EventID, art.LogicalPath, ev.SourceLine, len(starts))
		case !offsetInLine(starts, ev.SourceLine, ev.SourceOffset):
			// The offset is the line's start, or the record's own start
			// within that line (a JSON document export cites the object
			// inside a pretty-printed line). Anything outside the cited
			// line points the reader at the wrong bytes.
			c.p.EventsOffsetMismatch++
			c.example("%s: event %s cites %s:%d at offset %d; that line starts at %d", fixture, ev.EventID, art.LogicalPath, ev.SourceLine, ev.SourceOffset, starts[ev.SourceLine-1])
		default:
			c.p.EventsResolved++
		}
	}
	for _, f := range a.findings {
		c.p.Findings++
		if len(f.EvidenceRefs) == 0 && len(f.ChainSteps) == 0 {
			c.p.FindingsUnreferenced++
			c.example("%s: %s cites no evidence", fixture, f.RuleID)
			continue
		}
		external := isWitnessRule(f)
		for _, ref := range f.EvidenceRefs {
			c.p.Refs++
			switch ix.resolve(ref) {
			case refOK:
				c.p.RefsResolved++
			case refBadLine:
				c.p.RefsDangling++
				c.example("%s: %s cites %q: line or offset not in the artifact", fixture, f.RuleID, ref)
			default:
				if external {
					c.p.RefsExternal++
					continue
				}
				c.p.RefsDangling++
				c.example("%s: %s cites %q: not in the package", fixture, f.RuleID, ref)
			}
		}
		for _, s := range f.ChainSteps {
			if s.EventID != "" && !eventIDs[s.EventID] {
				c.p.ChainStepsDangling++
				c.example("%s: %s step %q cites event %s, not in the overlay", fixture, f.RuleID, s.Step, s.EventID)
			}
		}
	}
}

// isWitnessRule: findings the endpoint and cloud witnesses raise from
// records that have no transcript counterpart cite the external log.
func isWitnessRule(f schema.Finding) bool {
	if r, ok := catalog.ByID(f.RuleID); ok && r.Surface == "endpoint" {
		return true
	}
	return strings.HasPrefix(f.RuleID, "UNLOGGED_") || strings.HasPrefix(f.RuleID, "CLOUD_")
}

type refState int

const (
	refMissing refState = iota
	refOK
	refBadLine
)

var (
	// "path:line (artifact <id>[, offset n | , byte offset n])" and the
	// same without a line.
	reArt = regexp.MustCompile(`^(.*?)(?::(\d+))? \(artifact ([0-9a-f]{6,64})(?:, (?:byte )?offset (\d+))?\)$`)
	// "path (server name)" and other trailing notes.
	reNote   = regexp.MustCompile(`^(.*?) \([^()]*\)$`)
	rePathLn = regexp.MustCompile(`^(.*):(\d+)$`)
)

func (ix *pkgIndex) resolve(ref string) refState {
	var (
		art  casepkg.ArtifactRecord
		ok   bool
		line int
		off  = int64(-1)
	)
	if m := reArt.FindStringSubmatch(ref); m != nil {
		art, ok = ix.byPrefix(m[3], m[1])
		line, _ = strconv.Atoi(m[2])
		if m[4] != "" {
			off, _ = strconv.ParseInt(m[4], 10, 64)
		}
	} else {
		path := ref
		if m := reNote.FindStringSubmatch(path); m != nil {
			path = m[1]
		}
		if m := rePathLn.FindStringSubmatch(path); m != nil {
			if _, exact := ix.byPath[path]; !exact {
				path = m[1]
				line, _ = strconv.Atoi(m[2])
			}
		}
		art, ok = ix.byLogical(path)
	}
	if !ok {
		return refMissing
	}
	if off > art.Size {
		return refBadLine
	}
	if line <= 0 {
		return refOK
	}
	starts, err := ix.lines(art.ArtifactID)
	if err != nil || line > len(starts) {
		return refBadLine
	}
	return refOK
}

// byLogical resolves a bare path: an exact logical path, or one that ends
// with it at a path boundary (references made relative to a repository).
func (ix *pkgIndex) byLogical(path string) (casepkg.ArtifactRecord, bool) {
	if as := ix.byPath[path]; len(as) > 0 {
		return as[0], true
	}
	if path == "" {
		return casepkg.ArtifactRecord{}, false
	}
	best := ""
	for lp := range ix.byPath {
		if strings.HasSuffix(lp, "/"+path) && (best == "" || lp < best) {
			best = lp
		}
	}
	if best == "" {
		return casepkg.ArtifactRecord{}, false
	}
	return ix.byPath[best][0], true
}

// offsetInLine reports whether off falls inside line (1-based), given the
// start offsets of every line.
func offsetInLine(starts []int64, line int, off int64) bool {
	if off < starts[line-1] {
		return false
	}
	return line >= len(starts) || off < starts[line]
}
