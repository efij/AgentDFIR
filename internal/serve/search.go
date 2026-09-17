package serve

import (
	"bufio"
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/efij/AgentDFIR/internal/casepkg"
	"github.com/efij/AgentDFIR/internal/sanitize"
)

// ---- /api/search ----
//
// One query over everything in the case: every field of every normalized
// event, every finding, and the raw bytes of every sealed artifact (a
// streaming scan, bounded by time and hit count, never indexed to disk).
// Regexes are RE2 (Go), so no input can make the scan pathological.

const (
	searchMaxQuery   = 512
	searchDefaultHit = 500
	searchMaxHit     = 2000
	searchDeadline   = 20 * time.Second
	rawMaxArtifact   = 1 << 30 // artifacts above 1 GiB are skipped, reported
	rawMaxLine       = 16 << 20
)

type rawHit struct {
	Artifact string `json:"artifact"`
	Path     string `json:"path"`
	Line     int    `json:"line"`
	Offset   int64  `json:"offset"`
	Snippet  string `json:"snippet"`
	EventID  string `json:"event_id,omitempty"`
}

func (s *Server) apiSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	query := q.Get("q")
	if strings.TrimSpace(query) == "" {
		http.Error(w, "q required", http.StatusBadRequest)
		return
	}
	if len(query) > searchMaxQuery {
		http.Error(w, "query too long", http.StatusBadRequest)
		return
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > searchMaxHit {
		if limit <= 0 {
			limit = searchDefaultHit
		} else {
			limit = searchMaxHit
		}
	}
	scope := q.Get("scope")
	if scope == "" {
		scope = "events,findings,raw"
	}
	want := map[string]bool{}
	for _, sc := range strings.Split(scope, ",") {
		want[strings.TrimSpace(sc)] = true
	}
	pattern := "(?i)" + regexp.QuoteMeta(query)
	if q.Get("mode") == "regex" {
		pattern = "(?i)" + query
	}
	if q.Get("case") == "1" {
		pattern = strings.TrimPrefix(pattern, "(?i)")
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		http.Error(w, "bad regex: "+err.Error(), http.StatusBadRequest)
		return
	}
	start := time.Now()
	out := map[string]any{"query": query}

	if want["events"] {
		var rows []map[string]any
		total := 0
		for _, e := range s.events {
			hay := strings.Join([]string{e.Command, e.Summary, e.Result, e.Tool, e.File, e.NetworkDest, e.MCPServer, e.MCPTool, e.Action,
				e.AgentID, e.ParentAgentID, e.SessionID, e.EventType, e.ActorType, e.Model, e.Product, e.User, e.Host, e.SourcePath, e.ToolCallID, e.TaskID}, "\n")
			if re.MatchString(hay) {
				total++
				if len(rows) < limit {
					rows = append(rows, rowOf(e))
				}
			}
		}
		out["events"] = map[string]any{"total": total, "items": rows}
	}
	if want["findings"] {
		var items []map[string]any
		for i, f := range s.findings {
			hay := strings.Join(append([]string{f.RuleID, f.Title, f.Description, f.SessionID, f.AgentID, f.MitreATLAS, f.MitreATTACK, f.FalsePositive}, append(f.EvidenceRefs, f.Related...)...), "\n")
			if re.MatchString(hay) && len(items) < limit {
				items = append(items, s.findingRow(i, f))
			}
		}
		out["findings"] = items
	}
	if want["raw"] {
		ctx, cancel := context.WithTimeout(r.Context(), searchDeadline)
		defer cancel()
		hits, scanned, nArt, skipped, truncated := s.scanRaw(ctx, re, limit)
		out["raw"] = map[string]any{"items": hits, "scanned_bytes": scanned, "artifacts_scanned": nArt, "artifacts_skipped": skipped,
			"truncated": truncated, "timed_out": ctx.Err() == context.DeadlineExceeded}
	}
	out["ms"] = time.Since(start).Milliseconds()
	writeJSON(w, out)
}

// scanRaw greps every acquired artifact in parallel.
func (s *Server) scanRaw(ctx context.Context, re *regexp.Regexp, limit int) ([]rawHit, int64, int, int, bool) {
	var arts []casepkg.ArtifactRecord
	skipped := 0
	for _, a := range s.man.Artifacts {
		if a.ArtifactID == "" || strings.ContainsAny(a.ArtifactID, "/\\.") {
			continue
		}
		if a.Size > rawMaxArtifact {
			skipped++
			continue
		}
		arts = append(arts, a)
	}
	var (
		mu        sync.Mutex
		hits      []rawHit
		scanned   int64
		nArt      int32
		nHits     int32
		skipBin   int32
		trunc     atomic.Bool
		wg        sync.WaitGroup
		jobs      = make(chan casepkg.ArtifactRecord)
		workers   = runtime.NumCPU()
		lineByRef = s.byRef
	)
	if workers > 8 {
		workers = 8
	}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for a := range jobs {
				if ctx.Err() != nil || int(atomic.LoadInt32(&nHits)) >= limit {
					continue
				}
				local, n, binary := scanArtifact(ctx, filepath.Join(s.pkg, "raw", a.ArtifactID), a, re, limit-int(atomic.LoadInt32(&nHits)), lineByRef)
				atomic.AddInt64(&scanned, n)
				if binary {
					atomic.AddInt32(&skipBin, 1)
					continue
				}
				atomic.AddInt32(&nArt, 1)
				if len(local) == 0 {
					continue
				}
				atomic.AddInt32(&nHits, int32(len(local)))
				mu.Lock()
				hits = append(hits, local...)
				mu.Unlock()
			}
		}()
	}
	for _, a := range arts {
		if ctx.Err() != nil || int(atomic.LoadInt32(&nHits)) >= limit {
			trunc.Store(true)
			break
		}
		jobs <- a
	}
	close(jobs)
	wg.Wait()
	if len(hits) > limit {
		hits = hits[:limit]
		trunc.Store(true)
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Path != hits[j].Path {
			return hits[i].Path < hits[j].Path
		}
		return hits[i].Offset < hits[j].Offset
	})
	return hits, scanned, int(nArt), skipped + int(skipBin), trunc.Load()
}

func scanArtifact(ctx context.Context, path string, a casepkg.ArtifactRecord, re *regexp.Regexp, limit int, byRef map[string]string) ([]rawHit, int64, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, false
	}
	defer f.Close()
	head := make([]byte, 8192)
	n, _ := f.Read(head)
	if bytes.IndexByte(head[:n], 0) >= 0 {
		return nil, int64(n), true // binary (sqlite, images): not line-searchable
	}
	if _, err := f.Seek(0, 0); err != nil {
		return nil, 0, false
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 256*1024), rawMaxLine)
	var hits []rawHit
	var off, read int64
	line := 0
	for sc.Scan() {
		if line%2048 == 0 && ctx.Err() != nil {
			break
		}
		line++
		b := sc.Bytes()
		read += int64(len(b)) + 1
		if loc := re.FindIndex(b); loc != nil {
			hits = append(hits, rawHit{Artifact: a.ArtifactID, Path: sanitize.Terminal(a.LogicalPath), Line: line, Offset: off,
				Snippet: snippet(b, loc), EventID: byRef[a.LogicalPath+":"+strconv.Itoa(line)]})
			if len(hits) >= limit {
				break
			}
		}
		off += int64(len(b)) + 1
	}
	return hits, read, false
}

func snippet(b []byte, loc []int) string {
	const around = 90
	s, e := loc[0]-around, loc[1]+around
	if s < 0 {
		s = 0
	}
	if e > len(b) {
		e = len(b)
	}
	out := string(b[s:e])
	if s > 0 {
		out = "…" + out
	}
	if e < len(b) {
		out += "…"
	}
	return sanitize.Terminal(strings.ToValidUTF8(out, "�"))
}
