package serve

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/efij/AgentDFIR/v5/internal/analysis"
	"github.com/efij/AgentDFIR/v5/internal/chain"
	"github.com/efij/AgentDFIR/v5/internal/correlate"
	"github.com/efij/AgentDFIR/v5/internal/gaps"
	"github.com/efij/AgentDFIR/v5/internal/overlay"
	"github.com/efij/AgentDFIR/v5/internal/sanitize"
)

// The investigation layer the explorer shows next to the findings: what the
// case does and does not establish (normalized/coverage.json), who did what
// through whom (normalized/lineage.json, or a scoped graph built on demand),
// and the independent record behind every confirmed action (the
// correlation pairings in detections/corroboration.json). All of it is
// derived data; a package analyzed before it existed, or one whose overlay
// was deleted, gets a plain "not in this case" answer with the command that
// regenerates it, never an error page.

// regenerate is the command that rebuilds the overlay files of this case.
func (s *Server) regenerate() string { return "agentdfir analyze " + s.pkg }

// missing is the answer for an overlay file the case does not have.
func (s *Server) missing(w http.ResponseWriter, what string) {
	writeJSON(w, map[string]any{"available": false, "reason": what, "regenerate": sanitize.Terminal(s.regenerate())})
}

// ---- /api/coverage ----

// apiCoverage serves normalized/coverage.json (gzip or plain, through the
// overlay reader like every other overlay read), every string sanitized,
// plus a lookup from each evidence reference it cites to what the page can
// open: the event, or failing that the sealed artifact line.
func (s *Server) apiCoverage(w http.ResponseWriter, r *http.Request) {
	data, err := overlay.ReadFile(filepath.Join(s.pkg, "normalized", analysis.CoverageFile))
	if err != nil {
		s.missing(w, "This case has no coverage report (normalized/coverage.json). It was analyzed by an older version, or the derived files were removed.")
		return
	}
	var v map[string]any
	if json.Unmarshal(data, &v) != nil {
		s.missing(w, "The coverage report in this case could not be read.")
		return
	}
	if sch, _ := v["schema"].(string); sch != gaps.Schema {
		s.missing(w, "The coverage report in this case uses a format this version does not read ("+sanitize.Terminal(trimTo(sch, 60))+"); UNSUPPORTED.")
		return
	}
	refs := map[string]map[string]any{}
	collectRefs(v, refs, s)
	writeJSON(w, map[string]any{"available": true, "report": sanitizeJSON(v), "refs": refs, "regenerate": sanitize.Terminal(s.regenerate())})
}

// refKeys are the coverage fields that hold finding-format evidence
// references.
var refKeys = map[string]bool{"evidence_ref": true, "evidence_refs": true, "example_ref": true, "last_record_before": true, "first_record_after": true}

// collectRefs walks the report and resolves every evidence reference it
// finds, bounded so a hostile report cannot make the answer unbounded.
func collectRefs(v any, out map[string]map[string]any, s *Server) {
	const maxRefs = 2000
	var walk func(key string, v any)
	walk = func(key string, v any) {
		if len(out) >= maxRefs {
			return
		}
		switch t := v.(type) {
		case map[string]any:
			for k, val := range t {
				walk(k, val)
			}
		case []any:
			for _, val := range t {
				walk(key, val)
			}
		case string:
			if refKeys[key] && t != "" {
				if _, ok := out[sanitize.Terminal(t)]; !ok {
					if loc := s.locate(t); loc != nil {
						out[sanitize.Terminal(t)] = loc
					}
				}
			}
		}
	}
	walk("", v)
}

// refRE reads the finding reference format: "path:line (artifact <hex>,
// offset N)".
var refRE = regexp.MustCompile(`^(.*):(\d+) \(artifact ([0-9a-f]{6,64})(?:, offset (\d+))?\)$`)

// locate resolves one evidence reference to the event it names, and the
// sealed artifact (full id) and offset the raw-line pane reads. An
// artifact is accepted only when it is one of this case's artifacts: a
// reference is evidence-derived text and is never used as a path.
func (s *Server) locate(ref string) map[string]any {
	out := map[string]any{}
	if id := chain.EventForRef(s.byRef, ref); id != "" {
		out["event_id"] = id
	}
	if m := refRE.FindStringSubmatch(ref); m != nil {
		for _, a := range s.arts {
			if strings.HasPrefix(a.ArtifactID, m[3]) {
				out["artifact"] = a.ArtifactID
				out["path"] = sanitize.Terminal(m[1])
				out["line"], _ = strconv.Atoi(m[2])
				off, _ := strconv.ParseInt(m[4], 10, 64)
				out["offset"] = off
				break
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ---- correlation pairings (shared by lineage and the witness view) ----

type corrCache struct {
	once    sync.Once
	res     *correlate.EndpointResult
	byEvent map[string][]int // event id → positions in res.Matches
}

// correlation reads detections/corroboration.json once.
func (s *Server) correlation() (*correlate.EndpointResult, map[string][]int) {
	s.corr.once.Do(func() {
		s.corr.res = analysis.LoadCorrelation(s.pkg)
		s.corr.byEvent = map[string][]int{}
		if s.corr.res != nil {
			for i, m := range s.corr.res.Matches {
				s.corr.byEvent[m.EventID] = append(s.corr.byEvent[m.EventID], i)
			}
		}
	})
	return s.corr.res, s.corr.byEvent
}
