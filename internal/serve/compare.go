package serve

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/efij/AgentDFIR/v3/internal/crosscase"
	"github.com/efij/AgentDFIR/v3/internal/sanitize"
)

// Case compare: `agentdfir serve A --compare B` runs the same comparison as
// `agentdfir correlate-cases A B` — both packages fully verified (every
// blob re-hashed, both hash chains, the signature) and both analyzed by
// this version, or B is refused with the reason — and the Compare view
// shows what the two cases have in common and when.

// compareState is what SetCompare left for the view.
type compareState struct {
	path     string
	report   any      // the crosscase report, decoded and sanitized
	problems []string // why the comparison was refused
}

// SetCompare compares the loaded case with the package at other. A refusal
// (seal does not verify, analysis not current) is kept for the view and
// returned, so the caller can print it; the explorer still serves the case.
// run lets tests substitute crosscase.Run with cheaper options.
func (s *Server) SetCompare(other string) error {
	return s.setCompare(other, crosscase.Run, crosscase.Options{})
}

func (s *Server) setCompare(other string, run func([]string, crosscase.Options) (*crosscase.Report, error), o crosscase.Options) error {
	st := &compareState{path: sanitize.Terminal(other)}
	s.cmp = st
	rep, err := run([]string{s.pkg, other}, o)
	if err != nil {
		var re *crosscase.RefusedError
		if errors.As(err, &re) {
			st.problems = sanitizeAll(re.Problems)
		} else {
			st.problems = []string{sanitize.Terminal(err.Error())}
		}
		return err
	}
	// Round-trip through JSON so every string in the report, whatever its
	// field, passes through the same sanitizer as the other overlay reads.
	b, err := json.Marshal(rep)
	if err != nil {
		st.problems = []string{sanitize.Terminal(err.Error())}
		return err
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		st.problems = []string{sanitize.Terminal(err.Error())}
		return err
	}
	st.report = sanitizeJSON(v)
	return nil
}

// ---- /api/compare ----

func (s *Server) apiCompare(w http.ResponseWriter, r *http.Request) {
	st := s.cmp
	if st == nil {
		writeJSON(w, map[string]any{"available": false, "reason": "No second case was given.",
			"howto": sanitize.Terminal("agentdfir serve " + s.pkg + " --compare <other-case.adfir>")})
		return
	}
	if st.report == nil {
		writeJSON(w, map[string]any{"available": false, "compare": st.path, "problems": st.problems,
			"reason": "The second case could not be compared."})
		return
	}
	writeJSON(w, map[string]any{"available": true, "compare": st.path, "report": st.report})
}
