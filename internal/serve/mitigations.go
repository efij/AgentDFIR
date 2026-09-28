package serve

import (
	"net/http"
	"os"
	"os/user"
	"path/filepath"

	"github.com/efij/AgentDFIR/v3/internal/mitigate"
	"github.com/efij/AgentDFIR/v3/internal/notes"
	"github.com/efij/AgentDFIR/v3/internal/schema"
	"github.com/efij/AgentDFIR/v3/internal/store"
)

// apiMitigations is the Protect tab: what can be done about this case's
// findings, and which guardrails are already on this machine. It is
// read-only on purpose. A loopback page that edited ~/.claude/settings.json
// on a request would be a CSRF-shaped hazard even behind the header checks
// that guard /api/notes, and notes are opinions while this is host state.
// The page builds a command; the person runs it in a terminal.
func (s *Server) apiMitigations(w http.ResponseWriter, r *http.Request) {
	nst, _ := s.notes.Load()
	cleared := func(f schema.Finding) bool {
		v := nst.Verdicts[notes.FindingKey(f.RuleID, f.EvidenceRefs)].Verdict
		return v == "benign" || v == "false_positive"
	}
	same := s.sameMachine()
	var states []mitigate.State
	var ledgerErr string
	if same {
		if home, err := store.Home(); err == nil {
			var err error
			states, err = mitigate.Status(mitigate.Env{StateDir: filepath.Join(home, "mitigations")})
			if err != nil {
				ledgerErr = err.Error()
			}
		}
	}
	host := ""
	if s.info != nil {
		host = s.info.Host
	}
	writeJSON(w, map[string]any{
		"assessment":   mitigate.Assess(s.findings, cleared, states),
		"same_machine": same,
		"host":         host,
		"case_path":    s.pkg,
		"ledger_error": ledgerErr,
		"defaults":     mitigate.DefaultPacks(),
	})
}

// sameMachine: this machine's guardrails say something about a case only
// when the case was collected here, by this user.
func (s *Server) sameMachine() bool {
	if s.info == nil {
		return false
	}
	host, _ := os.Hostname()
	u := ""
	if cu, err := user.Current(); err == nil {
		u = cu.Username
	}
	return s.info.Host == host && (s.info.OperatorOSUser == "" || s.info.OperatorOSUser == u)
}
