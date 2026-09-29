package serve

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/user"
	"strings"

	"github.com/efij/AgentDFIR/v3/internal/mitigate"
	"github.com/efij/AgentDFIR/v3/internal/notes"
	"github.com/efij/AgentDFIR/v3/internal/sanitize"
	"github.com/efij/AgentDFIR/v3/internal/schema"
	"github.com/efij/AgentDFIR/v3/internal/store"
)

// The Protect tab. GET /api/mitigations says what can be done about this
// case's findings and which guardrails are already on this machine. The
// three POSTs under /api/mitigations/ make it happen from the page —
// plan (writes nothing), apply, revert — but only when the case was
// collected on this machine by this user, and only with the per-process
// token the GET hands out: a page that did not load from this server does
// not have it, and a cross-site request cannot read it (no CORS headers)
// or carry the custom header (see guard). Every apply still backs each
// file up and goes into the hash-chained ledger, exactly as the CLI does.

// newApplyToken is the secret a page has to present to change host state.
func newApplyToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

func defaultMitigateEnv() (mitigate.Env, error) {
	root, err := store.Home()
	if err != nil {
		return mitigate.Env{}, err
	}
	return mitigate.DefaultEnv(root)
}

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
		if env, err := s.mitEnv(); err == nil {
			states, err = mitigate.Status(env)
			if err != nil {
				ledgerErr = err.Error()
			}
		}
	}
	host := ""
	if s.info != nil {
		host = s.info.Host
	}
	out := map[string]any{
		"assessment":   mitigate.Assess(s.findings, cleared, states),
		"same_machine": same,
		"host":         host,
		"case_path":    s.pkg,
		"ledger_error": ledgerErr,
		"defaults":     mitigate.DefaultPacks(),
		"applied":      appliedRows(states),
	}
	if same && s.applyToken != "" {
		out["token"] = s.applyToken
	}
	writeJSON(w, out)
}

// appliedRows is the ledger as the page shows it: one row per applied
// change, newest first, with what the CLI's --status prints.
func appliedRows(states []mitigate.State) []map[string]any {
	rows := []map[string]any{}
	for i := len(states) - 1; i >= 0; i-- {
		st := states[i]
		rows = append(rows, map[string]any{
			"id":      st.Record.ID,
			"ts":      st.Record.TS,
			"target":  sanitize.Terminal(st.Record.Target),
			"product": st.Record.Product,
			"packs":   st.Record.Packs,
			"state":   st.State,
			"missing": len(st.Missing),
		})
	}
	return rows
}

// mitigateRequest is the body of every POST under /api/mitigations/.
type mitigateRequest struct {
	Packs []string `json:"packs"`
	Fix   bool     `json:"fix"`
	Deny  []string `json:"deny"`
	ID    string   `json:"id"`  // revert: one change
	All   bool     `json:"all"` // revert: every change
}

func (s *Server) apiMitigate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "read-only", http.StatusMethodNotAllowed)
		return
	}
	if !s.sameMachine() {
		http.Error(w, "this case was collected on another computer: run agentdfir mitigate there", http.StatusForbidden)
		return
	}
	got := r.Header.Get("X-AgentDFIR-Mitigate")
	if s.applyToken == "" || subtle.ConstantTimeCompare([]byte(got), []byte(s.applyToken)) != 1 {
		http.Error(w, "bad token: reload the page", http.StatusForbidden)
		return
	}
	var in mitigateRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil || json.Unmarshal(body, &in) != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	env, err := s.mitEnv()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	action := strings.TrimPrefix(r.URL.Path, "/api/mitigations/")

	// One host change at a time: two tabs pressing Apply must not race
	// on the same settings file and ledger.
	s.mitMu.Lock()
	defer s.mitMu.Unlock()

	switch action {
	case "plan", "apply":
		sel, err := selection(in)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		pl, err := mitigate.BuildPlan(env, sel)
		if err != nil {
			http.Error(w, sanitize.Terminal(err.Error()), http.StatusInternalServerError)
			return
		}
		pl.Recommend = append(pl.Recommend, mitigate.MCPRecommendations(env)...)
		if action == "plan" {
			writeJSON(w, planJSON(pl))
			return
		}
		results := []map[string]any{}
		failed := 0
		for _, res := range mitigate.Apply(env, pl) {
			row := map[string]any{"target": sanitize.Terminal(res.Target), "id": res.ID, "note": sanitize.Terminal(res.Note)}
			if res.Err != nil {
				failed++
				row["error"] = sanitize.Terminal(res.Err.Error())
			}
			results = append(results, row)
		}
		writeJSON(w, map[string]any{"results": results, "failed": failed, "ledger": env.StateDir})
	case "revert":
		switch {
		case in.All:
			n, errs := mitigate.RevertAll(env, false)
			msgs := []string{}
			for _, e := range errs {
				msgs = append(msgs, sanitize.Terminal(e.Error()))
			}
			writeJSON(w, map[string]any{"reverted": n, "errors": msgs})
		case strings.TrimSpace(in.ID) != "":
			if err := mitigate.Revert(env, strings.TrimSpace(in.ID), false); err != nil {
				http.Error(w, sanitize.Terminal(err.Error()), http.StatusConflict)
				return
			}
			writeJSON(w, map[string]any{"reverted": 1, "errors": []string{}})
		default:
			http.Error(w, "revert needs an id or all", http.StatusBadRequest)
		}
	default:
		http.NotFound(w, r)
	}
}

// selection validates what the page picked, the same way the CLI's
// --select/--deny do.
func selection(in mitigateRequest) (mitigate.Selection, error) {
	sel := mitigate.Selection{Fix: in.Fix, Deny: map[string]bool{}}
	seen := map[string]bool{}
	for _, id := range in.Packs {
		if _, ok := mitigate.PackByID(id); !ok {
			return sel, errors.New("unknown pack " + sanitize.Terminal(id))
		}
		if !seen[id] {
			seen[id] = true
			sel.Packs = append(sel.Packs, id)
		}
	}
	for _, id := range in.Deny {
		if _, ok := mitigate.PackByID(id); !ok {
			return sel, errors.New("unknown pack " + sanitize.Terminal(id))
		}
		sel.Deny[id] = true
	}
	if len(sel.Packs) == 0 && !sel.Fix {
		return sel, errors.New("nothing selected")
	}
	return sel, nil
}

func planJSON(pl *mitigate.Plan) map[string]any {
	changes := []map[string]any{}
	for _, c := range pl.Changes {
		sum := []string{}
		for _, l := range c.Summary {
			sum = append(sum, sanitize.Terminal(l))
		}
		changes = append(changes, map[string]any{
			"product": c.Product,
			"kind":    c.Kind,
			"target":  sanitize.Terminal(c.Target),
			"existed": c.Existed,
			"summary": sum,
			"diff":    sanitize.Terminal(c.Diff),
		})
	}
	clean := func(l []string) []string {
		out := []string{}
		for _, x := range l {
			out = append(out, sanitize.Terminal(x))
		}
		return out
	}
	return map[string]any{
		"changes":   changes,
		"in_place":  clean(pl.InPlace),
		"recommend": clean(pl.Recommend),
		"refused":   clean(pl.Refused),
	}
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
