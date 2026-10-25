package serve

import (
	"bufio"
	"encoding/json"
	"net/http"
	"sort"

	"github.com/efij/AgentDFIR/v4/internal/accounts"
	"github.com/efij/AgentDFIR/v4/internal/sanitize"
	"github.com/efij/AgentDFIR/v4/internal/schema"
)

// ---- accounts ----
//
// Which AI login each piece of activity ran under. The identity readers
// live in internal/accounts (the accountability report needs them too);
// this file counts events per profile and serves the list.

// Account is one AI login found in the case.
type Account = accounts.Account

// accountKey maps a logical evidence path to the profile it belongs to.
func accountKey(logical, product string) string { return accounts.Key(logical, product) }

func labelFor(a *Account) string { return accounts.Label(a) }

func codexFromAuth(b []byte, logical string) *Account { return accounts.Codex(b, logical) }

// loadAccounts reads the identity out of every collected login file and
// counts the events each profile holds.
func (s *Server) loadAccounts() {
	accts, uuids := accounts.Identities(s.store, s.arts)
	s.claudeUUID = uuids
	s.acctOf = make([]string, s.idx.Len())
	for i, n := 0, s.idx.Len(); i < n; i++ {
		e := s.idx.At(i)
		acc := accounts.Resolve(accts, uuids, e.SourcePath, e.Product)
		s.acctOf[i] = acc.Key
		acc.Events++
	}
	s.accounts = accts
}

// accountForRef resolves an evidence reference ("path:line (artifact …)")
// or a logical path to an account key.
func (s *Server) accountForRef(ref, product string) string {
	return accounts.KeyForRef(ref, product)
}

func (s *Server) apiAccounts(w http.ResponseWriter, r *http.Request) {
	out := make([]*Account, 0, len(s.accounts))
	for _, a := range s.accounts {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Events != out[j].Events {
			return out[i].Events > out[j].Events
		}
		return out[i].Key < out[j].Key
	})
	writeJSON(w, out)
}

// byTime returns positions ordered by timestamp (overlay order breaks ties),
// cached like text queries: the UI pages through the same ordering.
func (s *Server) byTime(matched []int, key string) []int {
	s.qmu.Lock()
	if hit, ok := s.qhits[key]; ok {
		s.qmu.Unlock()
		return hit
	}
	s.qmu.Unlock()
	out := append([]int(nil), matched...)
	// Undated records go last: at the top they bury the case under
	// "unknown time" rows.
	sort.SliceStable(out, func(a, b int) bool {
		ta, tb := s.idx.At(out[a]).Timestamp, s.idx.At(out[b]).Timestamp
		if (ta == "") != (tb == "") {
			return tb == ""
		}
		return ta < tb
	})
	s.qmu.Lock()
	if len(s.qhits) >= 8 {
		s.qhits = map[string][]int{}
	}
	s.qhits[key] = out
	s.qmu.Unlock()
	return out
}

// mcpExchange returns what an MCP tool call sent and what came back, both
// trimmed and sanitized. The input is read out of the call's own sealed
// transcript line (any JSON object whose id names the call); the answer is
// the tool result with the same call id, a few events later.
func (s *Server) mcpExchange(i int, ev schema.Event) (sent, answer string) {
	if ev.SourceArtifact != "" && ev.SourceArtifact != "live" {
		if f, err := s.store.OpenAt(ev.SourceArtifact, ev.SourceOffset); err == nil {
			line, _ := bufio.NewReaderSize(f, 1<<20).ReadString('\n')
			f.Close()
			var v any
			if json.Unmarshal([]byte(line), &v) == nil {
				if in := findCallInput(v, ev.ToolCallID); in != nil {
					if b, err := json.Marshal(in); err == nil {
						sent = sanitize.Terminal(trimTo(string(b), 300))
					}
				}
			}
		}
	}
	if ev.ToolCallID != "" {
		for j := i + 1; j < s.idx.Len() && j < i+200; j++ {
			if s.idx.At(j).EventType != schema.EventToolResult {
				continue
			}
			r, err := s.idx.Event(j)
			if err != nil || r.ToolCallID != ev.ToolCallID {
				continue
			}
			text := r.Summary
			if text == "" {
				text = r.Result
			}
			answer = sanitize.Terminal(trimTo(text, 300))
			break
		}
	}
	return sent, answer
}

func findCallInput(v any, id string) any {
	switch t := v.(type) {
	case map[string]any:
		if id != "" && (t["id"] == id || t["call_id"] == id) {
			if in, ok := t["input"]; ok {
				return in
			}
			if in, ok := t["arguments"]; ok {
				if str, ok := in.(string); ok {
					var parsed any
					if json.Unmarshal([]byte(str), &parsed) == nil {
						return parsed
					}
				}
				return in
			}
		}
		for _, c := range t {
			if r := findCallInput(c, id); r != nil {
				return r
			}
		}
	case []any:
		for _, c := range t {
			if r := findCallInput(c, id); r != nil {
				return r
			}
		}
	}
	return nil
}
