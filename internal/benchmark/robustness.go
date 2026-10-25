package benchmark

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/efij/AgentDFIR/v3/internal/analysis"
	"github.com/efij/AgentDFIR/v3/internal/endpoint"
	"github.com/efij/AgentDFIR/v3/internal/schema"
)

// Robustness is the hostile-input section. Every case must run through the
// whole pipeline without crashing, raise the findings its label names
// (TRACE_GAP for a damaged transcript), keep the evidence-state contract,
// and meet its own state expectations.
type Robustness struct {
	Cases  []RobustnessResult `json:"cases"`
	Passed int                `json:"passed"`
	Total  int                `json:"total"`
}

// RobustnessResult is one case.
type RobustnessResult struct {
	Name     string   `json:"name"`
	What     string   `json:"what"`
	Crashed  bool     `json:"crashed"`
	Error    string   `json:"error,omitempty"`
	Events   int      `json:"events"`
	Expected []string `json:"expected_rules,omitempty"`
	Missing  []string `json:"missing_rules,omitempty"`
	Problems []string `json:"problems,omitempty"`
	OK       bool     `json:"ok"`
}

type robustCase struct {
	name, what string
	prods      []string
	expect     []string
	build      func(profile, logs string) (telemetry []string, err error)
	// check returns problems beyond the contract and the expected rules.
	check func(events []schema.Event) []string
}

func stateOf(events []schema.Event, match func(schema.Event) bool) string {
	for _, e := range events {
		if match(e) {
			return e.Corroboration
		}
	}
	return "missing"
}

func want(events []schema.Event, desc string, match func(schema.Event) bool, states ...string) []string {
	got := stateOf(events, match)
	for _, s := range states {
		if got == s {
			return nil
		}
	}
	return []string{fmt.Sprintf("%s is %s, want one of %v", desc, schema.Label(got), states)}
}

func robustCases() []robustCase {
	baseSession := func(id string) *session {
		s := newSession(id, t0)
		s.user(0, "tidy up the repository")
		s.bash(5, "git status", "clean")
		s.bash(10, "rm -rf build", "")
		s.bash(15, "ls -la", "total 0")
		return s
	}
	return []robustCase{
		{
			name: "truncated-transcript", what: "last record cut mid-JSON (a transcript being written, or cut short)",
			prods: []string{"claude-code"}, expect: []string{"TRACE_GAP"},
			build: func(profile, _ string) ([]string, error) {
				s := baseSession("cccccccc-0001-4000-8000-000000000001")
				data := s.bytes()
				_, err := writeTranscript(profile, s.id, data[:len(data)-40])
				return nil, err
			},
		},
		{
			name: "rewritten-line", what: "one record in the middle replaced by non-JSON text",
			prods: []string{"claude-code"}, expect: []string{"TRACE_GAP"},
			build: func(profile, _ string) ([]string, error) {
				s := baseSession("cccccccc-0002-4000-8000-000000000002")
				s.lines[3] = "<<< this line was edited by hand >>>"
				_, err := s.write(profile)
				return nil, err
			},
		},
		{
			name: "clock-skew", what: "timestamps that run backwards and jump to 2099, with telemetry for the real times",
			prods: []string{"claude-code"},
			build: func(profile, logs string) ([]string, error) {
				s := newSession("cccccccc-0003-4000-8000-000000000003", t0)
				s.user(60, "go")
				s.bash(30, "rm -rf build", "")
				s.bash(5, "git status", "clean")
				s.bash(float64(73*365*24*3600), "date", "Thu Jan 1 2099")
				if _, err := s.write(profile); err != nil {
					return nil, err
				}
				var a auditd
				a.exec(sec(0), 4400, 1, "/usr/local/bin/node", "node", "cli.js")
				a.exec(sec(30), 4411, 4400, "/bin/zsh", "/bin/zsh", "-c", "rm -rf build")
				a.exec(sec(90), 4412, 4400, "/usr/bin/uname", "uname", "-a")
				p := filepath.Join(logs, "audit.log")
				return []string{p}, os.WriteFile(p, []byte(a.text()), 0o644)
			},
			check: func(ev []schema.Event) []string {
				// The 2099 call lies outside every record: it must stay
				// RECORDED, never be matched to whatever ran at the real time.
				return append(want(ev, "Bash `date` stamped 2099", toolCall("date"), schema.StateObserved),
					want(ev, "Bash `rm -rf build`", toolCall("rm -rf build"), schema.StateCorroborated)...)
			},
		},
		{
			name: "timestamp-manipulation", what: "empty, free-text, epoch-zero and numeric timestamps",
			prods: []string{"claude-code"},
			build: func(profile, logs string) ([]string, error) {
				s := baseSession("cccccccc-0004-4000-8000-000000000004")
				for i, ts := range []string{`""`, `"yesterday"`, `"1970-01-01T00:00:00Z"`, `1758362400`} {
					s.lines[i] = strings.Replace(s.lines[i], `"timestamp":"`+s.at(map[int]float64{0: 0, 1: 5, 2: 6, 3: 10}[i])+`"`, `"timestamp":`+ts, 1)
				}
				if _, err := s.write(profile); err != nil {
					return nil, err
				}
				var a auditd
				a.exec(sec(0), 4400, 1, "/usr/local/bin/node", "node", "cli.js")
				a.exec(sec(5), 4410, 4400, "/usr/bin/git", "git", "status")
				a.exec(sec(60), 4412, 4400, "/usr/bin/uname", "uname", "-a")
				p := filepath.Join(logs, "audit.log")
				return []string{p}, os.WriteFile(p, []byte(a.text()), 0o644)
			},
			check: func(ev []schema.Event) []string {
				// `git status` lost its real timestamp; nothing may be
				// matched to it on the strength of the command alone.
				return want(ev, "Bash `git status` with a free-text timestamp", toolCall("git status"), schema.StateObserved)
			},
		},
		{
			name: "corrupted-source", what: "binary garbage, NUL bytes, invalid UTF-8, 10,000-deep nesting and a 2 MiB line in a transcript",
			prods: []string{"claude-code"}, expect: []string{"TRACE_GAP"},
			build: func(profile, _ string) ([]string, error) {
				var b strings.Builder
				x := uint32(2463534242)
				for i := 0; i < 4096; i++ { // xorshift: deterministic noise
					x ^= x << 13
					x ^= x >> 17
					x ^= x << 5
					b.WriteByte(byte(x))
				}
				b.WriteString("\n{\"type\":\"user\",\"message\":\"\x00\x00\xff\xfe\"}\n")
				b.WriteString(strings.Repeat("[", 10000) + "\n")
				b.WriteString("{\"type\":\"user\",\"message\":{\"content\":\"" + strings.Repeat("A", 2<<20) + "\"}}\n")
				s := baseSession("cccccccc-0005-4000-8000-000000000005")
				b.Write(s.bytes())
				if _, err := writeTranscript(profile, s.id, []byte(b.String())); err != nil {
					return nil, err
				}
				if _, err := writeTranscript(profile, "cccccccc-0005-empty", nil); err != nil {
					return nil, err
				}
				_, err := writeTranscript(profile, "cccccccc-0005-blank", []byte("\n\n\n"))
				return nil, err
			},
			check: func(ev []schema.Event) []string {
				// The intact records after the garbage are still read.
				if stateOf(ev, toolCall("rm -rf build")) == "missing" {
					return []string{"intact records after the corrupted region were not parsed"}
				}
				return nil
			},
		},
		{
			name: "contradictory-endpoint", what: "two telemetry sources disagreeing about one PID, duplicates, an epoch-zero record and malformed lines",
			prods: []string{"claude-code"},
			build: func(profile, logs string) ([]string, error) {
				s := baseSession("cccccccc-0006-4000-8000-000000000006")
				if _, err := s.write(profile); err != nil {
					return nil, err
				}
				var a auditd
				a.exec(sec(0), 4400, 1, "/usr/local/bin/node", "node", "cli.js")
				a.exec(sec(10), 4411, 4400, "/bin/zsh", "/bin/zsh", "-c", "rm -rf build")
				a.exec(sec(10), 4411, 4400, "/bin/zsh", "/bin/zsh", "-c", "rm -rf build")
				p1 := filepath.Join(logs, "audit.log")
				if err := os.WriteFile(p1, []byte(a.text()+"type=SYSCALL garbage\nnot audit at all\n"), 0o644); err != nil {
					return nil, err
				}
				jl := strings.Join([]string{
					jsonlExec(sec(10), 4411, 4400, "/usr/bin/python3", "python3 -c pass"),
					jsonlExec(sec(5), 4410, 4400, "/usr/bin/git", "git status"),
					`{"Timestamp":"1970-01-01T00:00:00Z","Pid":1,"Exe":"/sbin/init","CommandLine":"init"}`,
					`{"Timestamp":"not a time","Pid":"x"}`,
					`{broken json`,
				}, "\n") + "\n"
				p2 := filepath.Join(logs, "process.jsonl")
				return []string{p1, p2}, os.WriteFile(p2, []byte(jl), 0o644)
			},
			check: func(ev []schema.Event) []string {
				return want(ev, "Bash `rm -rf build` (seen by one source, contradicted in detail by the other)",
					toolCall("rm -rf build"), schema.StateCorroborated)
			},
		},
		{
			name: "cross-agent", what: "a Claude Code session with a subagent and a Codex session running the same commands at the same times",
			prods: []string{"claude-code", "codex-cli"},
			build: func(profile, _ string) ([]string, error) {
				s := baseSession("cccccccc-0007-4000-8000-000000000007")
				if _, err := s.write(profile); err != nil {
					return nil, err
				}
				sub := newSession("cccccccc-0007-4000-8000-000000000007", t0)
				sub.bash(6, "rm -rf build", "")
				if err := os.WriteFile(filepath.Join(profile, ".claude", "projects", "-home-dev-app", "agent-a1b2c3d4.jsonl"),
					[]byte(strings.ReplaceAll(string(sub.bytes()), `"isSidechain":false`, `"isSidechain":true,"agentId":"a1b2c3d4"`)), 0o644); err != nil {
					return nil, err
				}
				dir := filepath.Join(profile, ".codex", "sessions", "2026", "09", "20")
				if err := os.MkdirAll(dir, 0o755); err != nil {
					return nil, err
				}
				codex := strings.Join([]string{
					`{"timestamp":"2026-09-20T10:00:00Z","type":"session_meta","payload":{"id":"cccccccc-0007-4000-8000-000000000007","cwd":"/home/dev/app","cli_version":"0.29.0"}}`,
					`{"timestamp":"2026-09-20T10:00:10Z","type":"response_item","payload":{"type":"function_call","name":"shell","arguments":"{\"command\":[\"bash\",\"-lc\",\"rm -rf build\"]}","call_id":"call-1"}}`,
					`{"timestamp":"2026-09-20T10:00:11Z","type":"response_item","payload":{"type":"function_call_output","call_id":"call-1","output":""}}`,
				}, "\n") + "\n"
				return nil, os.WriteFile(filepath.Join(dir, "rollout-2026-09-20T10-00-00-cccccccc.jsonl"), []byte(codex), 0o644)
			},
			check: func(ev []schema.Event) []string {
				byProduct := map[string]int{}
				for _, e := range ev {
					// Codex wraps the command: `bash -lc rm -rf build`.
					if e.EventType == schema.EventToolCall && strings.HasSuffix(e.FullCommand(), "rm -rf build") {
						byProduct[e.Product]++
					}
				}
				var out []string
				if byProduct["codex-cli"] == 0 || byProduct["claude-code"] < 2 {
					out = append(out, fmt.Sprintf("tool calls by product: %v; want the Codex call and both Claude Code calls (session + subagent) kept apart", byProduct))
				}
				return out
			},
		},
	}
}

func runRobustness(r *Report, o Options, work string, prov *provenanceChecker) error {
	rb := &r.Robustness
	for _, rc := range robustCases() {
		res := RobustnessResult{Name: rc.name, What: rc.what, Expected: rc.expect}
		dir := filepath.Join(work, rc.name)
		profile, logs := filepath.Join(dir, "home"), filepath.Join(dir, "logs")
		for _, d := range []string{profile, logs} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				return err
			}
		}
		telemetry, err := rc.build(profile, logs)
		if err != nil {
			return fmt.Errorf("%s: %w", rc.name, err)
		}
		a, err := collectAndAnalyze(dir, "case", profile, rc.prods, analysis.Options{EndpointLogs: telemetry, EndpointFormat: endpoint.FormatAuto})
		rb.Total++
		if err != nil {
			res.Crashed, res.Error = isCrash(err), err.Error()
			if res.Crashed {
				res.Error = strings.SplitN(res.Error, "\n", 2)[0]
			}
			r.fail("robustness: %s: %s", rc.name, res.Error)
			rb.Cases = append(rb.Cases, res)
			continue
		}
		prov.check("robustness/"+rc.name, a)
		res.Events = len(a.events)
		got := map[string]bool{}
		for _, f := range a.findings {
			got[f.RuleID] = true
		}
		for _, id := range rc.expect {
			if !got[id] {
				res.Missing = append(res.Missing, id)
			}
		}
		res.Problems = contractViolations(a.events, len(telemetry) > 0)
		if rc.check != nil {
			res.Problems = append(res.Problems, rc.check(a.events)...)
		}
		res.OK = len(res.Missing) == 0 && len(res.Problems) == 0
		if res.OK {
			rb.Passed++
		} else {
			r.fail("robustness: %s: missing %v, problems %v", rc.name, res.Missing, res.Problems)
		}
		rb.Cases = append(rb.Cases, res)
	}
	return nil
}
