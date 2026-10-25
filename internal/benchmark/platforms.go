package benchmark

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/efij/AgentDFIR/v4/internal/analysis"
	"github.com/efij/AgentDFIR/v4/internal/corpus"
	"github.com/efij/AgentDFIR/v4/internal/endpoint"
	"github.com/efij/AgentDFIR/v4/internal/schema"
)

// Platforms is the per-OS corroboration section: an agent session whose
// tool calls claim commands, file writes and network use, analyzed with
// one platform's OS telemetry, and the labeled outcome of every claim.
//
// On top of the expected CORROBORATED count, every platform is held to
// the incomplete-telemetry contract, checked on the states the findings
// and events end in (not on any internal coverage structure):
//
//   - telemetry that does not record a kind never contradicts a claim of
//     that kind (process-only telemetry and a file write or a fetch);
//   - a collection gap (a source sequence number that skips) never turns
//     a claim inside the gap into DISPROVED;
//   - one source file that stops recording a kind does not keep that
//     kind "covered" because another file of another kind goes on;
//   - a partial witness (Falco, container-runtime events, unified log)
//     can corroborate, never contradict.
type Platforms struct {
	Label     string             `json:"label"`
	Scenarios []PlatformScenario `json:"scenarios"`
	Corpus    []PlatformCorpus   `json:"corpus_cases"`
	Checks    []Check            `json:"checks"`
}

// PlatformScenario is one generated session + telemetry.
type PlatformScenario struct {
	Platform     string `json:"platform"`
	Name         string `json:"name"`
	Telemetry    string `json:"telemetry"`
	ToolCalls    int    `json:"tool_calls_checked"`
	Corroborated int    `json:"corroborated"`
	WantCorr     int    `json:"want_corroborated"`
	Contradicted int    `json:"contradicted"`
	Outside      int    `json:"outside_coverage"`
	Contract     int    `json:"contract_violations"`
}

// PlatformCorpus is one labeled corpus case that carries endpoint
// telemetry, analyzed the way the detection section analyzes it.
type PlatformCorpus struct {
	Platform     string `json:"platform"`
	Case         string `json:"case"`
	Telemetry    string `json:"telemetry"`
	ToolCalls    int    `json:"tool_calls_checked"`
	Corroborated int    `json:"corroborated"`
	Contradicted int    `json:"contradicted"`
	Outside      int    `json:"outside_coverage"`
	Expected     int    `json:"expected_rules"`
	Fired        int    `json:"expected_rules_fired"`
	Contract     int    `json:"contract_violations"`
	OK           bool   `json:"ok"`
}

// The known defect the per-kind coverage work fixes: coverage is one
// time window for every kind of record from every file.
const perKindFix = "fixed by per-kind coverage: on this build coverage is one time window for every record kind and every file, and sequence gaps are not tracked, so a missing record is read as absence"

// claim is one labeled expectation about a tool call.
type claim struct {
	desc  string
	match func(schema.Event) bool
	want  string // a state, or "not:<state>"
	xfail string
}

type platformScenario struct {
	platform, name, telemetry string
	build                     func(profile, logs string) ([]string, error)
	wantCorr                  int // -1: not labeled
	claims                    []claim
}

func fileWrite(path string) func(schema.Event) bool {
	return func(e schema.Event) bool { return e.EventType == schema.EventToolCall && e.File == path }
}

func toolNamed(tool string) func(schema.Event) bool {
	return func(e schema.Event) bool { return e.EventType == schema.EventToolCall && e.Tool == tool }
}

// write records an agent tool call with input at sec and its result.
func (s *session) tool(sec float64, name string, input map[string]any) {
	id := fmt.Sprintf("toolu_%s_%04d", s.id[:8], s.n+1)
	s.emit("assistant", sec, map[string]any{"role": "assistant", "model": "claude-sonnet-5",
		"content": []any{map[string]any{"type": "tool_use", "id": id, "name": name, "input": input}}})
	s.emit("user", sec+1, map[string]any{"role": "user",
		"content": []any{map[string]any{"type": "tool_result", "tool_use_id": id, "content": "ok"}}})
}

func writeLogs(logs string, ts ...telemetry) ([]string, error) {
	var out []string
	for _, t := range ts {
		p := filepath.Join(logs, t.name())
		if err := os.WriteFile(p, t.bytes(), 0o644); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func writeLines(logs, name string, lines ...string) (string, error) {
	p := filepath.Join(logs, name)
	return p, os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

// osShape names the paths and programs one platform uses.
type osShape struct {
	platform, shell, curl, git string
	note                       string // the agent's file write target
	wrap                       func(cmd string) []string
	newTel                     func(name string, first uint64) telemetry
	telName, ext               string
	hasNet                     bool
}

func shapes() []osShape {
	return []osShape{
		{platform: "windows", shell: `C:\Windows\System32\cmd.exe`, curl: `C:\Windows\System32\curl.exe`, git: `C:\Program Files\Git\cmd\git.exe`,
			note: `C:\Users\dev\app\notes.md`, wrap: func(c string) []string { return []string{"cmd.exe", "/c", c} },
			newTel: func(n string, f uint64) telemetry { return newSysmonEVTX(n, f) }, telName: "Sysmon (native .evtx)", ext: ".evtx", hasNet: true},
		{platform: "macos", shell: "/bin/zsh", curl: "/usr/bin/curl", git: "/usr/bin/git",
			note: "/Users/dev/app/notes.md", wrap: func(c string) []string { return []string{"/bin/zsh", "-c", c} },
			newTel: func(n string, _ uint64) telemetry { return newESLogger(n) }, telName: "eslogger JSON (Endpoint Security)", ext: ".jsonl"},
		{platform: "linux", shell: "/bin/bash", curl: "/usr/bin/curl", git: "/usr/bin/git",
			note: "/home/dev/app/notes.md", wrap: func(c string) []string { return []string{"/bin/bash", "-c", c} },
			newTel: func(n string, _ uint64) telemetry { return newAuditLog(n) }, telName: "auditd (execve, PATH, SOCKADDR)", ext: ".log", hasNet: true},
	}
}

func platformScenarios() []platformScenario {
	var out []platformScenario
	for i, o := range shapes() {
		o := o
		sid := func(n int) string { return fmt.Sprintf("cccccccc-%02d%02d-4000-8000-%012d", i+1, n, n) }
		// 1. Full telemetry: commands, a file write and a fetch are each
		// corroborated by the matching record; a command with no process
		// inside contiguous coverage is DISPROVED.
		out = append(out, platformScenario{platform: o.platform, name: "full", telemetry: o.telName, wantCorr: 4,
			build: func(profile, logs string) ([]string, error) {
				s := newSession(sid(1), t0)
				s.user(0, "check, test, note, report")
				s.bash(5, "git status", "clean")
				s.bash(15, "npm test", "ok")
				s.tool(25, "Write", map[string]any{"file_path": o.note, "content": "done\n"})
				s.bash(35, "curl -s https://api.example.org/v1/status", "{}")
				s.bash(45, "pytest -q", "12 passed")
				if _, err := s.write(profile); err != nil {
					return nil, err
				}
				t := o.newTel("telemetry"+o.ext, 100)
				t.proc(sec(5), 5001, 5000, o.shell, o.wrap("git status")...)
				t.proc(sec(15), 5002, 5000, o.shell, o.wrap("npm test")...)
				t.file(sec(25), 5000, o.shell, o.note)
				t.proc(sec(35), 5003, 5000, o.curl, "curl", "-s", "https://api.example.org/v1/status")
				t.net(sec(35.4), 5003, o.curl, "api.example.org", "203.0.113.10", 443)
				t.proc(sec(60), 5004, 5000, o.git, "git", "fetch")
				return writeLogs(logs, t)
			},
			claims: []claim{
				{desc: "Bash `git status`", match: toolCall("git status"), want: schema.StateCorroborated},
				{desc: "Bash `npm test`", match: toolCall("npm test"), want: schema.StateCorroborated},
				{desc: "Write " + o.note, match: fileWrite(o.note), want: schema.StateCorroborated},
				{desc: "Bash `curl …` (command + network)", match: toolCall("curl -s https://api.example.org/v1/status"), want: schema.StateCorroborated},
				{desc: "Bash `pytest -q`, no process in contiguous coverage", match: toolCall("pytest -q"), want: schema.StateContradicted},
			}})
		// 2. Process-only telemetry: a file write and a fetch are claims
		// it cannot witness; neither is contradicted.
		out = append(out, platformScenario{platform: o.platform, name: "process-only", telemetry: o.telName + ", process records only", wantCorr: 1,
			build: func(profile, logs string) ([]string, error) {
				s := newSession(sid(2), t0)
				s.user(0, "write the note and fetch the docs")
				s.tool(10, "Write", map[string]any{"file_path": o.note, "content": "x\n"})
				s.tool(20, "WebFetch", map[string]any{"url": "https://docs.example.org/guide", "prompt": "summarize"})
				s.bash(30, "curl -s https://api.example.org/v1/status", "{}")
				if _, err := s.write(profile); err != nil {
					return nil, err
				}
				t := o.newTel("process"+o.ext, 200)
				t.proc(sec(0), 5101, 5100, o.git, "git", "status")
				t.proc(sec(30), 5102, 5100, o.curl, "curl", "-s", "https://api.example.org/v1/status")
				t.proc(sec(60), 5103, 5100, o.git, "git", "diff")
				return writeLogs(logs, t)
			},
			claims: []claim{
				{desc: "Write with no file telemetry", match: fileWrite(o.note), want: "not:" + schema.StateContradicted},
				{desc: "WebFetch with no network telemetry", match: toolNamed("WebFetch"), want: "not:" + schema.StateContradicted},
				{desc: "Bash `curl …`: process seen, connection not witnessed", match: toolCall("curl -s https://api.example.org/v1/status"), want: schema.StateCorroborated},
			}})
		// 3. A sequence gap: the source skipped numbers around the first
		// command, so its absence there proves nothing; the second falls
		// where numbering is contiguous and is still checked.
		{
			out = append(out, platformScenario{platform: o.platform, name: "sequence-gap", telemetry: o.telName + ", numbers skipped around 20 s", wantCorr: -1,
				build: func(profile, logs string) ([]string, error) {
					s := newSession(sid(3), t0)
					s.user(0, "test and vet")
					s.bash(20, "pytest -q", "12 passed")
					s.bash(45, "go vet ./...", "")
					if _, err := s.write(profile); err != nil {
						return nil, err
					}
					t := o.newTel("gap"+o.ext, 300)
					t.proc(sec(0), 5201, 5200, o.git, "git", "status")
					t.proc(sec(10), 5202, 5200, o.git, "git", "log", "-1")
					t.skip(6)
					t.proc(sec(30), 5203, 5200, o.git, "git", "diff")
					t.proc(sec(60), 5204, 5200, o.git, "git", "show")
					return writeLogs(logs, t)
				},
				claims: []claim{
					{desc: "Bash `pytest -q` inside the sequence gap", match: toolCall("pytest -q"), want: "not:" + schema.StateContradicted, xfail: perKindFix},
					{desc: "Bash `go vet ./...` where numbering is contiguous", match: toolCall("go vet ./..."), want: schema.StateContradicted},
				}})
		}
		// 4. Process records stop at 30 s; another file recording a
		// different kind goes on for 20 minutes. The command at 10 minutes
		// is outside process coverage.
		out = append(out, platformScenario{platform: o.platform, name: "process-stops-other-kind-continues", telemetry: o.telName + ": process file 0-30 s, " + otherKind(o) + " file 0-20 min", wantCorr: -1,
			build: func(profile, logs string) ([]string, error) {
				s := newSession(sid(4), t0)
				s.user(0, "apply")
				s.bash(600, "terraform apply -auto-approve", "applied")
				if _, err := s.write(profile); err != nil {
					return nil, err
				}
				p := o.newTel("process"+o.ext, 400)
				for k := 0; k <= 3; k++ {
					p.proc(sec(float64(k*10)), 5300+k, 5299, o.git, "git", "status")
				}
				q := o.newTel("other"+o.ext, 500)
				if o.platform == "linux" {
					q = newTetragon("tetragon-network.jsonl")
				}
				for k := 0; k <= 4; k++ {
					if o.hasNet {
						q.net(sec(float64(k*300)), 5400+k, o.curl, "updates.example.org", "203.0.113.20", 443)
					} else {
						q.file(sec(float64(k*300)), 5400+k, "/usr/sbin/cfprefsd", fmt.Sprintf("/Users/dev/Library/Preferences/p%d.plist", k))
					}
				}
				return writeLogs(logs, p, q)
			},
			claims: []claim{
				{desc: "Bash at 10 min, after the process file ended", match: toolCall("terraform apply -auto-approve"), want: "not:" + schema.StateContradicted, xfail: perKindFix},
			}})
	}
	// Linux: Tetragon as the host witness.
	out = append(out, platformScenario{platform: "linux", name: "tetragon", telemetry: "Tetragon export (process_exec, kprobes)", wantCorr: 3,
		build: func(profile, logs string) ([]string, error) {
			s := newSession("cccccccc-0901-4000-8000-000000000901", t0)
			s.user(0, "build and note")
			s.bash(5, "make build", "ok")
			s.tool(15, "Write", map[string]any{"file_path": "/home/dev/app/notes.md", "content": "x\n"})
			s.bash(25, "curl -s https://203.0.113.10/v1/status", "{}")
			s.bash(35, "pytest -q", "12 passed")
			if _, err := s.write(profile); err != nil {
				return nil, err
			}
			t := newTetragon("tetragon.jsonl")
			t.proc(sec(5), 6001, 6000, "/usr/bin/make", "make", "build")
			t.file(sec(15), 6000, "/usr/local/bin/claude", "/home/dev/app/notes.md")
			t.proc(sec(25), 6002, 6000, "/usr/bin/curl", "curl", "-s", "https://203.0.113.10/v1/status")
			t.net(sec(25.3), 6002, "/usr/bin/curl", "", "203.0.113.10", 443)
			t.proc(sec(60), 6003, 6000, "/usr/bin/git", "git", "status")
			return writeLogs(logs, t)
		},
		claims: []claim{
			{desc: "Bash `make build`", match: toolCall("make build"), want: schema.StateCorroborated},
			{desc: "Write /home/dev/app/notes.md", match: fileWrite("/home/dev/app/notes.md"), want: schema.StateCorroborated},
			{desc: "Bash `curl …` to an IP", match: toolCall("curl -s https://203.0.113.10/v1/status"), want: schema.StateCorroborated},
			{desc: "Bash `pytest -q`, no exec in coverage", match: toolCall("pytest -q"), want: schema.StateContradicted},
		}})
	// Linux: Falco alerts and docker events are partial witnesses.
	out = append(out, platformScenario{platform: "linux", name: "falco-and-container-events", telemetry: "Falco alerts + docker events (partial witnesses)", wantCorr: 2,
		build: func(profile, logs string) ([]string, error) {
			s := newSession("cccccccc-0902-4000-8000-000000000902", t0)
			s.user(0, "status, lint in the container, deploy")
			s.bash(5, `bash -c "git status"`, "clean")
			s.bash(15, "docker exec web sh -c make lint", "ok")
			s.bash(25, "make deploy", "deployed")
			if _, err := s.write(profile); err != nil {
				return nil, err
			}
			f, err := writeLines(logs, "falco.jsonl",
				falcoExec(sec(5), 7001, 7000, "/bin/bash", `bash -c "git status"`),
				falcoExec(sec(40), 7002, 7000, "/bin/bash", `bash -c "id"`))
			if err != nil {
				return nil, err
			}
			d, err := writeLines(logs, "docker-events.jsonl", dockerExec(sec(15), "web", "sh -c make lint"), dockerExec(sec(50), "web", "sh -c true"))
			return []string{f, d}, err
		},
		claims: []claim{
			{desc: "Bash seen by a Falco execve alert", match: toolCall(`bash -c "git status"`), want: schema.StateCorroborated},
			{desc: "docker exec seen in docker events", match: toolCall("docker exec web sh -c make lint"), want: schema.StateCorroborated},
			{desc: "Bash with no Falco/docker record nearby", match: toolCall("make deploy"), want: "not:" + schema.StateContradicted},
		}})
	// macOS: the unified log is a partial witness; it never contradicts.
	out = append(out, platformScenario{platform: "macos", name: "unified-log-only", telemetry: "unified log ndjson (partial witness)", wantCorr: 0,
		build: func(profile, logs string) ([]string, error) {
			s := newSession("cccccccc-0903-4000-8000-000000000903", t0)
			s.user(0, "list launch agents")
			s.bash(10, "sudo launchctl list", "ok")
			s.bash(20, "pytest -q", "12 passed")
			if _, err := s.write(profile); err != nil {
				return nil, err
			}
			p, err := writeLines(logs, "unified.ndjson",
				unifiedLogLine(sec(0), "/usr/libexec/opendirectoryd", "session started"),
				unifiedLogLine(sec(10), "/usr/bin/sudo", "    dev : TTY=ttys004 ; PWD=/Users/dev/app ; USER=root ; COMMAND=/bin/launchctl list"),
				unifiedLogLine(sec(60), "/usr/libexec/opendirectoryd", "session ended"))
			return []string{p}, err
		},
		claims: []claim{
			{desc: "sudo command named in a unified log line (log record, not execution)", match: toolCall("sudo launchctl list"), want: "not:" + schema.StateContradicted},
			{desc: "Bash with no unified log line", match: toolCall("pytest -q"), want: "not:" + schema.StateContradicted},
		}})
	return out
}

func otherKind(o osShape) string {
	if o.hasNet {
		if o.platform == "linux" {
			return "Tetragon network-only"
		}
		return "network-only"
	}
	return "file-only"
}

func runPlatforms(r *Report, o Options, work string, prov *provenanceChecker) {
	p := &Platforms{Label: SuiteLabel, Scenarios: []PlatformScenario{}, Corpus: []PlatformCorpus{}, Checks: []Check{}}
	r.Platforms = p
	failed := false
	for _, sc := range platformScenarios() {
		name := sc.platform + "/" + sc.name
		dir := filepath.Join(work, sc.platform+"-"+sc.name)
		profile, logs := filepath.Join(dir, "home"), filepath.Join(dir, "logs")
		for _, d := range []string{profile, logs} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				r.fail("per-OS corroboration: %s: %v", name, err)
				failed = true
			}
		}
		files, err := sc.build(profile, logs)
		if err != nil {
			r.fail("per-OS corroboration: %s: %v", name, err)
			failed = true
			continue
		}
		a, err := collectAndAnalyze(dir, "case", profile, []string{"claude-code"}, analysis.Options{EndpointLogs: files, EndpointFormat: endpoint.FormatAuto})
		if err != nil {
			r.fail("per-OS corroboration: %s: pipeline failed: %v", name, err)
			failed = true
			continue
		}
		prov.check("platform/"+name, a)
		r.newPackages = append(r.newPackages, a.pkg)
		ps := PlatformScenario{Platform: sc.platform, Name: sc.name, Telemetry: sc.telemetry, WantCorr: sc.wantCorr}
		if c := a.result.Correlation; c != nil {
			ps.ToolCalls, ps.Outside = c.ToolCalls, c.OutsideCover
		}
		ps.Corroborated, ps.Contradicted = countState(a.events, schema.StateCorroborated), countState(a.events, schema.StateContradicted)
		for _, cl := range sc.claims {
			c := Check{Name: name + ": " + cl.desc, Want: wantLabel(cl.want), Got: "event not found", ExpectedFail: cl.xfail}
			ok := false
			for _, e := range a.events {
				if cl.match(e) {
					c.Got = schema.Label(e.Corroboration)
					if not, neg := strings.CutPrefix(cl.want, "not:"); neg {
						ok = e.Corroboration != not
					} else {
						ok = e.Corroboration == cl.want
					}
					break
				}
			}
			r.record("per-OS corroboration", &c, ok)
			p.Checks = append(p.Checks, c)
		}
		if sc.wantCorr >= 0 {
			c := Check{Name: name + ": CORROBORATED tool calls", Want: fmt.Sprint(sc.wantCorr), Got: fmt.Sprint(countState(a.events, schema.StateCorroborated))}
			r.record("per-OS corroboration", &c, c.Got == c.Want)
			p.Checks = append(p.Checks, c)
		}
		vs := contractViolations(a.events, true)
		ps.Contract = len(vs)
		for _, v := range vs {
			c := Check{Name: name + ": evidence-state contract", Want: "no violation", Got: v}
			r.record("per-OS corroboration", &c, false)
			p.Checks = append(p.Checks, c)
		}
		p.Scenarios = append(p.Scenarios, ps)
	}
	if err := runPlatformCorpus(r, o, filepath.Join(work, "corpus"), p, prov); err != nil {
		r.fail("per-OS corroboration: corpus: %v", err)
		failed = true
	}
	r.Suites = append(r.Suites, verdict("per-OS corroboration", platformSummary(p), p.Checks, failed))
}

func wantLabel(w string) string {
	if not, ok := strings.CutPrefix(w, "not:"); ok {
		return "not " + schema.Label(not)
	}
	return schema.Label(w)
}

func countState(events []schema.Event, state string) int {
	n := 0
	for _, e := range events {
		if e.EventType == schema.EventToolCall && e.Corroboration == state {
			n++
		}
	}
	return n
}

// runPlatformCorpus analyzes every labeled corpus case with endpoint
// telemetry and records its correlation numbers per platform.
func runPlatformCorpus(r *Report, o Options, work string, p *Platforms, prov *provenanceChecker) error {
	if err := os.MkdirAll(work, 0o700); err != nil {
		return err
	}
	root := o.CorpusDir
	if root == "" {
		var err error
		if root, err = corpus.Extract(filepath.Join(work, "src")); err != nil {
			return err
		}
	}
	cases, err := corpus.Load(root)
	if err != nil {
		return err
	}
	for i, c := range cases {
		if len(c.Endpoint) == 0 {
			continue
		}
		pc := PlatformCorpus{Platform: casePlatform(c), Case: c.Kind + "/" + c.Name, Telemetry: strings.Join(c.Endpoint, ", ")}
		a, err := buildAndAnalyze(work, fmt.Sprintf("c%d", i), c, analysis.Options{})
		if err != nil {
			ck := Check{Name: "corpus " + pc.Case, Want: "analyzed", Got: err.Error()}
			r.record("per-OS corroboration", &ck, false)
			p.Checks = append(p.Checks, ck)
			continue
		}
		prov.check("platform-corpus/"+c.Name, a)
		if cr := a.result.Correlation; cr != nil {
			pc.ToolCalls, pc.Corroborated, pc.Contradicted, pc.Outside = cr.ToolCalls, cr.Corroborated+cr.WitnessCorroborated, cr.Contradicted, cr.OutsideCover
		}
		got := map[string]bool{}
		for _, f := range a.findings {
			got[f.RuleID] = true
		}
		if c.Kind == "attack" {
			pc.Expected = len(c.Expect)
			for _, id := range c.Expect {
				if got[id] {
					pc.Fired++
				}
			}
		}
		pc.Contract = len(contractViolations(a.events, true))
		pc.OK = pc.Contract == 0 && pc.Fired == pc.Expected
		ck := Check{Name: "corpus " + pc.Case + " (" + pc.Platform + ")", Want: "expected rules fire, contract holds",
			Got: fmt.Sprintf("%d/%d rules, %d contract violations, %d corroborated, %d disproved", pc.Fired, pc.Expected, pc.Contract, pc.Corroborated, pc.Contradicted)}
		r.record("per-OS corroboration", &ck, pc.OK)
		p.Checks = append(p.Checks, ck)
		p.Corpus = append(p.Corpus, pc)
	}
	return nil
}

// casePlatform names the OS a corpus case's telemetry comes from, by its
// endpoint files first and its name second.
func casePlatform(c corpus.Case) string {
	for _, e := range c.Endpoint {
		l := strings.ToLower(e)
		switch {
		case strings.HasSuffix(l, ".evtx") || strings.Contains(l, "windows") || strings.Contains(l, "sysmon"):
			return "windows"
		case strings.Contains(l, "eslogger") || strings.Contains(l, "unified"):
			return "macos"
		case strings.Contains(l, "tetragon") || strings.Contains(l, "audit") || strings.Contains(l, "falco") || strings.Contains(l, "bpftrace") || strings.Contains(l, "docker") || strings.Contains(l, "podman"):
			return "linux"
		}
	}
	for _, p := range []string{"windows", "macos", "linux"} {
		if strings.HasPrefix(c.Name, p+"-") {
			return p
		}
	}
	return "any"
}

func platformSummary(p *Platforms) string {
	type agg struct{ scen, corr, want, corpus int }
	m := map[string]*agg{}
	get := func(k string) *agg {
		if m[k] == nil {
			m[k] = &agg{}
		}
		return m[k]
	}
	for _, s := range p.Scenarios {
		a := get(s.Platform)
		a.scen++
		if s.WantCorr >= 0 {
			a.want += s.WantCorr
			a.corr += s.Corroborated
		}
	}
	for _, c := range p.Corpus {
		get(c.Platform).corpus++
	}
	var parts []string
	keys := sortedKeys(m)
	sort.Strings(keys)
	for _, k := range keys {
		a := m[k]
		parts = append(parts, fmt.Sprintf("%s: %d scenarios, CORROBORATED %d/%d, %d corpus cases", k, a.scen, a.corr, a.want, a.corpus))
	}
	pass, xfail := 0, 0
	for _, c := range p.Checks {
		switch c.Status {
		case SuitePass, CheckXPass:
			pass++
		case CheckXFail:
			xfail++
		}
	}
	return fmt.Sprintf("%d/%d checks (%d expected failures); %s", pass, len(p.Checks), xfail, strings.Join(parts, "; "))
}
