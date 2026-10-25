package benchmark

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/analysis"
	"github.com/efij/AgentDFIR/v4/internal/endpoint"
	"github.com/efij/AgentDFIR/v4/internal/schema"
)

// Evidence is the evidence-state section.
//
// Each scenario is a transcript plus (or without) endpoint telemetry in a
// format the tool reads today, and a label for what every interesting
// event's state must be afterwards. On top of the labels, every event of
// every scenario is held to the contract:
//
//	CONFIRMED (CORROBORATED)  only with a second-witness record behind it
//	DISPROVED (CONTRADICTED)  only on endpoint or host-witness evidence
//	CLAIMED narrative         never promoted, whatever the telemetry says
type Evidence struct {
	Scenarios          []string     `json:"scenarios"`
	Checks             []StateCheck `json:"checks"`
	Passed             int          `json:"passed"`
	Total              int          `json:"total"`
	Events             int          `json:"events_checked"`
	ContractViolations []string     `json:"contract_violations"`
	States             []StateCount `json:"states"`
}

// StateCheck is one labeled expectation.
type StateCheck struct {
	Scenario string `json:"scenario"`
	Witness  string `json:"witness"`
	Event    string `json:"event"`
	Want     string `json:"want"`
	Got      string `json:"got"`
	OK       bool   `json:"ok"`
}

// StateCount is how many events ended in one state, across the section.
type StateCount struct {
	Label string `json:"label"`
	Count int    `json:"count"`
}

type stateWant struct {
	desc  string
	match func(schema.Event) bool
	state string
}

func toolCall(cmd string) func(schema.Event) bool {
	return func(e schema.Event) bool { return e.EventType == schema.EventToolCall && e.FullCommand() == cmd }
}

func narrative(text string) func(schema.Event) bool {
	return func(e schema.Event) bool {
		return e.EventType == schema.EventModelResponse && strings.Contains(e.Summary, text)
	}
}

type stateScenario struct {
	name    string
	witness string // what the second witness is, for the report
	build   func(profile, logs string) (telemetry string, err error)
	wants   []stateWant
}

var t0 = time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)

func sec(n float64) time.Time { return t0.Add(time.Duration(n * float64(time.Second))) }

func stateScenarios() []stateScenario {
	return []stateScenario{
		{
			name: "confirmed", witness: "auditd execve log",
			build: func(profile, logs string) (string, error) {
				s := newSession("aaaaaaaa-0001-4000-8000-000000000001", t0)
				s.user(0, "clean the build and push")
				s.bash(7, "rm -rf build", "")
				s.bash(31, "git push origin main", "Everything up-to-date")
				s.say(40, "I ran curl https://reports.example/upload and uploaded the summary.")
				if _, err := s.write(profile); err != nil {
					return "", err
				}
				var a auditd
				a.exec(sec(1), 4400, 1, "/usr/local/bin/node", "node", "/usr/local/lib/node_modules/@anthropic-ai/claude-code/cli.js")
				a.exec(sec(7), 4411, 4400, "/bin/zsh", "/bin/zsh", "-c", "rm -rf build")
				a.exec(sec(31), 4420, 4400, "/usr/bin/git", "git", "push", "origin", "main")
				// The command the narrative claims really is in the
				// telemetry. The claim must still not become CONFIRMED:
				// no tool call was recorded, so nothing links the two.
				a.exec(sec(40), 4430, 4400, "/usr/bin/curl", "curl", "https://reports.example/upload")
				p := filepath.Join(logs, "audit.log")
				return p, os.WriteFile(p, []byte(a.text()), 0o644)
			},
			wants: []stateWant{
				{"Bash `rm -rf build`", toolCall("rm -rf build"), schema.StateCorroborated},
				{"Bash `git push origin main`", toolCall("git push origin main"), schema.StateCorroborated},
				{"narrative claiming a curl upload", narrative("I ran curl"), schema.StateReported},
			},
		},
		{
			name: "disproved", witness: "Sysmon XML export",
			build: func(profile, logs string) (string, error) {
				s := newSession("aaaaaaaa-0002-4000-8000-000000000002", t0)
				s.user(0, "run the tests")
				s.bash(10, "ls -la", "total 8")
				s.bash(20, "pytest -q", "12 passed")
				s.say(25, "All tests passed.")
				if _, err := s.write(profile); err != nil {
					return "", err
				}
				docs := []string{`<?xml version="1.0" encoding="utf-8"?>`,
					sysmonExec(sec(0), 1, 4400, 1, `/usr/local/bin/node`, `node /usr/local/lib/node_modules/@anthropic-ai/claude-code/cli.js`),
					sysmonExec(sec(10), 2, 4411, 4400, `/bin/zsh`, `/bin/zsh -c ls -la`),
					sysmonExec(sec(60), 3, 4412, 4400, `/usr/bin/uname`, `uname -a`),
				}
				p := filepath.Join(logs, "sysmon.xml")
				return p, os.WriteFile(p, []byte(strings.Join(docs, "\n")+"\n"), 0o644)
			},
			wants: []stateWant{
				{"Bash `ls -la`", toolCall("ls -la"), schema.StateCorroborated},
				{"Bash `pytest -q` inside coverage, no process", toolCall("pytest -q"), schema.StateContradicted},
				{"narrative claiming the tests passed", narrative("All tests passed"), schema.StateReported},
			},
		},
		{
			name: "partial", witness: "generic JSONL process export covering the first 30 s",
			build: func(profile, logs string) (string, error) {
				s := newSession("aaaaaaaa-0003-4000-8000-000000000003", t0)
				s.user(0, "build and deploy")
				s.bash(10, "make build", "ok")
				s.bash(600, "make deploy", "deployed")
				if _, err := s.write(profile); err != nil {
					return "", err
				}
				lines := []string{
					jsonlExec(sec(0), 4400, 1, "/usr/local/bin/node", "node /usr/local/lib/node_modules/@anthropic-ai/claude-code/cli.js"),
					jsonlExec(sec(10), 4411, 4400, "/usr/bin/make", "make build"),
					jsonlExec(sec(30), 4412, 4400, "/usr/bin/uname", "uname -a"),
				}
				p := filepath.Join(logs, "process.jsonl")
				return p, os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
			},
			wants: []stateWant{
				{"Bash `make build` inside coverage", toolCall("make build"), schema.StateCorroborated},
				// Ten minutes later the telemetry has nothing to say, and
				// absence of evidence is not a contradiction.
				{"Bash `make deploy` outside coverage", toolCall("make deploy"), schema.StateObserved},
			},
		},
		{
			name: "no-telemetry", witness: "none",
			build: func(profile, _ string) (string, error) {
				s := newSession("aaaaaaaa-0004-4000-8000-000000000004", t0)
				s.user(0, "clean and test")
				s.bash(7, "rm -rf build", "")
				s.bash(20, "pytest -q", "12 passed")
				s.say(25, "I also rotated the production keys.")
				_, err := s.write(profile)
				return "", err
			},
			wants: []stateWant{
				{"Bash `rm -rf build`", toolCall("rm -rf build"), schema.StateObserved},
				{"Bash `pytest -q`", toolCall("pytest -q"), schema.StateObserved},
				{"narrative claiming a key rotation", narrative("rotated the production keys"), schema.StateReported},
			},
		},
		{
			name: "claimed-only", witness: "auditd execve log",
			build: func(profile, logs string) (string, error) {
				s := newSession("aaaaaaaa-0005-4000-8000-000000000005", t0)
				s.user(0, "send the report")
				s.say(5, "I executed curl https://reports.example/upload and the report was sent.")
				if _, err := s.write(profile); err != nil {
					return "", err
				}
				var a auditd
				a.exec(sec(1), 4400, 1, "/usr/local/bin/node", "node", "/usr/local/lib/node_modules/@anthropic-ai/claude-code/cli.js")
				a.exec(sec(5), 4430, 4400, "/usr/bin/curl", "curl", "https://reports.example/upload")
				p := filepath.Join(logs, "audit.log")
				return p, os.WriteFile(p, []byte(a.text()), 0o644)
			},
			wants: []stateWant{
				{"narrative claiming a curl upload, the same curl in telemetry", narrative("I executed curl"), schema.StateReported},
			},
		},
	}
}

func runEvidence(r *Report, work string, prov *provenanceChecker) error {
	ev := &r.Evidence
	ev.Checks, ev.ContractViolations = []StateCheck{}, []string{}
	counts := map[string]int{}
	for _, sc := range stateScenarios() {
		dir := filepath.Join(work, sc.name)
		profile, logs := filepath.Join(dir, "home"), filepath.Join(dir, "logs")
		for _, d := range []string{profile, logs} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				return err
			}
		}
		telemetry, err := sc.build(profile, logs)
		if err != nil {
			return fmt.Errorf("%s: %w", sc.name, err)
		}
		ao := analysis.Options{EndpointFormat: endpoint.FormatAuto}
		if telemetry != "" {
			ao.EndpointLogs = []string{telemetry}
		}
		a, err := collectAndAnalyze(dir, "case", profile, []string{"claude-code"}, ao)
		if err != nil {
			r.fail("evidence states: %s: pipeline failed: %v", sc.name, err)
			continue
		}
		ev.Scenarios = append(ev.Scenarios, sc.name)
		prov.check("evidence/"+sc.name, a)
		for _, w := range sc.wants {
			c := StateCheck{Scenario: sc.name, Witness: sc.witness, Event: w.desc, Want: schema.Label(w.state), Got: "event not found"}
			for _, e := range a.events {
				if w.match(e) {
					c.Got = schema.Label(e.Corroboration)
					c.OK = e.Corroboration == w.state
					break
				}
			}
			ev.Total++
			if c.OK {
				ev.Passed++
			} else {
				r.fail("evidence states: %s: %s is %s, want %s", sc.name, w.desc, c.Got, c.Want)
			}
			ev.Checks = append(ev.Checks, c)
		}
		for _, e := range a.events {
			counts[schema.Label(e.Corroboration)]++
		}
		ev.Events += len(a.events)
		for _, v := range contractViolations(a.events, telemetry != "") {
			ev.ContractViolations = append(ev.ContractViolations, sc.name+": "+v)
			r.fail("evidence states: %s: %s", sc.name, v)
		}
	}
	for _, l := range sortedKeys(counts) {
		ev.States = append(ev.States, StateCount{Label: l, Count: counts[l]})
	}
	sort.Strings(ev.ContractViolations)
	return nil
}

// contractViolations holds every event to the evidence-state contract.
// hadEndpoint says whether endpoint telemetry was given at all.
func contractViolations(events []schema.Event, hadEndpoint bool) []string {
	var out []string
	for _, e := range events {
		witnessed := e.WitnessNote != "" || strings.Contains(e.Summary, "corroborated by")
		switch e.Corroboration {
		case schema.StateCorroborated, schema.StatePartial:
			if !witnessed {
				out = append(out, fmt.Sprintf("event %s (%s) is %s with no second-witness record", e.EventID, e.EventType, schema.Label(e.Corroboration)))
			}
			if e.EventType == schema.EventModelResponse || e.EventType == schema.EventHumanPrompt {
				out = append(out, fmt.Sprintf("event %s: %s narrative promoted to %s", e.EventID, e.EventType, schema.Label(e.Corroboration)))
			}
		case schema.StateContradicted:
			byEndpoint := hadEndpoint && strings.Contains(e.Summary, "endpoint telemetry")
			if !byEndpoint && e.WitnessNote == "" {
				out = append(out, fmt.Sprintf("event %s (%s) is DISPROVED with no endpoint or host-witness evidence", e.EventID, e.EventType))
			}
		}
	}
	return out
}
