package proof

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v4/internal/analysis"
	"github.com/efij/AgentDFIR/v4/internal/casepkg"
	"github.com/efij/AgentDFIR/v4/internal/collector"
	"github.com/efij/AgentDFIR/v4/internal/endpoint"
	"github.com/efij/AgentDFIR/v4/internal/overlay"
	"github.com/efij/AgentDFIR/v4/internal/products"
	"github.com/efij/AgentDFIR/v4/internal/schema"
)

// A collected Claude Code profile: one corroborated command whose process
// connected out and wrote a file, one command auditd never saw (inside
// healthy coverage: DISPROVED), and one inside an audit-serial gap (not
// disproved: the telemetry may have lost it).
func buildCase(t *testing.T) (pkg, telemetry string) {
	t.Helper()
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, ".claude", "projects", "p"), 0o755)
	lines := []string{
		`{"type":"user","uuid":"u1","sessionId":"s1","timestamp":"2026-08-30T10:00:00Z","message":{"role":"user","content":"build, upload, test"}}`,
		`{"type":"assistant","uuid":"a1","parentUuid":"u1","sessionId":"s1","timestamp":"2026-08-30T10:00:05Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"curl -s https://upload.example/x -o /w/out.txt"}}]}}`,
		`{"type":"assistant","uuid":"a2","parentUuid":"a1","sessionId":"s1","timestamp":"2026-08-30T10:00:20Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"t2","name":"Bash","input":{"command":"pytest -q"}}]}}`,
		`{"type":"assistant","uuid":"a3","parentUuid":"a2","sessionId":"s1","timestamp":"2026-08-30T10:00:45Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"t3","name":"Bash","input":{"command":"make lint"}}]}}`,
	}
	_ = os.WriteFile(filepath.Join(root, ".claude", "projects", "p", "s1.jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o644)
	pkg = filepath.Join(t.TempDir(), "p.adfir")
	b, err := casepkg.New(pkg, "PROOF", casepkg.CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	man, _ := products.ManifestAllPlatforms("claude-code")
	if _, err := collector.Run(b, man, collector.Options{ProfileRoot: root, ConfigRoot: filepath.Join(root, ".claude"), SystemRoot: root, Product: "claude-code"}); err != nil {
		t.Fatal(err)
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	// 1788084000 = 2026-08-30T10:00:00Z
	audit := strings.Join([]string{
		`type=SYSCALL msg=audit(1788084001.000:10): arch=c000003e syscall=59 success=yes exit=0 ppid=1 pid=4400 auid=1000 uid=1000 comm="node" exe="/usr/local/bin/node"`,
		`type=EXECVE msg=audit(1788084001.000:10): argc=2 a0="node" a1="/usr/local/lib/node_modules/@anthropic-ai/claude-code/cli.js"`,
		`type=SYSCALL msg=audit(1788084005.500:11): arch=c000003e syscall=59 success=yes exit=0 ppid=4400 pid=4411 auid=1000 uid=1000 comm="curl" exe="/usr/bin/curl"`,
		`type=EXECVE msg=audit(1788084005.500:11): argc=5 a0="curl" a1="-s" a2="https://upload.example/x" a3="-o" a4="/w/out.txt"`,
		`type=SYSCALL msg=audit(1788084006.000:12): arch=c000003e syscall=42 success=yes exit=0 ppid=4400 pid=4411 auid=1000 uid=1000 comm="curl" exe="/usr/bin/curl"`,
		`type=SOCKADDR msg=audit(1788084006.000:12): saddr=020001BBCB0071090000000000000000`,
		`type=SYSCALL msg=audit(1788084007.000:13): arch=c000003e syscall=257 success=yes exit=3 a2=241 ppid=4400 pid=4411 auid=1000 uid=1000 comm="curl" exe="/usr/bin/curl"`,
		`type=PATH msg=audit(1788084007.000:13): item=0 name="/w/out.txt" nametype=CREATE`,
		`type=SYSCALL msg=audit(1788084030.000:14): arch=c000003e syscall=59 success=yes exit=0 ppid=4400 pid=4420 auid=1000 uid=1000 comm="git" exe="/usr/bin/git"`,
		`type=EXECVE msg=audit(1788084030.000:14): argc=2 a0="git" a1="status"`,
		// serials 15..19 never written
		`type=SYSCALL msg=audit(1788084050.000:20): arch=c000003e syscall=59 success=yes exit=0 ppid=4400 pid=4430 auid=1000 uid=1000 comm="git" exe="/usr/bin/git"`,
		`type=EXECVE msg=audit(1788084050.000:20): argc=2 a0="git" a1="diff"`,
		`type=SYSCALL msg=audit(1788084060.000:21): arch=c000003e syscall=59 success=yes exit=0 ppid=4400 pid=4431 auid=1000 uid=1000 comm="git" exe="/usr/bin/git"`,
		`type=EXECVE msg=audit(1788084060.000:21): argc=2 a0="git" a1="log"`,
	}, "\n") + "\n"
	telemetry = filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(telemetry, []byte(audit), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := analysis.Run(pkg, analysis.Options{EndpointLogs: []string{telemetry}, EndpointFormat: endpoint.FormatAuditd}); err != nil {
		t.Fatal(err)
	}
	return pkg, telemetry
}

func actionFor(r *Report, sub string) *Action {
	for i := range r.Actions {
		if strings.Contains(r.Actions[i].Claim, sub) {
			return &r.Actions[i]
		}
	}
	return nil
}

func TestProofReport(t *testing.T) {
	pkg, telemetry := buildCase(t)
	r, err := Load(pkg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Telemetry.Imported || len(r.Telemetry.Sources) != 1 || r.Telemetry.Sources[0].Verdict != endpoint.HealthPartial {
		t.Fatalf("telemetry: %+v", r.Telemetry)
	}
	curl := actionFor(r, "curl")
	if curl == nil || curl.State != schema.StateCorroborated || curl.Confidence == "inferred" {
		t.Fatalf("curl: %+v", curl)
	}
	roles := map[string]bool{}
	for _, s := range curl.Chain {
		roles[s.Role] = true
	}
	for _, want := range []string{"human", "agent", "tool_call", "process", "network", "file", "outcome"} {
		if !roles[want] {
			t.Errorf("curl chain lacks %s: %+v", want, curl.Chain)
		}
	}
	if curl.Chain[0].Role != "human" {
		t.Errorf("chain does not start at the human: %+v", curl.Chain[0])
	}
	pytest := actionFor(r, "pytest")
	if pytest == nil || pytest.State != schema.StateContradicted || pytest.Coverage[0].Coverage != "healthy" || !pytest.Coverage[0].Decided {
		t.Fatalf("pytest: %+v", pytest)
	}
	lint := actionFor(r, "make lint")
	if lint == nil || lint.State == schema.StateContradicted || lint.Coverage[0].Coverage != "partial" {
		t.Fatalf("make lint inside the serial gap: %+v", lint)
	}
	if !strings.Contains(strings.Join(lint.Limitations, "|"), "process telemetry partial") {
		t.Errorf("lint limitations: %v", lint.Limitations)
	}

	// Golden-ish text: the sections and the facts that justify the states.
	var buf bytes.Buffer
	WriteText(&buf, r)
	text := buf.String()
	if os.Getenv("PROOF_DUMP") != "" {
		t.Log(text)
	}
	for _, want := range []string{"TELEMETRY COVERAGE & HEALTH", "PARTIAL  audit.log", "sequence auditd/audit.log", "gap: 5 missing after 14",
		"DISPROVED", "coverage:   process (needed) healthy", "coverage:   process (needed) partial", "─executed_as→ process", "─resulted_in→ outcome", "CHECKING THIS REPORT"} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q:\n%s", want, text)
		}
	}

	// Deterministic: the same package gives byte-identical output.
	r2, _ := Load(pkg, Options{})
	a, _ := json.Marshal(r)
	b, _ := json.Marshal(r2)
	if !bytes.Equal(a, b) {
		t.Fatal("proof JSON differs between two runs")
	}
	checkRefs(t, pkg, telemetry, a)
}

// checkRefs is what an independent verifier does with the JSON: every
// artifact reference resolves to a sealed artifact whose plaintext hashes
// to its id, every telemetry reference names a telemetry file whose hash
// matches, and every derived file hashes as listed.
func checkRefs(t *testing.T, pkg, telemetry string, doc []byte) {
	t.Helper()
	var r Report
	if err := json.Unmarshal(doc, &r); err != nil {
		t.Fatal(err)
	}
	store, err := casepkg.OpenStore(pkg)
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, a := range r.Artifacts {
		data, err := store.ReadAll(a.ArtifactID, 64<<20)
		if err != nil || SHA256(data) != a.ArtifactID || !a.InManifest || a.LogicalPath == "" {
			t.Errorf("artifact %s does not resolve: %v", a.ArtifactID, err)
		}
		listed[a.ArtifactID] = true
	}
	sources := map[string]string{}
	for _, s := range r.Telemetry.Sources {
		sources[s.File] = s.SHA256
	}
	tdata, _ := os.ReadFile(telemetry)
	if sources[filepath.Base(telemetry)] != SHA256(tdata) {
		t.Errorf("telemetry source hash %q, file hashes %s", sources[filepath.Base(telemetry)], SHA256(tdata))
	}
	telemetryRefs := 0
	check := func(ref SourceRef, where string) {
		switch {
		case ref.ArtifactID != "":
			if !listed[ref.ArtifactID] {
				t.Errorf("%s: artifact %s not in the artifacts list", where, ref.ArtifactID)
			}
		case ref.Telemetry != "":
			telemetryRefs++
			if ref.TelemetryFile == "" || sources[ref.TelemetryFile] == "" || ref.TelemetrySHA256 != sources[ref.TelemetryFile] {
				t.Errorf("%s: telemetry ref %q not tied to a source file: %+v", where, ref.Telemetry, ref)
			}
			// the record is findable in that file: file:line
			if i := strings.Index(ref.Telemetry, "audit.log:"); i < 0 {
				t.Errorf("%s: telemetry ref %q has no file:line", where, ref.Telemetry)
			}
		default:
			if ref.EventID == "" {
				t.Errorf("%s: reference names nothing: %+v", where, ref)
			}
		}
	}
	for _, a := range r.Actions {
		check(a.Source, a.EventID)
		for _, s := range a.Chain {
			for _, ref := range s.Refs {
				check(ref, a.EventID+" "+s.Node)
			}
		}
	}
	if telemetryRefs == 0 {
		t.Error("no telemetry reference was checked")
	}
	for _, d := range r.Derived {
		data, err := overlay.ReadFile(filepath.Join(pkg, filepath.FromSlash(d.Path)))
		if err != nil || SHA256(data) != d.SHA256 {
			t.Errorf("derived %s does not hash as listed: %v", d.Path, err)
		}
	}
	if len(r.Derived) != 2 {
		t.Errorf("derived files: %+v", r.Derived)
	}
}

// Without telemetry the report says so and nothing is disproved.
func TestProofReportNoTelemetry(t *testing.T) {
	r := Build(Input{CaseID: "X", Events: []schema.Event{{EventID: "e1", EventType: schema.EventToolCall, Tool: "Bash", Command: "ls", Corroboration: schema.StateObserved}}}, Options{})
	if r.Telemetry.Imported || r.Telemetry.Note == "" || len(r.Actions) != 1 || r.Actions[0].Confidence != "inferred" {
		t.Fatalf("%+v", r)
	}
}
