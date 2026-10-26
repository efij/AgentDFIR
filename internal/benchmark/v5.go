package benchmark

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/analysis"
	"github.com/efij/AgentDFIR/v4/internal/catalog"
	"github.com/efij/AgentDFIR/v4/internal/chain"
	"github.com/efij/AgentDFIR/v4/internal/crosscase"
	"github.com/efij/AgentDFIR/v4/internal/mitre"
	"github.com/efij/AgentDFIR/v4/internal/mitre/coverage"
	"github.com/efij/AgentDFIR/v4/internal/normalize"
	"github.com/efij/AgentDFIR/v4/internal/overlay"
	"github.com/efij/AgentDFIR/v4/internal/rulepack"
	"github.com/efij/AgentDFIR/v4/internal/schema"
)

// The v5 suites: the rules and chains v5 added, measured on labeled
// corpus cases (attack case + benign twin, transcripts through the real
// parsers); the structured tool-call evidence fields, end to end, with
// credentials placed in tool arguments; the cross-case activity graph
// (correlate-cases --graph) on sealed packages; and every MITRE reference
// against the pinned catalogs plus the ATLAS relevance inventory gate.

// V5Rules are the rule and chain IDs v5 added. Each must have an attack
// case in the corpus that names it and a benign twin that must not raise it.
var V5Rules = []string{
	"MCP_ARGUMENT_BEHAVIOR_MISMATCH", "MCP_TOOL_IDENTITY_DRIFT", "AGENT_PERMISSION_STATE_DRIFT",
	"AGENT_CREDENTIAL_TO_EXTERNAL_TOOL", "AGENT_UNAUTHORIZED_RESOURCE_CHANGE", "AGENT_AUTONOMOUS_RECON_SEQUENCE",
	"AGENT_ADAPTIVE_ATTACK_SEQUENCE", "AGENT_DELEGATION_SCOPE_EXPANSION", "AGENT_RESOURCE_EXHAUSTION",
	"AGENT_MULTIMODAL_TRIGGER_CHAIN",
	"CHAIN_SKILL_POISON_TO_EXEC", "CHAIN_MCP_RUG_PULL_TO_ACTION", "CHAIN_TOOL_RESPONSE_TO_SECRET_EXFIL",
	"CHAIN_SHARED_MEMORY_TO_SUBAGENT", "CHAIN_BROWSER_TOKEN_TO_ACCOUNT_ACTION", "CHAIN_AGENT_RECON_TO_IMPACT",
	"CHAIN_ADAPTIVE_RETRY_TO_BYPASS",
}

// V5 holds the checks of the v5 suites, by suite.
type V5 struct {
	Detections []Check `json:"v5_detections"`
	Evidence   []Check `json:"evidence_fields"`
	CrossCase  []Check `json:"cross_case_graph"`
	MITRE      []Check `json:"mitre_catalogs"`
}

func runV5Suites(r *Report, o Options, work string, prov *provenanceChecker) {
	logf := func(format string, a ...any) {
		if o.Log != nil {
			fmt.Fprintf(o.Log, format+"\n", a...)
		}
	}
	r.V5 = &V5{}
	logf("v5 detections: attack cases and benign twins")
	v5DetectionSuite(r, o)
	logf("evidence fields: credentials in tool arguments")
	evidenceFieldSuite(r, filepath.Join(work, "suites", "evidence-fields"), prov)
	logf("cross-case graph: strong and weak joins")
	crossCaseSuite(r, filepath.Join(work, "suites", "crosscase"))
	logf("MITRE: pinned catalogs and the ATLAS inventory gate")
	mitreSuite(r)
}

// ---------------------------------------------------------------- v5 detections

// v5DetectionSuite checks, per v5 rule or chain, that the corpus has an
// attack case naming it and a benign twin naming that case back, and, when
// the detection section ran those fixtures, that the attack case raised
// the rule and the twin did not. In the quick subset only the labels are
// checked.
func v5DetectionSuite(r *Report, o Options) {
	var checks []Check
	byName := map[string]fixture{}
	for _, f := range r.fixtures {
		if f.case_ != nil {
			byName[f.case_.Kind+"/"+f.case_.Name] = f
		}
	}
	fired := 0
	for _, id := range V5Rules {
		c := Check{Name: id, Want: "an attack case raises it; its benign twin does not", Got: "no attack case names it"}
		var good, bad, unrun []string
		for _, f := range r.fixtures {
			if f.case_ == nil || !f.attack || !contains(f.expect, id) {
				continue
			}
			twin, has := byName["benign/"+f.case_.Twin]
			if !has || twin.case_.Twin != f.case_.Name {
				bad = append(bad, f.case_.Name+": no benign twin naming it back")
				continue
			}
			if _, allowed := twin.allow[id]; allowed {
				continue // this pair is about another rule; its twin raises id on purpose
			}
			got, gotRan := r.fired[f.name]
			tgot, twinRan := r.fired[twin.name]
			switch {
			case !gotRan || !twinRan:
				unrun = append(unrun, f.case_.Name+" / "+twin.case_.Name)
			case got[id] == 0:
				bad = append(bad, f.case_.Name+": not raised")
			case tgot[id] > 0:
				bad = append(bad, fmt.Sprintf("twin %s raised it ×%d", twin.case_.Name, tgot[id]))
			default:
				good = append(good, fmt.Sprintf("%s ×%d; twin %s silent", f.case_.Name, got[id], twin.case_.Name))
			}
		}
		ok := false
		switch {
		case len(bad) > 0:
			c.Got = strings.Join(bad, "; ")
		case len(good) > 0:
			c.Got, ok = strings.Join(good, "; "), true
			fired++
		case len(unrun) > 0:
			c.Got, ok = strings.Join(unrun, "; ")+": labels present (not run in this subset)", o.Quick
		}
		r.record("v5 detections", &c, ok)
		checks = append(checks, c)
	}
	r.V5.Detections = checks
	sum := fmt.Sprintf("%d v5 rules and chains: %d raised by their attack case with a silent benign twin", len(V5Rules), fired)
	if o.Quick {
		sum += " (quick subset: labels checked, fixtures not all run)"
	}
	r.Suites = append(r.Suites, verdict("v5 detections", sum, checks, false))
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- evidence fields

// fieldSecrets are credential-shaped values built at run time (a
// key-shaped literal in the repository is refused by push protection).
func fieldSecrets() []string {
	sum := sha256.Sum256([]byte("agentdfir benchmark evidence fields"))
	h := hex.EncodeToString(sum[:])
	return []string{
		"gh" + "p_" + h[:36],
		"AKIA" + strings.ToUpper(h[36:52]),
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJiZW5jaC12NSJ9." + h[:40],
	}
}

// evidenceFieldSuite collects a transcript whose tool calls carry
// credentials in their arguments (an MCP message, nested MCP arguments, a
// URL query, file content) and checks that the parsers filled the
// structured fields (argument keys, digests, allowlisted values, paired
// results), that the credential-to-external-tool rule saw the credential,
// and that no credential value appears anywhere in the derived outputs
// (events, findings, reports): only the sealed source holds them.
func evidenceFieldSuite(r *Report, work string, prov *provenanceChecker) {
	secrets := fieldSecrets()
	profile := filepath.Join(work, "home")
	s := newSession("eeeeeeee-5000-4000-8000-000000000001", t0)
	s.user(0, "post the release note and fetch the changelog")
	s.tool(5, "mcp__slack__post_message", map[string]any{"channel": "#release", "text": "token " + secrets[0]})
	s.tool(10, "mcp__vault__put_secret", map[string]any{"path": "/kv/ci", "data": map[string]any{"aws_key": secrets[1], "list": []any{secrets[2]}}})
	s.tool(15, "WebFetch", map[string]any{"url": "https://changelog.example.net/v5?access_token=" + secrets[0], "prompt": "summarize"})
	s.tool(20, "Write", map[string]any{"file_path": "/home/dev/app/.env.ci", "content": "AWS_ACCESS_KEY_ID=" + secrets[1] + "\n"})
	s.say(25, "Done.")
	var checks []Check
	add := func(name, want, got string, ok bool) {
		c := Check{Name: name, Want: want, Got: got}
		r.record("evidence fields", &c, ok)
		checks = append(checks, c)
	}
	finish := func(sum string) {
		r.V5.Evidence = checks
		r.Suites = append(r.Suites, verdict("evidence fields", sum, checks, false))
	}
	if _, err := s.write(profile); err != nil {
		add("fixture written", "ok", err.Error(), false)
		finish("fixture could not be written")
		return
	}
	a, err := collectAndAnalyze(work, "fields", profile, []string{"claude-code"}, analysis.Options{})
	if err != nil {
		add("pipeline", "collect and analyze", err.Error(), false)
		finish("pipeline failed")
		return
	}
	r.newPackages = append(r.newPackages, a.pkg)
	prov.check("evidence-fields", a)

	call := func(tool string) (schema.Event, bool) {
		for _, e := range a.events {
			if e.EventType == schema.EventToolCall && e.Tool == tool {
				return e, true
			}
		}
		return schema.Event{}, false
	}
	slack, _ := call("mcp__slack__post_message")
	add("MCP call: argument keys, digest, paired outcome", "arg_keys channel,text; args_digest; result_status ok; result_ref",
		fmt.Sprintf("arg_keys %q, digest %t, status %q, result_ref %t", slack.ArgKeys, slack.ArgsDigest != "", slack.ResultStatus, slack.ResultRef != ""),
		slack.ArgKeys == "channel,text" && slack.ArgsDigest != "" && slack.ResultStatus == "ok" && slack.ResultRef != "")
	vault, _ := call("mcp__vault__put_secret")
	add("nested MCP arguments: top-level keys only, path allowlisted", "arg_keys data,path; safe_args path=/kv/ci only",
		fmt.Sprintf("arg_keys %q, safe_args %v", vault.ArgKeys, vault.SafeArgs),
		vault.ArgKeys == "data,path" && len(vault.SafeArgs) == 1 && vault.SafeArgs["path"] == "/kv/ci")
	fetch, _ := call("WebFetch")
	add("URL argument reduced to scheme and host", "safe_args url=https://changelog.example.net",
		fmt.Sprintf("safe_args %v", fetch.SafeArgs), fetch.SafeArgs["url"] == "https://changelog.example.net")
	n := 0
	for _, f := range a.findings {
		if f.RuleID == "AGENT_CREDENTIAL_TO_EXTERNAL_TOOL" && f.Severity != "INFO" {
			n++
		}
	}
	add("credential in tool arguments is seen", "AGENT_CREDENTIAL_TO_EXTERNAL_TOOL ≥ 1", fmt.Sprintf("%d", n), n > 0)

	// No credential value in any derived output: everything in the
	// package except the sealed source blobs.
	leaks, files := scanDerived(a.pkg, secrets)
	js, _ := json.Marshal(struct {
		E []schema.Event
		F []schema.Finding
	}{a.events, a.findings})
	for i, sec := range secrets {
		if bytes.Contains(js, []byte(sec)) {
			leaks = append(leaks, fmt.Sprintf("secret %d in events/findings", i+1))
		}
	}
	got := fmt.Sprintf("none in %d derived files, %d events, %d findings", files, len(a.events), len(a.findings))
	if len(leaks) > 0 {
		got = strings.Join(leaks, "; ")
	}
	add("no credential value in events, findings or reports", "none", got, len(leaks) == 0)
	finish(fmt.Sprintf("%d credentials in 4 tool calls; structured fields filled; %s", len(secrets), got))
}

// scanDerived searches every file of a package outside the sealed source
// (raw/) and the seal itself for the given values.
func scanDerived(pkg string, values []string) (leaks []string, files int) {
	_ = filepath.WalkDir(pkg, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(pkg, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == "raw" || rel == "seals" {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > 64<<20 {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		files++
		for i, v := range values {
			if bytes.Contains(data, []byte(v)) {
				leaks = append(leaks, fmt.Sprintf("secret %d in %s", i+1, rel))
			}
		}
		return nil
	})
	return leaks, files
}

// ---------------------------------------------------------------- cross-case graph

// crossCaseSuite builds two pairs of sealed, analyzed packages and runs
// correlate-cases --graph over each. The strong pair: a session on one
// machine resumes a named session on another over ssh, and that session
// then deletes a release directory; the graph must join them strongly
// and raise the propagation chain. The weak pair: two unrelated sessions
// share only a destination, a file name and near-identical prompt text;
// the graph must show only weak edges and raise no finding.
func crossCaseSuite(r *Report, work string) {
	var checks []Check
	add := func(name, want, got string, ok bool) {
		c := Check{Name: name, Want: want, Got: got}
		r.record("cross-case graph", &c, ok)
		checks = append(checks, c)
	}
	finish := func(sum string) {
		r.V5.CrossCase = checks
		r.Suites = append(r.Suites, verdict("cross-case graph", sum, checks, false))
	}
	const (
		sidP = "aaaaaaaa-5000-4000-8000-00000000000a"
		sidS = "bbbbbbbb-5000-4000-8000-00000000000b"
		sidU = "cccccccc-5000-4000-8000-00000000000c"
		sidV = "dddddddd-5000-4000-8000-00000000000d"
	)
	// Both packages of a pair are collected on this machine and record the
	// same host name, so each case's events are stamped with the execution
	// environment of the machine it stands for: the field a container or
	// endpoint witness sets, and what tells the graph the activity is on
	// two hosts.
	build := func(name, sid string, at time.Time, fill func(s *session)) (string, error) {
		s := newSession(sid, at)
		fill(s)
		profile := filepath.Join(work, name)
		if _, err := s.write(profile); err != nil {
			return "", err
		}
		a, err := collectAndAnalyze(work, name, profile, []string{"claude-code"}, analysis.Options{})
		if err != nil {
			return "", err
		}
		evs := a.events
		for i := range evs {
			evs[i].ExecEnv = "bench-" + name
		}
		if err := overlay.WriteJSONLPlain(filepath.Join(a.pkg, "normalized", "events.jsonl"), len(evs), func(i int) any { return evs[i] }); err != nil {
			return "", err
		}
		if err := normalize.RecordEvents(a.pkg); err != nil {
			return "", err
		}
		r.newPackages = append(r.newPackages, a.pkg)
		return a.pkg, nil
	}
	pkgs := map[string]string{}
	for _, c := range []struct {
		name, sid string
		at        time.Time
		fill      func(s *session)
	}{
		{"laptop", sidP, t0, func(s *session) {
			s.user(0, "continue the deploy on the dev box")
			s.bash(5, `ssh dev@devbox "claude --resume `+sidS+` -p 'finish the deploy'"`, "ok")
		}},
		{"devbox", sidS, t0.Add(time.Minute), func(s *session) {
			s.user(0, "finish the deploy")
			s.bash(5, "rm -rf /srv/app/releases/old", "")
		}},
		{"weak-a", sidU, t0, func(s *session) {
			s.user(0, "please refactor the payment reconciliation module and add tests for currency rounding")
			s.bash(5, "curl -s http://203.0.113.50/status", "ok")
		}},
		{"weak-b", sidV, t0.Add(2 * time.Minute), func(s *session) {
			s.user(0, "please refactor the payment reconciliation module and add tests for currency rounding, thanks")
			s.bash(5, "curl -s http://203.0.113.50/health", "ok")
		}},
	} {
		p, err := build(c.name, c.sid, c.at, c.fill)
		if err != nil {
			add("build "+c.name, "sealed and analyzed", err.Error(), false)
			finish("fixture packages could not be built")
			return
		}
		pkgs[c.name] = p
	}

	run := func(a, b string) (*crosscase.Graph, error) {
		rep, err := crosscase.Run([]string{pkgs[a], pkgs[b]}, crosscase.Options{Graph: true})
		if err != nil {
			return nil, err
		}
		return rep.Graph, nil
	}
	joins := func(g *crosscase.Graph) map[string]int {
		m := map[string]int{}
		for _, e := range g.Edges {
			if e.JoinKey != "" {
				m[e.Confidence]++
			}
		}
		return m
	}
	g, err := run("laptop", "devbox")
	if err != nil {
		add("strong pair", "graph", err.Error(), false)
	} else {
		var strong []string
		for _, e := range g.Edges {
			if e.JoinKey != "" && e.Confidence == crosscase.Strong {
				strong = append(strong, e.JoinKey)
			}
		}
		sort.Strings(strong)
		add("strong join: session id named in a remote launch", "≥ 1 strong edge (session_id_in_command)",
			fmt.Sprintf("strong edges %v", strong), contains(strong, crosscase.JoinSessionInCommand))
		var ids []string
		for _, f := range g.Findings {
			ids = append(ids, f.RuleID)
		}
		add("strong join raises the propagation chain", crosscase.RuleCrossHostPropagation,
			fmt.Sprintf("findings %v", ids), contains(ids, crosscase.RuleCrossHostPropagation))
	}
	g2, err := run("weak-a", "weak-b")
	if err != nil {
		add("weak pair", "graph", err.Error(), false)
	} else {
		j := joins(g2)
		add("weak-only pair: weak edges only", "≥ 1 weak edge, no strong or moderate edge",
			fmt.Sprintf("strong %d, moderate %d, weak %d", j[crosscase.Strong], j[crosscase.Moderate], j[crosscase.Weak]),
			j[crosscase.Weak] > 0 && j[crosscase.Strong] == 0 && j[crosscase.Moderate] == 0)
		add("weak-only pair raises no finding", "0 findings", fmt.Sprintf("%d", len(g2.Findings)), len(g2.Findings) == 0)
		out, _ := json.Marshal(g2)
		add("prompt text is not copied into the graph", "absent", fmt.Sprintf("present: %t", bytes.Contains(out, []byte("reconciliation"))),
			!bytes.Contains(out, []byte("reconciliation")))
	}
	finish("strong pair (ssh resume of a named session, then a deletion) and weak-only pair (shared destination and prompt text), sealed and run through correlate-cases --graph")
}

// ---------------------------------------------------------------- MITRE

var (
	atlasIDRe  = regexp.MustCompile(`AML\.T\d{4}(?:\.\d{3})?`)
	attackIDRe = regexp.MustCompile(`\bT\d{4}(?:\.\d{3})?\b`)
)

// mitreSuite checks every ATLAS and ATT&CK reference the binary can emit
// (built-in rules, embedded pack rules, built-in chains, and every finding
// this run produced) against the pinned catalogs, and runs the ATLAS
// relevance inventory gate.
func mitreSuite(r *Report) {
	var checks []Check
	add := func(name, want, got string, ok bool) {
		c := Check{Name: name, Want: want, Got: got}
		r.record("MITRE", &c, ok)
		checks = append(checks, c)
	}
	add("pinned catalogs load", "ATLAS "+mitre.ATLASVersion+", ATT&CK Enterprise "+mitre.ATTACKVersion,
		fmt.Sprintf("error: %v; %d ATLAS techniques", mitre.Err(), len(mitre.ATLAS().Techniques)), mitre.Err() == nil && len(mitre.ATLAS().Techniques) > 0)

	refs := map[string]string{} // "source: field" → value
	for _, c := range catalog.Builtin {
		refs["rule "+c.ID+" atlas"], refs["rule "+c.ID+" attack"] = c.MitreATLAS, c.MitreATTACK
	}
	if packs, _, err := rulepack.Embedded(); err == nil {
		for _, p := range packs {
			for _, x := range p.Rules {
				refs["pack rule "+x.ID+" atlas"], refs["pack rule "+x.ID+" attack"] = x.MitreATLAS, x.MitreATTACK
			}
		}
	} else {
		add("embedded rule packs", "load", err.Error(), false)
	}
	for _, c := range chain.Builtin {
		refs["chain "+c.ID+" atlas"], refs["chain "+c.ID+" attack"] = c.MitreATLAS, c.MitreATTACK
	}
	for k, v := range r.mitreSeen {
		refs["finding "+k] = v
	}
	var bad []string
	nATLAS, nATTACK := 0, 0
	for _, k := range sortedKeys(refs) {
		v := refs[k]
		for _, id := range atlasIDRe.FindAllString(v, -1) {
			nATLAS++
			if !mitre.ValidATLAS(id) {
				bad = append(bad, k+": "+id+" not in ATLAS "+mitre.ATLASVersion)
			}
		}
		for _, id := range attackIDRe.FindAllString(atlasIDRe.ReplaceAllString(v, ""), -1) {
			nATTACK++
			if st := mitre.ATTACKStatus(id); st != mitre.StatusActive {
				bad = append(bad, k+": "+id+" is "+st+" in ATT&CK "+mitre.ATTACKVersion)
			}
		}
	}
	got := fmt.Sprintf("%d ATLAS and %d ATT&CK references, all valid", nATLAS, nATTACK)
	if len(bad) > 0 {
		got = fmt.Sprintf("%d invalid: %s", len(bad), strings.Join(firstN(bad, 8), "; "))
	}
	add("every rule, chain and emitted finding cites valid IDs", "ATLAS techniques exist; ATT&CK techniques active (not revoked or deprecated)", got, len(bad) == 0)

	u, err := coverage.Load()
	if err != nil {
		add("ATLAS relevance inventory", "loads", err.Error(), false)
	} else {
		errs := coverage.Validate(u)
		var msgs []string
		for _, e := range errs {
			msgs = append(msgs, e.Error())
		}
		rep := coverage.Build()
		sm := rep.Summary
		add("ATLAS relevance inventory gate", fmt.Sprintf("%d/%d classified, 0 errors", sm.Techniques, sm.Techniques),
			fmt.Sprintf("%d/%d classified, %d errors %s", sm.Classified, sm.Techniques, len(errs), strings.Join(firstN(msgs, 4), "; ")),
			len(errs) == 0 && sm.Classified == sm.Techniques && len(mitre.Relevance()) == sm.Techniques)
		add("no planned placeholders; every P0 observable technique covered or excepted", "planned 0; P0 observable = covered + exceptions",
			fmt.Sprintf("planned %d; P0 observable %d, covered %d, exceptions %d", sm.Planned, sm.P0Observable, sm.P0Covered, sm.Exceptions),
			sm.Planned == 0 && sm.P0Observable == sm.P0Covered+sm.Exceptions)
		var missing []string
		for _, id := range V5Rules {
			listed := false
			for _, row := range rep.Techniques {
				if contains(row.Rules, id) || contains(row.Chains, id) {
					listed = true
					break
				}
			}
			if !listed {
				missing = append(missing, id)
			}
		}
		add("every v5 rule and chain is listed in the inventory", "17 of 17",
			fmt.Sprintf("%d of %d; missing %v", len(V5Rules)-len(missing), len(V5Rules), missing), len(missing) == 0)
	}
	r.V5.MITRE = checks
	r.Suites = append(r.Suites, verdict("MITRE catalogs", fmt.Sprintf("ATLAS %s, ATT&CK Enterprise %s: %s", mitre.ATLASVersion, mitre.ATTACKVersion, got), checks, false))
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return append(s[:n:n], fmt.Sprintf("… %d more", len(s)-n))
	}
	return s
}
