package accountability_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v4/internal/accountability"
	"github.com/efij/AgentDFIR/v4/internal/analysis"
	"github.com/efij/AgentDFIR/v4/internal/casepkg"
	"github.com/efij/AgentDFIR/v4/internal/collector"
	"github.com/efij/AgentDFIR/v4/internal/products"
	"github.com/efij/AgentDFIR/v4/internal/simulate"
)

// build collects a scenario into a sealed package and analyzes it, the way
// `run` does, then returns the package path.
func build(t *testing.T, scenario string) string {
	t.Helper()
	t.Setenv("AGENTDFIR_HOME", t.TempDir())
	t.Setenv("AGENTDFIR_MIN_FREE_GB", "1")
	root := filepath.Join(t.TempDir(), "home")
	sc, ok := simulate.ByID(scenario)
	if !ok {
		t.Fatalf("unknown scenario %s", scenario)
	}
	if err := sc.Run(root); err != nil {
		t.Fatal(err)
	}
	abs, _ := filepath.Abs(root)
	pkg := filepath.Join(t.TempDir(), "case.adfir")
	b, err := casepkg.New(pkg, "ACC-"+scenario, casepkg.CaseInfo{OperatorOSUser: "tester", Authorization: "IR-TEST"})
	if err != nil {
		t.Fatal(err)
	}
	for _, prod := range []string{"claude-code", "host-shell"} {
		man, err := products.ManifestAllPlatforms(prod)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := collector.Run(b, man, collector.Options{ProfileRoot: abs, ConfigRoot: filepath.Join(abs, ".claude"), SystemRoot: abs, Product: prod}); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	b.Close()
	if _, err := analysis.Run(pkg, analysis.Options{}); err != nil {
		t.Fatal(err)
	}
	return pkg
}

func TestPocketWipeShowsForbiddenTargetAndReassurance(t *testing.T) {
	pkg := build(t, "pocketos-wipe")
	rep, err := accountability.Build(pkg, accountability.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Summary.Actions == 0 {
		t.Fatal("no consequential actions found")
	}
	var dropRow *accountability.Row
	for i := range rep.Rows {
		if strings.Contains(rep.Rows[i].Action.Command, "DROP DATABASE") {
			dropRow = &rep.Rows[i]
		}
	}
	if dropRow == nil {
		t.Fatal("no row for the DROP DATABASE action")
	}
	if dropRow.Instruction.Trigger != "human_prompt" {
		t.Errorf("drop instruction trigger = %q, want human_prompt", dropRow.Instruction.Trigger)
	}
	gaps := gapCodes(*dropRow)
	if !gaps["INSTRUCTION_FORBADE_TARGET"] {
		t.Errorf("drop row missing INSTRUCTION_FORBADE_TARGET (the prompt said don't touch prod); gaps=%v", gaps)
	}
	// The reassurance gap fires on at least one destructive row in the case.
	anyReassure := false
	for _, r := range rep.Rows {
		if gapCodes(r)["REASSURANCE_UNVERIFIED"] {
			anyReassure = true
		}
	}
	if !anyReassure {
		t.Error("no REASSURANCE_UNVERIFIED gap; the agent claimed backups were safe")
	}
	if rep.Case.Authorization.Reference != "IR-TEST" {
		t.Errorf("authorization reference not carried: %q", rep.Case.Authorization.Reference)
	}
}

func TestToxicChainShowsToolTriggerAndPermissionWeakened(t *testing.T) {
	pkg := build(t, "toxic-chain")
	rep, err := accountability.Build(pkg, accountability.Options{})
	if err != nil {
		t.Fatal(err)
	}
	sawToolTrigger, sawWeakened := false, false
	for _, r := range rep.Rows {
		if r.Instruction.Trigger == "tool_result" && gapCodes(r)["NO_HUMAN_INSTRUCTION"] {
			sawToolTrigger = true
		}
		if gapCodes(r)["PERMISSION_WEAKENED_BY_AGENT"] {
			sawWeakened = true
		}
	}
	if !sawToolTrigger {
		t.Error("expected a row triggered by tool output with NO_HUMAN_INSTRUCTION (the injection path)")
	}
	if !sawWeakened {
		t.Error("expected PERMISSION_WEAKENED_BY_AGENT after the agent wrote its own settings")
	}
}

func TestBenignTriggerShowsNoneDetected(t *testing.T) {
	// orphan-agent's consequential action (the orphan's claimed curl) has no
	// destructive/credential class and follows a human prompt about analysis;
	// the keyv first action (npm install at a human's request) is the benign
	// control.
	pkg := build(t, "keyv-hook")
	rep, err := accountability.Build(pkg, accountability.Options{})
	if err != nil {
		t.Fatal(err)
	}
	foundNone := false
	for _, r := range rep.Rows {
		if gapCodes(r)["NONE_DETECTED"] {
			foundNone = true
			if len(r.Gaps) != 1 {
				t.Errorf("NONE_DETECTED must be the only gap on a row, got %v", r.Gaps)
			}
		}
	}
	if !foundNone {
		t.Error("expected at least one row with NONE_DETECTED (the install the user asked for)")
	}
}

func TestJSONRoundTripsAndHasHeader(t *testing.T) {
	pkg := build(t, "pocketos-wipe")
	rep, err := accountability.Build(pkg, accountability.Options{})
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "a.json")
	if err := accountability.WriteJSON(rep, p); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p)
	var back accountability.Report
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("report JSON does not round-trip: %v", err)
	}
	if back.Schema != accountability.Schema {
		t.Errorf("schema = %q", back.Schema)
	}
	if back.Case.SealDigest == "" {
		t.Error("header missing seal digest or signature state")
	}
	if len(back.Limits) == 0 {
		t.Error("report has no limits section")
	}
	// Every row cites an evidence reference.
	for _, r := range back.Rows {
		if r.Action.Evidence == "" {
			t.Errorf("row %d has no evidence reference", r.Index)
		}
	}
}

func TestSessionFilter(t *testing.T) {
	pkg := build(t, "toxic-chain")
	full, _ := accountability.Build(pkg, accountability.Options{})
	if len(full.Rows) == 0 {
		t.Fatal("no rows")
	}
	sid := full.Rows[0].SessionID
	one, err := accountability.Build(pkg, accountability.Options{SessionID: sid})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range one.Rows {
		if r.SessionID != sid {
			t.Errorf("session filter leaked row from %s", r.SessionID)
		}
	}
}

func gapCodes(r accountability.Row) map[string]bool {
	m := map[string]bool{}
	for _, g := range r.Gaps {
		m[g.Code] = true
	}
	return m
}
