package corpus

import (
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

var updateChainGolden = flag.Bool("update-chain-golden", false, "regenerate testdata/chains-v45.golden")

// v45Chains are the attack chains that shipped in v4.5. Their output over
// the corpus is frozen: a change to the chain engine (links, case scope,
// new step predicates) must leave every one of them matching exactly the
// same events with exactly the same text.
var v45Chains = map[string]bool{
	"CHAIN_CONTEXT_POISON_TO_EXEC": true, "CHAIN_SECRET_TO_EXFIL": true, "CHAIN_ORPHAN_PERSISTENCE": true,
	"CHAIN_MCP_RESULT_TO_DESTRUCTIVE": true, "CHAIN_INJECTION_TO_PUSH": true, "CHAIN_DOWNLOAD_AND_EXECUTE": true,
	"CHAIN_ACTION_THEN_LOG_TAMPER": true, "CHAIN_SUBAGENT_CROSS_TALK_EXFIL": true, "CHAIN_CROSS_TOOL_EXFIL": true,
	"CHAIN_MCP_RESULT_TO_PRIVILEGED": true, "CHAIN_PERMISSION_ESCALATION_TO_IMPACT": true,
	"CHAIN_STAGED_DATA_TO_TRANSFER": true, "CHAIN_SECRET_TO_NEW_REMOTE_PUSH": true,
}

// TestV45ChainOutputUnchanged compares the v4.5 chains' findings over the
// whole corpus with a golden file recorded before the v5 engine changes.
//
//	go test ./internal/corpus -run TestV45ChainOutputUnchanged -update-chain-golden
func TestV45ChainOutputUnchanged(t *testing.T) {
	if testing.Short() {
		t.Skip("analyses the whole corpus")
	}
	cases, err := Load("testdata")
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, c := range cases {
		for _, f := range analyseCase(t, c) {
			if !v45Chains[f.RuleID] {
				continue
			}
			var b strings.Builder
			b.WriteString(c.Kind + "/" + c.Name + " " + f.RuleID + " " + f.Severity + " " + f.Status + " " + f.SessionID + " " + f.AgentID + "\n")
			b.WriteString("  " + f.Description + "\n")
			for _, s := range f.ChainSteps {
				b.WriteString("  - " + s.Step + " | " + s.Timestamp + " | " + s.AgentID + " | " + s.Summary + " | " + s.Evidence + "\n")
			}
			lines = append(lines, b.String())
		}
	}
	sort.Strings(lines)
	got := strings.Join(lines, "")
	path := filepath.Join("testdata", "chains-v45.golden")
	if *updateChainGolden {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update-chain-golden on the v4.5 engine)", err)
	}
	if got != string(want) {
		t.Errorf("v4.5 chain output changed over the corpus.\n--- want\n%s\n--- got\n%s", want, got)
	}
}
