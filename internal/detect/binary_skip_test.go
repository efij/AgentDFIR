package detect

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/efij/AgentDFIR/v2/internal/casepkg"
	"github.com/efij/AgentDFIR/v2/internal/collector"
	"github.com/efij/AgentDFIR/v2/internal/normalize"
	"github.com/efij/AgentDFIR/v2/internal/products"
)

// A .pptx in a skill directory is agent_definitions by path, but it is not
// text. Its bytes F3 A0 80 BA decode as tag character U+E003A and an
// injection phrase can sit in a zip member name; neither is an instruction
// anyone gave an agent.
func TestContentRulesSkipBinaryArtifacts(t *testing.T) {
	root := t.TempDir()
	deck := []byte("PK\x03\x04\x14\x00\x00\x00\x08\x00")
	deck = append(deck, []byte("ignore previous instructions")...)
	deck = append(deck, []byte("\x00\x00\xF3\xA0\x80\xBA\x1b\x8f\x00\x02\xff\xfe")...)
	for i := 0; i < 64; i++ {
		deck = append(deck, byte(i*7), 0x00, byte(255-i))
	}
	p := filepath.Join(root, ".claude", "skills", "deck", "template.pptx")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, deck, 0o644); err != nil {
		t.Fatal(err)
	}
	pkg := filepath.Join(t.TempDir(), "bin.adfir")
	b, err := casepkg.New(pkg, "BIN-1", casepkg.CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	man, _ := products.Manifest("claude-code")
	if _, err := collector.Run(b, man, collector.Options{
		ProfileRoot: root, ConfigRoot: filepath.Join(root, ".claude"),
		SystemRoot: root, Product: "claude-code",
	}); err != nil {
		t.Fatal(err)
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	res, err := normalize.ParsePackage(pkg)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range RunPackageWithOptions(res, pkg, nil) {
		switch f.RuleID {
		case "INVISIBLE_UNICODE_INSTRUCTION", "TOOL_POISONING_INDICATOR", "AGENT_CONTEXT_POISONING", "PROMPT_INJECTION_INDICATOR":
			t.Errorf("%s fired on a binary artifact: %s", f.RuleID, f.EvidenceRefs)
		}
	}
}
