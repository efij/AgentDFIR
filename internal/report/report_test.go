package report

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/internal/casepkg"
	"github.com/efij/AgentDFIR/internal/schema"
)

func hostileCase() *Case {
	// Evidence deliberately carries HTML injection, an external-resource
	// beacon attempt, ANSI escapes and bidi text.
	return &Case{
		Manifest: &casepkg.Manifest{
			CaseID: "R-1", Host: "h", OS: "darwin", Arch: "arm64",
			CollectorName: "agentdfir", CollectorVersion: "test",
			Artifacts: []casepkg.ArtifactRecord{{
				LogicalPath:  `<img src="https://evil.example/beacon.png">.jsonl`,
				ArtifactType: "agent_session", Status: casepkg.StatusOK,
				ArtifactID: strings.Repeat("a", 64), Size: 10,
			}},
		},
		CaseInfo: &casepkg.CaseInfo{OperatorOSUser: "op"},
		Verify:   &casepkg.VerifyResult{},
		Events: []schema.Event{{
			EventID: "e1", EventType: schema.EventModelResponse,
			ActorType: schema.ActorModel, Corroboration: schema.StateReported,
			Summary:    "<script>alert(1)</script>\x1b[2Jhidden‮txt",
			SourcePath: "s.jsonl", SourceLine: 1, SourceArtifact: "aa",
			Timestamp: "2026-08-30T10:00:00Z",
		}},
		Findings: []schema.Finding{{
			RuleID: "ORPHAN_AGENT", Severity: "HIGH",
			Title:       `Unexpected <b onmouseover=alert(2)>Agent</b>`,
			Description: `see <a href="http://evil.example">link</a>`,
			Status:      schema.StateObserved, Endpoint: schema.StateUnknown,
			EvidenceRefs: []string{"s.jsonl:1"},
		}},
	}
}

func TestHTMLReportIsNetworkSilentAndEscaped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.html")
	if err := WriteHTML(hostileCase(), path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)

	// CSP must forbid all external loads.
	if !strings.Contains(html, `default-src 'none'`) {
		t.Fatal("missing restrictive CSP")
	}
	// No unescaped tags from evidence.
	for _, banned := range []string{"<script>alert", `<img src="https://evil`, `<a href="http://evil`, "<b onmouseover"} {
		if strings.Contains(html, banned) {
			t.Fatalf("evidence HTML not escaped: found %q", banned)
		}
	}
	// No live external URL in an attribute position (src=/href= with scheme).
	extAttr := regexp.MustCompile(`(?i)(src|href)\s*=\s*["']https?://`)
	if extAttr.MatchString(html) {
		t.Fatal("report references an external resource — must be network-silent")
	}
	// ANSI escape must not survive.
	if strings.Contains(html, "\x1b") {
		t.Fatal("ANSI escape survived into report")
	}
}

func TestCSVOutputs(t *testing.T) {
	dir := t.TempDir()
	c := hostileCase()
	if err := WriteFindingsCSV(c, filepath.Join(dir, "f.csv")); err != nil {
		t.Fatal(err)
	}
	if err := WriteTimelineCSV(c, filepath.Join(dir, "t.csv")); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "t.csv"))
	if !strings.Contains(string(data), "REPORTED") {
		t.Fatal("timeline CSV missing corroboration state")
	}
}
