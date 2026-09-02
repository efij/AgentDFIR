package report

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/internal/casepkg"
	"github.com/efij/AgentDFIR/internal/schema"
)

func pdfCase() *Case {
	var events []schema.Event
	for i := 0; i < 400; i++ { // forces several pages
		events = append(events, schema.Event{EventID: "e", Timestamp: "2026-08-30T10:00:00Z", EventType: schema.EventToolCall,
			Tool: "Bash", Command: "echo " + strings.Repeat("x", 60) + " — ünïcödé ok, 日本語 replaced (paren) back\\slash", AgentID: "main:s1", Corroboration: schema.StateObserved})
	}
	return &Case{
		Manifest: &casepkg.Manifest{CaseID: "PDF-1", Host: "h1", OS: "darwin", Arch: "arm64", ADFIRVersion: "0.1", CollectorName: "agentdfir", CollectorVersion: "x",
			Artifacts: []casepkg.ArtifactRecord{{ArtifactID: "abcdef0123456789", LogicalPath: ".claude/projects/p/s.jsonl", Size: 1234, ArtifactType: "agent_session", Status: casepkg.StatusOK}}},
		CaseInfo: &casepkg.CaseInfo{OperatorOSUser: "op", Authorization: "IR-1", Notes: map[string]string{"mode": "offline-path"}},
		Verify:   &casepkg.VerifyResult{FilesChecked: 5, ArtifactsOK: 1, CollectionRecs: 3, CustodyRecs: 3},
		Events:   events,
		Findings: []schema.Finding{
			{RuleID: "ORPHAN_AGENT", Severity: "HIGH", Title: "Unexpected Agent Activity", Description: "Agent appeared without a verified parent (see evidence).", Status: schema.StateObserved, Endpoint: schema.StateUnknown,
				EvidenceRefs: []string{".claude/projects/p/s.jsonl:1 (artifact abcdef012345, offset 0)"}, ParentAgentID: "UNKNOWN"},
			{RuleID: "AGENT_GENERATED_COMMIT", Severity: "INFO", Title: "Commit", Description: "d", Status: schema.StateObserved, Endpoint: schema.StateUnknown},
			{RuleID: "MCP_TOOL_POISONING", Severity: "CRITICAL", Title: "Poison", Description: "d", Status: schema.StateObserved, Endpoint: schema.StateUnknown, MitreATLAS: "AML.T0053"},
		},
	}
}

// TestPDFStructure re-parses the xref table and checks every offset lands
// on the declared object, the trailer points at the xref, and stream
// lengths are exact — the properties a strict reader (qpdf, Acrobat) checks.
func TestPDFStructure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.pdf")
	custody := []CustodyRecord{{Seq: 0, TS: "2026-08-30T10:00:00Z", Event: "acquisition_started", Extra: "operator_os_user=op"}}
	replaced, err := WritePDF(pdfCase(), custody, "none (package is unsigned)", path, PDFOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if replaced == 0 {
		t.Fatal("CJK runes should have been counted as replaced")
	}
	data, _ := os.ReadFile(path)
	if !bytes.HasPrefix(data, []byte("%PDF-1.4\n")) || !bytes.HasSuffix(data, []byte("%%EOF\n")) {
		t.Fatal("header/trailer markers")
	}
	// startxref → xref table
	sx := regexp.MustCompile(`startxref\n(\d+)\n%%EOF\n$`).FindSubmatch(data)
	if sx == nil {
		t.Fatal("startxref missing")
	}
	xrefOff, _ := strconv.Atoi(string(sx[1]))
	if !bytes.HasPrefix(data[xrefOff:], []byte("xref\n")) {
		t.Fatalf("startxref %d does not point at xref", xrefOff)
	}
	lines := strings.Split(string(data[xrefOff:]), "\n")
	count, _ := strconv.Atoi(strings.Fields(lines[1])[1])
	if count < 8 {
		t.Fatalf("too few objects: %d", count)
	}
	pages := 0
	for i := 1; i < count; i++ {
		fields := strings.Fields(lines[2+i])
		off, _ := strconv.Atoi(fields[0])
		want := []byte(strconv.Itoa(i) + " 0 obj\n")
		if !bytes.HasPrefix(data[off:], want) {
			t.Fatalf("xref entry %d offset %d does not start object (%q)", i, off, data[off:off+12])
		}
		if bytes.HasPrefix(data[off+len(want):], []byte("<< /Type /Page ")) {
			pages++
		}
	}
	if pages < 3 {
		t.Fatalf("expected a multi-page report, got %d pages", pages)
	}
	// Every stream's declared /Length equals the bytes between stream\n and endstream.
	re := regexp.MustCompile(`<< /Length (\d+) >>\nstream\n`)
	for _, m := range re.FindAllSubmatchIndex(data, -1) {
		n, _ := strconv.Atoi(string(data[m[2]:m[3]]))
		body := data[m[1] : m[1]+n]
		if !bytes.HasPrefix(data[m[1]+n:], []byte("endstream")) {
			t.Fatalf("stream length %d wrong (got %q after)", n, data[m[1]+n:m[1]+n+9])
		}
		if bytes.Contains(body, []byte("\x1b")) {
			t.Fatal("escape byte leaked into content stream")
		}
	}
	// Findings are ordered by severity, CRITICAL first; unbalanced parens are escaped.
	s := string(data)
	if strings.Index(s, "[CRITICAL] MCP_TOOL_POISONING") > strings.Index(s, "[HIGH] ORPHAN_AGENT") {
		t.Fatal("findings not sorted by severity")
	}
	if !strings.Contains(s, `\(paren\)`) || !strings.Contains(s, `back\\slash`) {
		t.Fatal("PDF string escaping missing")
	}
	if strings.Contains(s, "日本語") {
		t.Fatal("non-WinAnsi text must not be emitted raw")
	}
	if !strings.Contains(s, "/Info 6 0 R") || !strings.Contains(s, "/Root 1 0 R") {
		t.Fatal("trailer refs")
	}
}

func TestWrapNeverExceedsWidth(t *testing.T) {
	long := strings.Repeat("abcdefghij", 40) + " short words here " + strings.Repeat("Z", 200)
	for _, l := range wrap("F1", pdfBodySize, long, 200) {
		if w := textWidth("F1", pdfBodySize, l); w > 200.01 {
			t.Fatalf("line too wide (%.1f): %q", w, l)
		}
	}
}
