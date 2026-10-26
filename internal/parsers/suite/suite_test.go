package suite

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v5/internal/casepkg"
	"github.com/efij/AgentDFIR/v5/internal/collector"
	"github.com/efij/AgentDFIR/v5/internal/products"
	"github.com/efij/AgentDFIR/v5/internal/redact"
	"github.com/efij/AgentDFIR/v5/internal/schema"
)

// sealDir seals every file of a fixture directory the way the planner
// does: report.xml as the UFDR report, recognized suite files under their
// rules, everything else as a plain file. It returns the package path.
func sealDir(t *testing.T, dir string) string {
	t.Helper()
	root, _ := filepath.Abs(dir)
	var specs []collector.FileSpec
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rule, typ, prod := "ufdr.file", "ufdr_file", "ufdr"
		if filepath.Base(p) == "report.xml" {
			rule, typ = RuleUFDRReport, "ufdr_report"
		} else if det, ok := ClassifyFile(p, rel); ok {
			rule, typ, prod = det.Rule, det.Type, det.Product
		}
		specs = append(specs, collector.FileSpec{Path: p, Product: prod,
			Entry: products.ManifestEntry{ID: rule, Category: typ, Sensitivity: "high"}})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	pkg := filepath.Join(t.TempDir(), "s.adfir")
	b, err := casepkg.New(pkg, "SUITE", casepkg.CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := collector.IngestFiles(b, specs, collector.Options{ProfileRoot: root, SystemRoot: root}); err != nil {
		t.Fatal(err)
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	return pkg
}

func parseDir(t *testing.T, dir string) (*schema.Normalized, string) {
	t.Helper()
	pkg := sealDir(t, dir)
	res, err := ParsePackage(pkg)
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range res.Events {
		if !strings.HasPrefix(ev.TimestampSrc, TimestampPrefix) {
			t.Errorf("event %s timestamp source %q lacks the %s prefix", ev.EventID, ev.TimestampSrc, TimestampPrefix)
		}
	}
	return res, pkg
}

func find(res *schema.Normalized, pred func(schema.Event) bool) []schema.Event {
	var out []schema.Event
	for _, ev := range res.Events {
		if pred(ev) {
			out = append(out, ev)
		}
	}
	return out
}

func byResult(res *schema.Normalized, prefix string) []schema.Event {
	return find(res, func(e schema.Event) bool { return strings.HasPrefix(e.Result, prefix) })
}

func allText(res *schema.Normalized) string {
	var b strings.Builder
	for _, ev := range res.Events {
		b.WriteString(ev.Summary + "\n" + ev.SourceJSONPath + "\n")
	}
	for _, e := range res.Entities {
		for k, v := range e.Attributes {
			b.WriteString(k + "=" + v + "\n")
		}
	}
	return b.String()
}

func TestUFDRReport(t *testing.T) {
	res, _ := parseDir(t, "testdata/ufdr")
	app := byResult(res, "ai-app:")
	// The ChatGPT chat itself plus its two messages; the Party under a
	// message is not a record type that is reported.
	if len(app) != 3 {
		t.Fatalf("ai-app events = %d, want 3: %+v", len(app), app)
	}
	for _, ev := range app {
		if ev.Vendor != "chatgpt" || ev.Product != ProductUFDR || ev.SessionID != "ufdr:chatgpt:Chat:chat-ai-1" {
			t.Errorf("ai-app event: %+v", ev)
		}
		if !strings.HasPrefix(ev.SourceJSONPath, "/project/decodedData/modelType[@type='Chat']/model[@type='Chat'][@id='chat-ai-1']") {
			t.Errorf("provenance path %q", ev.SourceJSONPath)
		}
		if ev.SourceOffset == 0 || ev.SourceLine == 0 {
			t.Errorf("no source position: %+v", ev)
		}
	}
	msg := find(res, func(e schema.Event) bool { return strings.Contains(e.Summary, "model id=msg-2") })
	if len(msg) != 1 || msg[0].Timestamp != "2025-02-28T09:15:05Z" || !strings.Contains(msg[0].Summary, "deleted_state=Deleted") ||
		!strings.Contains(msg[0].TimestampSrc, "TimeStamp=2025-02-28T09:15:05.000+00:00") {
		t.Fatalf("msg-2: %+v", msg)
	}
	urls := byResult(res, "ai-url:")
	var gotVP, gotWA bool
	for _, ev := range urls {
		switch {
		case strings.Contains(ev.Summary, "model id=vp-1"):
			gotVP = ev.Vendor == "chatgpt" && ev.Result == "ai-url:conversation" && ev.Timestamp == "2025-02-28T09:14:00Z"
		case strings.Contains(ev.Summary, "model id=msg-wa-2"):
			gotWA = ev.Vendor == "claude" && ev.Result == "ai-url:share"
		case strings.Contains(ev.Summary, "vp-2"), strings.Contains(ev.Summary, "msg-wa-1"):
			t.Errorf("non-AI record normalized: %s", ev.Summary)
		}
	}
	if !gotVP || !gotWA || len(urls) != 2 {
		t.Fatalf("ai-url events: %+v", urls)
	}
	inv := byResult(res, "ufdr:inventory")
	if len(inv) != 1 || !strings.Contains(inv[0].Summary, "Contact=2") || !strings.Contains(inv[0].Summary, "FutureModelKind=1") ||
		!strings.Contains(inv[0].Summary, "1 tagged file") || !strings.Contains(inv[0].Summary, "5 AI record(s)") {
		t.Fatalf("inventory: %+v", inv)
	}
	unsup := find(res, func(e schema.Event) bool { return e.EventType == schema.EventTraceGap && e.Result == resultUnsup })
	if len(unsup) != 1 || !strings.Contains(unsup[0].Summary, "weirdElement") {
		t.Fatalf("unsupported structure: %+v", unsup)
	}
	case_ := byResult(res, "ufdr:case")
	if len(case_) != 1 || !strings.Contains(case_[0].Summary, "Case number=CASE-SYN-001") || !strings.Contains(case_[0].Summary, "Examiner name=Synthetic Examiner") {
		t.Fatalf("case info: %+v", case_)
	}
	// Device identifiers: masked everywhere in normalized output, with
	// the derivative-redaction marker.
	text := allText(res)
	for _, raw := range []string{"490154203237518", "SYNSERIAL0001", "+15555550100"} {
		if strings.Contains(text, raw) {
			t.Errorf("identifier %q leaked into normalized output", raw)
		}
	}
	if !strings.Contains(text, redact.Marker("imei", "490154203237518")) || !strings.Contains(text, redact.Marker("serial", "SYNSERIAL0001")) {
		t.Errorf("masked identifiers missing:\n%s", text)
	}
	var sess *schema.Entity
	for i, e := range res.Entities {
		if strings.HasPrefix(e.EntityID, "session:suite:ufdr:") {
			sess = &res.Entities[i]
		}
	}
	if sess == nil || sess.Attributes["device_model"] != "iPhone 15 (synthetic)" || sess.Attributes["os"] != "17.3" ||
		sess.Attributes["extraction_type"] != "AdvancedLogical" || !strings.Contains(sess.Attributes["tool_version"], "7.99") ||
		sess.Attributes["extraction_start"] != "2025-03-01T10:00:00.000+00:00" {
		t.Fatalf("report session entity: %+v", sess)
	}
}

func TestMarkerMatchesRedact(t *testing.T) {
	for _, c := range [][2]string{{"imei", "123"}, {"serial", "abc"}, {"mac", "00:11"}} {
		if marker(c[0], c[1]) != redact.Marker(c[0], c[1]) {
			t.Fatalf("marker format diverged from internal/redact for %v", c)
		}
	}
}

func TestUFDRMalformed(t *testing.T) {
	res, _ := parseDir(t, "testdata/ufdr-malformed")
	gaps := find(res, func(e schema.Event) bool { return e.EventType == schema.EventTraceGap && e.Result == resultUnparsed })
	if len(gaps) != 1 || !strings.Contains(gaps[0].Summary, "malformed or truncated") {
		t.Fatalf("gap: %+v", gaps)
	}
	if len(byResult(res, "ufdr:inventory")) != 1 || len(byResult(res, "ufdr:case")) != 1 {
		t.Fatal("what was read before the cut must still be reported")
	}
}

func TestUFDRNotProject(t *testing.T) {
	res, _ := parseDir(t, "testdata/ufdr-notproject")
	u := find(res, func(e schema.Event) bool { return e.Result == resultUnsup })
	if len(u) != 1 || !strings.Contains(u[0].Summary, "<reportRoot>") {
		t.Fatalf("%+v", res.Events)
	}
}

// encoding/xml neither fetches external entities nor expands DTD
// entities: both hostile documents stop at the first entity reference.
func TestUFDRHostileEntities(t *testing.T) {
	for _, dir := range []string{"testdata/ufdr-xxe", "testdata/ufdr-laughs"} {
		f, err := os.Open(filepath.Join(dir, "report.xml"))
		if err != nil {
			t.Fatal(err)
		}
		res, err := ReadUFDRReport(f, func(UFDRRecord) { t.Error("no record expected") })
		f.Close()
		if err == nil || !strings.Contains(err.Error(), "entity") {
			t.Fatalf("%s: err = %v, want an undefined-entity syntax error", dir, err)
		}
		for _, kv := range res.CaseInfo {
			if strings.Contains(kv.Value, "root:") || strings.Contains(kv.Value, "lol") {
				t.Fatalf("%s: entity expanded: %q", dir, kv.Value)
			}
		}
		parsed, _ := parseDir(t, dir)
		if len(find(parsed, func(e schema.Event) bool { return e.Result == resultUnparsed })) != 1 {
			t.Fatalf("%s: no malformed gap", dir)
		}
		if strings.Contains(allText(parsed), "root:") {
			t.Fatalf("%s: external entity content leaked", dir)
		}
	}
}

func TestUFDRTokenBound(t *testing.T) {
	var b bytes.Buffer
	b.WriteString(`<project><caseInformation><field name="x"><value>`)
	b.Write(bytes.Repeat([]byte("A"), maxTokenBytes+(64<<10)))
	b.WriteString(`</value></field></caseInformation></project>`)
	_, err := ReadUFDRReport(&b, func(UFDRRecord) {})
	if err == nil || !strings.Contains(err.Error(), "bound") {
		t.Fatalf("err = %v, want the token bound", err)
	}
}

func TestUFDRDepthBound(t *testing.T) {
	doc := "<project>" + strings.Repeat("<a>", maxXMLDepth+5) + strings.Repeat("</a>", maxXMLDepth+5) + "</project>"
	if _, err := ReadUFDRReport(strings.NewReader(doc), func(UFDRRecord) {}); err == nil || !strings.Contains(err.Error(), "nesting") {
		t.Fatalf("err = %v", err)
	}
}

func TestDescriptors(t *testing.T) {
	res, _ := parseDir(t, "testdata/ufd")
	d := byResult(res, "ufd:descriptor")
	if len(d) != 2 {
		t.Fatalf("descriptor events: %+v", res.Events)
	}
	text := allText(res)
	if strings.Contains(text, "490154203237518") || !strings.Contains(text, redact.Marker("imei", "490154203237518")) {
		t.Fatal("IMEI not masked in descriptor output")
	}
	if !strings.Contains(text, "linked files: synthetic.bin") || !strings.Contains(text, "ExtractionType=Physical") {
		t.Fatalf("descriptor summary:\n%s", text)
	}
	links := DescriptorsFor("testdata/ufd/synthetic.bin")
	if len(links) != 2 {
		t.Fatalf("DescriptorsFor: %+v", links)
	}
	if len(DescriptorsFor("testdata/ufdr/report.xml")) != 0 {
		t.Fatal("unrelated file linked")
	}
}

func TestParseUFDBad(t *testing.T) {
	if _, err := ParseUFD(strings.NewReader("just text\nno sections")); err == nil {
		t.Fatal("want error")
	}
	if _, err := ParseUFD(bytes.NewReader(bytes.Repeat([]byte("k=v\n"), MaxDescriptorBytes))); err == nil {
		t.Fatal("want size error")
	}
	if _, err := ParseUFDX(strings.NewReader("<a><b>")); err == nil {
		t.Fatal("want truncated XML error")
	}
}

func TestAxiomCSV(t *testing.T) {
	res, _ := parseDir(t, "testdata/axiom")
	web := find(res, func(e schema.Event) bool {
		return e.Action == actionRecord && strings.Contains(e.SourcePath, "Chrome Web History")
	})
	if len(web) != 2 {
		t.Fatalf("web history AI rows = %d: %+v", len(web), web)
	}
	if web[0].Vendor != "chatgpt" || web[0].Timestamp != "2025-02-28T09:14:00Z" || !strings.Contains(web[0].Summary, "Item ID=1001") ||
		web[0].SourceLine != 2 || !strings.Contains(web[0].TimestampSrc, "Visit Date/Time - UTC (yyyy-mm-dd)=2025-02-28 09:14:00") {
		t.Fatalf("chatgpt row: %+v", web[0])
	}
	if web[1].Vendor != "perplexity" || !strings.Contains(web[1].Summary, "Item ID=1003") {
		t.Fatalf("perplexity row: %+v", web[1])
	}
	msgs := find(res, func(e schema.Event) bool {
		return e.Action == actionRecord && strings.Contains(e.SourcePath, "ChatGPT Messages")
	})
	if len(msgs) != 2 || msgs[0].Vendor != "chatgpt" || msgs[0].Timestamp != "2025-02-28T09:15:00Z" ||
		!strings.Contains(msgs[0].Summary, "Message=how do i rotate an api key") {
		t.Fatalf("UTF-16 TAB AXIOM rows: %+v", msgs)
	}
	inv := byResult(res, "axiom:inventory")
	if len(inv) != 2 {
		t.Fatalf("inventory: %+v", inv)
	}
	for _, ev := range inv {
		if strings.Contains(ev.SourcePath, "Chrome") && !strings.Contains(ev.Summary, "4 row(s), 10 column(s) (utf-8-bom") {
			t.Errorf("web inventory: %s", ev.Summary)
		}
		if strings.Contains(ev.SourcePath, "ChatGPT") && !strings.Contains(ev.Summary, "utf-16le") {
			t.Errorf("messages inventory: %s", ev.Summary)
		}
	}
	if strings.Contains(allText(res), "example.com/news") {
		t.Error("a non-AI row was normalized")
	}
}

func TestAxiomCaseDB(t *testing.T) {
	res, _ := parseDir(t, "testdata/portable")
	u := find(res, func(e schema.Event) bool { return e.Result == resultUnsup })
	if len(u) != 1 || !strings.Contains(u[0].Summary, "AXIOM_CASE_DB_UNSUPPORTED") || !strings.Contains(u[0].Summary, "export to CSV/Portable Case") {
		t.Fatalf("case db finding: %+v", u)
	}
	inv := byResult(res, "axiom:casedb")
	if len(inv) != 1 || !strings.Contains(inv[0].Summary, "synthetic_hits(3)") || !strings.Contains(inv[0].Summary, "synthetic_meta(1)") {
		t.Fatalf("table inventory: %+v", inv)
	}
	if len(byResult(res, "axiom:inventory")) != 1 {
		t.Fatal("the CSV inside the portable case must be read")
	}
}

func TestCaseDBNotSQLite(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "Case.mfdb"), []byte("not a database"), 0o644)
	res, _ := parseDir(t, dir)
	if len(find(res, func(e schema.Event) bool { return strings.Contains(e.Summary, "AXIOM_CASE_DB_UNSUPPORTED") })) != 1 {
		t.Fatalf("%+v", res.Events)
	}
	if inv := byResult(res, "axiom:casedb"); len(inv) != 1 || !strings.Contains(inv[0].Summary, "not possible") {
		t.Fatalf("%+v", inv)
	}
}

func TestPlaso(t *testing.T) {
	res, _ := parseDir(t, "testdata/plaso")
	recs := find(res, func(e schema.Event) bool { return e.Action == actionRecord })
	var claude, path, gemini int
	for _, ev := range recs {
		switch {
		case ev.Vendor == "claude":
			claude++
			if ev.Timestamp != "2025-02-28T09:15:00Z" || ev.SourceLine != 1 {
				t.Errorf("claude: %+v", ev)
			}
		case ev.Result == "agent-path":
			path++
		case ev.Vendor == "gemini":
			gemini++
			if ev.Timestamp != "2025-02-28T09:15:00Z" {
				t.Errorf("gemini l2tcsv: %+v", ev)
			}
		case ev.Vendor == "chatgpt":
			// CET zone: kept raw, not normalized.
			if ev.Timestamp != "" || !strings.Contains(ev.TimestampSrc, "not normalized") {
				t.Errorf("non-UTC l2tcsv time normalized: %+v", ev)
			}
		}
	}
	if claude != 1 || path != 1 || gemini != 1 || len(recs) != 4 {
		t.Fatalf("plaso records: %+v", recs)
	}
	gaps := find(res, func(e schema.Event) bool { return e.Result == resultUnparsed })
	if len(gaps) != 2 { // one non-JSON line, one short l2tcsv line
		t.Fatalf("gaps: %+v", gaps)
	}
	inv := byResult(res, "plaso:inventory")
	if len(inv) != 2 {
		t.Fatalf("%+v", inv)
	}
}

func TestPlasoLineBound(t *testing.T) {
	var b bytes.Buffer
	b.WriteString(`{"data_type": "x:y", "timestamp": 1740734100000000, "parser": "p", "message": "`)
	b.Write(bytes.Repeat([]byte("A"), 2<<20))
	b.WriteString("\"}\n")
	b.WriteString(`{"data_type": "chrome:history:page_visited", "timestamp": 1740734100000000, "parser": "p", "url": "https://claude.ai/chat/0123abcd-4567-89ef"}` + "\n")
	n := 0
	st, err := plasoRead(&b, func() { n++ })
	if err != nil || st.Overlong != 1 || n != 1 {
		t.Fatalf("st=%+v n=%d err=%v", st, n, err)
	}
}

func TestAutopsy(t *testing.T) {
	res, _ := parseDir(t, "testdata/autopsy")
	recs := find(res, func(e schema.Event) bool { return e.Action == actionRecord })
	if len(recs) != 2 {
		t.Fatalf("%+v", recs)
	}
	if recs[0].Timestamp != "2025-02-28T09:01:00Z" || !strings.Contains(recs[0].Summary, "/.claude/settings.json") {
		t.Fatalf("%+v", recs[0])
	}
	if recs[1].Timestamp != "" || !strings.Contains(recs[1].TimestampSrc, "PST (not normalized)") {
		t.Fatalf("PST time must stay raw: %+v", recs[1])
	}
	if inv := byResult(res, "autopsy:inventory"); len(inv) != 1 || !strings.Contains(inv[0].Summary, "3 row(s)") {
		t.Fatalf("%+v", inv)
	}
}

func TestTableRecordBound(t *testing.T) {
	var b bytes.Buffer
	b.WriteString("URL,Item ID,Source\n\"")
	b.Write(bytes.Repeat([]byte("A"), maxRecordBytes+(64<<10)))
	b.WriteString("\",1,x\n")
	_, rows, err := readTable(&b, nil, func([]string, int) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "bound") || rows != 0 {
		t.Fatalf("rows=%d err=%v", rows, err)
	}
}

func TestSniff(t *testing.T) {
	for _, c := range []struct {
		rel, want string
	}{
		{"testdata/axiom/Chrome Web History.csv", KindAxiomCSV},
		{"testdata/axiom/ChatGPT Messages.csv", KindAxiomCSV},
		{"testdata/axiom/notes.csv", ""},
		{"testdata/portable/Case.mfdb", KindAxiomCaseDB},
		{"testdata/plaso/timeline.jsonl", KindPlasoJSON},
		{"testdata/plaso/timeline.l2tcsv", KindPlasoCSV},
		{"testdata/autopsy/files.txt", KindAutopsy},
		{"testdata/ufd/synthetic.ufd", KindUFD},
		{"testdata/ufd/group.ufdx", KindUFDX},
		{"testdata/README.md", ""},
	} {
		d, ok := ClassifyFile(c.rel, c.rel)
		if d.Kind != c.want || ok != (c.want != "") {
			t.Errorf("%s: %+v %v, want %q", c.rel, d, ok, c.want)
		}
	}
	if d, _ := ClassifyFile("testdata/axiom/ChatGPT Messages.csv", "ChatGPT Messages.csv"); d.Artifact != "ChatGPT Messages" || d.Encoding != "utf-16le" {
		t.Errorf("%+v", d)
	}
}

func TestMatchApp(t *testing.T) {
	for in, want := range map[string]string{
		"ChatGPT": "chatgpt", "com.openai.chatgpt": "chatgpt", "Claude by Anthropic": "claude", "Character.AI": "character-ai",
		"Le Chat": "mistral", "Meta AI": "meta-ai", "Poe": "poe", "DeepSeek": "deepseek", "Grok": "grok",
		"Microsoft Copilot": "copilot", "Perplexity": "perplexity", "Gemini": "gemini",
		"WhatsApp": "", "Metadata": "", "Poetry": "", "Chrome Web History": "", "": "",
	} {
		got := ""
		if a := MatchApp(in); a != nil {
			got = a.Key
		}
		if got != want {
			t.Errorf("MatchApp(%q) = %q, want %q", in, got, want)
		}
	}
}

// The parser reads the sealed blobs only; the originals and the sealed
// bytes stay identical.
func TestOriginalsSealedByteIdentical(t *testing.T) {
	for _, dir := range []string{"testdata/ufdr", "testdata/axiom", "testdata/portable", "testdata/plaso", "testdata/autopsy", "testdata/ufd"} {
		pkg := sealDir(t, dir)
		before := map[string]string{}
		filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				b, _ := os.ReadFile(p)
				s := sha256.Sum256(b)
				before[hex.EncodeToString(s[:])] = p
			}
			return nil
		})
		if _, err := ParsePackage(pkg); err != nil {
			t.Fatal(err)
		}
		man, err := casepkg.ReadManifest(pkg)
		if err != nil {
			t.Fatal(err)
		}
		st := casepkg.NewStore(pkg, man)
		for _, a := range man.Current() {
			rc, err := st.Open(a.ArtifactID)
			if err != nil {
				t.Fatal(err)
			}
			h := sha256.New()
			io.Copy(h, rc)
			rc.Close()
			sum := hex.EncodeToString(h.Sum(nil))
			if sum != a.ArtifactID || before[sum] == "" {
				t.Errorf("%s: sealed bytes differ from the original", a.LogicalPath)
			}
		}
		if len(man.Current()) != len(before) {
			t.Errorf("%s: %d sealed of %d files", dir, len(man.Current()), len(before))
		}
	}
}
