package browser

import (
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/efij/AgentDFIR/v3/internal/casepkg"
	"github.com/efij/AgentDFIR/v3/internal/collector"
	"github.com/efij/AgentDFIR/v3/internal/products"
	"github.com/efij/AgentDFIR/v3/internal/schema"
)

// The fixtures under testdata are written by make_fixtures.sh with the
// sqlite3 CLI in the column layout of each browser's history database.
// Every row is synthetic; each database mixes AI-service visits with
// ordinary pages and look-alike hosts.

const (
	chromeDir  = "Library/Application Support/Google/Chrome/Default"
	firefoxDir = ".mozilla/firefox/abcd1234.default-release"
	safariDir  = "Library/Safari"
)

func put(t *testing.T, home, dir, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", src))
	if err != nil {
		t.Fatal(err)
	}
	put2(t, home, dir, dst, b)
}

func put2(t *testing.T, home, dir, dst string, b []byte) {
	t.Helper()
	d := filepath.Join(home, filepath.FromSlash(dir))
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, dst), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func fixtureHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	put(t, home, chromeDir, "chrome_History", "History")
	put(t, home, firefoxDir, "firefox_places.sqlite", "places.sqlite")
	put(t, home, firefoxDir, "firefox_places.sqlite-wal", "places.sqlite-wal")
	put(t, home, safariDir, "safari_History.db", "History.db")
	return home
}

func sealed(t *testing.T, home string) string {
	t.Helper()
	pkg := filepath.Join(t.TempDir(), "browser.adfir")
	b, err := casepkg.New(pkg, "BROWSER-T1", casepkg.CaseInfo{OperatorOSUser: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	man, err := products.ManifestAllPlatforms("browser")
	if err != nil || man == nil {
		t.Fatalf("browser manifest: %v %v", man, err)
	}
	if _, err := collector.Run(b, man, collector.Options{ProfileRoot: home, ConfigRoot: home, SystemRoot: home, Product: "browser"}); err != nil {
		t.Fatal(err)
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	return pkg
}

func parseHome(t *testing.T, home string) *schema.Normalized {
	t.Helper()
	res, err := ParsePackage(sealed(t, home))
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestOnlyAIServiceVisitsComeOutOfHistory(t *testing.T) {
	res := parseHome(t, fixtureHome(t))
	// Nothing from an ordinary page may leave the parser: not its URL, not
	// its title, not a look-alike host.
	for _, ev := range res.Events {
		for _, banned := range []string{"example.com", "bank statement", "mail.google", "Inbox", "evil.example", "lookalike", "news.example", "Some news", "shop.example", "Your cart"} {
			if strings.Contains(ev.Summary, banned) {
				t.Fatalf("non-AI history leaked (%q): %+v", banned, ev)
			}
		}
		if ev.EventType == schema.EventHumanPrompt || ev.EventType == schema.EventModelResponse || ev.EventType == schema.EventToolCall {
			t.Fatalf("history must never produce conversation content or tool calls: %+v", ev)
		}
		if ev.Product != Product || ev.SourceArtifact == "" || ev.SourcePath == "" {
			t.Fatalf("event provenance missing: %+v", ev)
		}
		if ev.Timestamp != "" && ev.TimestampSrc != "browser_history" {
			t.Fatalf("timestamp source = %q", ev.TimestampSrc)
		}
	}
	for _, e := range res.Entities {
		if strings.Contains(e.Label, "bank") || strings.Contains(e.Label, "Inbox") {
			t.Fatalf("non-AI entity: %+v", e)
		}
	}

	visits := map[string]int{} // session -> visit events
	for _, ev := range res.Events {
		if ev.Action == "browser_visit" {
			visits[ev.SessionID]++
		}
	}
	want := map[string]int{
		"web:chatgpt:conversation:6710aa00-1111-2222-3333-444455556666": 3,
		"web:chatgpt:share:6710bb00-aaaa-bbbb-cccc-ddddeeeeffff":        1,
		"web:claude:conversation:0b6f2a3c-1d2e-4f50-8a9b-0c1d2e3f4a5b":  2,
		"web:gemini:conversation:a1b2c3d4e5f6":                          1,
		"web:deepseek:conversation:9f8e7d6c-1234":                       1,
		"web:perplexity:conversation:how-to-rotate-aws-keys-AbC123":     1,
		"web:grok:conversation:1850000000000000001":                     1,
		"web:openai-platform:console:chrome/Default":                    1,
		"web:claude:project:0199aaaa-bbbb-7ccc-8ddd-eeeeffff0000":       1,
		"web:poe:share:Ab12Cd34Ef56":                                    1,
		"web:huggingchat:conversation:66ffeedd0011223344556677":         1, // WAL-only row
		"web:mistral:conversation:7c1e9a52-0d3b-4f6e-9a1c-2b3d4e5f6a7b": 1, // WAL-only row
		"web:copilot:conversation:AbCdEf123456":                         2,
		"web:m365-copilot:app:safari/Safari":                            1,
		"web:notebooklm:project:5e6f7a8b-1c2d-3e4f-5a6b-7c8d9e0f1a2b":   1,
	}
	for s, n := range want {
		if visits[s] != n {
			t.Errorf("session %s: %d visit event(s), want %d", s, visits[s], n)
		}
	}
	if len(visits) != len(want) {
		t.Errorf("got %d sessions, want %d: %v", len(visits), len(want), visits)
	}
}

func TestVisitTimesAreUTCWithTheRawValueKept(t *testing.T) {
	res := parseHome(t, fixtureHome(t))
	first := map[string]schema.Event{}
	for _, ev := range res.Events {
		if ev.Action != "browser_visit" {
			continue
		}
		if _, ok := first[ev.SessionID]; !ok {
			first[ev.SessionID] = ev
		}
	}
	cases := []struct{ session, ts, clock string }{
		{"web:chatgpt:conversation:6710aa00-1111-2222-3333-444455556666", "2026-10-20T10:00:00.000000Z", ClockWebKit},
		{"web:claude:project:0199aaaa-bbbb-7ccc-8ddd-eeeeffff0000", "2026-10-21T08:00:00.000000Z", ClockPRTime},
		{"web:copilot:conversation:AbCdEf123456", "2026-10-22T12:00:00.500000Z", ClockCocoa},
	}
	for _, c := range cases {
		ev := first[c.session]
		if ev.Timestamp != c.ts {
			t.Errorf("%s: timestamp %q, want %q", c.session, ev.Timestamp, c.ts)
		}
		if !strings.Contains(ev.Summary, "raw_time=") || !strings.Contains(ev.Summary, c.clock) {
			t.Errorf("%s: raw time not kept: %s", c.session, ev.Summary)
		}
	}
	chat := first["web:chatgpt:conversation:6710aa00-1111-2222-3333-444455556666"]
	if !strings.Contains(chat.Summary, "transition=typed") || !strings.Contains(chat.Summary, "typed") ||
		!strings.Contains(chat.Summary, "chrome/Default") || !strings.Contains(chat.Summary, "row visits:1 → urls:1") ||
		!strings.Contains(chat.Summary, "url_visit_count=3") || !strings.Contains(chat.Summary, `"Quarterly numbers cleanup"`) {
		t.Errorf("chatgpt visit summary = %s", chat.Summary)
	}
	if chat.SourceOffset != 1 || !strings.HasSuffix(chat.SourcePath, "Default/History") {
		t.Errorf("source ref = %s offset %d", chat.SourcePath, chat.SourceOffset)
	}
	// Safari stores the title per visit.
	if cop := first["web:copilot:conversation:AbCdEf123456"]; !strings.Contains(cop.Summary, "Draft vendor email") || !strings.Contains(cop.Summary, "safari/Safari") {
		t.Errorf("safari visit = %s", cop.Summary)
	}
}

func TestVisitsAreGroupedIntoBrowserSessions(t *testing.T) {
	res := parseHome(t, fixtureHome(t))
	var sum *schema.Event
	for i, ev := range res.Events {
		if ev.Action == "browser_session" && ev.SessionID == "web:chatgpt:conversation:6710aa00-1111-2222-3333-444455556666" {
			sum = &res.Events[i]
		}
	}
	if sum == nil {
		t.Fatal("no browser_session summary for the ChatGPT conversation")
	}
	want := `ChatGPT conversation "Quarterly numbers cleanup" visited 3 time(s) between 2026-10-20T10:00:00.000000Z and 2026-10-20T12:00:00.000000Z (chrome/Default)`
	if !strings.HasPrefix(sum.Summary, want) || !strings.Contains(sum.Summary, "not conversation content") {
		t.Errorf("summary = %s", sum.Summary)
	}
	if sum.Result != KindConversation || sum.Vendor != "chatgpt" || sum.Timestamp != "2026-10-20T10:00:00.000000Z" {
		t.Errorf("summary event = %+v", sum)
	}
	var ent *schema.Entity
	for i, e := range res.Entities {
		if e.EntityID == "session:"+sum.SessionID {
			ent = &res.Entities[i]
		}
	}
	if ent == nil {
		t.Fatal("no session entity")
	}
	if ent.Attributes["evidence_class"] != EvidenceClass || ent.Attributes["visit_rows"] != "3" ||
		ent.Attributes["browser_visit_count"] != "3" || ent.Attributes["conversation_id"] != "6710aa00-1111-2222-3333-444455556666" ||
		ent.Attributes["title"] != "Quarterly numbers cleanup" {
		t.Errorf("entity = %+v", ent)
	}
	// Each database reports what it read, as counts only.
	dbs := 0
	for _, ev := range res.Events {
		if ev.Result == "browser_db_read" {
			dbs++
			if strings.Contains(ev.SessionID, "firefox") && !strings.Contains(ev.Summary, "write-ahead log applied") {
				t.Errorf("firefox WAL not reported: %s", ev.Summary)
			}
		}
	}
	if dbs != 3 {
		t.Errorf("%d browser_db_read events, want 3", dbs)
	}
}

func TestSameConversationInTwoBrowsersIsOneSession(t *testing.T) {
	home := fixtureHome(t)
	put(t, home, "Library/Application Support/BraveSoftware/Brave-Browser/Profile 2", "chrome_History", "History")
	res := parseHome(t, home)
	for _, ev := range res.Events {
		if ev.Action == "browser_session" && ev.SessionID == "web:chatgpt:conversation:6710aa00-1111-2222-3333-444455556666" {
			if !strings.Contains(ev.Summary, "visited 6 time(s)") || !strings.Contains(ev.Summary, "brave/Profile 2, chrome/Default") {
				t.Fatalf("cross-browser session = %s", ev.Summary)
			}
			return
		}
	}
	t.Fatal("session missing")
}

func TestHostileDatabasesBecomeRecordedProblems(t *testing.T) {
	good, err := os.ReadFile(filepath.Join("testdata", "chrome_History"))
	if err != nil {
		t.Fatal(err)
	}
	other, err := os.ReadFile(filepath.Join("..", "codexdb", "testdata", "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"garbage":   []byte("this is not a database at all, just text pretending\x00\x01"),
		"truncated": good[:4096],
		"empty":     {},
		"wrong-db":  other,
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			put2(t, home, chromeDir, "History", data)
			res := parseHome(t, home)
			var problem bool
			for _, ev := range res.Events {
				if ev.EventType == schema.EventTraceGap || ev.Result == "unsupported" {
					problem = true
				}
				if ev.Action == "browser_visit" && name != "truncated" {
					t.Fatalf("visit from a %s database: %+v", name, ev)
				}
			}
			if !problem && name != "empty" {
				t.Fatalf("%s database produced no recorded problem: %+v", name, res.Events)
			}
			if name == "wrong-db" {
				for _, ev := range res.Events {
					if ev.Result == "unsupported" && !strings.Contains(ev.Summary, "UNSUPPORTED") {
						t.Fatalf("unsupported without the word: %s", ev.Summary)
					}
				}
			}
		})
	}
}

// Random corruption of a real-layout database must never panic or hang.
func TestCorruptedHistoryNeverPanics(t *testing.T) {
	good, err := os.ReadFile(filepath.Join("testdata", "chrome_History"))
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 25; i++ {
		b := append([]byte(nil), good...)
		for j := 0; j < 40; j++ {
			b[100+rng.Intn(len(b)-100)] = byte(rng.Intn(256))
		}
		home := t.TempDir()
		put2(t, home, chromeDir, "History", b)
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = ParsePackage(sealed(t, home))
		}()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Fatal("parser hung on a corrupted database")
		}
	}
}

func TestBrowserNameFromRule(t *testing.T) {
	for rule, want := range map[string]string{
		"browser.chrome_macos": "chrome", "browser.firefox_linux": "firefox", "browser.safari_macos": "safari", "browser.opera_windows": "opera",
	} {
		if got := browserName(casepkg.ArtifactRecord{CollectorRule: rule}); got != want {
			t.Errorf("%s -> %s, want %s", rule, got, want)
		}
	}
	if got := browserName(casepkg.ArtifactRecord{LogicalPath: "x/places.sqlite"}); got != "firefox" {
		t.Errorf("fallback = %s", got)
	}
}

func TestClocks(t *testing.T) {
	ts, ok := webkitTime((1792490400 + webkitToUnixSec) * 1_000_000)
	if !ok || ts.Format(time.RFC3339) != time.Unix(1792490400, 0).UTC().Format(time.RFC3339) {
		t.Errorf("webkit = %v %v", ts, ok)
	}
	if _, ok := webkitTime(0); ok {
		t.Error("zero webkit time accepted")
	}
	if _, ok := webkitTime(1); ok {
		t.Error("1601 accepted as plausible")
	}
	if _, ok := prTime(-5); ok {
		t.Error("negative PRTime accepted")
	}
	if ts, ok := cocoaTime(float64(0.25) + 800000000); !ok || ts.Unix() != 800000000+cocoaToUnixSec {
		t.Errorf("cocoa = %v", ts)
	}
	if _, ok := cocoaTime("x"); ok {
		t.Error("string cocoa time accepted")
	}
	if _, ok := cocoaTime(1e300); ok {
		t.Error("huge cocoa time accepted")
	}
}
