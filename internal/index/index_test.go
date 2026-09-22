package index

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/efij/AgentDFIR/v2/internal/schema"
)

// writeOverlay lays out a package with just the normalized overlay in it,
// which is all this package ever reads.
func writeOverlay(t *testing.T, lines []string) string {
	t.Helper()
	pkg := t.TempDir()
	dir := filepath.Join(pkg, "normalized")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	body := ""
	if len(lines) > 0 {
		body = strings.Join(lines, "\n") + "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return pkg
}

func event(id, ts, typ, session, agent, path string, line int, off int64) string {
	return fmt.Sprintf(`{"event_id":%q,"timestamp":%q,"event_type":%q,"actor_type":"agent","session_id":%q,`+
		`"agent_id":%q,"product":"claude-code","tool":"Bash","command":"echo %s","summary":"ran echo %s",`+
		`"source_logical_path":%q,"source_line":%d,"source_offset":%d,"corroboration_state":"RECORDED"}`,
		id, ts, typ, session, agent, id, id, path, line, off)
}

func TestBuildReadRoundTrip(t *testing.T) {
	pkg := writeOverlay(t, []string{
		event("e1", "2026-08-30T10:00:00Z", "human_prompt", "s1", "main:s1", "a/t.jsonl", 1, 0),
		`{"event_id":"broken",`, // a line no parser can use: skipped, and must not shift any offset
		"",
		event("e2", "2026-08-30T10:00:05Z", "tool_call", "s1", "main:s1", "a/t.jsonl", 3, 512),
		event("e3", "2026-08-30T10:01:05Z", "tool_result", "s1", "sub:1", "a/t.jsonl", 4, 900),
	})
	x, err := Open(pkg)
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	if !x.Rebuilt() {
		t.Fatal("first Open should have built the index")
	}
	if x.Len() != 3 {
		t.Fatalf("len=%d, want 3 (the malformed and empty lines are not events)", x.Len())
	}
	e := x.At(1)
	if e.EventID != "e2" || e.EventType != "tool_call" || e.SessionID != "s1" || e.SourceLine != 3 || e.SourceOffset != 512 {
		t.Fatalf("summary wrong: %+v", e)
	}
	// The offset really points at that event's line in the overlay.
	full, err := x.Event(1)
	if err != nil || full.EventID != "e2" || full.Command != "echo e2" || full.Summary != "ran echo e2" {
		t.Fatalf("event by offset: %v %+v", err, full)
	}
	if i, ok := x.Lookup("e3"); !ok || i != 2 {
		t.Fatalf("lookup e3: %d %v", i, ok)
	}
	if _, ok := x.Lookup("broken"); ok {
		t.Fatal("a malformed line must not be indexed")
	}
	// Reopening uses the file on disk: same rows, no rebuild.
	if _, err := os.Stat(filepath.Join(pkg, Dir, File)); err != nil {
		t.Fatalf("index file not written: %v", err)
	}
	y, err := Open(pkg)
	if err != nil {
		t.Fatal(err)
	}
	defer y.Close()
	if y.Rebuilt() {
		t.Fatal("second Open rebuilt an index that was current")
	}
	if y.Len() != x.Len() {
		t.Fatalf("len after reopen: %d != %d", y.Len(), x.Len())
	}
	for i := 0; i < x.Len(); i++ {
		if x.At(i) != y.At(i) || x.Rows()[i] != y.Rows()[i] {
			t.Fatalf("row %d differs after a round trip: %+v vs %+v", i, x.Rows()[i], y.Rows()[i])
		}
	}
}

func TestEachMatchesPositions(t *testing.T) {
	pkg := writeOverlay(t, []string{
		event("e1", "t1", "human_prompt", "s1", "main:s1", "a", 1, 0),
		`not json at all`,
		event("e2", "t2", "tool_call", "s1", "main:s1", "a", 2, 10),
		event("e3", "t3", "tool_result", "s1", "main:s1", "a", 3, 20),
	})
	x, err := Open(pkg)
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	got := map[int]string{}
	if err := x.Each(func(i int, e *schema.Event) bool {
		got[i] = e.EventID
		return true
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < x.Len(); i++ {
		if got[i] != x.At(i).EventID {
			t.Fatalf("Each gave position %d event %q, index says %q", i, got[i], x.At(i).EventID)
		}
	}
	// Stopping early really stops.
	n := 0
	_ = x.Each(func(int, *schema.Event) bool { n++; return false })
	if n != 1 {
		t.Fatalf("Each did not stop: %d", n)
	}
}

func TestStaleAndMissingIndexRebuild(t *testing.T) {
	pkg := writeOverlay(t, []string{event("e1", "t1", "tool_call", "s1", "a1", "a", 1, 0)})
	x, err := Open(pkg)
	if err != nil {
		t.Fatal(err)
	}
	x.Close()

	// The overlay grows under the index (the second witness rewrites it,
	// or the case is re-normalized): the old index must not be trusted.
	src := filepath.Join(pkg, "normalized", "events.jsonl")
	f, err := os.OpenFile(src, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(f, event("e2", "t2", "tool_call", "s1", "a1", "a", 2, 10))
	f.Close()
	// Filesystems with coarse mtimes would otherwise leave the two writes
	// indistinguishable within one test run.
	_ = os.Chtimes(src, time.Now().Add(time.Second), time.Now().Add(time.Second))
	y, err := Open(pkg)
	if err != nil {
		t.Fatal(err)
	}
	defer y.Close()
	if !y.Rebuilt() || y.Len() != 2 {
		t.Fatalf("stale index not rebuilt: rebuilt=%v len=%d", y.Rebuilt(), y.Len())
	}

	// It is derived data: deleting it, or half-writing it, is survivable.
	path := filepath.Join(pkg, Dir, File)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	z, err := Open(pkg)
	if err != nil {
		t.Fatal(err)
	}
	z.Close()
	if z.Len() != 2 {
		t.Fatalf("rebuild after delete: len=%d", z.Len())
	}
	data, _ := os.ReadFile(path)
	if err := os.WriteFile(path, data[:len(data)-7], 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := Open(pkg)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if !w.Rebuilt() || w.Len() != 2 {
		t.Fatalf("truncated index not rebuilt: rebuilt=%v len=%d", w.Rebuilt(), w.Len())
	}
}

func TestRefreshIsIdempotent(t *testing.T) {
	pkg := writeOverlay(t, []string{event("e1", "t1", "tool_call", "s1", "a1", "a", 1, 0)})
	if err := Refresh(pkg); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(pkg, Dir, File)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := Refresh(pkg); err != nil {
		t.Fatal(err)
	}
	fi2, _ := os.Stat(path)
	if !fi2.ModTime().Equal(fi.ModTime()) {
		t.Fatal("Refresh rewrote a current index")
	}
	if _, err := os.Stat(path + ".tmp"); err == nil {
		t.Fatal("the temp file was left behind")
	}
}

// TestBeyondTheOldCap is the regression the index exists for: the explorer
// used to stop at 500,000 events, so a bigger case lost its tail. Nothing
// caps it now — every event is addressable, including the last one.
func TestBeyondTheOldCap(t *testing.T) {
	if testing.Short() {
		t.Skip("writes a 520,001-event overlay")
	}
	const n = 520001 // one more than the cap that used to be there, and then some
	pkg := t.TempDir()
	dir := filepath.Join(pkg, "normalized")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	w := bufio.NewWriterSize(f, 1<<20)
	for i := 0; i < n; i++ {
		fmt.Fprintln(w, event(fmt.Sprintf("e%d", i), "2026-08-30T10:00:00Z", "tool_call",
			fmt.Sprintf("s%d", i%7), fmt.Sprintf("main:s%d", i%7), "a/t.jsonl", i+1, int64(i)*64))
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	f.Close()

	x, err := Open(pkg)
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	if x.Len() != n {
		t.Fatalf("indexed %d of %d events", x.Len(), n)
	}
	last := fmt.Sprintf("e%d", n-1)
	i, ok := x.Lookup(last)
	if !ok || i != n-1 {
		t.Fatalf("the last event is not addressable: %d %v", i, ok)
	}
	ev, err := x.Event(i)
	if err != nil || ev.EventID != last || ev.Command != "echo "+last {
		t.Fatalf("last event: %v %+v", err, ev)
	}
	// And the same holds after the round trip through the file.
	y, err := Open(pkg)
	if err != nil {
		t.Fatal(err)
	}
	defer y.Close()
	if y.Rebuilt() || y.Len() != n {
		t.Fatalf("reopen: rebuilt=%v len=%d", y.Rebuilt(), y.Len())
	}
	if e := y.At(n - 1); e.EventID != last || e.SourceLine != n {
		t.Fatalf("last summary after reopen: %+v", e)
	}
}
