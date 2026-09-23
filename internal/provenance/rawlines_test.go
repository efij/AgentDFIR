package provenance

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v2/internal/casepkg"
	"github.com/efij/AgentDFIR/v2/internal/collector"
	"github.com/efij/AgentDFIR/v2/internal/normalize"
	"github.com/efij/AgentDFIR/v2/internal/products"
	"github.com/efij/AgentDFIR/v2/internal/schema"
)

// bigPackage builds a package whose transcript is large enough to be
// stored gzip-compressed (the store compresses above 4 KiB), with two
// sessions so raw-line lookups span more than one artifact.
func bigPackage(t *testing.T, writesPerSession int) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, ".claude", "projects", "-Users-dev")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for s := 1; s <= 2; s++ {
		var b strings.Builder
		prev := ""
		for i := 0; i < writesPerSession; i++ {
			id := fmt.Sprintf("a%d-%d", s, i)
			b.WriteString(fmt.Sprintf(`{"type":"assistant","uuid":%q,"parentUuid":%q,"sessionId":"s%d","timestamp":"2026-08-30T10:%02d:%02dZ","message":{"role":"assistant","content":[{"type":"tool_use","id":"t%d-%d","name":"Write","input":{"file_path":"/Users/dev/.claude/CLAUDE.md","content":"rule %d of session %d %s"}}]}}`,
				id, prev, s, i/60, i%60, s, i, i, s, strings.Repeat("padding ", 8)) + "\n")
			prev = id
		}
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("s%d.jsonl", s)), []byte(b.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pkg := filepath.Join(t.TempDir(), "big.adfir")
	b, err := casepkg.New(pkg, "PROV-BIG", casepkg.CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	man, _ := products.ManifestAllPlatforms("claude-code")
	if _, err := collector.Run(b, man, collector.Options{ProfileRoot: root, ConfigRoot: filepath.Join(root, ".claude"), SystemRoot: root, Product: "claude-code"}); err != nil {
		t.Fatal(err)
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	return pkg
}

// Provenance used to re-open every tool call's source artifact at its
// byte offset. On a gzip-stored transcript above the seek cache that is
// a decompress-from-zero per event: 107 GB of gunzip on one real machine.
// rawLines reads each artifact once, in offset order, and must return
// exactly the lines the per-event reads did — regardless of the order the
// events arrive in, and including a repeated offset.
func TestRawLinesMatchPerEventReads(t *testing.T) {
	pkg := bigPackage(t, 120)
	res, err := normalize.ParsePackage(pkg)
	if err != nil {
		t.Fatal(err)
	}
	store, err := casepkg.OpenStore(pkg)
	if err != nil {
		t.Fatal(err)
	}
	man, _ := casepkg.ReadManifest(pkg)
	compressed := 0
	for _, a := range man.Current() {
		if a.ArtifactType == "agent_session" && a.Codec == casepkg.CodecGzip {
			compressed++
		}
	}
	if compressed != 2 {
		t.Fatalf("fixture must store both transcripts gzip-compressed, got %d", compressed)
	}

	// Reverse the events so artifacts interleave and offsets run backwards.
	events := make([]schema.Event, 0, len(res.Events))
	for i := len(res.Events) - 1; i >= 0; i-- {
		events = append(events, res.Events[i])
	}
	// And repeat one tool call verbatim: same artifact, same offset.
	for _, ev := range events {
		if ev.EventType == schema.EventToolCall {
			events = append(events, ev)
			break
		}
	}

	got := map[int][]byte{}
	rawLines(store, events, func(i int, line []byte) { got[i] = line })
	calls := 0
	for i, ev := range events {
		if ev.EventType != schema.EventToolCall {
			if _, ok := got[i]; ok {
				t.Errorf("event %d is not a tool call but got a raw line", i)
			}
			continue
		}
		calls++
		want, ok := readRawLine(store, ev)
		if !ok {
			t.Fatalf("event %d: per-event read failed (%s@%d)", i, ev.SourceArtifact, ev.SourceOffset)
		}
		if !bytes.Equal(got[i], want) {
			t.Errorf("event %d (%s@%d): sequential read differs\n got %.80q\nwant %.80q", i, ev.SourceArtifact, ev.SourceOffset, got[i], want)
		}
	}
	if calls < 240 {
		t.Fatalf("fixture yielded %d tool calls, want at least 240", calls)
	}
}

// The end-to-end result must not move: every write is still attributed.
func TestRunOnLargeCompressedTranscriptAttributesEveryWrite(t *testing.T) {
	pkg := bigPackage(t, 50)
	res, err := normalize.ParsePackage(pkg)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Run(pkg, res.Events, "")
	if err != nil {
		t.Fatal(err)
	}
	// CLAUDE.md itself is not collected in this fixture, so every write
	// lands in writes_to_instruction_paths — one per tool call.
	if len(rep.OtherWrite) != 100 {
		t.Fatalf("writes to instruction paths = %d, want 100", len(rep.OtherWrite))
	}
}
