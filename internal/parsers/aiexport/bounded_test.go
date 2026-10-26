package aiexport

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v5/internal/casepkg"
	"github.com/efij/AgentDFIR/v5/internal/schema"
)

// genExport streams a synthetic ChatGPT conversations.json of n
// conversations without ever holding the document in memory.
type genExport struct {
	n, i  int
	pad   string
	buf   []byte
	done  bool
	bytes int64
}

func (g *genExport) Read(p []byte) (int, error) {
	for len(g.buf) == 0 {
		switch {
		case g.done:
			return 0, io.EOF
		case g.i == 0 && g.buf == nil:
			g.buf = []byte("[\n")
		case g.i >= g.n:
			g.buf, g.done = []byte("\n]\n"), true
		default:
			sep := ""
			if g.i > 0 {
				sep = ",\n"
			}
			g.buf = []byte(fmt.Sprintf(`%s{"title":"c%d","create_time":%d,"current_node":"b","id":"conv-%d","mapping":{`+
				`"r":{"id":"r","parent":null,"children":["a"],"message":null},`+
				`"a":{"id":"a","parent":"r","children":["b"],"message":{"id":"a","author":{"role":"user"},"create_time":%d,"content":{"content_type":"text","parts":["%s"]},"recipient":"all"}},`+
				`"b":{"id":"b","parent":"a","children":[],"message":{"id":"b","author":{"role":"assistant"},"create_time":%d,"content":{"content_type":"text","parts":["ok"]},"recipient":"all","metadata":{"model_slug":"m"}}}}}`,
				sep, g.i, 1788084000+g.i, g.i, 1788084000+g.i, g.pad, 1788084001+g.i))
			g.i++
		}
	}
	n := copy(p, g.buf)
	g.buf = g.buf[n:]
	g.bytes += int64(n)
	return n, nil
}

// TestBoundedMemoryLargeExport parses a ~130 MB generated export through
// the real conversation reader and checks the heap never holds more than
// a small multiple of one conversation.
func TestBoundedMemoryLargeExport(t *testing.T) {
	if testing.Short() {
		t.Skip("large generated input")
	}
	const n = 6000
	gen := &genExport{n: n, pad: strings.Repeat("lorem ipsum ", 1800)}
	p := &parser{res: &schema.Normalized{}, entities: map[string]schema.Entity{}, relSeen: map[string]bool{},
		art: casepkg.ArtifactRecord{ArtifactID: "gen", LogicalPath: "conversations.json"},
		det: Detection{Service: ServiceChatGPT, Kind: KindConversations}}
	var events int
	var peak uint64
	var ms runtime.MemStats
	p.sink = func(ev schema.Event) {
		events++
		if events%3000 == 0 {
			runtime.GC() // live heap, not garbage awaiting collection
			runtime.ReadMemStats(&ms)
			if ms.HeapAlloc > peak {
				peak = ms.HeapAlloc
			}
		}
	}
	// Entities grow with the number of conversations (one session each),
	// which is the bounded-by-entity-count contract every parser has; the
	// events themselves are never retained.
	if err := p.parseMappingConversations(gen); err != nil {
		t.Fatal(err)
	}
	if want := n * 3; events != want {
		t.Fatalf("events: got %d want %d", events, want)
	}
	t.Logf("input %d MB, peak live heap %d MB", gen.bytes>>20, peak>>20)
	if peak > 32<<20 {
		t.Fatalf("heap peaked at %d MB while streaming", peak>>20)
	}
}

func TestElementBound(t *testing.T) {
	big := `[{"title":"ok","mapping":{}},{"title":"` + strings.Repeat("x", 3<<20) + `"},{"title":"never read"}]`
	var got []int
	err := walkArray(strings.NewReader(big), 1<<20, func(el element) error {
		got = append(got, el.Index)
		return nil
	})
	we, ok := err.(*walkError)
	if !ok || we.Index != 1 || !strings.Contains(we.Reason, "bound") || len(got) != 1 {
		t.Fatalf("got %v err %v", got, err)
	}
}

func TestWalkOffsetsAndLines(t *testing.T) {
	doc := "[\n  {\"a\": 1},\n\n  {\"b\":\n 2}\n]"
	var els []element
	if err := walkArray(strings.NewReader(doc), 1<<20, func(el element) error {
		els = append(els, el)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(els) != 2 || els[0].Line != 2 || els[1].Line != 4 || doc[els[1].Offset] != '{' || doc[els[0].Offset:els[0].Offset+4] != `{"a"` {
		t.Fatalf("%+v", els)
	}
	for _, bad := range []string{``, `{}`, `[{"a":1}`, `[{"a":`, `nope`} {
		if err := walkArray(strings.NewReader(bad), 1<<20, func(element) error { return nil }); err == nil {
			t.Errorf("%q: want a walk error", bad)
		}
	}
	if pointer(0, "mapping", "a/b~c") != "/0/mapping/a~1b~0c" {
		t.Fatal(pointer(0, "mapping", "a/b~c"))
	}
}

// TestTruncatedAnywhere cuts each fixture at many points and feeds the
// prefix to its reader: a hostile or partial export must yield events and
// recorded gaps, never a panic or an error.
func TestTruncatedAnywhere(t *testing.T) {
	for _, fx := range []struct {
		file string
		det  Detection
	}{
		{"chatgpt/conversations.json", Detection{Service: ServiceChatGPT, Kind: KindConversations}},
		{"claude/conversations.json", Detection{Service: ServiceClaudeAI, Kind: KindConversations}},
		{"deepseek/conversations.json", Detection{Service: ServiceDeepSeek, Kind: KindConversations}},
		{"gemini/Takeout/My Activity/Gemini Apps/MyActivity.json", Detection{Service: ServiceGemini, Kind: KindActivity}},
	} {
		data, err := os.ReadFile(filepath.Join("testdata", filepath.FromSlash(fx.file)))
		if err != nil {
			t.Fatal(err)
		}
		for cut := 0; cut < len(data)-2; cut += 37 {
			p := &parser{res: &schema.Normalized{}, entities: map[string]schema.Entity{}, relSeen: map[string]bool{},
				art: casepkg.ArtifactRecord{ArtifactID: "cut", LogicalPath: fx.file}, det: fx.det}
			r := strings.NewReader(string(data[:cut]))
			var err error
			switch fx.det.Service {
			case ServiceClaudeAI:
				err = p.parseClaudeConversations(r)
			case ServiceGemini:
				err = p.parseGeminiActivity(r)
			default:
				err = p.parseMappingConversations(r)
			}
			if err != nil {
				t.Fatalf("%s cut at %d: %v", fx.file, cut, err)
			}
			if len(gaps(p.res)) == 0 {
				t.Fatalf("%s cut at %d: truncation not recorded", fx.file, cut)
			}
		}
	}
}
