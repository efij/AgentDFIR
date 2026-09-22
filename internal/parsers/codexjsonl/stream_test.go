package codexjsonl

import (
	"path/filepath"
	"testing"

	"github.com/efij/AgentDFIR/v2/internal/casepkg"
	"github.com/efij/AgentDFIR/v2/internal/collector"
	"github.com/efij/AgentDFIR/v2/internal/products"
	"github.com/efij/AgentDFIR/v2/internal/schema"
)

// streamFixturePackage seals the codex fixture into a real package.
func streamFixturePackage(t *testing.T) string {
	t.Helper()
	root := codexFixture(t)
	pkg := filepath.Join(t.TempDir(), "codex.adfir")
	b, err := casepkg.New(pkg, "CODEX-STREAM", casepkg.CaseInfo{OperatorOSUser: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	man, err := products.Manifest("codex-cli")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := collector.Run(b, man, collector.Options{
		ProfileRoot: root, ConfigRoot: filepath.Join(root, ".codex"),
		SystemRoot: root, Product: "codex-cli",
	}); err != nil {
		t.Fatal(err)
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	return pkg
}

// TestStreamPackageEmitsTheSameEventsAsParsePackage.
//
// StreamPackage is what analysis uses. It did not pass its sink to the
// parser, so every event went into a slice the streaming caller throws
// away and no Codex session reached any rule. ParsePackage, which passes a
// nil sink, was unaffected — which is exactly why this went unnoticed.
//
// The two entry points must agree, whichever one a caller reaches for.
func TestStreamPackageEmitsTheSameEventsAsParsePackage(t *testing.T) {
	pkg := streamFixturePackage(t)

	batch, err := ParsePackage(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Events) == 0 {
		t.Fatal("fixture produced no events; the test would prove nothing")
	}

	var streamed []schema.Event
	if _, err := StreamPackage(pkg, func(ev schema.Event) { streamed = append(streamed, ev) }); err != nil {
		t.Fatal(err)
	}
	if len(streamed) != len(batch.Events) {
		t.Fatalf("StreamPackage emitted %d events, ParsePackage produced %d", len(streamed), len(batch.Events))
	}
	for i := range streamed {
		if streamed[i].EventID != batch.Events[i].EventID || streamed[i].Action != batch.Events[i].Action {
			t.Fatalf("event %d differs: streamed %+v, batch %+v", i, streamed[i], batch.Events[i])
		}
	}
}
