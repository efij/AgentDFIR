package segment

import (
	"testing"

	"github.com/efij/AgentDFIR/v5/internal/schema"
)

// A cached segment moved to a new base keeps its call/result pairing: the
// paired event lives in the same artifact and moves by the same delta.
func TestRebaseMovesResultRef(t *testing.T) {
	ev := schema.Event{EventID: "evt-000005", Sequence: 5, ResultRef: "evt-000003"}
	Rebase(&ev, "evt-%06d", 10)
	if ev.EventID != "evt-000015" || ev.ResultRef != "evt-000013" {
		t.Fatalf("rebased to %s → %s", ev.EventID, ev.ResultRef)
	}
	none := schema.Event{EventID: "evt-x-000001", Sequence: 1}
	Rebase(&none, "evt-x-%06d", 2)
	if none.ResultRef != "" {
		t.Fatal("empty ResultRef filled in")
	}
}
