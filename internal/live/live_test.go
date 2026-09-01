package live

import (
	"path/filepath"
	"testing"

	"github.com/efij/AgentDFIR/internal/casepkg"
)

// Live acquisition must degrade gracefully: every step either produces
// a hashed artifact or a recorded failure — never a silent skip — and
// the resulting package must still seal and verify.
func TestLiveCollectSealsAndVerifies(t *testing.T) {
	pkg := filepath.Join(t.TempDir(), "live.adfir")
	b, err := casepkg.New(pkg, "LIVE-T", casepkg.CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	st, err := Collect(b, "testhost", "tester")
	if err != nil {
		t.Fatal(err)
	}
	if st.Collected+st.Failed != len(steps()) {
		t.Fatalf("steps unaccounted: collected=%d failed=%d want total=%d",
			st.Collected, st.Failed, len(steps()))
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	res, err := casepkg.Verify(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Problems) != 0 {
		t.Fatalf("live package fails verification: %v", res.Problems)
	}
}
