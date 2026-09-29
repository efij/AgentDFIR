package cli

import (
	"os"
	"testing"

	"github.com/efij/AgentDFIR/v3/internal/store"
)

// TestMain points the AgentDFIR home at a throwaway directory. Sealing now
// signs with the machine key and records an anchor in the home; a test must
// never create a key in, or write anchors to, the developer's real one.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "agentdfir-home-*")
	if err != nil {
		panic(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		panic(err)
	}
	os.Setenv(store.EnvHome, dir)
	// The free-disk floor protects real machines; tests must not depend
	// on how full the machine running them is.
	os.Setenv("AGENTDFIR_MIN_FREE_GB", "1")
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
