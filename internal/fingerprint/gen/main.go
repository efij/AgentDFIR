// Command gen regenerates internal/fingerprint/zz_generated.go.
// Run it through `go generate ./internal/fingerprint`.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/efij/AgentDFIR/v3/internal/fingerprint/compute"
)

func main() {
	// go generate runs in the package directory: internal/fingerprint.
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		fail(err)
	}
	parse, err := compute.Compute(root, compute.Roots["parse"])
	if err != nil {
		fail(err)
	}
	analysis, err := compute.Compute(root, compute.Roots["analysis"])
	if err != nil {
		fail(err)
	}
	if err := os.WriteFile("zz_generated.go", []byte(compute.Source(parse, analysis)), 0o644); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "fingerprint:", err)
	os.Exit(1)
}
