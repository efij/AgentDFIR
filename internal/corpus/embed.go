package corpus

import (
	"embed"
	"io/fs"
	"os"
)

// fixtures is the corpus itself, embedded so `agentdfir benchmark` measures
// the same labeled cases the build gates on, from an installed binary.
// all: keeps each case's .claude profile directory.
//
//go:embed all:testdata
var fixtures embed.FS

// Extract writes the embedded corpus to dst and returns the root to pass
// to Load.
func Extract(dst string) (string, error) {
	sub, err := fs.Sub(fixtures, "testdata")
	if err != nil {
		return "", err
	}
	if err := os.CopyFS(dst, sub); err != nil {
		return "", err
	}
	return dst, nil
}
