package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/efij/AgentDFIR/v2/internal/casepkg"
	"github.com/efij/AgentDFIR/v2/internal/store"
)

// openPackage opens the destination package for writing: a new one when
// the path is free, an additional collection round when a sealed package
// is already there.
//
// Reusing a package is what stops a second run duplicating gigabytes of
// identical evidence. It is append-only: the existing manifest and both
// hash chains are continued, the previous seal is archived, and nothing
// already recorded is rewritten.
func openPackage(dest, caseID string, info casepkg.CaseInfo, share bool) (b *casepkg.Builder, reopened bool, err error) {
	if _, statErr := os.Stat(dest); statErr == nil {
		b, err = casepkg.Reopen(dest, info)
		reopened = true
	} else if errors.Is(statErr, os.ErrNotExist) {
		b, err = casepkg.New(dest, caseID, info)
	} else {
		return nil, false, statErr
	}
	if err != nil {
		return nil, reopened, err
	}
	if share {
		if sh, sErr := store.Open(); sErr == nil {
			b.Shared = sh
		} else {
			fmt.Fprintln(os.Stderr, "note: shared blob store unavailable, storing bytes in the package:", sErr)
		}
	}
	return b, reopened, nil
}
