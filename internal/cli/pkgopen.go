package cli

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/efij/AgentDFIR/v3/internal/casepkg"
	"github.com/efij/AgentDFIR/v3/internal/integrity"
	"github.com/efij/AgentDFIR/v3/internal/sanitize"
	"github.com/efij/AgentDFIR/v3/internal/seal"
	"github.com/efij/AgentDFIR/v3/internal/store"
)

// openPackage opens the destination package for writing: a new one when
// the path is free, an additional collection round when a sealed package
// is already there.
//
// Reusing a package is what stops a second run duplicating gigabytes of
// identical evidence. It is append-only: the existing manifest and both
// hash chains are continued, the previous seal is archived, and nothing
// already recorded is rewritten.
//
// beforeRound, when set, runs on an existing package once it is locked and
// before this round writes anything to it — where the earlier rounds are
// checked.
func openPackage(dest, caseID string, info casepkg.CaseInfo, share bool, beforeRound func()) (b *casepkg.Builder, reopened bool, err error) {
	if _, statErr := os.Stat(dest); statErr == nil {
		b, err = casepkg.ReopenChecked(dest, info, beforeRound)
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

// exitPriorFailed is the exit status when an earlier round of the case
// failed its integrity check. The new round is still sealed.
const exitPriorFailed = 4

// checkPrior proves an existing case's earlier rounds before a round is
// added and prints what it found. The caller records it on the round
// (Prior.Apply) once the builder exists.
func checkPrior(w io.Writer, dest string, depth string) integrity.Prior {
	p := integrity.CheckPrior(dest, depth == "full")
	switch p.Status {
	case integrity.Verified:
		how := "signature valid"
		if p.Anchored {
			how += ", matches the anchor"
		}
		fmt.Fprintf(w, "  Earlier rounds verified (%s, %s check)\n", how, p.Depth)
	case integrity.Unsigned:
		fmt.Fprintf(w, "  Earlier rounds verified (%s check; unsigned, so tampering by someone who could rewrite the seal is not excluded)\n", p.Depth)
	default:
		fmt.Fprintf(w, "  WARNING: earlier rounds of this case FAILED their integrity check (%s):\n", p.Depth)
		for _, pr := range p.Problems {
			fmt.Fprintf(w, "    - %s\n", sanitize.Terminal(pr))
		}
		fmt.Fprintln(w, "    The new round is collected and sealed, and records this failure permanently. Nothing earlier is repaired or re-signed as clean.")
	}
	for _, n := range p.Notes {
		fmt.Fprintln(w, "  note:", sanitize.Terminal(n))
	}
	return p
}

// prepareSigning chooses the round's key before sealing and records it on
// the round, so case.json names the key its seal was made for.
func prepareSigning(b *casepkg.Builder, explicitKey string, noSign bool) integrity.Signing {
	s := integrity.Prepare(explicitKey, noSign)
	if s.KeyPath != "" {
		b.Signer = s.Public
	}
	return s
}

// finishSeal signs the sealed round and anchors it, then prints the one
// line an analyst can paste into a ticket to pin this exact state.
func finishSeal(w io.Writer, dest string, s integrity.Signing, caseID string, round int, anchor bool) (integrity.Sealed, error) {
	res, err := integrity.Finish(dest, s, caseID, round, anchor)
	if err != nil {
		return res, err
	}
	line := fmt.Sprintf("  Seal %s · round %d", res.Digest[:16], round)
	if res.Signed {
		line += " · signed " + seal.Fingerprint(s.Public)
	}
	if res.Anchored {
		line += " · anchored"
	}
	fmt.Fprintln(w, line)
	for _, n := range res.Notes {
		fmt.Fprintln(w, "  note:", sanitize.Terminal(n))
	}
	return res, nil
}
