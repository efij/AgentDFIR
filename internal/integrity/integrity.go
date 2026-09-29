// Package integrity proves a case's earlier rounds are intact before a new
// round is added to it, and signs and anchors each round once it is
// sealed.
//
// The order matters. A new round's seal re-states every earlier blob's
// hash, and a new signature covers that seal. Signing without checking
// first would put this machine's signature on whatever someone left in the
// case since the last run. So before collecting, the previous signature is
// checked against the current SHA256SUMS, the seal is checked against the
// anchor recorded outside the case, and the sealed files, both hash chains
// and every blob's presence and length are verified. A full re-hash of
// every blob is available on request; it is not needed for this guarantee,
// because the new seal carries the old hashes forward rather than
// re-deriving them, so a swapped blob stays detectable by any later
// verify.
package integrity

import (
	"fmt"
	"path/filepath"

	"github.com/efij/AgentDFIR/v3/internal/casepkg"
	"github.com/efij/AgentDFIR/v3/internal/seal"
	"github.com/efij/AgentDFIR/v3/internal/store"
)

// Status values recorded in a round's prior_integrity.
const (
	Verified = "verified" // signature and anchor matched, quick verify clean
	Unsigned = "unsigned" // nothing to check a signature against; quick verify clean
	Failed   = "FAILED"
)

// Prior is what checking a case's earlier rounds found.
type Prior struct {
	Status   string
	Problems []string
	Signer   string // public key the previous round was signed with, if any
	Anchored bool   // the anchor log had a record for this case and it matched
	Depth    string // "quick" or "full"
	Notes    []string
}

// CheckPrior verifies an existing case before a round is added. full also
// re-hashes every stored blob.
func CheckPrior(pkg string, full bool) Prior {
	p := Prior{Depth: "quick"}
	fail := func(format string, a ...any) { p.Problems = append(p.Problems, fmt.Sprintf(format, a...)) }

	ci, err := casepkg.ReadCaseInfo(pkg)
	if err != nil {
		fail("case.json: %v", err)
		p.Status = Failed
		return p
	}
	expected := ""
	for _, r := range ci.Rounds {
		if r.Signer != "" {
			expected = r.Signer
		}
	}

	sig, err := seal.Verify(pkg, expected)
	switch {
	case err != nil:
		fail("signature: %v", err)
	case sig.Present && !sig.Valid && expected == "":
		// No round recorded a signer, so this SEAL.sig predates signed
		// rounds. `run --sign` in those versions signed before sealing, so
		// its signature never matched the seal it sat next to. It proves
		// nothing either way; it is reported, not trusted, and not counted
		// as tampering.
		p.Notes = append(p.Notes, "SEAL.sig from an earlier version does not match the seal ("+sig.Reason+"); not trusted")
	case sig.Present && !sig.Valid:
		fail("signature: %s", sig.Reason)
	case !sig.Present && expected != "":
		fail("signature: %s is missing, but an earlier round was sealed for key %s", seal.SigFile, seal.Fingerprint(expected))
	case sig.Present && sig.Valid:
		p.Signer = sig.PublicKey
	}

	abs, _ := filepath.Abs(pkg)
	if a, err := store.LatestAnchor(ci.CaseID, abs); err != nil {
		fail("anchor log: %v", err)
	} else if a != nil {
		digest, err := seal.Digest(pkg)
		switch {
		case err != nil:
			fail("seal: %v", err)
		case digest != a.SealsDigest:
			fail("seal: SHA256SUMS does not match the anchor recorded when round %d was sealed (%s) — the case was changed or rolled back since", a.Round, a.TimeUTC)
		default:
			p.Anchored = true
		}
	}

	verify := casepkg.VerifyQuick
	if full {
		verify, p.Depth = casepkg.Verify, "full"
	}
	if res, err := verify(pkg); err != nil {
		fail("verify: %v", err)
	} else {
		for _, pr := range res.Problems {
			fail("verify: %s", pr)
		}
	}

	switch {
	case len(p.Problems) > 0:
		p.Status = Failed
	case p.Signer != "":
		p.Status = Verified
	default:
		p.Status = Unsigned
	}
	return p
}

// Apply records the result on the round about to be collected.
func (p Prior) Apply(b *casepkg.Builder) {
	b.PriorIntegrity = p.Status
	b.PriorProblems = p.Problems
	_ = b.Log("prior_integrity_checked", map[string]any{
		"status": p.Status, "problems": p.Problems, "depth": p.Depth,
		"anchored": p.Anchored, "signer": p.Signer,
	})
}

// Signing is how a round will be signed: the key file, its public half,
// and why there is none when there is none.
type Signing struct {
	KeyPath string
	Public  string
	Skipped string
}

// Prepare picks the key a round will be signed with: an explicit key
// file, else this machine's key (created on first use). noSign turns
// signing off and says so. Call it before sealing and set b.Signer to the
// Public half, so the round records which key it was sealed for.
func Prepare(explicitKey string, noSign bool) Signing {
	if noSign {
		return Signing{Skipped: "--no-sign"}
	}
	key := explicitKey
	if key == "" {
		k, err := store.MachineKey()
		if err != nil {
			return Signing{Skipped: "no machine key: " + err.Error()}
		}
		key = k
	}
	pub, err := seal.PublicKeyHex(key)
	if err != nil {
		return Signing{Skipped: "signing key: " + err.Error()}
	}
	return Signing{KeyPath: key, Public: pub}
}

// Sealed is what Finish did.
type Sealed struct {
	Digest   string // sha256 of SHA256SUMS
	Signed   bool
	Anchored bool
	Notes    []string
}

// Finish signs a freshly sealed package and records its anchor. It runs
// after Seal, because the signature covers the SHA256SUMS Seal writes.
// anchor is false for runs that must leave nothing on the machine.
func Finish(pkg string, s Signing, caseID string, round int, anchor bool) (Sealed, error) {
	var out Sealed
	if s.KeyPath != "" {
		if err := seal.Sign(pkg, s.KeyPath); err != nil {
			return out, fmt.Errorf("sign: %w", err)
		}
		out.Signed = true
	} else if s.Skipped != "" {
		out.Notes = append(out.Notes, "round not signed ("+s.Skipped+")")
	}
	digest, err := seal.Digest(pkg)
	if err != nil {
		return out, err
	}
	out.Digest = digest
	if anchor {
		abs, _ := filepath.Abs(pkg)
		if err := store.RecordAnchor(store.Anchor{
			CaseID: caseID, Round: round, SealsDigest: digest, Signer: s.Public, Package: abs,
		}); err != nil {
			out.Notes = append(out.Notes, "anchor not recorded: "+err.Error())
		} else {
			out.Anchored = true
		}
	}
	return out, nil
}
