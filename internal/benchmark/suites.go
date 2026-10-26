package benchmark

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// The cross-platform suites (acquisition, per-OS corroboration, forensic
// interop, detection per platform, evidence integrity) each end in one
// verdict, reported in text and JSON next to the numbers they measured.
//
// Their fixtures are synthetic or made by the real tools (mkfs, hdiutil,
// qemu-img, lvcreate); each fixture's README says which. Nothing here
// runs or compares any other product.

// SuiteLabel heads every cross-platform suite.
const SuiteLabel = "synthetic or tool-generated fixtures; not a comparison with any other product"

// Suite verdicts.
const (
	SuitePass = "PASS"
	SuiteFail = "FAIL"
	SuiteSkip = "SKIP"
)

// Suite is one cross-platform suite's verdict.
type Suite struct {
	Name   string `json:"name"`
	Label  string `json:"label"`
	Status string `json:"status"` // PASS | FAIL | SKIP
	// Summary is the measured headline ("27/27 fixtures, 4123 files…").
	Summary string `json:"summary"`
	// Reason says why the suite was skipped, when it was.
	Reason string `json:"reason,omitempty"`
	// ExpectedFailures are checks that fail on this build for a known,
	// documented reason; they do not fail the suite (see Check).
	ExpectedFailures []string `json:"expected_failures,omitempty"`
}

// Check is one labeled hard check of a suite. A check with ExpectedFail
// set documents a known defect: failing, it is reported XFAIL and does
// not fail the run; passing, it is reported XPASS as a warning, so the
// expectation can be removed.
type Check struct {
	Name         string `json:"name"`
	Want         string `json:"want"`
	Got          string `json:"got"`
	Status       string `json:"status"` // PASS | FAIL | XFAIL | XPASS
	ExpectedFail string `json:"expected_fail,omitempty"`
}

// Check statuses beyond PASS/FAIL.
const (
	CheckXFail = "XFAIL"
	CheckXPass = "XPASS"
)

// record finalizes c: sets its status from ok, fails the run on an
// unexpected failure and warns on an unexpected pass.
func (r *Report) record(suite string, c *Check, ok bool) {
	switch {
	case ok && c.ExpectedFail == "":
		c.Status = SuitePass
	case ok:
		c.Status = CheckXPass
		r.Warnings = append(r.Warnings, suite+": "+c.Name+" passed although it is marked as an expected failure ("+c.ExpectedFail+"); remove the expectation")
	case c.ExpectedFail != "":
		c.Status = CheckXFail
	default:
		c.Status = SuiteFail
		r.fail("%s: %s: got %s, want %s", suite, c.Name, c.Got, c.Want)
	}
}

// verdict builds a suite verdict from its checks and its own failures.
func verdict(name, summary string, checks []Check, failed bool) Suite {
	s := Suite{Name: name, Label: SuiteLabel, Status: SuitePass, Summary: summary}
	for _, c := range checks {
		switch c.Status {
		case SuiteFail:
			s.Status = SuiteFail
		case CheckXFail:
			s.ExpectedFailures = append(s.ExpectedFailures, c.Name+": "+c.ExpectedFail)
		}
	}
	if failed {
		s.Status = SuiteFail
	}
	return s
}

// repoFinder is findRepoRoot; tests replace it to exercise the skips.
var repoFinder = findRepoRoot

// findRepoRoot locates a source checkout of this module: the disk-image,
// telemetry and interop fixtures and the Python verifier live in the
// repository, not in the binary. It tries hint, the working directory
// and this file's build-time directory, each walked up to the root.
func findRepoRoot(hint string) string {
	var starts []string
	if hint != "" {
		starts = append(starts, hint)
	}
	if wd, err := os.Getwd(); err == nil {
		starts = append(starts, wd)
	}
	if _, file, _, ok := runtime.Caller(0); ok {
		starts = append(starts, filepath.Dir(file))
	}
	for _, s := range starts {
		dir, err := filepath.Abs(s)
		if err != nil {
			continue
		}
		for {
			if isRepoRoot(dir) {
				return dir
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	return ""
}

func isRepoRoot(dir string) bool {
	b, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil || !declaresModule(b) {
		return false
	}
	fi, err := os.Stat(filepath.Join(dir, "internal", "diskimage"))
	return err == nil && fi.IsDir()
}

// declaresModule reports whether a go.mod declares this module. A Windows
// checkout with git's end-of-line conversion has CRLF line endings, so the
// module line is matched after trimming, not byte for byte.
func declaresModule(gomod []byte) bool {
	for _, line := range bytes.Split(gomod, []byte("\n")) {
		if string(bytes.TrimSpace(line)) == "module github.com/efij/AgentDFIR/v4" {
			return true
		}
	}
	return false
}

// noCheckout is the skip reason when no source checkout was found.
const noCheckout = "the fixtures for this suite are in the source repository, not in the binary; run from a checkout or pass --repo <checkout>"

// fileSHA256 hashes a file.
func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
