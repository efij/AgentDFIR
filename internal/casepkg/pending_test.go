package casepkg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sealedCase is a package with one sealed round.
func sealedCase(t *testing.T) (pkg, src string) {
	t.Helper()
	pkg = filepath.Join(t.TempDir(), "p.adfir")
	src = filepath.Join(t.TempDir(), "a.jsonl")
	writeFile(t, src, "round one\n")
	b, err := New(pkg, "PEND", CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	ingest(t, b, src, "a.jsonl")
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	return pkg, src
}

func mustVerify(t *testing.T, pkg, when string) {
	t.Helper()
	res, err := Verify(pkg)
	if err != nil || len(res.Problems) > 0 {
		t.Fatalf("%s: package does not verify: %v %v", when, err, res.Problems)
	}
}

func custody(t *testing.T, pkg string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(pkg, "chain-of-custody.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// A round that is abandoned (an error, a refused disk floor, Ctrl+C that
// reaches Close) leaves the package exactly as it was sealed, and the next
// round records that it happened.
func TestAbandonedRoundRollsBack(t *testing.T) {
	pkg, src := sealedCase(t)
	writeFile(t, src, "round one\nround two\n")
	b, err := Reopen(pkg, CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "b.jsonl")
	writeFile(t, other, "new file\n")
	ingest(t, b, src, "a.jsonl")
	ingest(t, b, other, "b.jsonl")
	b.Close() // never sealed
	mustVerify(t, pkg, "after an abandoned round")
	if _, err := os.Stat(filepath.Join(pkg, pendingFile)); err == nil {
		t.Fatal("pending state left behind")
	}

	b2, err := Reopen(pkg, CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if err := b2.Seal(); err != nil {
		t.Fatal(err)
	}
	mustVerify(t, pkg, "after the next round")
	c := custody(t, pkg)
	if !strings.Contains(c, `"event":"round_aborted"`) || !strings.Contains(c, `"how":"abandoned"`) {
		t.Fatal("the next round did not record the abandoned one")
	}
}

// A process that dies mid-round leaves its lock and pending state. The
// next round rolls the package back before checking or extending it.
func TestCrashedRoundIsRolledBackByTheNextRound(t *testing.T) {
	pkg, src := sealedCase(t)
	writeFile(t, src, "round one\nround two\n")
	b, err := Reopen(pkg, CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	ingest(t, b, src, "a.jsonl")
	// Simulate the process dying: files closed by the OS, nothing rolled
	// back, the lock left as a stale lock of a dead process.
	b.pending = false
	b.coll.Close()
	b.custody.Close()
	b.mf.Close()
	b.coll, b.custody, b.mf = nil, nil, nil
	b.lock.release()
	b.lock = nil
	if res, _ := VerifyQuick(pkg); len(res.Problems) == 0 {
		t.Fatal("setup: a crashed round should leave the package not matching its seal")
	}

	var sawClean bool
	b2, err := ReopenChecked(pkg, CaseInfo{OperatorOSUser: "t"}, func() {
		res, err := VerifyQuick(pkg)
		sawClean = err == nil && len(res.Problems) == 0
	})
	if err != nil {
		t.Fatal(err)
	}
	if !sawClean {
		t.Fatal("the check before the next round saw the crashed round's tail")
	}
	if err := b2.Seal(); err != nil {
		t.Fatal(err)
	}
	mustVerify(t, pkg, "after recovery")
	if !strings.Contains(custody(t, pkg), `"how":"crashed"`) {
		t.Fatal("the crashed round was not recorded")
	}
}

// A crash after the new seal was written is a completed round: nothing is
// rolled back.
func TestCrashAfterTheSealKeepsTheRound(t *testing.T) {
	pkg, src := sealedCase(t)
	writeFile(t, src, "round one\nround two\n")
	b, err := Reopen(pkg, CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	ingest(t, b, src, "a.jsonl")
	pending, err := os.ReadFile(filepath.Join(pkg, pendingFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	// Put the pending file back, as if the process died right after the
	// seal was written.
	if err := os.WriteFile(filepath.Join(pkg, pendingFile), pending, 0o600); err != nil {
		t.Fatal(err)
	}
	b2, err := Reopen(pkg, CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if err := b2.Seal(); err != nil {
		t.Fatal(err)
	}
	ci, err := ReadCaseInfo(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if len(ci.Rounds) != 3 {
		t.Fatalf("rounds = %d, want 3: the sealed round 2 was rolled back", len(ci.Rounds))
	}
	mustVerify(t, pkg, "after a crash past the seal")
}

// A package whose first round never seals is removed: there is no sealed
// state to keep, and a half-built package would only be mistaken for one.
func TestUnsealedFirstRoundIsRemoved(t *testing.T) {
	pkg := filepath.Join(t.TempDir(), "new.adfir")
	src := filepath.Join(t.TempDir(), "a.jsonl")
	writeFile(t, src, "x\n")
	b, err := New(pkg, "NEW", CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	ingest(t, b, src, "a.jsonl")
	b.Close()
	if _, err := os.Stat(pkg); !os.IsNotExist(err) {
		t.Fatalf("unsealed first-round package left behind: %v", err)
	}
}
