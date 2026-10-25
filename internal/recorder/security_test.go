package recorder

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/journal"
)

// A symlink planted in the state dir must never be written through.
func TestStatusSaveDoesNotFollowPlantedLinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	_ = os.WriteFile(victim, []byte("keep"), 0o600)
	_ = os.Symlink(victim, filepath.Join(dir, "status.json.tmp"))
	_ = os.Symlink(victim, filepath.Join(dir, StatusFile))
	r := New(dir, nil)
	if err := r.Save(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatalf("planted link was written through: %q", b)
	}
	fi, err := os.Lstat(filepath.Join(dir, StatusFile))
	if err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("status.json is not a regular file: %v %v", fi, err)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "status-*.tmp")); len(m) != 0 {
		t.Fatalf("temp files left: %v", m)
	}
}

func TestCheckDirAsRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX ownership")
	}
	oldRoot, oldUID := runningAsRoot, effectiveUID
	defer func() { runningAsRoot, effectiveUID = oldRoot, oldUID }()
	dir := t.TempDir()
	if err := CheckDir(dir); err != nil {
		t.Fatalf("own dir, not root: %v", err)
	}
	runningAsRoot = func() bool { return true }
	if err := CheckDir(dir); err != nil {
		t.Fatalf("dir owned by the effective uid: %v", err)
	}
	me := os.Geteuid()
	effectiveUID = func() int { return me + 1 }
	if err := CheckDir(dir); err == nil {
		t.Fatal("a root monitor accepted a state dir owned by another uid")
	}
	effectiveUID = oldUID
	link := filepath.Join(t.TempDir(), "monitor")
	_ = os.Symlink(dir, link)
	if err := CheckDir(link); err == nil {
		t.Fatal("a root monitor accepted a symlinked state dir")
	}
	if err := CheckDir(filepath.Join(t.TempDir(), "absent")); err != nil {
		t.Fatalf("absent dir: %v", err)
	}
}

// Retention ignores mtime and look-alike files: a backdated mtime neither
// ages a capture out nor goes unreported, and a planted capture-named file
// the journal never recorded is not counted toward the size bound or
// deleted.
func TestRetentionIgnoresForgeableInputs(t *testing.T) {
	dir := t.TempDir()
	jn, _ := openJournal(t, dir)
	c := NewCapture(dir, "auditd", ".log", jn, nil)
	_, _ = c.Write([]byte(auditLines(1, 1)))
	_ = c.Close()
	fresh := c.Path()
	old := time.Now().Add(-90 * 24 * time.Hour)
	_ = os.Chtimes(fresh, old, old) // backdated
	planted := filepath.Join(dir, "auditd-20200101T000000Z.log")
	_ = os.WriteFile(planted, make([]byte, 1<<20), 0o600)
	pruned, problems := Retention{MaxAge: 7 * 24 * time.Hour, MaxBytes: 1 << 19}.Prune(dir, known(t, dir), nil, jn, time.Now())
	_ = jn.Close()
	if len(pruned) != 0 {
		t.Fatalf("pruned on forgeable input: %v", pruned)
	}
	if _, err := os.Stat(planted); err != nil {
		t.Fatal("planted look-alike deleted")
	}
	joined := strings.Join(problems, "\n")
	if !strings.Contains(joined, "backdated") || !strings.Contains(joined, "never recorded") {
		t.Fatalf("problems: %v", problems)
	}
}

// Journaled bytes altered before pruning are caught even when more bytes
// were appended after the last flush (prune size > journaled size).
func TestPruneCatchesAlteredJournaledRangeWithUnjournaledTail(t *testing.T) {
	dir := t.TempDir()
	jn, jp := openJournal(t, dir)
	c := NewCapture(dir, "auditd", ".log", jn, nil)
	created := time.Now().Add(-10 * 24 * time.Hour)
	c.SetClock(func() time.Time { return created })
	_, _ = c.Write([]byte(auditLines(1, 1)))
	_ = c.Close() // journaled
	b, _ := os.ReadFile(c.Path())
	b[12] ^= 1
	b = append(b, []byte(auditLines(2, 1))...) // never journaled
	_ = os.WriteFile(c.Path(), b, 0o600)
	pruned, _ := Retention{MaxAge: 24 * time.Hour}.Prune(dir, known(t, dir), nil, jn, time.Now())
	_ = jn.Close()
	if len(pruned) != 1 {
		t.Fatalf("pruned %v", pruned)
	}
	rep, _ := journal.VerifyFiles(jp, resolveIn(dir))
	if rep.Problems != 1 || rep.Files[0].State != journal.FilePruneMismatch {
		t.Fatalf("altered journaled range passed: %+v", rep.Files)
	}
	data, _ := os.ReadFile(jp)
	if !strings.Contains(string(data), `"prune_prefix_sha256"`) {
		t.Fatal("prune record lacks the journaled-range hash")
	}
}

// The same with the prune done by a later monitor run, which only knows
// the journaled size from the journal file.
func TestPrunePrefixFromEarlierSession(t *testing.T) {
	dir := t.TempDir()
	jn, jp := openJournal(t, dir)
	c := NewCapture(dir, "auditd", ".log", jn, nil)
	created := time.Now().Add(-10 * 24 * time.Hour)
	c.SetClock(func() time.Time { return created })
	_, _ = c.Write([]byte(auditLines(1, 1)))
	_ = c.Close()
	_ = jn.Close()
	f, _ := os.OpenFile(c.Path(), os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(auditLines(2, 1)) // unjournaled tail, journaled bytes intact
	f.Close()
	jn2, _ := openJournal(t, dir)
	pruned, _ := Retention{MaxAge: 24 * time.Hour}.Prune(dir, known(t, dir), nil, jn2, time.Now())
	_ = jn2.Close()
	if len(pruned) != 1 {
		t.Fatalf("pruned %v", pruned)
	}
	rep, _ := journal.VerifyFiles(jp, resolveIn(dir))
	if rep.Problems != 0 || rep.Pruned != 1 || !strings.Contains(rep.Files[0].Detail, "never journaled") {
		t.Fatalf("intact journaled range with a tail: %+v", rep.Files)
	}
}
