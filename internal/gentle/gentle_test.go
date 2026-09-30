package gentle

import (
	"errors"
	"runtime"
	"testing"
	"time"
)

// The host probes must return real numbers on the platforms that have
// them, or the governor and the disk floor silently do nothing.
func TestHostProbes(t *testing.T) {
	if runtime.GOOS != "windows" {
		l, ok := loadAverage()
		if !ok || l < 0 {
			t.Fatalf("load average unavailable: %v %v", l, ok)
		}
	}
	if m := totalMemory(); m < 256<<20 {
		t.Fatalf("total memory %d: implausible", m)
	}
	dir := t.TempDir()
	free, err := FreeBytes(dir)
	if err != nil || free <= 0 {
		t.Fatalf("free bytes: %d %v", free, err)
	}
	total, err := TotalBytes(dir)
	if err != nil || total < free {
		t.Fatalf("total bytes %d < free %d (%v)", total, free, err)
	}
}

func TestMemoryLimitBounds(t *testing.T) {
	l := DefaultMemoryLimit()
	if l < 512<<20 || l > 4<<30 {
		t.Fatalf("default memory limit %d outside [512 MiB, 4 GiB]", l)
	}
}

func TestWorkers(t *testing.T) {
	if got := Workers(Gentle, 3); got != 3 {
		t.Fatalf("explicit jobs ignored: %d", got)
	}
	if got := Workers(Gentle, 0); got < 1 || got > 4 || got > max(1, runtime.NumCPU()/2) {
		t.Fatalf("gentle workers %d: want 1..min(NumCPU/2, 4)", got)
	}
	if got := Workers(Normal, 0); got != min(runtime.NumCPU(), 8) {
		t.Fatalf("normal workers %d", got)
	}
}

// The read-rate cap holds: 3 MB at 1 MB/s (with 1 s of burst) takes ~2 s.
func TestPaceCapsReadRate(t *testing.T) {
	g := NewGovernor(GovernorOptions{ReadMBps: 1})
	defer g.Close()
	start := time.Now()
	for i := 0; i < 12; i++ {
		if err := g.Pace(256 << 10); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d < 1500*time.Millisecond || d > 3500*time.Millisecond {
		t.Fatalf("3 MB at 1 MB/s took %v, want ~2s", d)
	}
}

// Once free space is below the floor, every further read is refused.
func TestPaceStopsAtTheDiskFloor(t *testing.T) {
	dir := t.TempDir()
	free, err := FreeBytes(dir)
	if err != nil {
		t.Skip(err)
	}
	g := NewGovernor(GovernorOptions{DiskPath: dir, FloorByte: free + 1<<40})
	defer g.Close()
	var got error
	for i := 0; i < 4 && got == nil; i++ {
		got = g.Pace(64 << 20)
	}
	if !errors.Is(got, ErrDiskFloor) {
		t.Fatalf("pace past the floor: %v, want ErrDiskFloor", got)
	}
	if err := g.Pace(1); !errors.Is(err, ErrDiskFloor) {
		t.Fatalf("after the floor: %v, want every read refused", err)
	}
}

func TestPreflight(t *testing.T) {
	dir := t.TempDir()
	free, err := FreeBytes(dir)
	if err != nil {
		t.Skip(err)
	}
	if err := Preflight(dir, 1<<20, 0); err != nil {
		t.Fatalf("1 MB with no floor refused: %v", err)
	}
	if err := Preflight(dir, free, 1<<30); err == nil {
		t.Fatal("a run needing all free space plus a floor was allowed")
	}
}

// A busy machine pauses work, but never forever.
func TestPauseIsBounded(t *testing.T) {
	g := NewGovernor(GovernorOptions{})
	defer g.Close()
	g.paused.Store(true)
	go func() { time.Sleep(600 * time.Millisecond); g.paused.Store(false) }()
	start := time.Now()
	if err := g.Pace(1); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d < 500*time.Millisecond || d > 2*time.Second {
		t.Fatalf("paused %v, want until the machine was idle (~0.6s)", d)
	}
	if _, paused := g.Stats(); paused < 500*time.Millisecond {
		t.Fatalf("pause not accounted: %v", paused)
	}
}

func TestParseMode(t *testing.T) {
	for in, want := range map[string]Mode{"": Gentle, "gentle": Gentle, "background": Background, "normal": Normal} {
		if got, err := ParseMode(in); err != nil || got != want {
			t.Errorf("ParseMode(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseMode("turbo"); err == nil {
		t.Error("unknown mode accepted")
	}
}

// The default floor never demands more than 5 GiB: a developer machine
// that is already fairly full must still be able to take a small round.
func TestFloorIsBounded(t *testing.T) {
	f := Floor(t.TempDir(), 0)
	if f < 2<<30 || f > 5<<30 {
		t.Fatalf("floor %d outside [2 GiB, 5 GiB]", f)
	}
	if got := Floor(t.TempDir(), 7); got != 7<<30 {
		t.Fatalf("--min-free-gb 7 gave %d", got)
	}
}
