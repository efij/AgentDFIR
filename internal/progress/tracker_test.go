package progress

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTest(t *testing.T, steps []Step, m *Model) (*Tracker, *clock, *bytes.Buffer) {
	t.Helper()
	c := &clock{t: time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)}
	var out bytes.Buffer
	tty := true
	tr := New(steps, Options{Out: &out, TTY: &tty, Now: c.now, Model: m})
	return tr, c, &out
}

// The displayed time remaining counts down one second per second while
// the work goes as predicted — it ticks like the elapsed clock does.
func TestETACountsDownSteadily(t *testing.T) {
	tr, c, _ := newTest(t, []Step{{Name: "collect", Units: 100, Rate: 1}}, nil) // 100 s predicted
	tr.Begin("collect")
	prev := tr.shownETA
	for i := 1; i <= 40; i++ {
		c.advance(time.Second)
		tr.Progress(float64(i)) // exactly on prediction: 1 unit/s
		tr.mu.Lock()
		tr.tick()
		got := tr.shownETA
		tr.mu.Unlock()
		if d := prev - got; d < 900*time.Millisecond || d > 1100*time.Millisecond {
			t.Fatalf("second %d: ETA moved by %v, want ~1s (from %v to %v)", i, d, prev, got)
		}
		prev = got
	}
	if prev < 55*time.Second || prev > 65*time.Second {
		t.Fatalf("after 40 of 100 units at the predicted pace, ETA = %v, want ~60s", prev)
	}
}

// When the machine is slower than predicted the estimate is pulled
// towards reality instead of running out while work remains.
func TestETAFollowsASlowerMachineWithoutJumping(t *testing.T) {
	tr, c, _ := newTest(t, []Step{{Name: "collect", Units: 100, Rate: 1}}, nil)
	tr.Begin("collect")
	var last time.Duration = tr.shownETA
	for i := 1; i <= 100; i++ {
		c.advance(time.Second)
		tr.Progress(float64(i) / 2) // half the predicted pace
		tr.mu.Lock()
		tr.tick()
		got := tr.shownETA
		tr.mu.Unlock()
		if got-last > 60*time.Second {
			t.Fatalf("second %d: ETA leapt from %v to %v", i, last, got)
		}
		last = got
	}
	// 50 of 100 units in 100 s: about 100 s remain.
	if last < 80*time.Second || last > 120*time.Second {
		t.Fatalf("at half pace, halfway, ETA = %v, want ~100s", last)
	}
}

// The display never claims 0:00 while a step is still running.
func TestETANeverZeroWhileWorkRemains(t *testing.T) {
	tr, c, _ := newTest(t, []Step{{Name: "analyze", Rate: 5}}, nil) // no units, 5 s predicted
	tr.Begin("analyze")
	for i := 0; i < 30; i++ {
		c.advance(time.Second)
		tr.mu.Lock()
		tr.tick()
		s := tr.eta()
		tr.mu.Unlock()
		if s == "0:00" {
			t.Fatalf("second %d: ETA shows 0:00 while the step is still running", i+1)
		}
	}
	tr.End()
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if s := tr.eta(); s != "0:00" {
		t.Fatalf("after the last step, ETA = %q, want 0:00", s)
	}
}

// The history makes the second run's prediction match what the first run
// took, per unit.
func TestModelLearnsFromHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "perf.jsonl")
	m := LoadModel(path)
	m.Record("analyze", "case1", 1000, 50*time.Second) // 0.05 s/unit
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
	m2 := LoadModel(path)
	if !m2.Known("analyze") {
		t.Fatal("history not read back")
	}
	if got := m2.Predict("analyze", "case1", 2000, 1); got < 99*time.Second || got > 101*time.Second {
		t.Fatalf("predicted %v for twice the units, want ~100s", got)
	}
	if got := m2.Predict("unknown-step", "", 10, 2); got != 20*time.Second {
		t.Fatalf("no history: predicted %v, want the default 20s", got)
	}
}

// The first run on a machine has no history and says its estimate is one.
func TestUncalibratedETAIsMarked(t *testing.T) {
	tr, c, out := newTest(t, []Step{{Name: "collect", Units: 100, Rate: 1}}, nil)
	tr.Begin("collect")
	c.advance(time.Second)
	tr.Progress(1)
	tr.mu.Lock()
	tr.tick()
	tr.mu.Unlock()
	if !strings.Contains(out.String(), "ETA ~") {
		t.Fatalf("uncalibrated estimate not marked with ~:\n%q", out.String())
	}
}

// Skipped steps leave the estimate.
func TestSkippedStepLeavesTheEstimate(t *testing.T) {
	tr, _, _ := newTest(t, []Step{{Name: "collect", Rate: 10}, {Name: "analyze", Rate: 100}}, nil)
	tr.Begin("collect")
	tr.Skip("analyze")
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if rem := tr.modelRemaining(tr.now()); rem > 11*time.Second {
		t.Fatalf("remaining %v still includes the skipped step", rem)
	}
}

func TestClock(t *testing.T) {
	for d, want := range map[time.Duration]string{0: "0:00", 59 * time.Second: "0:59", 61 * time.Second: "1:01", 3661 * time.Second: "1:01:01"} {
		if got := Clock(d); got != want {
			t.Errorf("Clock(%v) = %q, want %q", d, got, want)
		}
	}
}
