// Package gentle keeps AgentDFIR from ever being the reason a machine is
// slow.
//
// It runs on developers' machines, often while they work, and on fleets
// where an SRE watches every host. A forensic sweep that saturates the CPU,
// stalls the disk, balloons memory or fills the volume is itself an
// incident. So by default the process yields: it lowers its own CPU (and,
// in background mode, I/O) priority, caps its parallelism and its heap,
// paces its reads, pauses while the machine is busy, and refuses to take
// the last of the free disk space.
//
// None of this hides anything. Priority and pacing change how fast the
// work is done, never what is collected or in what order, and every pause
// and refusal is counted and reported.
package gentle

import (
	"errors"
	"fmt"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"
)

// Mode is how much the process yields to everything else on the machine.
type Mode string

const (
	// Gentle lowers CPU priority (nice 10 / below normal): the process
	// yields to anything interactive and loses nothing on an idle machine.
	Gentle Mode = "gentle"
	// Background also puts I/O at the lowest priority (macOS background
	// QoS, Linux idle I/O class, Windows background mode). For fleets.
	Background Mode = "background"
	// Normal leaves priority alone: full speed, for an analyst's own box.
	Normal Mode = "normal"
)

// ParseMode validates a --priority value.
func ParseMode(s string) (Mode, error) {
	switch Mode(s) {
	case Gentle, Background, Normal:
		return Mode(s), nil
	case "":
		return Gentle, nil
	}
	return "", fmt.Errorf("unknown priority %q (gentle | background | normal)", s)
}

// Settings is what Apply put in place.
type Settings struct {
	Mode        Mode
	Priority    string // what the OS was asked for, or why it could not be
	Workers     int
	GoMaxProcs  int
	MemoryLimit int64
}

// Apply lowers this process's priority for the mode and caps its
// parallelism and heap. jobs and memLimit are the operator's explicit
// values (0: the mode's default).
func Apply(m Mode, jobs int, memLimit int64) Settings {
	s := Settings{Mode: m}
	if err := setPriority(m); err != nil {
		s.Priority = "unchanged (" + err.Error() + ")"
	} else {
		s.Priority = priorityName(m)
	}
	s.Workers = Workers(m, jobs)
	if m != Normal {
		// The Go scheduler too: half the cores, at least two.
		s.GoMaxProcs = max(2, runtime.NumCPU()/2)
		runtime.GOMAXPROCS(s.GoMaxProcs)
	} else {
		s.GoMaxProcs = runtime.GOMAXPROCS(0)
	}
	if memLimit == 0 && m != Normal {
		memLimit = DefaultMemoryLimit()
	}
	if memLimit > 0 {
		debug.SetMemoryLimit(memLimit)
		s.MemoryLimit = memLimit
	}
	return s
}

// Workers is the acquisition parallelism for a mode: an explicit value
// wins; normal uses up to 8 as before; the yielding modes use half the
// cores, at most 4.
func Workers(m Mode, jobs int) int {
	if jobs > 0 {
		return jobs
	}
	if m == Normal {
		return min(runtime.NumCPU(), 8)
	}
	return max(1, min(runtime.NumCPU()/2, 4))
}

// DefaultMemoryLimit is a soft heap goal: a quarter of physical memory,
// between 512 MiB and 4 GiB. It is soft — the Go runtime collects harder
// as the heap approaches it and caps its own GC effort — so it steers
// memory without risking a failure.
func DefaultMemoryLimit() int64 {
	const lo, hi = 512 << 20, 4 << 30
	total := totalMemory()
	if total <= 0 {
		return 2 << 30
	}
	return min(hi, max(lo, total/4))
}

// ErrDiskFloor is returned by Pace once the volume holding the evidence
// reaches its free-space floor.
var ErrDiskFloor = errors.New("stopped: free disk space reached the safety floor")

// Governor paces acquisition: a read-rate cap, a pause while the machine
// is busy, and the disk floor.
type Governor struct {
	rate      float64 // bytes/s, 0 = unlimited
	floor     int64
	diskPath  string
	loadHigh  float64
	loadLow   float64
	checkDisk int64

	mu      sync.Mutex
	tokens  float64
	last    time.Time
	sinceDk int64
	full    bool

	paused     atomic.Bool
	pauses     atomic.Int64
	pausedNano atomic.Int64
	stop       chan struct{}
	stopOnce   sync.Once
}

// GovernorOptions configure a Governor.
type GovernorOptions struct {
	ReadMBps  int    // 0 = unlimited
	DiskPath  string // the volume the evidence is written to
	FloorByte int64  // free space never to go below (0 = none)
	Adaptive  bool   // pause while the machine is busy
}

// NewGovernor starts a governor. Close stops its sampler.
func NewGovernor(o GovernorOptions) *Governor {
	g := &Governor{
		rate: float64(o.ReadMBps) * (1 << 20), floor: o.FloorByte, diskPath: o.DiskPath,
		loadHigh: 0.8 * float64(runtime.NumCPU()), loadLow: 0.6 * float64(runtime.NumCPU()),
		checkDisk: 64 << 20, last: time.Now(), stop: make(chan struct{}),
	}
	g.tokens = g.rate // one second of burst
	if o.Adaptive {
		go g.sample()
	}
	return g
}

// Close stops the load sampler.
func (g *Governor) Close() { g.stopOnce.Do(func() { close(g.stop) }) }

// Busy reports whether the governor is holding work back right now.
func (g *Governor) Busy() bool { return g.paused.Load() }

// Stats reports how often and how long the governor paused work.
func (g *Governor) Stats() (pauses int64, paused time.Duration) {
	return g.pauses.Load(), time.Duration(g.pausedNano.Load())
}

func (g *Governor) sample() {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-g.stop:
			return
		case <-t.C:
		}
		l, ok := loadAverage()
		pressure := memoryPressure()
		switch {
		case (ok && l > g.loadHigh) || pressure:
			if !g.paused.Swap(true) {
				g.pauses.Add(1)
			}
		case (!ok || l < g.loadLow) && !pressure:
			g.paused.Store(false)
		}
	}
}

// maxPause bounds one wait: on a machine that is always busy the work
// still finishes, at low priority, instead of never.
const maxPause = 30 * time.Second

// Pace is collector.Options.Pace: it blocks while the machine is busy and
// while the read-rate budget is spent, and refuses once the disk floor is
// reached.
func (g *Governor) Pace(size int64) error {
	if g.paused.Load() {
		start := time.Now()
		for g.paused.Load() && time.Since(start) < maxPause {
			select {
			case <-g.stop:
				return nil
			case <-time.After(250 * time.Millisecond):
			}
		}
		g.pausedNano.Add(int64(time.Since(start)))
	}
	g.mu.Lock()
	if g.full {
		g.mu.Unlock()
		return ErrDiskFloor
	}
	if g.floor > 0 && g.diskPath != "" {
		g.sinceDk += size
		if g.sinceDk >= g.checkDisk {
			g.sinceDk = 0
			if free, err := FreeBytes(g.diskPath); err == nil && free < g.floor {
				g.full = true
				g.mu.Unlock()
				return ErrDiskFloor
			}
		}
	}
	var wait time.Duration
	if g.rate > 0 {
		now := time.Now()
		g.tokens = min(g.rate, g.tokens+now.Sub(g.last).Seconds()*g.rate)
		g.last = now
		g.tokens -= float64(size)
		if g.tokens < 0 {
			wait = time.Duration(-g.tokens / g.rate * float64(time.Second))
		}
	}
	g.mu.Unlock()
	if wait > 0 {
		time.Sleep(wait)
	}
	return nil
}

// Floor is the free space never to go below on a volume: 2 GiB, raised to
// 1% of a large volume but never past 5 GiB. It protects the machine from
// this tool, not from the state it was found in: a volume that is already
// fuller than a percentage-based rule would like still takes a small
// round, and one that is truly nearly full does not. minGB overrides it
// when positive.
func Floor(path string, minGB int) int64 {
	if minGB > 0 {
		return int64(minGB) << 30
	}
	floor := int64(2 << 30)
	if total, err := TotalBytes(path); err == nil {
		floor = max(floor, min(total/100, 5<<30))
	}
	return floor
}

// Preflight refuses to start when writing need more bytes to the volume
// holding path would leave less than the floor.
func Preflight(path string, need, floor int64) error {
	free, err := FreeBytes(path)
	if err != nil {
		return nil // cannot tell; the in-run check still applies
	}
	if free-need < floor {
		return fmt.Errorf("not enough free disk space on the evidence volume: %s free, about %s needed, and %s must stay free (--min-free-gb to change)",
			HumanBytes(free), HumanBytes(need), HumanBytes(floor))
	}
	return nil
}

// HumanBytes renders a byte count.
func HumanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.0f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

func priorityName(m Mode) string {
	switch m {
	case Background:
		return "background (lowest CPU and I/O priority)"
	case Gentle:
		return "lowered CPU priority"
	}
	return "normal"
}
