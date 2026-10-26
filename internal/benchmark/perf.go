package benchmark

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/efij/AgentDFIR/v5/internal/analysis"
)

// Performance is the performance section. It is measured, compared with
// a recorded baseline, and reported; a regression is a warning and never
// fails a run, because wall time depends on the machine. The numbers are
// kept out of `go test` for the same reason.
type Performance struct {
	Measured    PerfNumbers `json:"measured"`
	Baseline    PerfNumbers `json:"baseline"`
	TimeDelta   *float64    `json:"analyze_time_delta"` // measured / baseline - 1
	HeapDelta   *float64    `json:"peak_heap_delta"`
	Regressions []string    `json:"regressions"` // over the 25% tolerance
}

// PerfNumbers is one measurement, in the form testdata/perf-baseline.json
// records it.
type PerfNumbers struct {
	Sessions     int     `json:"sessions"`
	ToolCalls    int     `json:"tool_calls"`
	Events       int     `json:"events"`
	InputBytes   int64   `json:"input_bytes"`
	CollectMS    int64   `json:"collect_ms"`
	AnalyzeMS    int64   `json:"analyze_ms"`
	PeakHeapMB   float64 `json:"peak_heap_mb"`
	AllocMB      float64 `json:"alloc_mb"`
	GoVersion    string  `json:"go"`
	Platform     string  `json:"platform"`
	CPUs         int     `json:"cpus"`
	RecordedUTC  string  `json:"recorded_utc,omitempty"`
	AgentVersion string  `json:"agentdfir_version,omitempty"`
}

// RegressionTolerance is how much slower or larger a measurement may be
// than the baseline before it is reported.
const RegressionTolerance = 0.25

//go:embed testdata/perf-baseline.json
var embeddedBaseline []byte

// EmbeddedBaseline returns the baseline recorded in the source tree.
func EmbeddedBaseline() (*PerfNumbers, error) {
	var b PerfNumbers
	if err := json.Unmarshal(embeddedBaseline, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

const perfCallsPerSession = 60

// writePerfProfile generates a large synthetic case: sessions of tool
// calls with ordinary results, plus a few shapes the rules look at.
func writePerfProfile(profile string, sessions int) (int, int64, error) {
	calls := 0
	var total int64
	cmds := []string{"git status", "go test ./...", "ls -la", "cat README.md", "npm run build", "grep -rn TODO src", "make lint", "curl -s https://api.github.com/repos"}
	for i := 0; i < sessions; i++ {
		s := newSession(fmt.Sprintf("dddddddd-%04d-4000-8000-%012d", i%10000, i), t0.Add(time.Duration(i)*time.Hour))
		s.user(0, "work through the backlog item")
		for j := 0; j < perfCallsPerSession; j++ {
			s.bash(float64(j*4+1), cmds[(i+j)%len(cmds)], fmt.Sprintf("output line %d of a long and unremarkable result", j))
			calls++
		}
		s.say(float64(perfCallsPerSession*4+2), "Done; all checks pass.")
		data := s.bytes()
		total += int64(len(data))
		if _, err := writeTranscript(profile, s.id, data); err != nil {
			return 0, 0, err
		}
	}
	return calls, total, nil
}

// heapSampler records the peak live heap while a function runs.
func heapSampler() (stop func() (peakMB, allocMB float64)) {
	var mu sync.Mutex
	var peak uint64
	var start runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&start)
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(10 * time.Millisecond)
		defer t.Stop()
		for {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			mu.Lock()
			if m.HeapAlloc > peak {
				peak = m.HeapAlloc
			}
			mu.Unlock()
			select {
			case <-done:
				return
			case <-t.C:
			}
		}
	}()
	return func() (float64, float64) {
		close(done)
		wg.Wait()
		var end runtime.MemStats
		runtime.ReadMemStats(&end)
		mu.Lock()
		defer mu.Unlock()
		if end.HeapAlloc > peak {
			peak = end.HeapAlloc
		}
		return float64(peak) / (1 << 20), float64(end.TotalAlloc-start.TotalAlloc) / (1 << 20)
	}
}

func runPerf(r *Report, o Options, work string) error {
	sessions := o.PerfSessions
	if sessions <= 0 {
		sessions = 400
	}
	profile := filepath.Join(work, "home")
	if err := os.MkdirAll(profile, 0o755); err != nil {
		return err
	}
	calls, size, err := writePerfProfile(profile, sessions)
	if err != nil {
		return err
	}
	m := PerfNumbers{Sessions: sessions, ToolCalls: calls, InputBytes: size, GoVersion: runtime.Version(),
		Platform: runtime.GOOS + "/" + runtime.GOARCH, CPUs: runtime.NumCPU()}

	// Collect is timed separately so analyze is measured on its own.
	start := time.Now()
	a, err := collect(work, "perf", profile, []string{"claude-code"})
	if err != nil {
		return err
	}
	m.CollectMS = time.Since(start).Milliseconds()

	stop := heapSampler()
	start = time.Now()
	res, err := analysis.Run(a, analysis.Options{})
	m.AnalyzeMS = time.Since(start).Milliseconds()
	m.PeakHeapMB, m.AllocMB = stop()
	if err != nil {
		return err
	}
	m.Events = res.Events
	m.PeakHeapMB, m.AllocMB = round1(m.PeakHeapMB), round1(m.AllocMB)

	base := o.Baseline
	if base == nil {
		if base, err = EmbeddedBaseline(); err != nil {
			return fmt.Errorf("embedded baseline: %w", err)
		}
	}
	p := &Performance{Measured: m, Baseline: *base, Regressions: []string{}}
	if base.Sessions == m.Sessions && base.AnalyzeMS > 0 {
		d := float64(m.AnalyzeMS)/float64(base.AnalyzeMS) - 1
		p.TimeDelta = &d
		if d > RegressionTolerance {
			p.Regressions = append(p.Regressions, fmt.Sprintf("analyze took %d ms, %.0f%% over the baseline's %d ms", m.AnalyzeMS, d*100, base.AnalyzeMS))
		}
	}
	if base.Sessions == m.Sessions && base.PeakHeapMB > 0 {
		d := m.PeakHeapMB/base.PeakHeapMB - 1
		p.HeapDelta = &d
		if d > RegressionTolerance {
			p.Regressions = append(p.Regressions, fmt.Sprintf("peak heap %.1f MiB, %.0f%% over the baseline's %.1f MiB", m.PeakHeapMB, d*100, base.PeakHeapMB))
		}
	}
	if base.Sessions != m.Sessions {
		r.Warnings = append(r.Warnings, fmt.Sprintf("performance: case size %d sessions differs from the baseline's %d; not compared", m.Sessions, base.Sessions))
	} else if base.Platform != m.Platform {
		r.Warnings = append(r.Warnings, fmt.Sprintf("performance: baseline recorded on %s, measured on %s; compare with care", base.Platform, m.Platform))
	}
	for _, reg := range p.Regressions {
		r.Warnings = append(r.Warnings, "performance regression: "+reg)
	}
	r.Performance = p
	return nil
}

func round1(v float64) float64 { return float64(int64(v*10+0.5)) / 10 }

// SaveBaseline writes r's performance numbers as a baseline file.
func SaveBaseline(path string, r *Report) error {
	if r.Performance == nil {
		return fmt.Errorf("no performance numbers in this report")
	}
	m := r.Performance.Measured
	m.RecordedUTC = time.Now().UTC().Format(time.RFC3339)
	m.AgentVersion = r.Version
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}
