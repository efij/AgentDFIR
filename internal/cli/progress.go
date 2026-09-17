package cli

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// progress is the one status line a long step keeps redrawing on a terminal
// ("  claude-code   3,120 artifacts · 412 MB · 14s"). It is silent when stdout
// is not a terminal, and it is an io.Writer so ordinary log lines from the
// analysis stages print cleanly above it instead of tearing through it.
type progress struct {
	mu     sync.Mutex
	out    io.Writer
	tty    bool
	label  string
	detail string
	start  time.Time
	shown  bool
	stop   chan struct{}
	done   chan struct{}
}

func newProgress() *progress {
	p := &progress{out: os.Stdout}
	if fi, err := os.Stdout.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb" {
		p.tty = true
	}
	return p
}

// Start begins a status line for one step; the elapsed time ticks on its own.
func (p *progress) Start(label string) {
	p.Stop()
	p.mu.Lock()
	p.label, p.detail, p.start = label, "", time.Now()
	p.stop, p.done = make(chan struct{}), make(chan struct{})
	p.mu.Unlock()
	if !p.tty {
		return
	}
	go func() {
		defer close(p.done)
		t := time.NewTicker(250 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-p.stop:
				return
			case <-t.C:
				p.mu.Lock()
				p.draw()
				p.mu.Unlock()
			}
		}
	}()
}

// Set updates the variable part of the line (counts, bytes).
func (p *progress) Set(detail string) {
	p.mu.Lock()
	p.detail = detail
	p.mu.Unlock()
}

// Stop ends the step and clears the line so the final summary can take its place.
func (p *progress) Stop() {
	p.mu.Lock()
	if p.stop == nil {
		p.mu.Unlock()
		return
	}
	close(p.stop)
	p.stop = nil
	done := p.done
	p.mu.Unlock()
	if p.tty {
		<-done
	}
	p.mu.Lock()
	p.clear()
	p.label = ""
	p.mu.Unlock()
}

// Write lets stage log lines print above the status line.
func (p *progress) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clear()
	n, err := p.out.Write(b)
	p.draw()
	return n, err
}

func (p *progress) clear() {
	if p.tty && p.shown {
		fmt.Fprint(p.out, "\r\033[2K")
		p.shown = false
	}
}

func (p *progress) draw() {
	if !p.tty || p.label == "" {
		return
	}
	line := p.label
	if p.detail != "" {
		line += " · " + p.detail
	}
	fmt.Fprintf(p.out, "\r\033[2K%s · %s", line, elapsed(time.Since(p.start)))
	p.shown = true
}

func elapsed(d time.Duration) string {
	s := int(d.Seconds())
	if s < 60 {
		return fmt.Sprintf("%ds", s)
	}
	return fmt.Sprintf("%dm%02ds", s/60, s%60)
}

func humanBytes(n int64) string {
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
