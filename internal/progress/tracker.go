// Package progress draws the one status display a long command keeps
// redrawing: an overall bar across every step of the run, elapsed time,
// and a time remaining that is predicted from this machine's own history
// and counts down steadily instead of jumping.
//
//	AgentDFIR  ▕████████████▋              ▏  46%   elapsed 0:41   ETA 0:48
//	  analyze · rule packs (stage 4/7)
//
// Every step reports progress in units that mean work (bytes actually
// read, not bytes carried forward from an earlier round). The time
// remaining is the model's prediction for what is left, scaled by how the
// finished steps compared with their predictions today. The displayed
// value then counts down one second per second and is only pulled towards
// the model when the two disagree by more than max(10%, 3 s), so it neither
// flickers nor leaps. It never reads 0:00 while work remains.
//
// On a terminal it redraws in place; otherwise it prints a plain line when
// a step starts and every ten seconds. Log lines written through it print
// above the display without tearing it.
package progress

import (
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"sync"
	"time"
)

// Step is one planned part of a run.
type Step struct {
	Name  string  // stable id, used for the timing history
	Label string  // what the display calls it
	Units float64 // work units expected (0: the step reports none)
	// Rate is seconds per unit (or plain seconds when Units is 0) to
	// assume when this machine has no history for the step.
	Rate float64
}

type stepState struct {
	Step
	predicted time.Duration
	done      float64
	started   time.Time
	took      time.Duration
	finished  bool
	skipped   bool
}

// Tracker is the display for one run.
type Tracker struct {
	mu     sync.Mutex
	out    io.Writer
	tty    bool
	title  string
	key    string
	model  *Model
	now    func() time.Time
	steps  []*stepState
	cur    int
	start  time.Time
	detail string

	shownETA   time.Duration
	etaSet     bool
	lastTick   time.Time
	lastPlain  time.Time
	drawn      bool
	calibrated bool

	stop chan struct{}
	done chan struct{}
}

// Options configure a Tracker.
type Options struct {
	Out   io.Writer // default os.Stdout
	Title string    // default "AgentDFIR"
	Key   string    // groups history (e.g. the case), optional
	Model *Model    // timing history; nil = none
	TTY   *bool     // override terminal detection (tests)
	Now   func() time.Time
}

// New plans a run.
func New(steps []Step, o Options) *Tracker {
	t := &Tracker{out: o.Out, title: o.Title, key: o.Key, model: o.Model, now: o.Now, cur: -1}
	if t.out == nil {
		t.out = os.Stdout
	}
	if t.title == "" {
		t.title = "AgentDFIR"
	}
	if t.model == nil {
		t.model = LoadModel("")
	}
	if t.now == nil {
		t.now = time.Now
	}
	if o.TTY != nil {
		t.tty = *o.TTY
	} else {
		t.tty = IsTerminal(t.out)
	}
	t.calibrated = true
	for _, s := range steps {
		st := &stepState{Step: s}
		st.predicted = t.model.Predict(s.Name, t.key, s.Units, s.Rate)
		if !t.model.Known(s.Name) {
			t.calibrated = false
		}
		t.steps = append(t.steps, st)
	}
	t.start = t.now()
	return t
}

// IsTerminal reports whether w is an interactive terminal that can take
// in-place redraws.
func IsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	return os.Getenv("TERM") != "dumb"
}

// Run starts the redraw ticker.
func (t *Tracker) Run() {
	t.mu.Lock()
	if t.stop != nil {
		t.mu.Unlock()
		return
	}
	stop, done := make(chan struct{}), make(chan struct{})
	t.stop, t.done = stop, done
	t.mu.Unlock()
	go func() {
		defer close(done)
		tk := time.NewTicker(250 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
				t.mu.Lock()
				t.tick()
				t.mu.Unlock()
			}
		}
	}()
}

func (t *Tracker) find(name string) int {
	for i, s := range t.steps {
		if s.Name == name {
			return i
		}
	}
	return -1
}

// Begin starts a step. Steps before it that never began are skipped.
func (t *Tracker) Begin(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	i := t.find(name)
	if i < 0 {
		return
	}
	t.finishCurrent()
	for j := t.cur + 1; j < i; j++ {
		if !t.steps[j].finished {
			t.steps[j].skipped = true
		}
	}
	t.cur = i
	t.steps[i].started = t.now()
	t.detail = ""
	t.tick()
}

// Skip marks a planned step as not needed this run (its time leaves the
// estimate).
func (t *Tracker) Skip(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if i := t.find(name); i >= 0 && !t.steps[i].finished && i != t.cur {
		t.steps[i].skipped = true
	}
}

// SetUnits replaces a step's expected work once it is known (after a
// survey, say) and re-predicts it.
func (t *Tracker) SetUnits(name string, units float64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if i := t.find(name); i >= 0 {
		s := t.steps[i]
		s.Units = units
		s.predicted = t.model.Predict(s.Name, t.key, units, s.Rate)
	}
}

// Progress reports how many units of the current step are done.
func (t *Tracker) Progress(done float64) {
	t.mu.Lock()
	if t.cur >= 0 {
		t.steps[t.cur].done = done
	}
	t.mu.Unlock()
}

// Detail sets the second line (what the current step is doing).
func (t *Tracker) Detail(format string, a ...any) {
	t.mu.Lock()
	t.detail = fmt.Sprintf(format, a...)
	t.mu.Unlock()
}

// End finishes the current step.
func (t *Tracker) End() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.finishCurrent()
	t.clear()
}

func (t *Tracker) finishCurrent() {
	if t.cur < 0 {
		return
	}
	s := t.steps[t.cur]
	if s.finished || s.started.IsZero() {
		return
	}
	s.finished = true
	s.took = t.now().Sub(s.started)
	units := s.Units
	if units > 0 && s.done > 0 {
		units = s.done
	}
	t.model.Record(s.Name, t.key, units, s.took)
}

// Stop ends the display and saves the timing history.
func (t *Tracker) Stop() {
	t.mu.Lock()
	t.finishCurrent()
	stop, done := t.stop, t.done
	t.stop = nil
	t.mu.Unlock()
	if stop != nil {
		close(stop)
		<-done
	}
	t.mu.Lock()
	t.clear()
	t.mu.Unlock()
	_ = t.model.Save()
}

// Write prints log lines above the display.
func (t *Tracker) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.clear()
	n, err := t.out.Write(p)
	if t.tty && t.stop != nil {
		t.draw()
	}
	return n, err
}

// Summary is one line of per-step timings for the end of a run.
func (t *Tracker) Summary() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var parts []string
	for _, s := range t.steps {
		if s.finished {
			parts = append(parts, fmt.Sprintf("%s %s", s.Name, Clock(s.took)))
		}
	}
	return strings.Join(parts, " · ")
}

// Elapsed is the time since the run started.
func (t *Tracker) Elapsed() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.now().Sub(t.start)
}

// k is how today's finished steps compare with their predictions — a
// mild correction for how busy the machine is today.
func (t *Tracker) k() float64 {
	k, n := 1.0, 0
	for _, s := range t.steps {
		if !s.finished || s.predicted < 500*time.Millisecond {
			continue // tiny steps say nothing about the machine's pace
		}
		r := s.took.Seconds() / s.predicted.Seconds()
		if n == 0 {
			k = r
		} else {
			k = 0.5*r + 0.5*k
		}
		n++
	}
	// Narrow on purpose: steps have different bottlenecks (acquisition is
	// I/O, analysis is CPU), so a slow disk today says little about how
	// long the analysis will take. Each step switches to its own measured
	// pace once it is running.
	return math.Min(1.5, math.Max(0.67, k))
}

// modelRemaining is the model's current estimate of the time left.
func (t *Tracker) modelRemaining(now time.Time) time.Duration {
	k := t.k()
	var rem float64
	for i, s := range t.steps {
		if s.finished || s.skipped {
			continue
		}
		pred := s.predicted.Seconds() * k
		if i != t.cur {
			if i > t.cur {
				rem += pred
			}
			continue
		}
		el := now.Sub(s.started).Seconds()
		byTime := math.Max(pred-el, 0)
		if s.Units > 0 && s.done > 0 {
			f := math.Min(s.done/s.Units, 1)
			byRate := el * (1 - f) / f // today's measured pace
			byModel := pred * (1 - f)  // the work left, at the predicted pace
			w := math.Min(1, f/0.2)    // the measured pace is the answer once a fifth is done
			rem += w*byRate + (1-w)*byModel
		} else {
			// No units: the prediction, and never less than a moment once
			// it has been exceeded — the step is still running.
			rem += math.Max(byTime, math.Min(pred*0.1, 5))
		}
	}
	return time.Duration(rem * float64(time.Second))
}

// tick advances the displayed ETA and redraws.
func (t *Tracker) tick() {
	now := t.now()
	model := t.modelRemaining(now)
	if !t.etaSet {
		t.shownETA, t.etaSet, t.lastTick = model, true, now
	} else {
		dt := now.Sub(t.lastTick)
		t.lastTick = now
		t.shownETA -= dt
		if t.shownETA < 0 {
			t.shownETA = 0
		}
		diff := model - t.shownETA
		band := time.Duration(math.Max(0.1*model.Seconds(), 3) * float64(time.Second))
		if diff > band || diff < -band {
			// Pull towards the model with a one-second time constant.
			f := math.Min(1, dt.Seconds())
			t.shownETA += time.Duration(float64(diff) * f)
		}
	}
	if t.tty {
		t.draw()
	} else if now.Sub(t.lastPlain) >= 10*time.Second {
		fmt.Fprintf(t.out, "  %s\n", t.plainStatus(now))
		t.lastPlain = now
	}
}

func (t *Tracker) eta() string {
	allDone := true
	for _, s := range t.steps {
		if !s.finished && !s.skipped {
			allDone = false
		}
	}
	if allDone {
		return "0:00"
	}
	if t.shownETA < time.Second {
		return "finishing…"
	}
	s := Clock(t.shownETA)
	if !t.calibrated && t.fractionDone() < 0.05 {
		s = "~" + s
	}
	return s
}

func (t *Tracker) fractionDone() float64 {
	el := t.now().Sub(t.start).Seconds()
	total := el + t.shownETA.Seconds()
	if total <= 0 {
		return 0
	}
	return math.Min(1, el/total)
}

func (t *Tracker) plainStatus(now time.Time) string {
	label := ""
	if t.cur >= 0 {
		label = t.steps[t.cur].Label
	}
	return fmt.Sprintf("%3d%% · %s · elapsed %s · ETA %s", int(100*t.fractionDone()), label, Clock(now.Sub(t.start)), t.eta())
}

const barWidth = 28

func (t *Tracker) draw() {
	now := t.now()
	f := t.fractionDone()
	cells := f * barWidth
	full := int(cells)
	partial := []string{"", "▏", "▎", "▍", "▌", "▋", "▊", "▉"}[int((cells-float64(full))*8)]
	bar := strings.Repeat("█", full) + partial
	bar += strings.Repeat(" ", max(0, barWidth-full-len([]rune(partial))))
	line1 := fmt.Sprintf(" %s  ▕%s▏ %3d%%   elapsed %s   ETA %s", t.title, bar, int(100*f), Clock(now.Sub(t.start)), t.eta())
	line2 := ""
	if t.cur >= 0 {
		line2 = "   " + t.steps[t.cur].Label
		if t.detail != "" {
			line2 += " · " + t.detail
		}
	}
	if w := width(); w > 0 {
		line1, line2 = clip(line1, w), clip(line2, w)
	}
	t.clear()
	fmt.Fprintf(t.out, "%s\n\033[2K%s\033[1A\r", line1, line2)
	t.drawn = true
}

func (t *Tracker) clear() {
	if t.tty && t.drawn {
		fmt.Fprint(t.out, "\r\033[2K\n\033[2K\033[1A\r")
		t.drawn = false
	}
}

func clip(s string, w int) string {
	r := []rune(s)
	if len(r) >= w {
		return string(r[:w-1])
	}
	return s
}

func width() int {
	var n int
	if _, err := fmt.Sscan(os.Getenv("COLUMNS"), &n); err == nil && n > 20 {
		return n
	}
	return 100
}

// Clock renders a duration as m:ss or h:mm:ss.
func Clock(d time.Duration) string {
	s := int(d.Round(time.Second).Seconds())
	if s < 0 {
		s = 0
	}
	if s >= 3600 {
		return fmt.Sprintf("%d:%02d:%02d", s/3600, (s/60)%60, s%60)
	}
	return fmt.Sprintf("%d:%02d", s/60, s%60)
}
