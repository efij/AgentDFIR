package progress

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Model predicts how long a step takes on this machine from how long it
// took before.
//
// Each finished step is appended to <home>/perf.jsonl as (step, units,
// seconds). A step's prediction is the exponentially weighted average of
// its seconds-per-unit over recent runs, times this run's units — or, for a
// step that reports no units, of its seconds. With no history it falls
// back to the rate the caller supplies, so the first run is an estimate
// (shown with a "~") and every later run is calibrated on this machine.
type Model struct {
	path string
	all  []sample // file order, oldest first
	hist map[string][]sample
	new  []sample
}

type sample struct {
	Step    string  `json:"step"`
	Key     string  `json:"key,omitempty"`
	Units   float64 `json:"units"`
	Seconds float64 `json:"seconds"`
	TimeUTC string  `json:"ts_utc"`
}

// maxHistory bounds perf.jsonl; older samples say little about today.
const maxHistory = 400

// LoadModel reads the timing history at path. A missing or unreadable
// file is an empty history, never an error: timing is advisory.
func LoadModel(path string) *Model {
	m := &Model{path: path, hist: map[string][]sample{}}
	if path == "" {
		return m
	}
	f, err := os.Open(path)
	if err != nil {
		return m
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var s sample
		if json.Unmarshal(sc.Bytes(), &s) == nil && s.Step != "" && s.Seconds >= 0 {
			m.all = append(m.all, s)
			m.hist[s.Step] = append(m.hist[s.Step], s)
		}
	}
	return m
}

// Known reports whether the model has history for a step.
func (m *Model) Known(step string) bool { return len(m.hist[step]) > 0 }

// Predict estimates a step's duration. defaultRate is seconds per unit
// (or plain seconds when units is 0) to use without history.
func (m *Model) Predict(step, key string, units, defaultRate float64) time.Duration {
	hs := m.hist[step]
	// Prefer this key's history (the same case), else the step's.
	var use []sample
	for _, s := range hs {
		if key != "" && s.Key == key {
			use = append(use, s)
		}
	}
	if len(use) == 0 {
		use = hs
	}
	rate := defaultRate
	if len(use) > 0 {
		const alpha = 0.5
		r := -1.0
		for _, s := range use[max(0, len(use)-8):] {
			var x float64
			if units > 0 && s.Units > 0 {
				x = s.Seconds / s.Units
			} else if units > 0 {
				continue
			} else {
				x = s.Seconds
			}
			if r < 0 {
				r = x
			} else {
				r = alpha*x + (1-alpha)*r
			}
		}
		if r >= 0 {
			rate = r
		}
	}
	if units > 0 {
		return time.Duration(rate * units * float64(time.Second))
	}
	return time.Duration(rate * float64(time.Second))
}

// Record notes a finished step for the next prediction.
func (m *Model) Record(step, key string, units float64, took time.Duration) {
	m.new = append(m.new, sample{Step: step, Key: key, Units: units, Seconds: took.Seconds(),
		TimeUTC: time.Now().UTC().Format(time.RFC3339)})
}

// Save appends this run's samples, trimming the file to its newest
// maxHistory lines.
func (m *Model) Save() error {
	if m.path == "" || len(m.new) == 0 {
		return nil
	}
	all := append(append([]sample(nil), m.all...), m.new...)
	if len(all) > maxHistory {
		all = all[len(all)-maxHistory:]
	}
	tmp, err := os.CreateTemp(filepath.Dir(m.path), ".perf-*.tmp")
	if err != nil {
		return err
	}
	w := bufio.NewWriter(tmp)
	enc := json.NewEncoder(w)
	for _, s := range all {
		if err := enc.Encode(s); err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			return err
		}
	}
	if err := w.Flush(); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), m.path)
}
