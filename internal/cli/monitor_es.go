package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/endpoint"
	"github.com/efij/AgentDFIR/v4/internal/journal"
	"github.com/efij/AgentDFIR/v4/internal/recorder"
	"github.com/efij/AgentDFIR/v4/internal/sanitize"
)

// esHandle stops a running `monitor --es` capture. Safe to call before
// one is started, and more than once.
type esHandle struct {
	mu   sync.Mutex
	stop func()
	done chan struct{}
	// rec, when set (monitor --record), owns the capture: it reports the
	// eslogger source in status.json, keeps the open file out of
	// retention and flushes it with the other captures.
	rec *recorder.Recorder
}

func (h *esHandle) set(f func(), done chan struct{}) {
	h.mu.Lock()
	h.stop, h.done = f, done
	h.mu.Unlock()
}

// Done is closed when the capture ends on its own or is stopped; nil when
// none was started.
func (h *esHandle) Done() <-chan struct{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.done
}

// Stop cancels eslogger and waits for the capture to flush.
func (h *esHandle) Stop() {
	h.mu.Lock()
	f := h.stop
	h.stop = nil
	h.mu.Unlock()
	if f != nil {
		f()
	}
}

// esPrintKinds are echoed to the terminal; file and fork records are
// captured but not printed (they arrive by the thousand).
var esPrintKinds = map[string]bool{"process": true, endpoint.KindPersistence: true, endpoint.KindTCC: true, "auth": true, endpoint.KindAV: true}

// startES launches eslogger when the host allows it. The raw stream goes
// to ~/.agentdfir/monitor/eslogger-<UTC>.jsonl (importable later with
// --endpoint; rolled over by size/age); with a journal, every flushed
// range of that file is journaled like a transcript append. When eslogger
// cannot run, the reason is printed and the monitor continues without it.
func startES(l *endpoint.ESLauncher, events string, quiet bool, jn *journal.Journal, home string, h *esHandle) {
	if events != "" {
		l.Events = strings.Split(events, ",")
	}
	var src *recorder.Source
	if h.rec != nil {
		src = h.rec.AddSource("eslogger", "eslogger", "/usr/bin/eslogger")
		src.SetSeq(recorder.SeqESGlobal)
		src.SetFormat(string(endpoint.FormatESLogger))
	}
	ctx, cancel := context.WithCancel(context.Background())
	evs, err := l.Check(ctx)
	if err != nil {
		cancel()
		if src != nil {
			src.Problem("not started: " + err.Error())
		}
		fmt.Fprintf(os.Stderr, "monitor --es: not started: %v; continuing without Endpoint Security\n", err)
		return
	}
	dir := recorder.Dir(home)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		cancel()
		fmt.Fprintln(os.Stderr, "monitor --es: not started:", err)
		return
	}
	var capw *recorder.Capture
	if h.rec != nil {
		capw = h.rec.NewCapture(src, ".jsonl")
	} else {
		var j recorder.Journal
		if jn != nil {
			j = jn
		}
		capw = recorder.NewCapture(dir, "eslogger", ".jsonl", j, nil)
	}
	if src != nil {
		src.SetState("running")
	}
	fmt.Printf("monitor --es: eslogger %s → %s\n", strings.Join(evs, " "), filepath.Join(dir, "eslogger-<UTC>.jsonl"))
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(2 * time.Second)
		defer tick.Stop()
		finished := make(chan struct{})
		go func() {
			for {
				select {
				case <-tick.C:
					capw.Flush()
				case <-finished:
					return
				}
			}
		}()
		res, err := l.Run(ctx, evs, capw, func(r endpoint.Record) {
			if quiet || !esPrintKinds[r.Kind] {
				return
			}
			what := firstNonEmptyStr(r.Cmdline, r.FilePath, r.Resource, r.User)
			fmt.Printf("es %s %-11s %s %s\n", r.Time.Format("15:04:05"), r.Kind, sanitize.Terminal(baseNameOf(r.Exe)), sanitize.Terminal(trimTo(what, 160)))
		})
		close(finished)
		_ = capw.Close()
		if src != nil {
			src.SetState("stopped")
		}
		if err != nil {
			if src != nil {
				src.Problem("eslogger: " + err.Error())
			}
			fmt.Fprintln(os.Stderr, "monitor --es:", err)
		}
		if res != nil {
			fmt.Printf("monitor --es: %d record(s) captured to %s\n", len(res.Records), strings.Join(capw.Paths(), ", "))
			for _, n := range res.Notices {
				if src != nil {
					src.Note(n)
				}
				fmt.Println("  " + sanitize.Terminal(n))
			}
		}
	}()
	h.set(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	}, done)
}

type writerFunc func([]byte) (int, error)

func (w writerFunc) Write(p []byte) (int, error) { return w(p) }

func baseNameOf(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

func firstNonEmptyStr(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}
