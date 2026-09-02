// Package realtime turns the read-only transcript tail into a live
// sensor: new lines are normalized by the product's line parser, run
// through the streaming detection rules, and findings are pushed to alert
// sinks within one poll interval. Nothing is ever written to, signalled
// or blocked on the observed agents.
package realtime

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/efij/AgentDFIR/internal/detect"
	"github.com/efij/AgentDFIR/internal/parsers/claudejsonl"
	"github.com/efij/AgentDFIR/internal/parsers/codexjsonl"
	"github.com/efij/AgentDFIR/internal/parsers/genericchat"
	"github.com/efij/AgentDFIR/internal/products"
	"github.com/efij/AgentDFIR/internal/sanitize"
	"github.com/efij/AgentDFIR/internal/schema"
)

// Root binds a watched directory to the product whose transcripts it holds.
type Root struct {
	Path    string
	Product string // "" = infer per file
}

// Engine consumes tailed lines and emits findings.
type Engine struct {
	Host        string
	Opts        detect.Options
	MinSeverity string // INFO|LOW|MEDIUM|HIGH|CRITICAL (default LOW)
	Sinks       []Sink
	Out         io.Writer // console

	roots   []Root
	live    *detect.Live
	parsers map[string]lineParser // product -> parser
	mu      sync.Mutex
	stats   Stats
}

// Stats counts what the engine saw.
type Stats struct {
	Lines    int `json:"lines"`
	Events   int `json:"events"`
	Findings int `json:"findings"`
	Alerts   int `json:"alerts"`
	Dropped  int `json:"alerts_dropped"`
}

type lineParser interface {
	Line(path string, raw []byte, off int64, line int)
}

// New builds an engine over the given roots.
func New(host string, roots []Root, opts detect.Options) *Engine {
	e := &Engine{Host: host, Opts: opts, roots: roots, live: detect.NewLive(opts), parsers: map[string]lineParser{}, Out: os.Stdout}
	sort.Slice(e.roots, func(i, j int) bool { return len(e.roots[i].Path) > len(e.roots[j].Path) }) // longest prefix first
	return e
}

// Paths returns the watched directories.
func (e *Engine) Paths() []string {
	var out []string
	for _, r := range e.roots {
		out = append(out, r.Path)
	}
	return out
}

// OnLine is the watcher hook.
func (e *Engine) OnLine(path string, raw []byte, off int64, line int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stats.Lines++
	prod := e.productFor(path, raw)
	p := e.parsers[prod]
	if p == nil {
		p = e.newParser(prod)
		e.parsers[prod] = p
	}
	p.Line(path, raw, off, line)
}

func (e *Engine) newParser(product string) lineParser {
	sink := func(ev schema.Event) { e.onEvent(ev) }
	switch product {
	case "claude-code":
		return claudejsonl.NewLive(e.Host, sink)
	case "codex-cli":
		return codexjsonl.NewLive(e.Host, sink)
	default:
		return genericchat.NewLive(product, e.Host, sink)
	}
}

func (e *Engine) onEvent(ev schema.Event) {
	e.stats.Events++
	for _, f := range e.live.Eval(ev) {
		if sevRank(f.Severity) < sevRank(e.minSev()) {
			continue
		}
		e.stats.Findings++
		e.render(f)
		for _, s := range e.Sinks {
			if err := s.Send(f); err != nil {
				e.stats.Dropped++
				fmt.Fprintf(e.Out, "%s ALERT-ERROR %s: %v\n", time.Now().UTC().Format(time.RFC3339), s.Name(), err)
			} else {
				e.stats.Alerts++
			}
		}
	}
}

func (e *Engine) render(f schema.Finding) {
	fmt.Fprintf(e.Out, "%s FINDING %-8s %-32s %s\n", time.Now().UTC().Format(time.RFC3339), f.Severity, f.RuleID, sanitize.Terminal(f.Title))
	fmt.Fprintf(e.Out, "    %s\n", sanitize.Terminal(f.Description))
	for _, r := range f.EvidenceRefs {
		fmt.Fprintf(e.Out, "    evidence: %s\n", sanitize.Terminal(r))
	}
}

func (e *Engine) minSev() string {
	if e.MinSeverity == "" {
		return "LOW"
	}
	return strings.ToUpper(e.MinSeverity)
}

// Stats returns a snapshot.
func (e *Engine) Snapshot() Stats {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stats
}

// Close flushes sinks.
func (e *Engine) Close() {
	for _, s := range e.Sinks {
		s.Close()
	}
}

// productFor picks the parser: explicit root binding, then path hints,
// then the line's own shape.
func (e *Engine) productFor(path string, raw []byte) string {
	clean := filepath.Clean(path)
	for _, r := range e.roots {
		if r.Product != "" && strings.HasPrefix(clean, filepath.Clean(r.Path)+string(filepath.Separator)) {
			return r.Product
		}
	}
	p := strings.ReplaceAll(clean, "\\", "/")
	switch {
	case strings.Contains(p, "/.claude/"):
		return "claude-code"
	case strings.Contains(p, "/.codex/"):
		return "codex-cli"
	case strings.Contains(p, "/.openclaw/"):
		return "openclaw"
	case strings.Contains(p, "/.gemini/"):
		return "gemini-cli"
	}
	// Shape sniff.
	var probe struct {
		UUID    string          `json:"uuid"`
		Session string          `json:"sessionId"`
		Payload json.RawMessage `json:"payload"`
	}
	if json.Unmarshal(raw, &probe) == nil {
		if probe.UUID != "" && probe.Session != "" {
			return "claude-code"
		}
		if len(probe.Payload) > 0 {
			return "codex-cli"
		}
	}
	// Pack products: match a registered product's config dir in the path.
	if prods, err := products.All(); err == nil {
		for _, pr := range prods {
			for _, d := range pr.ConfigDirs {
				if strings.Contains(p, "/"+strings.Trim(d, "/")+"/") {
					return pr.ID
				}
			}
		}
	}
	return "unknown-jsonl"
}

func sevRank(s string) int {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "INFO":
		return 1
	}
	return 0
}
