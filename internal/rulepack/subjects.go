package rulepack

import (
	"strings"

	"github.com/efij/AgentDFIR/v3/internal/schema"
	"github.com/efij/AgentDFIR/v3/internal/shellshape"
)

// subjects prepares each event's match subject once for every rule that
// reads it, instead of once per rule. Deriving a command's subject strips
// heredocs or quoting and expands variables, and the rules also want it
// lowercased (contains) and case-folded (the regex prefilter). Doing that
// for each of 81 rules over 359,000 events was most of the rule packs'
// minute on a real case; the results are identical because the subject is
// a function of the event and the rule's scope alone.
type subjects struct {
	events []schema.Event
	text_  [kinds][]string
	lower_ [kinds][]string
	fold_  [kinds][]string
}

// Subject kinds: what a rule's match type and scope make it read.
const (
	kindCommand      = iota // full command, heredoc bodies removed
	kindCommandShell        // full command as the shell runs it
	kindSummary
	kinds
)

func newSubjects(events []schema.Event) *subjects { return &subjects{events: events} }

func subjectKind(r *Rule) int {
	switch {
	case r.Match.Type == "summary":
		return kindSummary
	case r.Match.Scope == "shell":
		return kindCommandShell
	}
	return kindCommand
}

func (s *subjects) text(kind, i int) string {
	if s.text_[kind] == nil {
		out := make([]string, len(s.events))
		for j := range s.events {
			ev := &s.events[j]
			switch kind {
			case kindSummary:
				out[j] = ev.Summary
			case kindCommandShell:
				// The full command, not the 300-character display copy:
				// the flag or payload that matters is often past the cut.
				out[j] = shellshape.Strip(shellshape.ExpandVars(ev.FullCommand()))
			default:
				// Quoted arguments stay (SQL in `psql -c '…'` is the
				// command); heredoc bodies — files being written, edit
				// scripts full of string literals — go.
				out[j] = shellshape.StripAllHeredocs(ev.FullCommand())
			}
		}
		s.text_[kind] = out
	}
	return s.text_[kind][i]
}

func (s *subjects) lower(kind, i int) string {
	if s.lower_[kind] == nil {
		out := make([]string, len(s.events))
		for j := range s.events {
			out[j] = strings.ToLower(s.text(kind, j))
		}
		s.lower_[kind] = out
	}
	return s.lower_[kind][i]
}

func (s *subjects) folded(kind, i int) string {
	if s.fold_[kind] == nil {
		out := make([]string, len(s.events))
		for j := range s.events {
			out[j] = fold(s.text(kind, j))
		}
		s.fold_[kind] = out
	}
	return s.fold_[kind][i]
}
