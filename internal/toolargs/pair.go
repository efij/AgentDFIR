package toolargs

import "github.com/efij/AgentDFIR/v5/internal/schema"

// Pairer links tool calls to their results by tool_call_id inside one
// source artifact and sets ResultRef on both: the result points at the
// call's event_id, the call at the result's.
//
// Events stream to the overlay in sequence order, and a call is emitted
// before its result exists. The Pairer therefore holds back events from the
// first call still waiting for a result, in order, and releases them once
// every held call has been answered or MaxHeld events are waiting. A call
// released unanswered keeps an empty ResultRef; its result, when it comes,
// still points back at it. The outcome depends only on the artifact's own
// content, so a cached and a fresh parse produce the same events.
//
// Pairing never crosses an artifact (End resets it): the incremental
// overlay renumbers each artifact's events independently, and a reference
// into another artifact would go stale.
//
// When a result is recorded as denied and its call is still held, the
// call's ApprovalState becomes "denied": the denial is the explicit record
// for that call, and it outranks an auto-approval read from the mode.
type Pairer struct {
	sink  func(schema.Event)
	held  []schema.Event
	open  map[string]int    // pairing key → index in held, calls still waiting
	calls map[string]string // pairing key → call event_id, for back-references
}

// MaxHeld bounds how many events a Pairer holds back; MaxCalls bounds how
// many call ids it remembers for back-references in one artifact.
const (
	MaxHeld  = 512
	MaxCalls = 1 << 16
)

// NewPairer returns a Pairer releasing events to sink.
func NewPairer(sink func(schema.Event)) *Pairer {
	return &Pairer{sink: sink, open: map[string]int{}, calls: map[string]string{}}
}

func pairKey(ev *schema.Event) string {
	if ev.ToolCallID == "" {
		return ""
	}
	return ev.SessionID + "\x00" + ev.ToolCallID
}

// Push takes one event (EventID already assigned).
func (p *Pairer) Push(ev schema.Event) {
	key := pairKey(&ev)
	switch {
	case key != "" && ev.EventType == schema.EventToolCall:
		if _, dup := p.calls[key]; !dup && len(p.calls) < MaxCalls {
			p.calls[key] = ev.EventID
			p.open[key] = len(p.held)
		}
	case key != "" && ev.EventType == schema.EventToolResult:
		if id, ok := p.calls[key]; ok {
			delete(p.calls, key) // first result only: a second one is not paired
			if ev.ResultRef == "" {
				ev.ResultRef = id
			}
			if i, held := p.open[key]; held {
				delete(p.open, key)
				c := &p.held[i]
				if c.ResultRef == "" {
					c.ResultRef = ev.EventID
				}
				if ev.ResultStatus == "denied" {
					c.ApprovalState = "denied"
				}
			}
		}
	}
	if len(p.open) == 0 && len(p.held) == 0 {
		p.sink(ev)
		return
	}
	p.held = append(p.held, ev)
	if len(p.open) == 0 || len(p.held) >= MaxHeld {
		p.Flush()
	}
}

// Flush releases every held event; calls still waiting stay unanswered.
func (p *Pairer) Flush() {
	for _, ev := range p.held {
		p.sink(ev)
	}
	p.held = p.held[:0]
	for k := range p.open {
		delete(p.open, k)
	}
}

// End flushes and forgets every call id: the artifact is done.
func (p *Pairer) End() {
	p.Flush()
	p.calls = map[string]string{}
}
