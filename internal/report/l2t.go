package report

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/internal/sanitize"
	"github.com/efij/AgentDFIR/internal/schema"
)

// DFIR-tool interop: the unified timeline in the two formats the classic
// timeline stack consumes — Timesketch JSONL and log2timeline/Plaso l2tcsv
// (also accepted by Autopsy, Magnet and most timeline viewers). Evidence
// strings are sanitized (terminal/invisible-char payloads neutralized)
// before they leave the package.

// TimelineStats reports what an export wrote.
type TimelineStats struct {
	Written int
	Undated int // events without a parsable timestamp (omitted from Timesketch; written to l2tcsv with a blank date)
}

func parseEventTime(ts string) (time.Time, bool) {
	if ts == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000Z", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, ts); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// eventMessage is the one-line human description shared by both formats.
func eventMessage(e schema.Event) string {
	var parts []string
	parts = append(parts, e.EventType)
	if e.ActorType != "" {
		parts = append(parts, "actor="+e.ActorType)
	}
	if e.Tool != "" {
		parts = append(parts, "tool="+e.Tool)
	}
	if e.MCPServer != "" {
		parts = append(parts, "mcp="+e.MCPServer)
	}
	if e.Command != "" {
		parts = append(parts, "cmd="+e.Command)
	}
	if e.File != "" {
		parts = append(parts, "file="+e.File)
	}
	if e.NetworkDest != "" {
		parts = append(parts, "dst="+e.NetworkDest)
	}
	if e.Summary != "" {
		parts = append(parts, "summary="+e.Summary)
	}
	parts = append(parts, "corroboration="+e.Corroboration)
	return sanitize.Terminal(strings.Join(parts, " | "))
}

// WriteTimesketchJSONL writes one Timesketch-importable JSON object per
// line: required keys message/datetime/timestamp_desc plus flat AgentDFIR
// attributes that become searchable fields. Events without a parsable
// timestamp are omitted (Timesketch rejects them) and counted.
func WriteTimesketchJSONL(c *Case, path string) (TimelineStats, error) {
	var st TimelineStats
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return st, err
	}
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	for _, e := range c.Events {
		t, ok := parseEventTime(e.Timestamp)
		if !ok {
			st.Undated++
			continue
		}
		row := map[string]any{
			"message":             eventMessage(e),
			"datetime":            t.Format("2006-01-02T15:04:05.000000Z07:00"),
			"timestamp_desc":      "Agent Event Time",
			"data_type":           "agentdfir:event",
			"event_id":            e.EventID,
			"case_id":             e.CaseID,
			"event_type":          e.EventType,
			"actor_type":          e.ActorType,
			"vendor":              e.Vendor,
			"product":             e.Product,
			"session_id":          e.SessionID,
			"agent_id":            e.AgentID,
			"parent_agent_id":     e.ParentAgentID,
			"task_id":             e.TaskID,
			"tool":                e.Tool,
			"mcp_server":          e.MCPServer,
			"command":             sanitize.Terminal(e.Command),
			"file":                sanitize.Terminal(e.File),
			"network_destination": e.NetworkDest,
			"action":              e.Action,
			"result":              sanitize.Terminal(e.Result),
			"corroboration_state": e.Corroboration,
			"hostname":            e.Host,
			"username":            e.User,
			"source_artifact":     e.SourceArtifact,
			"source_path":         sanitize.Terminal(e.SourcePath),
			"source_line":         e.SourceLine,
			"source_offset":       e.SourceOffset,
			"tag":                 []string{"agentdfir", e.EventType},
		}
		if err := enc.Encode(row); err != nil {
			f.Close()
			return st, err
		}
		st.Written++
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return st, err
	}
	return st, f.Close()
}

// l2tHeader is the canonical 17-column log2timeline CSV header.
var l2tHeader = []string{"date", "time", "timezone", "MACB", "source", "sourcetype", "type", "user", "host", "short", "desc", "version", "filename", "inode", "notes", "format", "extra"}

// WriteL2TCSV writes the timeline in l2tcsv format (Plaso psort's
// classic output), consumable by Timesketch, Autopsy, Magnet and
// spreadsheet triage. Undated events are kept with blank date/time so
// nothing disappears; they are counted for the caller to report.
func WriteL2TCSV(c *Case, path string) (TimelineStats, error) {
	var st TimelineStats
	f, err := os.Create(path)
	if err != nil {
		return st, err
	}
	w := csv.NewWriter(f)
	if err := w.Write(l2tHeader); err != nil {
		f.Close()
		return st, err
	}
	for _, e := range c.Events {
		date, clock := "", ""
		if t, ok := parseEventTime(e.Timestamp); ok {
			date = t.Format("01/02/2006")
			clock = t.Format("15:04:05")
		} else {
			st.Undated++
		}
		short := sanitize.Terminal(e.Summary)
		if short == "" {
			short = e.EventType
			if e.Command != "" {
				short = sanitize.Terminal(e.Command)
			}
		}
		if r := []rune(short); len(r) > 120 {
			short = string(r[:120]) + "…"
		}
		extra := fmt.Sprintf("session_id: %s  agent_id: %s  parent_agent_id: %s  tool: %s  mcp_server: %s  network_destination: %s  source_artifact: %s  source_offset: %d",
			e.SessionID, e.AgentID, e.ParentAgentID, e.Tool, e.MCPServer, e.NetworkDest, e.SourceArtifact, e.SourceOffset)
		row := []string{
			date, clock, "UTC", "...B",
			"AGENTDFIR", "AI Agent " + e.EventType, "Agent Event Time",
			e.User, e.Host,
			short, eventMessage(e),
			"2", sanitize.Terminal(e.SourcePath), fmt.Sprint(e.SourceLine),
			"corroboration=" + e.Corroboration + " product=" + e.Product,
			"agentdfir:event", sanitize.Terminal(extra),
		}
		if err := w.Write(row); err != nil {
			f.Close()
			return st, err
		}
		st.Written++
	}
	w.Flush()
	if err := w.Error(); err != nil {
		f.Close()
		return st, err
	}
	return st, f.Close()
}
