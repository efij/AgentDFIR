package correlate

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v5/internal/endpoint"
	"github.com/efij/AgentDFIR/v5/internal/schema"
)

// macOS host rules over endpoint records (eslogger) and collected host
// state (TCC.db rows). Each one asks a single question about the agent's
// process tree, so it fires on telemetry, not on what the transcript
// claims:
//
//   - MACOS_LAUNCHD_PERSISTENCE_BY_AGENT: a LaunchAgent/LaunchDaemon plist
//     written, or a Background Task Management launch item added, by a
//     process descended from the agent.
//   - MACOS_TCC_MODIFIED_BY_AGENT: a TCC grant (eslogger tcc_modify) or a
//     write to TCC.db by an agent-descended process (HIGH); a TCC change
//     with no process attribution that falls inside an agent session
//     window (MEDIUM: time overlap only).
//   - MACOS_KEYCHAIN_ACCESS_BY_AGENT: `security find-generic-password -w`
//     style secret reads, keychain dumps/exports, or a direct open of a
//     keychain database by an agent-descended process.
//
// The transcript-side counterpart of the keychain rule is the rule pack's
// command rule on `security find-*-password`; this one sees the same act
// when the transcript does not log it.

const macRuleRefs = 5

var (
	launchdPlistRe = regexp.MustCompile(`(?i)/Library/Launch(Agents|Daemons)/[^/]+\.plist$`)
	tccDBRe        = regexp.MustCompile(`(?i)/com\.apple\.TCC/TCC\.db(-wal|-journal|-shm)?$`)
	keychainDBRe   = regexp.MustCompile(`(?i)/Library/Keychains/(.+\.keychain(-db)?|[^/]+/keychain-2\.db(-wal)?)$`)
	keychainCmdRe  = regexp.MustCompile(`(?i)(?:^|[\s/])security\s+(?:find-(?:generic|internet)-password\b[^|;&]*\s-[A-Za-z]*[wg][A-Za-z]*\b|dump-keychain\b|export\b)`)
)

// keychainDaemons open keychain databases as their job.
var keychainDaemons = map[string]bool{"securityd": true, "secd": true, "trustd": true, "security": true, "keychainsharingmessagingd": true, "backupd": true, "mds": true, "mds_stores": true}

// macGroup collects the records behind one finding.
type macGroup struct {
	key   string
	first endpoint.Record
	refs  []string
	n     int
}

type macGroups struct {
	order []string
	by    map[string]*macGroup
}

func (g *macGroups) add(key string, r endpoint.Record) {
	if g.by == nil {
		g.by = map[string]*macGroup{}
	}
	m := g.by[key]
	if m == nil {
		m = &macGroup{key: key, first: r}
		g.by[key] = m
		g.order = append(g.order, key)
	}
	m.n++
	if len(m.refs) < macRuleRefs {
		m.refs = append(m.refs, r.Ref)
	}
}

func modifying(op string) bool {
	switch op {
	case "create", "modify", "rename":
		return true
	}
	return false
}

// macOSRules runs the agent-lineage rules over host records.
func macOSRules(events []schema.Event, records []endpoint.Record, lineage []bool) []schema.Finding {
	var launchd, tcc, keychain macGroups
	var tccTime []endpoint.Record
	for j, r := range records {
		agent := j < len(lineage) && lineage[j]
		switch {
		case r.Kind == "file" && modifying(r.FileOp) && launchdPlistRe.MatchString(r.FilePath),
			r.Kind == endpoint.KindPersistence && r.Operation == "btm_launch_item_add" && launchdPlistRe.MatchString(r.FilePath):
			if agent {
				launchd.add(r.FilePath, r)
			}
		case r.Kind == endpoint.KindPersistence && r.Operation == "btm_launch_item_add":
			if agent { // a login item or app-bundled item, not a plist path
				launchd.add(r.FilePath+" "+r.Resource, r)
			}
		case r.Kind == endpoint.KindTCC && r.Source == "eslogger",
			r.Kind == "file" && modifying(r.FileOp) && tccDBRe.MatchString(r.FilePath):
			if agent {
				tcc.add(firstNonEmptyStr(r.Resource, r.FilePath), r)
			} else if r.Kind == endpoint.KindTCC {
				tccTime = append(tccTime, r)
			}
		case r.Kind == "process" && keychainCmdRe.MatchString(r.Cmdline):
			if agent {
				keychain.add(trim(r.Cmdline, 160), r)
			}
		case r.Kind == "file" && r.FileOp == "open" && keychainDBRe.MatchString(r.FilePath) && !keychainDaemons[strings.ToLower(baseName(r.Exe))]:
			if agent {
				keychain.add(r.FilePath, r)
			}
		}
	}
	var out []schema.Finding
	for _, k := range launchd.order {
		g := launchd.by[k]
		r := g.first
		what := "wrote " + r.FilePath
		if r.Kind == endpoint.KindPersistence {
			what = "registered a Background Task Management launch item " + strings.TrimSpace(r.FilePath+" "+r.Resource)
		}
		out = append(out, schema.Finding{
			RuleID: "MACOS_LAUNCHD_PERSISTENCE_BY_AGENT", Severity: "HIGH", Title: "Agent Process Installed a macOS Launch Agent or Daemon",
			Description: fmt.Sprintf("Endpoint telemetry shows %s (pid %d, under the agent's process tree) %s at %s (%d record(s)). A launchd plist or launch item runs its program at every login or boot, outliving the agent session.",
				procLabel(r), r.PID, what, r.Time.Format(time.RFC3339), g.n),
			EvidenceRefs: g.refs, Timestamp: r.Time.UTC().Format(time.RFC3339Nano),
			Status: schema.StateObserved, Endpoint: schema.StateObserved, MitreATTACK: "T1543.001",
			FalsePositive: "Asked-for setup work (installing a dev service with brew services, a project's own launchd job); check the plist's Program and who asked for it.",
		})
	}
	for _, k := range tcc.order {
		g := tcc.by[k]
		r := g.first
		what := "changed a TCC privacy permission (" + firstNonEmptyStr(r.Resource, "service not recorded") + ")"
		if r.Kind == "file" {
			what = "wrote the TCC database " + r.FilePath
		} else if r.Message != "" {
			what += ": " + r.Message
		}
		out = append(out, schema.Finding{
			RuleID: "MACOS_TCC_MODIFIED_BY_AGENT", Severity: "HIGH", Title: "Agent Process Changed macOS Privacy Permissions (TCC)",
			Description: fmt.Sprintf("Endpoint telemetry shows %s (pid %d, under the agent's process tree) %s at %s (%d record(s)). TCC rights gate disk, screen, camera and automation access; granting one widens what every later process of that client may do.",
				procLabel(r), r.PID, what, r.Time.Format(time.RFC3339), g.n),
			EvidenceRefs: g.refs, Timestamp: r.Time.UTC().Format(time.RFC3339Nano),
			Status: schema.StateObserved, Endpoint: schema.StateObserved, MitreATTACK: "T1548.006",
			FalsePositive: "An installer or the user approving a prompt the agent's tool triggered; tccd attributes the change to the requesting process.",
		})
	}
	out = append(out, tccDuringSession(events, tccTime, "eslogger tcc_modify")...)
	for _, k := range keychain.order {
		g := keychain.by[k]
		r := g.first
		what := "ran " + trim(r.Cmdline, 160)
		if r.Kind == "file" {
			what = "opened the keychain database " + r.FilePath
		}
		out = append(out, schema.Finding{
			RuleID: "MACOS_KEYCHAIN_ACCESS_BY_AGENT", Severity: "HIGH", Title: "Agent Process Read from the macOS Keychain",
			Description: fmt.Sprintf("Endpoint telemetry shows %s (pid %d, under the agent's process tree) %s at %s (%d record(s)). This prints or copies stored credentials rather than using them through an application.",
				procLabel(r), r.PID, what, r.Time.Format(time.RFC3339), g.n),
			EvidenceRefs: g.refs, Timestamp: r.Time.UTC().Format(time.RFC3339Nano),
			Status: schema.StateObserved, Endpoint: schema.StateObserved, MitreATTACK: "T1555.001",
			FalsePositive: "A tool the user asked to fetch a token for (gh auth, a deploy script); the keychain prompt the user approved is not in the telemetry.",
		})
	}
	return out
}

// HostState runs the time-overlap TCC check over collected TCC.db rows
// (records with Source "tcc-db", Time = the row's last_modified). TCC.db
// does not record which process made a change, so the most a row can say
// is that the change falls inside an agent session window: MEDIUM.
func HostState(events []schema.Event, records []endpoint.Record) []schema.Finding {
	var rows []endpoint.Record
	for _, r := range records {
		if r.Source == "tcc-db" && !r.Time.IsZero() {
			rows = append(rows, r)
		}
	}
	return tccDuringSession(events, rows, "TCC.db row")
}

// sessionWindow is one agent session's time range.
type sessionWindow struct {
	id         string
	start, end time.Time
}

// agentSessions derives session windows from transcript events.
func agentSessions(events []schema.Event) []sessionWindow {
	by := map[string]*sessionWindow{}
	for i := range events {
		ev := &events[i]
		switch ev.EventType {
		case schema.EventToolCall, schema.EventToolResult, schema.EventModelResponse, schema.EventHumanPrompt:
		default:
			continue
		}
		t, ok := parseEventTime(ev.Timestamp)
		if !ok || ev.SessionID == "" {
			continue
		}
		w := by[ev.SessionID]
		if w == nil {
			by[ev.SessionID] = &sessionWindow{id: ev.SessionID, start: t, end: t}
			continue
		}
		if t.Before(w.start) {
			w.start = t
		}
		if t.After(w.end) {
			w.end = t
		}
	}
	out := make([]sessionWindow, 0, len(by))
	for _, w := range by {
		out = append(out, *w)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].start.Before(out[j].start) })
	return out
}

// macSessionPad widens a session window: a tool call is logged when it
// starts, the change it makes lands a moment later.
const macSessionPad = 30 * time.Second

func tccDuringSession(events []schema.Event, recs []endpoint.Record, what string) []schema.Finding {
	if len(recs) == 0 {
		return nil
	}
	sessions := agentSessions(events)
	var out []schema.Finding
	for _, r := range recs {
		for _, s := range sessions {
			if r.Time.Before(s.start.Add(-macSessionPad)) || r.Time.After(s.end.Add(macSessionPad)) {
				continue
			}
			client := r.Exe
			if r.Source == "eslogger" {
				client = procLabel(r)
			}
			out = append(out, schema.Finding{
				RuleID: "MACOS_TCC_MODIFIED_BY_AGENT", Severity: "MEDIUM", Title: "macOS Privacy Permission (TCC) Changed During an Agent Session",
				Description: fmt.Sprintf("A %s shows TCC service %s changed for %s at %s, inside agent session %s (%s to %s). Nothing in this record ties the change to the agent's processes: this is time overlap, not attribution. %s",
					what, firstNonEmptyStr(r.Resource, "(not recorded)"), firstNonEmptyStr(client, "(client not recorded)"), r.Time.Format(time.RFC3339), s.id,
					s.start.Format(time.RFC3339), s.end.Format(time.RFC3339), r.Message),
				SessionID: s.id, EvidenceRefs: []string{r.Ref}, Timestamp: r.Time.UTC().Format(time.RFC3339Nano),
				Status: schema.StateObserved, Endpoint: schema.StateObserved, MitreATTACK: "T1548.006",
				FalsePositive: "The user granting a permission in System Settings while an agent happened to be running.",
			})
			break
		}
	}
	return out
}

func procLabel(r endpoint.Record) string {
	if n := baseName(r.Exe); n != "" {
		return n
	}
	if t := firstToken(r.Cmdline); t != "" {
		return t
	}
	return "a process"
}

func firstNonEmptyStr(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}
