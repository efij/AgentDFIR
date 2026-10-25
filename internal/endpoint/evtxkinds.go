package endpoint

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/efij/AgentDFIR/v4/internal/endpoint/evtx"
)

// Windows event log context records: events that say what happened on
// the host around an agent session but are not process, file or network
// telemetry. They come from native .evtx files, the Windows XML export
// and evtx_dump JSON through one mapping (addWinContext), so all three
// inputs give the same records. Events used:
//
//	Microsoft-Windows-Sysmon             5 process terminated          → process-exit
//	                                     12 / 13 / 14 registry          → registry
//	Microsoft-Windows-Security-Auditing  4689 process exited            → process-exit
//	                                     4625 / 4648 / 4672             → auth
//	                                     4697 service installed         → service + operator notice
//	Microsoft-Windows-PowerShell         4103 module logging            → script (Operation "module")
//	Microsoft-Windows-TaskScheduler      106 / 140 / 141 / 200 / 201    → scheduled-task (106, 140, 141 also an operator notice)
//	Microsoft-Windows-WMI-Activity       5857 / 5858 / 5859 / 5860 / 5861 → wmi (5861 also an operator notice)
//
// None of these records is an execution witness. The correlation engine
// keeps them out of the corroborate / contradict passes and out of the
// coverage window (IsContext); "process-exit" bounds a process lifetime
// at most. Built-in rules read them for persistence and credential use
// by processes descended from an agent (internal/correlate/windows.go).
// 4103 records are script records and go through the same strict
// script-block matching as 4104.
//
// Security 4624 (successful logon) is not mapped: it is the most
// frequent Security event and says nothing about what an agent did.

const (
	KindProcessExit   = "process-exit"
	KindRegistry      = "registry"
	KindAuth          = "auth"
	KindScheduledTask = "scheduled-task"
	KindWMI           = "wmi"

	// maxContextDetail bounds Details and other free text (registry
	// data, WMI queries and consumer definitions, PowerShell payloads).
	maxContextDetail = 4 << 10
)

// maxContextPerKind bounds the context records kept per kind and input
// file; later ones are counted as skipped with one note. A variable so
// tests can lower it.
var maxContextPerKind = 100_000

// IsContext reports whether a record is a Windows context record: it may
// feed rules and notices but never corroborates, contradicts or widens
// telemetry coverage. Authentication records from the Linux auth log
// and journal are sightings (IsSighting) and are not context records.
func IsContext(r Record) bool {
	switch r.Kind {
	case KindProcessExit, KindRegistry, KindScheduledTask, KindWMI:
		return true
	case KindAuth:
		return !IsSighting(r)
	}
	return false
}

// isContextEvent reports whether addWinContext maps provider/id.
func isContextEvent(provider, id string) bool {
	switch strings.ToLower(provider) {
	case "microsoft-windows-sysmon":
		return id == "5" || id == "12" || id == "13" || id == "14"
	case "microsoft-windows-security-auditing":
		return id == "4689" || id == "4625" || id == "4648" || id == "4672" || id == "4697"
	case "microsoft-windows-powershell":
		return id == "4103"
	case "microsoft-windows-taskscheduler":
		return id == "106" || id == "140" || id == "141" || id == "200" || id == "201"
	case "microsoft-windows-wmi-activity":
		return id == "5857" || id == "5858" || id == "5859" || id == "5860" || id == "5861"
	}
	return false
}

// addWinContext maps one context event; it reports false for events it
// does not handle. at is the provenance after the record id ("file
// Security.evtx, offset 73728", "export.jsonl:12").
func (res *LoadResult) addWinContext(ev *evtx.Event, at string) bool {
	s, d := ev.System, ev.Data
	if !isContextEvent(s.Provider, s.EventID) {
		return false
	}
	if d == nil {
		d = map[string]string{}
	}
	recID := s.EventRecordID
	if recID == "" && ev.RecordID != 0 {
		recID = strconv.FormatUint(ev.RecordID, 10)
	}
	ref := func(prefix string, extra ...string) string {
		r := fmt.Sprintf("%s:%s (record %s", prefix, s.EventID, firstOf(recID, "?"))
		for _, e := range append(extra, at) {
			if e != "" {
				r += ", " + e
			}
		}
		if ev.Unverified {
			r += ", chunk checksum mismatch"
		}
		return r + ")"
	}
	prov := strings.ToLower(s.Provider)
	prefix := map[string]string{
		"microsoft-windows-sysmon": "sysmon", "microsoft-windows-security-auditing": "security", "microsoft-windows-powershell": "powershell",
		"microsoft-windows-taskscheduler": "taskscheduler", "microsoft-windows-wmi-activity": "wmi",
	}[prov]
	tsText := s.TimeCreated
	if prov == "microsoft-windows-sysmon" {
		tsText = firstOf(d["UtcTime"], s.TimeCreated)
	}
	ts, ok := parseTime(tsText)
	if !ok && !ev.Written.IsZero() {
		ts, ok = ev.Written.UTC(), true
	}
	if !ok {
		res.problem(ref(prefix) + ": no timestamp")
		return true
	}
	execPID, _ := strconv.Atoi(s.ProcessID)
	r := Record{Time: ts, Source: prefix, Ref: ref(prefix)}

	switch prov {
	case "microsoft-windows-sysmon":
		r.PID, _ = strconv.Atoi(d["ProcessId"])
		r.Exe, r.User = d["Image"], d["User"]
		if s.EventID == "5" {
			r.Kind = KindProcessExit
			break
		}
		r.Kind = KindRegistry
		target := d["TargetObject"]
		if target == "" {
			res.problem(r.Ref + ": registry event without TargetObject")
			return true
		}
		r.Operation = regOperation(d["EventType"], s.EventID)
		r.Resource = target
		switch r.Operation {
		case "set-value", "delete-value", "create-value":
			// TargetObject names the value: key\value.
			if i := strings.LastIndexByte(target, '\\'); i > 0 {
				r.Resource, r.ValueName = target[:i], target[i+1:]
			}
		}
		switch s.EventID {
		case "13":
			r.Details = bound(d["Details"])
		case "14":
			r.Details = bound(d["NewName"])
		}
	case "microsoft-windows-security-auditing":
		r.PID = winPID(d["ProcessId"])
		r.Exe = d["ProcessName"]
		subject := winUser(d["SubjectDomainName"], d["SubjectUserName"])
		switch s.EventID {
		case "4689":
			r.Kind, r.User = KindProcessExit, subject
			if st := d["Status"]; st != "" && st != "0x0" && st != "0" {
				r.Details = "exit status " + st
			}
		case "4697":
			r.Kind, r.Exe, r.Cmdline, r.User = "service", d["ServiceFileName"], d["ServiceFileName"], firstOf(d["ServiceAccount"], subject)
			r.SubjectUser, r.PID = subject, 0
			r.Ref = ref(prefix, "service "+d["ServiceName"])
			res.notice(fmt.Sprintf("%s service %q installed: %s (account %s, by %s) [%s]", ts.Format("2006-01-02T15:04:05Z"), d["ServiceName"],
				bound(d["ServiceFileName"]), d["ServiceAccount"], firstOf(subject, "unknown user"), r.Ref))
		default:
			r.Kind = KindAuth
			r.SubjectUser = subject
			r.User = winUser(d["TargetDomainName"], d["TargetUserName"])
			r.LogonType = d["LogonType"]
			if ip := d["IpAddress"]; ip != "-" {
				r.SourceIP = ip
			}
			switch s.EventID {
			case "4625":
				r.Operation = "logon-failed"
				r.Failed = firstOf(strings.TrimSpace(d["FailureReason"]), d["SubStatus"], d["Status"], "logon failed")
			case "4648":
				r.Operation = "explicit-credentials"
				r.Resource = firstOf(d["TargetServerName"], d["TargetInfo"])
			case "4672":
				r.Operation = "special-privileges"
				r.User, r.SubjectUser = subject, ""
				r.Details = bound(strings.Join(strings.Fields(d["PrivilegeList"]), " "))
			}
		}
	case "microsoft-windows-powershell":
		// Module logging: the payload lists command invocations and their
		// parameter bindings. It is matched like a script block (strict
		// rules in internal/correlate/evtxwitness.go), never rebuilt into a
		// command line.
		payload := firstOf(d["Payload"], d["Data[2]"])
		if payload == "" {
			res.problem(r.Ref + ": module log without payload")
			return true
		}
		r.Kind, r.Operation, r.PID, r.Exe = "script", "module", execPID, "powershell.exe"
		r.Cmdline = bound(payload)
		if cmd := contextField(firstOf(d["ContextInfo"], d["Data[0]"]), "Command Name"); cmd != "" {
			r.Ref = ref(prefix, "module "+cmd)
		}
	case "microsoft-windows-taskscheduler":
		r.Kind = KindScheduledTask
		r.Resource = d["TaskName"]
		r.User = firstOf(d["UserContext"], d["UserName"])
		r.Operation = map[string]string{"106": "registered", "140": "updated", "141": "deleted", "200": "action-started", "201": "action-completed"}[s.EventID]
		r.Exe = d["ActionName"]
		r.PID = winPID(d["EnginePID"])
		if rc := d["ResultCode"]; rc != "" && rc != "0" && rc != "0x0" {
			r.Failed = "result " + rc
		}
		if r.Resource == "" {
			res.problem(r.Ref + ": task event without TaskName")
			return true
		}
		r.Ref = ref(prefix, "task "+r.Resource)
		if s.EventID == "106" || s.EventID == "140" || s.EventID == "141" {
			res.notice(fmt.Sprintf("%s scheduled task %q %s by %s [%s]", ts.Format("2006-01-02T15:04:05Z"), r.Resource, r.Operation, firstOf(r.User, "unknown user"), r.Ref))
		}
	case "microsoft-windows-wmi-activity":
		r.Kind = KindWMI
		r.User = d["User"]
		r.PID, _ = strconv.Atoi(firstOf(d["ClientProcessId"], d["processid"], d["ProcessID"]))
		switch s.EventID {
		case "5857":
			r.Operation, r.Resource, r.Exe = "provider-started", d["ProviderName"], d["ProviderPath"]
			r.Details = bound(d["HostProcess"])
		case "5858":
			r.Operation, r.Resource = "client-failure", d["Operation"]
			r.Failed = firstOf(d["ResultCode"], "error")
			r.Details = bound(d["ClientMachine"])
		case "5859":
			r.Operation, r.Resource, r.Details = "permanent-subscription", d["NamespaceName"], bound(d["Query"])
		case "5860":
			r.Operation, r.Resource, r.Details = "temporary-subscription", d["NamespaceName"], bound(d["Query"])
		case "5861":
			// A permanent event consumer bound to a filter: WMI persistence.
			r.Operation = "consumer-binding"
			r.Resource = strings.TrimSpace(d["CONSUMER"] + " ← " + d["ESS"])
			r.Details = bound(firstOf(d["PossibleCause"], d["CONSUMER"]))
			res.notice(fmt.Sprintf("%s WMI permanent event consumer bound: %s (namespace %s) [%s]", ts.Format("2006-01-02T15:04:05Z"),
				boundN(d["CONSUMER"], 200), firstOf(d["Namespace"], "?"), r.Ref))
		}
	}
	if !res.keepContext(r.Kind) {
		return true
	}
	res.Records = append(res.Records, r)
	return true
}

// keepContext enforces maxContextPerKind; a record past the bound is
// counted as skipped and noted once per kind.
func (res *LoadResult) keepContext(kind string) bool {
	if res.ctxKept == nil {
		res.ctxKept, res.ctxNoted = map[string]int{}, map[string]bool{}
	}
	if res.ctxKept[kind] < maxContextPerKind {
		res.ctxKept[kind]++
		return true
	}
	res.Skipped++
	if !res.ctxNoted[kind] {
		res.ctxNoted[kind] = true
		res.note(fmt.Sprintf("windows event log: more than %d %s record(s) in one file; later ones counted as skipped, not kept", maxContextPerKind, kind))
	}
	return false
}

// regOperation names a Sysmon registry operation.
func regOperation(eventType, id string) string {
	switch strings.ToLower(eventType) {
	case "createkey":
		return "create-key"
	case "deletekey":
		return "delete-key"
	case "setvalue":
		return "set-value"
	case "deletevalue":
		return "delete-value"
	case "createvalue":
		return "create-value"
	case "renamekey":
		return "rename-key"
	}
	return map[string]string{"12": "create-or-delete", "13": "set-value", "14": "rename-key"}[id]
}

// contextField reads "Name = value" from a PowerShell 4103 ContextInfo block.
func contextField(info, name string) string {
	for _, line := range strings.Split(boundN(info, maxContextDetail), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), name) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func bound(s string) string { return boundN(s, maxContextDetail) }

// boundN cuts s to at most n bytes on a rune boundary and says so.
func boundN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut] + fmt.Sprintf("…[%d bytes cut]", len(s)-cut)
}
