package endpoint

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/efij/AgentDFIR/v4/internal/endpoint/evtx"
)

// Native Windows .evtx files, read with the pure-Go parser in
// internal/endpoint/evtx. Events used:
//
//	Microsoft-Windows-Sysmon          1, 2, 3, 11, 23, 26 (same mapping as the XML export), 22 DNS query
//	Microsoft-Windows-Security-Auditing 4688 process creation; kind "process-image" without a command line
//	Microsoft-Windows-PowerShell      4104 script block      → kind "script"
//	Service Control Manager           7045 service installed → kind "service"
//	Microsoft-Windows-Eventlog        1102 / 104 log cleared → kind "log-clear"
//
// "process-image", "script", "service" and "log-clear" records are not
// process telemetry: the correlation engine never lets them contradict a
// command or widen coverage, and the last two are surfaced to the
// operator as notices.
// Everything else (logons, registry, process exit, other providers) is
// counted and left out.

// KindProcessImage is a process creation known only by its image path
// (Security 4688 without command-line auditing).
const KindProcessImage = "process-image"

func loadEVTX(path string) (*LoadResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	res := &LoadResult{}
	unmapped := map[string]int{}
	st, err := evtx.Parse(f, fi.Size(), func(ev *evtx.Event) {
		if !res.addEVTX(ev) {
			unmapped[ev.System.Provider+" "+ev.System.EventID]++
		}
	})
	if err != nil {
		return nil, err
	}
	res.Skipped += st.BadRecords + st.BadChunks
	// Summary notes first: the per-problem list is capped.
	if st.Dirty {
		res.note("evtx: header dirty flag set (file was not closed cleanly); records read as found")
	}
	if st.SlackRecords > 0 {
		res.note(fmt.Sprintf("evtx: %d record(s) in chunk slack space not parsed", st.SlackRecords))
	}
	if n := len(unmapped); n > 0 {
		total, top, topN := 0, "", 0
		for k, v := range unmapped {
			total += v
			if v > topN || (v == topN && k < top) {
				top, topN = k, v
			}
		}
		res.note(fmt.Sprintf("evtx: %d event(s) of %d unused provider/event id(s) not mapped (most common: %s ×%d)", total, n, strings.TrimSpace(top), topN))
	}
	for _, p := range st.Problems {
		res.note("evtx: " + p)
	}
	if extra := st.ProblemCount - len(st.Problems); extra > 0 {
		res.note(fmt.Sprintf("evtx: %d more problem(s) not shown", extra))
	}
	return res, nil
}

// addEVTX maps one parsed event; it reports false for events it does
// not use.
func (res *LoadResult) addEVTX(ev *evtx.Event) bool {
	s, d := ev.System, ev.Data
	recID := s.EventRecordID
	if recID == "" {
		recID = strconv.FormatUint(ev.RecordID, 10)
	}
	ref := func(prefix string, extra ...string) string {
		r := fmt.Sprintf("%s:%s (record %s", prefix, s.EventID, recID)
		for _, e := range extra {
			if e != "" {
				r += ", " + e
			}
		}
		if ev.Unverified {
			r += ", chunk checksum mismatch"
		}
		return r + ")"
	}
	ts, tsOK := parseTime(s.TimeCreated)
	if !tsOK && !ev.Written.IsZero() {
		ts, tsOK = ev.Written.UTC(), true
	}
	execPID, _ := strconv.Atoi(s.ProcessID)

	switch prov := strings.ToLower(s.Provider); {
	case prov == "microsoft-windows-sysmon":
		switch s.EventID {
		case "1", "2", "3", "11", "22", "23", "26":
			// 22 (DNS query) included: the XML export and .evtx map it alike.
			n := len(res.Records)
			res.addSysmon(s.EventID, recID, s.TimeCreated, d)
			if ev.Unverified && len(res.Records) > n {
				extra := ""
				if s.EventID == "22" {
					extra = "dns"
				}
				res.Records[n].Ref = ref("sysmon", extra)
			}
			return true
		}
	case prov == "microsoft-windows-security-auditing" && s.EventID == "4688":
		if !tsOK {
			res.problem(ref("security") + ": no timestamp")
			return true
		}
		r := Record{Time: ts, Kind: "process", Exe: d["NewProcessName"], Cmdline: d["CommandLine"], ParentExe: d["ParentProcessName"],
			Source: "security", Ref: ref("security")}
		r.PID = winPID(d["NewProcessId"])
		r.PPID = winPID(d["ProcessId"])
		r.User = winUser(d["TargetDomainName"], d["TargetUserName"])
		if r.User == "" {
			r.User = winUser(d["SubjectDomainName"], d["SubjectUserName"])
		}
		if strings.TrimSpace(r.Cmdline) == "" {
			// Command-line auditing off: the image is all there is. Such a
			// record can only partly corroborate (by program name); it must
			// not contradict a command or widen process coverage.
			r.Kind, r.Cmdline = KindProcessImage, ""
		}
		res.Records = append(res.Records, r)
		return true
	case prov == "microsoft-windows-powershell" && s.EventID == "4104":
		if !tsOK || d["ScriptBlockText"] == "" {
			res.problem(ref("powershell") + ": script block without time or text")
			return true
		}
		part := ""
		if d["MessageTotal"] != "" && d["MessageTotal"] != "1" {
			part = "part " + d["MessageNumber"] + "/" + d["MessageTotal"]
		}
		res.Records = append(res.Records, Record{Time: ts, Kind: "script", PID: execPID, Exe: "powershell.exe", Cmdline: d["ScriptBlockText"],
			Source: "powershell", Ref: ref("powershell", part, d["Path"])})
		return true
	case prov == "service control manager" && s.EventID == "7045":
		if !tsOK {
			res.problem(ref("system") + ": no timestamp")
			return true
		}
		r := Record{Time: ts, Kind: "service", Exe: d["ImagePath"], Cmdline: d["ImagePath"], User: d["AccountName"],
			Source: "system", Ref: ref("system", "service "+d["ServiceName"])}
		res.Records = append(res.Records, r)
		res.notice(fmt.Sprintf("%s service %q installed: %s (account %s) [%s]", ts.Format("2006-01-02T15:04:05Z"), d["ServiceName"], d["ImagePath"], d["AccountName"], r.Ref))
		return true
	case prov == "microsoft-windows-eventlog" && (s.EventID == "1102" || s.EventID == "104"):
		if !tsOK {
			res.problem(ref("eventlog") + ": no timestamp")
			return true
		}
		channel := firstOf(d["Channel"], s.Channel)
		r := Record{Time: ts, Kind: "log-clear", User: winUser(d["SubjectDomainName"], d["SubjectUserName"]),
			Source: "eventlog", Ref: ref("eventlog", "channel "+channel)}
		res.Records = append(res.Records, r)
		res.notice(fmt.Sprintf("%s event log %q cleared by %s [%s]", ts.Format("2006-01-02T15:04:05Z"), channel, firstOf(r.User, "unknown user"), r.Ref))
		return true
	}
	return false
}

// winPID parses Security-log process ids, rendered as hex ("0x1a2b").
func winPID(s string) int {
	s = strings.TrimSpace(s)
	if h, ok := strings.CutPrefix(strings.ToLower(s), "0x"); ok {
		v, _ := strconv.ParseInt(h, 16, 64)
		return int(v)
	}
	v, _ := strconv.Atoi(s)
	return v
}

func winUser(domain, user string) string {
	if user == "" || user == "-" {
		return ""
	}
	if domain == "" || domain == "-" {
		return user
	}
	return domain + `\` + user
}
