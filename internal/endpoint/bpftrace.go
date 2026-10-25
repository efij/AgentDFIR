package endpoint

import (
	"encoding/json"
	"fmt"
	"strings"
)

// bpftrace JSON output (`bpftrace -f json script.bt`). Every line is an
// envelope {"type":"…","data":…}. Only printf output can describe single
// events, and only when the script prints one JSON object per event that
// follows this field contract (documented in docs/linux-telemetry.md):
//
//	required  time  wall-clock time: an RFC 3339 string, or a number of
//	                epoch nanoseconds (strftime("%Y-%m-%dT%H:%M:%SZ", nsecs)
//	                works; raw nsecs is boot-relative and is refused)
//	required  pid   process id (> 0)
//	required  one of comm | exe | args
//	optional  ppid, uid, exe (or filename), args (string or array), cwd,
//	          cgroup (a /proc/<pid>/cgroup path; gives the container id)
//	optional  event: "exec" (default) → process; "connect" with daddr and
//	          dport → network; "open" with path → file
//
// Everything else is UNSUPPORTED with its reason and counted: printf text
// that is not such an object, maps / histograms / stats (aggregates, not
// events) and unknown envelope types. lost_events lines are reported:
// the kernel ring buffer dropped events, so the trace is incomplete.
// bpftrace records are sightings: a user script can filter, and it says
// little about what it missed.

func loadBpftrace(path string) (*LoadResult, error) {
	res := &LoadResult{}
	unsup := unsupportedCounter{}
	lost := 0
	err := forEachJSONDoc(path, res, nil, func(doc map[string]any, ref string) {
		typ := leaf(doc, "type")
		switch typ {
		case "":
			res.problem(ref + ": not a bpftrace JSON envelope (no type)")
		case "attached_probes":
			res.ignore()
		case "lost_events":
			res.ignore()
			lost += num(dig(doc, "data.events"))
		case "printf":
			var objs []map[string]any
			switch d := doc["data"].(type) {
			case map[string]any:
				objs = append(objs, d)
			case string:
				for i, line := range strings.Split(strings.TrimSpace(d), "\n") {
					if i >= 64 {
						break
					}
					var o map[string]any
					if json.Unmarshal([]byte(strings.TrimSpace(line)), &o) != nil {
						unsup.add(res, "printf text")
						continue
					}
					objs = append(objs, o)
				}
			default:
				unsup.add(res, "printf text")
			}
			for _, o := range objs {
				r, why := bpftraceRecord(o)
				if why != "" {
					unsup.add(res, "printf object ("+why+")")
					continue
				}
				r.Ref = ref
				res.Records = append(res.Records, r)
			}
		case "map", "hist", "lhist", "stats", "value", "time", "join", "syscall", "cat", "helper_error":
			unsup.add(res, typ)
		default:
			unsup.add(res, "type "+typ)
		}
	})
	if lost > 0 {
		res.note(fmt.Sprintf("bpftrace reported %d lost event(s): the trace is incomplete", lost))
	}
	unsup.flush(res, "outside the bpftrace event field contract (time, pid, comm|exe|args; see docs/linux-telemetry.md)")
	return res, err
}

// bpftraceRecord applies the field contract; why says what failed.
func bpftraceRecord(o map[string]any) (Record, string) {
	// A number must be epoch nanoseconds (>= 1.5e18, 2017): smaller
	// values cannot be told apart from boot-relative nsecs.
	if f, isNum := o["time"].(float64); isNum && f < 1.5e18 {
		return Record{}, "numeric time is not epoch nanoseconds"
	}
	t, ok := parseTime(leaf(o, "time"))
	if !ok {
		return Record{}, "no wall-clock time"
	}
	pid := num(o["pid"])
	if pid <= 0 {
		return Record{}, "no pid"
	}
	args := leaf(o, "args")
	if a, ok := o["args"].([]any); ok {
		args = strList(a)
	}
	comm := leaf(o, "comm")
	exe := firstNonEmpty(leaf(o, "exe"), leaf(o, "filename"))
	if comm == "" && exe == "" && args == "" {
		return Record{}, "no comm, exe or args"
	}
	r := Record{Time: t, Source: "bpftrace", PID: pid, PPID: num(o["ppid"]), Exe: firstNonEmpty(exe, comm),
		Cmdline: firstNonEmpty(args, exe, comm), User: leaf(o, "uid"), Cwd: leaf(o, "cwd"),
		ContainerID: ContainerIDFromCgroup(leaf(o, "cgroup"))}
	switch ev := leaf(o, "event"); ev {
	case "", "exec":
		r.Kind = "process"
	case "connect":
		if leaf(o, "daddr") == "" {
			return Record{}, "connect without daddr"
		}
		r.Kind, r.DestIP, r.DestPort = "network", leaf(o, "daddr"), num(o["dport"])
	case "open":
		if leaf(o, "path") == "" {
			return Record{}, "open without path"
		}
		r.Kind, r.FilePath, r.FileOp = "file", leaf(o, "path"), "open"
	default:
		return Record{}, "event " + ev
	}
	return r, ""
}
