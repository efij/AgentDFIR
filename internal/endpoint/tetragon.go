package endpoint

import (
	"fmt"
	"sort"
	"strings"
)

// Tetragon JSON export (`tetra getevents -o json`, or the file the agent
// writes with --export-filename). One event per line; the single
// top-level key names the event type:
//
//	{"process_exec":{"process":{…},"parent":{…}},"node_name":"n1","time":"…"}
//
// process carries exec_id / parent_exec_id (unique across pid reuse), pid,
// uid, cwd, binary, arguments (argv[1:] as one string), cap.effective,
// ns.{pid,mnt,net}.inum, and pod.{namespace,name,container.{id,name,
// image.name}} for Kubernetes workloads (docker holds the short id).
//
// Mapping:
//   - process_exec            → kind process
//   - process_kprobe / _lsm   → network for *connect hooks with a sock_arg
//     (tcp_connect), file for file hooks with a path (security_file_permission:
//     MAY_WRITE → modify, otherwise open; fd_install → open; unlink → delete;
//     truncate → modify), syscall for everything else (setns, mount,
//     bpf_check, security_bpf_prog_load, …) with the hook as Operation and
//     the rendered arguments as Resource
//   - process_tracepoint      → kind syscall, Operation "<subsys>/<event>"
//   - process_exit            → folded (the exec already gave the process)
//   - rate_limit_info / process_throttle → a problem line: Tetragon itself
//     dropped events, so its coverage is incomplete for that period
//   - process_uprobe / process_loader and unknown types → UNSUPPORTED, counted

func loadTetragon(path string) (*LoadResult, error) {
	res := &LoadResult{}
	unsup := unsupportedCounter{}
	exits := 0
	err := forEachJSONDoc(path, res, nil, func(doc map[string]any, ref string) {
		typ, body := tetragonEvent(doc)
		if typ == "" {
			res.problem(ref + ": not a Tetragon event (no process_* key)")
			return
		}
		switch typ {
		case "process_exit":
			exits++
			res.ignore()
			return
		case "rate_limit_info":
			res.ignore()
			dt, _ := parseTime(leaf(doc, "time"))
			res.dropSignal(DropSignal{Signal: "rate-limit", End: dt, Count: num(body["number_of_dropped_process_events"]), Ref: ref,
				Detail: "Tetragon rate limiter dropped process events before this time"})
			res.note(fmt.Sprintf("%s: Tetragon rate limiter dropped %s process event(s): coverage incomplete around %s",
				ref, firstNonEmpty(leaf(body, "number_of_dropped_process_events"), "an unknown number of"), leaf(doc, "time")))
			return
		case "process_throttle":
			res.ignore()
			dt, _ := parseTime(leaf(doc, "time"))
			res.dropSignal(DropSignal{Signal: "throttle", Start: dt, Ref: ref,
				Detail: "Tetragon throttled events (" + leaf(body, "type") + ") for cgroup " + leaf(body, "cgroup")})
			res.note(fmt.Sprintf("%s: Tetragon throttled events (%s) for cgroup %s: coverage incomplete", ref, leaf(body, "type"), leaf(body, "cgroup")))
			return
		case "process_exec", "process_kprobe", "process_lsm", "process_tracepoint":
		default:
			unsup.add(res, typ)
			return
		}
		proc, _ := body["process"].(map[string]any)
		if proc == nil {
			res.problem(ref + ": " + typ + " without a process object")
			return
		}
		t, ok := parseTime(firstNonEmpty(leaf(doc, "time"), leaf(body, "time"), leaf(proc, "start_time")))
		if !ok {
			res.problem(ref + ": no recognizable time")
			return
		}
		r := tetragonProcess(proc, body)
		r.Time, r.Source, r.Ref = t, "tetragon", ref
		r.Host = leaf(doc, "node_name")
		switch typ {
		case "process_exec":
			r.Kind = "process"
		case "process_tracepoint":
			r.Kind = "syscall"
			r.Operation = strings.Trim(leaf(body, "subsys")+"/"+leaf(body, "event"), "/")
			r.Resource = tetragonArgs(body["args"])
		default:
			tetragonHook(&r, leaf(body, "function_name"), body["args"])
		}
		if r.Kind == "syscall" && r.Operation == "" {
			res.problem(ref + ": " + typ + " without a hook name")
			return
		}
		res.Records = append(res.Records, r)
	})
	if exits > 0 {
		res.note(fmt.Sprintf("%d process_exit event(s) folded into their exec", exits))
	}
	unsup.flush(res, "no mapping for this Tetragon event type")
	return res, err
}

// tetragonEvent returns the event type key and its body.
func tetragonEvent(doc map[string]any) (string, map[string]any) {
	keys := make([]string, 0, 2)
	for k, v := range doc {
		if _, ok := v.(map[string]any); ok && (strings.HasPrefix(k, "process_") || k == "rate_limit_info") {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return "", nil
	}
	sort.Strings(keys)
	body, _ := doc[keys[0]].(map[string]any)
	return keys[0], body
}

// tetragonProcess fills the process identity and its container and
// namespace attribution.
func tetragonProcess(p, body map[string]any) Record {
	r := Record{
		PID:          num(p["pid"]),
		Exe:          leaf(p, "binary"),
		ExecID:       leaf(p, "exec_id"),
		ParentExecID: leaf(p, "parent_exec_id"),
		Cwd:          leaf(p, "cwd"),
		Caps:         strList(dig(p, "cap.effective")),
		PIDNS:        unum(dig(p, "ns.pid.inum")),
		MntNS:        unum(dig(p, "ns.mnt.inum")),
		NetNS:        unum(dig(p, "ns.net.inum")),
	}
	if u := leaf(p, "uid"); u != "" {
		r.User = u
	}
	r.Cmdline = strings.TrimSpace(r.Exe + " " + leaf(p, "arguments"))
	if par, ok := body["parent"].(map[string]any); ok {
		r.PPID = num(par["pid"])
		r.ParentExe = leaf(par, "binary")
	}
	r.Pod = leaf(p, "pod.name")
	r.K8sNamespace = leaf(p, "pod.namespace")
	r.ContainerID = normContainerID(firstNonEmpty(leaf(p, "pod.container.id"), leaf(p, "docker")))
	r.ContainerName = leaf(p, "pod.container.name")
	r.ContainerImage = leaf(p, "pod.container.image.name")
	return r
}

// tetragonHook maps a kprobe / LSM hook by its function name.
func tetragonHook(r *Record, fn string, args any) {
	r.Kind, r.Operation = "syscall", fn
	name := strings.TrimPrefix(strings.TrimPrefix(fn, "__x64_sys_"), "__arm64_sys_")
	name = strings.TrimPrefix(name, "security_")
	list, _ := args.([]any)
	switch {
	case strings.Contains(name, "connect"):
		for _, a := range list {
			if s, ok := dig(asMap(a), "sock_arg").(map[string]any); ok && leaf(s, "daddr") != "" {
				r.Kind, r.Operation = "network", fn
				r.DestIP, r.DestPort = leaf(s, "daddr"), num(s["dport"])
				return
			}
		}
	case strings.Contains(name, "file") || strings.Contains(name, "open") || name == "fd_install" ||
		strings.Contains(name, "unlink") || strings.Contains(name, "truncate") || strings.Contains(name, "rename"):
		path, mask := "", 0
		for _, a := range list {
			m := asMap(a)
			switch {
			case leaf(m, "file_arg.path") != "":
				path = leaf(m, "file_arg.path")
			case leaf(m, "path_arg.path") != "":
				path = leaf(m, "path_arg.path")
			case path == "" && strings.HasPrefix(leaf(m, "string_arg"), "/"):
				path = leaf(m, "string_arg")
			case m["int_arg"] != nil:
				mask = num(m["int_arg"])
			}
		}
		if path == "" {
			break
		}
		op := "open"
		switch {
		case strings.Contains(name, "unlink"):
			op = "delete"
		case strings.Contains(name, "truncate"), strings.Contains(name, "rename"):
			op = "modify"
		case name == "file_permission" && mask&2 != 0: // MAY_WRITE
			op = "modify"
		}
		r.Kind, r.FilePath, r.FileOp = "file", path, op
		return
	}
	r.Resource = tetragonArgs(args)
}

// tetragonArgs renders hook arguments as short text: paths, strings,
// numbers, socket endpoints and BPF program attributes.
func tetragonArgs(v any) string {
	list, _ := v.([]any)
	var out []string
	for i, a := range list {
		if i >= 16 {
			break
		}
		for k, val := range asMap(a) {
			switch t := val.(type) {
			case map[string]any:
				switch {
				case leaf(t, "path") != "":
					out = append(out, leaf(t, "path"))
				case leaf(t, "daddr") != "":
					out = append(out, leaf(t, "daddr")+":"+leaf(t, "dport"))
				case k == "bpf_attr_arg":
					out = append(out, strings.TrimSpace(fmt.Sprintf("bpf prog %s %s insns=%s", leaf(t, "ProgType"), leaf(t, "ProgName"), leaf(t, "InsnCnt"))))
				default:
					out = append(out, k)
				}
			default:
				if s := anyStr(t); s != "" {
					out = append(out, s)
				}
			}
		}
	}
	return trimText(strings.Join(out, " "), 512)
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func trimText(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
