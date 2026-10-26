package endpoint

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Falco alerts written with json_output: true (file_output, stdout or
// falcosidekick's raw form). One alert per line:
//
//	{"time":"…","rule":"…","priority":"Warning","source":"syscall",
//	 "output":"…","output_fields":{"evt.type":"openat","proc.cmdline":"…",
//	 "fd.name":"/etc/shadow","container.id":"…","k8s.pod.name":"…"},
//	 "hostname":"…","tags":[…]}
//
// Falco emits only when one of its rules matched, so an alert is a
// sighting, never coverage. The record is built from output_fields by
// evt.type: execve/execveat → process; connect/sendto → network (or file
// for a unix socket path such as /var/run/docker.sock); open/openat/
// openat2/creat/unlink/rename/chmod → file; anything else (setns, mount,
// bpf, ptrace, …) → syscall with evt.type as Operation. An alert without
// evt.type but with proc.cmdline is the process it names.
//
// The Falco rule name and priority travel with the record as Detection,
// labelled as a third-party detection: AgentDFIR does not re-raise it as
// a finding of its own. Alerts from Falco plugin sources (k8s_audit,
// aws_cloudtrail, okta, …) are not host telemetry and are UNSUPPORTED.

var unixPathRe = regexp.MustCompile(`(/[^\s>]+)\s*$`)

func loadFalco(path string) (*LoadResult, error) {
	res := &LoadResult{}
	unsup := unsupportedCounter{}
	rules := map[string]int{}
	err := forEachJSONDoc(path, res, nil, func(doc map[string]any, ref string) {
		rule, prio := leaf(doc, "rule"), leaf(doc, "priority")
		if rule == "" || prio == "" {
			res.problem(ref + ": not a Falco alert (no rule/priority)")
			return
		}
		if src := leaf(doc, "source"); src != "" && src != "syscall" {
			unsup.add(res, "falco source "+src)
			return
		}
		of, _ := doc["output_fields"].(map[string]any)
		get := func(k string) string {
			if of == nil {
				return ""
			}
			return anyStr(of[k])
		}
		t, ok := parseTime(firstNonEmpty(leaf(doc, "time"), get("evt.time")))
		if !ok {
			res.problem(ref + ": no recognizable time")
			return
		}
		r := Record{Time: t, Source: "falco", Ref: ref,
			PID: num(of["proc.pid"]), PPID: num(of["proc.ppid"]),
			Exe:       firstNonEmpty(get("proc.exepath"), get("proc.exe")),
			Cmdline:   get("proc.cmdline"),
			ParentExe: firstNonEmpty(get("proc.pexepath"), get("proc.pname")),
			User:      firstNonEmpty(get("user.name"), get("user.uid")),
			Cwd:       get("proc.cwd"),
			TTY:       get("proc.tty"),
			Pod:       get("k8s.pod.name"), K8sNamespace: get("k8s.ns.name"),
			ContainerID: normContainerID(get("container.id")), ContainerName: get("container.name"),
			Detection: fmt.Sprintf("falco rule %q priority %s (third-party detection)", rule, prio),
		}
		if r.TTY == "0" {
			r.TTY = ""
		}
		if r.ContainerName == "host" {
			r.ContainerName = ""
		}
		if img := firstNonEmpty(get("container.image.repository"), get("container.image")); img != "" && img != "<NA>" {
			if tag := get("container.image.tag"); tag != "" && tag != "<NA>" {
				img += ":" + tag
			}
			r.ContainerImage = img
		}
		fdName := get("fd.name")
		switch typ := strings.ToLower(get("evt.type")); typ {
		case "execve", "execveat":
			r.Kind = "process"
		case "connect", "sendto", "sendmsg":
			ip, port := firstNonEmpty(get("fd.sip"), get("fd.rip")), num(of["fd.sport"])
			if port == 0 {
				port = num(of["fd.rport"])
			}
			if ip == "" && strings.Contains(fdName, "->") {
				ip, port = splitHostPort(fdName[strings.LastIndex(fdName, "->")+2:])
			}
			switch {
			case get("fd.type") == "unix" || unixPathRe.MatchString(fdName) && ip == "":
				r.Kind, r.FileOp = "file", "open"
				if m := unixPathRe.FindStringSubmatch(fdName); m != nil {
					r.FilePath = m[1]
				}
				r.Operation = typ
			case ip != "":
				r.Kind, r.DestIP, r.DestPort = "network", ip, port
			default:
				r.Kind, r.Operation, r.Resource = "syscall", typ, fdName
			}
		case "open", "openat", "openat2", "creat", "unlink", "unlinkat", "rename", "renameat", "renameat2", "chmod", "fchmodat", "truncate":
			p := firstNonEmpty(fdName, get("evt.arg.name"), get("evt.arg.path"), get("fs.path.name"))
			if p == "" {
				r.Kind, r.Operation = "syscall", typ
				break
			}
			r.Kind, r.FilePath = "file", p
			flags := get("evt.arg.flags")
			switch {
			case strings.HasPrefix(typ, "unlink"):
				r.FileOp = "delete"
			case typ == "creat" || strings.Contains(flags, "O_CREAT"):
				r.FileOp = "create"
			case strings.HasPrefix(typ, "open") && !strings.Contains(flags, "O_WRONLY") && !strings.Contains(flags, "O_RDWR") && !strings.Contains(flags, "O_TRUNC"):
				r.FileOp = "open"
			default:
				r.FileOp = "modify"
			}
		case "":
			if r.Cmdline == "" && r.Exe == "" {
				res.problem(ref + ": Falco alert without evt.type or process fields")
				return
			}
			r.Kind = "process"
		default:
			r.Kind, r.Operation = "syscall", typ
			r.Resource = falcoArgs(of, fdName)
		}
		if r.Cmdline == "" && r.Kind == "process" {
			r.Cmdline = firstNonEmpty(r.Exe, get("proc.name"))
		}
		rules[rule]++
		if rules[rule] == 1 {
			res.notice(fmt.Sprintf("Falco (third-party detection, not an AgentDFIR finding): rule %q [%s] first at %s: %s",
				rule, prio, t.Format("2006-01-02T15:04:05Z"), trimText(leaf(doc, "output"), 240)))
		}
		r.Host = leaf(doc, "hostname")
		res.Records = append(res.Records, r)
	})
	unsup.flush(res, "Falco plugin events are not host telemetry; import that source's own log instead")
	return res, err
}

// falcoArgs renders evt.arg.* fields (setns nstype, mount dev/dir, bpf
// cmd) plus fd.name, sorted for a stable record.
func falcoArgs(of map[string]any, fdName string) string {
	var parts []string
	for k, v := range of {
		if strings.HasPrefix(k, "evt.arg.") {
			if s := anyStr(v); s != "" {
				parts = append(parts, strings.TrimPrefix(k, "evt.arg.")+"="+s)
			}
		}
	}
	sort.Strings(parts)
	if fdName != "" {
		parts = append(parts, fdName)
	}
	return trimText(strings.Join(parts, " "), 512)
}

// splitHostPort splits "1.2.3.4:443" / "[v6]:443".
func splitHostPort(s string) (string, int) {
	s = strings.TrimSpace(s)
	i := strings.LastIndexByte(s, ':')
	if i <= 0 {
		return strings.Trim(s, "[]"), 0
	}
	return strings.Trim(s[:i], "[]"), num(s[i+1:])
}
