package correlate

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/endpoint"
	"github.com/efij/AgentDFIR/v4/internal/schema"
)

// Linux host-tampering rules over OS telemetry (auditd, Tetragon, Falco,
// bpftrace, journald/auth.log process records). Each fires only for
// activity the telemetry attributes to the agent's process tree, by pid
// ancestry, by Tetragon exec_id ancestry, or by the parent executable the
// record names. The transcript rules (community pack) judge what the
// agent said it ran; these judge what the operating system saw, so they
// still fire when the transcript is silent or edited.
//
//	AGENT_SYSTEMD_PERSISTENCE  unit/timer file written under a systemd unit
//	                           directory, `systemctl [--user] enable|link`,
//	                           or `systemd-run --on-*` (a transient timer)
//	AGENT_CRONTAB_MODIFIED     /etc/crontab, /etc/cron.*, /var/spool/cron
//	                           written, or `crontab` run to install/edit/remove
//	AGENT_NAMESPACE_ESCAPE     nsenter into pid 1's namespaces, setns naming
//	                           /proc/1/ns (or any setns from a container),
//	                           a block-device or host mount from a container,
//	                           the container runtime socket used from a container
//	AGENT_BPF_LOAD             bpftool prog load/attach, or a bpf() program
//	                           load seen by a kprobe / Falco
//
// Third-party detections (Falco rule names) are never re-raised here; a
// record fires only on its own fields.

var (
	systemdUnitRe = regexp.MustCompile(`(?:^|/)(?:etc/systemd/(?:system|user)|(?:usr/)?lib/systemd/(?:system|user)|run/systemd/(?:system|user)|\.config/systemd/user|\.local/share/systemd/user)(?:/[^/]+\.wants)?/[^/]+\.(service|timer|socket|path)$`)
	systemctlRe   = regexp.MustCompile(`(?:^|[\s/])systemctl\s+(?:--\S+\s+)*(?:enable|link|preset|reenable)\b`)
	systemdRunRe  = regexp.MustCompile(`(?:^|[\s/])systemd-run\s.*--on-(?:calendar|active|boot|startup|unit-active|unit-inactive)\b`)
	cronPathRe    = regexp.MustCompile(`^(?:/etc/crontab|/etc/anacrontab|/etc/cron\.(?:d|hourly|daily|weekly|monthly)/[^/]+|/var/spool/cron/(?:crontabs/)?[^/]+)$`)
	nsenterRe     = regexp.MustCompile(`(?:^|[\s/])nsenter\s(?:.*\s)?(?:-t\s*1|--target[=\s]1)(?:\s|$)`)
	bpftoolRe     = regexp.MustCompile(`(?:^|[\s/])bpftool\s+(?:-\S+\s+)*(?:prog\s+(?:load|loadall|attach)|net\s+attach|cgroup\s+attach)\b`)
	runtimeSockRe = regexp.MustCompile(`/(?:docker|containerd|crio|podman)\.sock\b`)
)

type linuxRule struct {
	ID                           string
	title, attack, sev, falsePos string
	what                         func(r endpoint.Record) (string, bool)
}

var linuxRules = []linuxRule{
	{
		ID:    "AGENT_SYSTEMD_PERSISTENCE",
		title: "Agent Process Installed a systemd Unit or Timer", attack: "T1543.002", sev: "HIGH",
		falsePos: "Package installs and provisioning tools run by the agent on request write unit files; check who asked and what ExecStart= runs.",
		what: func(r endpoint.Record) (string, bool) {
			switch r.Kind {
			case "file":
				if isWriteOp(r.FileOp) && systemdUnitRe.MatchString(r.FilePath) {
					return r.FileOp + " " + r.FilePath, true
				}
			case "process":
				if systemctlRe.MatchString(r.Cmdline) || systemdRunRe.MatchString(r.Cmdline) {
					return r.Cmdline, true
				}
			}
			return "", false
		}},
	{
		ID:    "AGENT_CRONTAB_MODIFIED",
		title: "Agent Process Modified a Crontab", attack: "T1053.003", sev: "HIGH",
		falsePos: "An agent asked to schedule a job writes a crontab on purpose; check the entry it added.",
		what: func(r endpoint.Record) (string, bool) {
			switch r.Kind {
			case "file":
				if isWriteOp(r.FileOp) && cronPathRe.MatchString(r.FilePath) {
					return r.FileOp + " " + r.FilePath, true
				}
			case "process":
				if crontabWrites(r.Cmdline) {
					return r.Cmdline, true
				}
			}
			return "", false
		}},
	{
		ID:    "AGENT_NAMESPACE_ESCAPE",
		title: "Agent Process Reached Into the Host's Namespaces", attack: "T1611", sev: "CRITICAL",
		falsePos: "Node debugging (kubectl debug node, nsenter by an administrator) uses the same primitives; it is never a normal coding-agent action.",
		what: func(r endpoint.Record) (string, bool) {
			inContainer := r.ContainerID != "" || r.Pod != ""
			op := strings.ToLower(r.Operation)
			switch r.Kind {
			case "process":
				if nsenterRe.MatchString(r.Cmdline) {
					return r.Cmdline, true
				}
				if inContainer && runtimeSockRe.MatchString(r.Cmdline) {
					return "container runtime socket from a container: " + r.Cmdline, true
				}
				if inContainer && exeName(firstToken(r.Cmdline)) == "mount" && strings.Contains(r.Cmdline, " /dev/") {
					return "block device mounted from a container: " + r.Cmdline, true
				}
			case "syscall":
				if strings.Contains(op, "setns") && (strings.Contains(r.Resource, "/proc/1/ns") || inContainer) {
					return "setns " + r.Resource, true
				}
				if strings.Contains(op, "mount") && inContainer && (strings.Contains(r.Resource, "/dev/") || strings.Contains(r.Resource, "/host")) {
					return "mount " + r.Resource + " from a container", true
				}
			case "file", "network":
				if inContainer && runtimeSockRe.MatchString(r.FilePath) {
					return "container runtime socket " + r.FilePath + " used from a container", true
				}
			}
			return "", false
		}},
	{
		ID:    "AGENT_BPF_LOAD",
		title: "Agent Process Loaded an eBPF Program", attack: "T1014", sev: "HIGH",
		falsePos: "Observability work (bpftrace one-liners, profilers) loads BPF programs; an agent doing so unasked can hide activity or read kernel memory.",
		what: func(r endpoint.Record) (string, bool) {
			switch r.Kind {
			case "process":
				if bpftoolRe.MatchString(r.Cmdline) {
					return r.Cmdline, true
				}
			case "syscall":
				op := strings.ToLower(r.Operation)
				if strings.Contains(op, "bpf") && !strings.Contains(op, "bpf_map") && !strings.Contains(op, "map_") {
					return strings.TrimSpace(r.Operation + " " + r.Resource), true
				}
			}
			return "", false
		}},
}

func isWriteOp(op string) bool { return op == "create" || op == "modify" }

// crontabWrites: `crontab` installing, editing or removing a table
// (`crontab file`, `crontab -`, `crontab -e`, `crontab -r`, or bare
// `crontab` reading stdin). Listing (-l) is not a change.
func crontabWrites(cmd string) bool {
	f := strings.Fields(cmd)
	for i, tok := range f {
		if exeName(tok) != "crontab" {
			continue
		}
		args := f[i+1:]
		for j := 0; j < len(args); j++ {
			switch {
			case args[j] == "-l" || args[j] == "-T":
				return false
			case args[j] == "-u":
				j++
			case args[j] == "|" || args[j] == "&&" || args[j] == ";":
				return true
			}
		}
		return true
	}
	return false
}

// linuxAgentRules evaluates the rules over every record that carries
// process identity, whatever its source.
func linuxAgentRules(records []endpoint.Record, opts EndpointOptions) []schema.Finding {
	var recs []endpoint.Record
	for _, r := range records {
		switch r.Kind {
		case "process", "file", "network", "syscall":
			recs = append(recs, r)
		}
	}
	if len(recs) == 0 {
		return nil
	}
	sort.SliceStable(recs, func(i, j int) bool { return recs[i].Time.Before(recs[j].Time) })
	names := agentBinaryNames(opts.AgentBinaries)
	lineage := agentLineage(recs, names)
	type hit struct {
		first time.Time
		n     int
		lines []string
		refs  []string
	}
	hits := make([]*hit, len(linuxRules))
	for i, r := range recs {
		if !lineage[i] {
			continue
		}
		for k, rule := range linuxRules {
			what, ok := rule.what(r)
			if !ok {
				continue
			}
			h := hits[k]
			if h == nil {
				h = &hit{first: r.Time}
				hits[k] = h
			}
			h.n++
			if len(h.lines) < 5 {
				line := fmt.Sprintf("%s %s pid %d: %s", r.Time.UTC().Format(time.RFC3339), r.Source, r.PID, trim(what, 160))
				if r.ContainerID != "" || r.Pod != "" {
					line += " [container " + firstNonBlank(r.ContainerName, shortID(r.ContainerID)) + noteIfStr(" pod "+r.K8sNamespace+"/"+r.Pod, r.Pod != "") + "]"
				}
				h.lines = append(h.lines, line)
				h.refs = append(h.refs, r.Source+" "+r.Ref)
			}
		}
	}
	var out []schema.Finding
	for k, rule := range linuxRules {
		h := hits[k]
		if h == nil {
			continue
		}
		attack := rule.attack
		if joined := strings.Join(h.lines, " "); rule.ID == "AGENT_SYSTEMD_PERSISTENCE" && (strings.Contains(joined, ".timer") || strings.Contains(joined, "systemd-run")) {
			attack = "T1053.006" // systemd timers
		}
		out = append(out, schema.Finding{
			RuleID: rule.ID, Severity: rule.sev, Title: rule.title,
			Description: fmt.Sprintf("Operating-system telemetry shows %d such action(s) by a process descended from the agent (first at %s). This is what the OS observed, independent of the transcript.",
				h.n, h.first.UTC().Format(time.RFC3339)),
			Related: h.lines, EvidenceRefs: h.refs, Timestamp: h.first.UTC().Format(time.RFC3339),
			Status: schema.StateObserved, Endpoint: schema.StateObserved, MitreATTACK: attack,
			FalsePositive: rule.falsePos,
		})
	}
	return out
}

// agentLineage marks records whose process descends from an agent binary:
// buildLineage's pid / parent-executable walk, plus Tetragon's exec_id
// ancestry, which survives pid reuse and spans pid namespaces.
func agentLineage(recs []endpoint.Record, names map[string]bool) []bool {
	out := buildLineage(recs, names)
	byExec := map[string]int{}
	for i, r := range recs {
		if r.Kind == "process" && r.ExecID != "" {
			byExec[r.ExecID] = i
		}
	}
	for i, r := range recs {
		if out[i] || r.ParentExecID == "" {
			continue
		}
		id := r.ParentExecID
		for hop := 0; hop < 32 && id != ""; hop++ {
			idx, ok := byExec[id]
			if !ok {
				break
			}
			p := recs[idx]
			if agentExe(names, p.Exe, p.Cmdline) {
				out[i] = true
				break
			}
			id = p.ParentExecID
		}
	}
	return out
}

// agentExe mirrors buildLineage's test for an agent process.
func agentExe(names map[string]bool, exe, cmd string) bool {
	if names[exeName(exe)] {
		return true
	}
	if ft := firstToken(cmd); ft != "" && names[exeName(ft)] {
		return true
	}
	low := strings.ToLower(cmd)
	if strings.Contains(low, "@anthropic-ai/claude-code") || strings.Contains(low, "@openai/codex") {
		return true
	}
	for name := range names {
		if strings.Contains(low, "/"+name+"/") || strings.Contains(low, "/"+name+".js") {
			return true
		}
	}
	return false
}

func noteIfStr(s string, ok bool) string {
	if ok {
		return s
	}
	return ""
}
