package endpoint

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Linux runtime-security telemetry produced by eBPF tools. AgentDFIR does
// not load eBPF programs itself (that needs a third-party library or cgo);
// it imports what Tetragon, Falco and bpftrace already wrote, and what the
// container runtime logged:
//
//   - tetragon:       `tetra getevents -o json` / the JSON export file
//   - falco:          Falco alerts with json_output: true
//   - bpftrace:       `bpftrace -f json` output that follows the documented
//     execsnoop-style field contract (see bpftrace.go)
//   - docker-events:  `docker events --format '{{json .}}'`
//   - podman-events:  `podman events --format json`
//
// Tetragon's process_exec stream sees every exec on the node while its
// agent runs, so its records count as process coverage like auditd. Falco
// only emits when a rule matched, bpftrace scripts drop events under load
// and container-runtime logs see only what the daemon did: those records
// corroborate but never contradict (see IsSighting).

const (
	FormatTetragon Format = "tetragon"
	FormatFalco    Format = "falco"
	FormatBpftrace Format = "bpftrace"
	FormatDocker   Format = "docker-events"
	FormatPodman   Format = "podman-events"

	linuxFormatList = "tetragon|falco|bpftrace|docker-events|podman-events"
)

func init() {
	for _, s := range []string{"falco", "bpftrace", "docker-events", "podman-events"} {
		sightingSources[s] = true
	}
}

func loadLinuxTelemetry(path string, f Format) (*LoadResult, bool, error) {
	var res *LoadResult
	var err error
	switch f {
	case FormatTetragon:
		res, err = loadTetragon(path)
	case FormatFalco:
		res, err = loadFalco(path)
	case FormatBpftrace:
		res, err = loadBpftrace(path)
	case FormatDocker:
		res, err = loadDockerEvents(path)
	case FormatPodman:
		res, err = loadPodmanEvents(path)
	default:
		return nil, false, nil
	}
	return res, true, err
}

var (
	tetragonKeyRe = regexp.MustCompile(`^\s*\{\s*"(process_exec|process_exit|process_kprobe|process_tracepoint|process_uprobe|process_lsm|process_loader|process_throttle|rate_limit_info)"\s*:`)
	bpftraceRe    = regexp.MustCompile(`^\s*\{\s*"type"\s*:\s*"(attached_probes|printf|map|hist|lhist|stats|lost_events|time|join|syscall|value|cat|helper_error)"`)
)

// sniffLinuxTelemetry recognizes the formats above from the first JSON
// object. It runs before the other JSON sniffers.
func sniffLinuxTelemetry(head []byte) Format {
	if !bytes.HasPrefix(head, []byte("{")) {
		return ""
	}
	first := head
	if i := bytes.IndexByte(head, '\n'); i >= 0 {
		first = head[:i]
	}
	has := func(k string) bool { return bytes.Contains(first, []byte(`"`+k+`"`)) }
	switch {
	case tetragonKeyRe.Match(first):
		return FormatTetragon
	case has("rule") && has("priority") && has("output") && (has("output_fields") || has("hostname") || has("source")):
		return FormatFalco
	case bpftraceRe.Match(first) && has("data"):
		return FormatBpftrace
	case has("Actor") && has("Action") && (has("timeNano") || has("time")):
		return FormatDocker
	case has("Status") && has("Type") && has("Time") && has("ID") && (has("Image") || has("Name")):
		return FormatPodman
	}
	return ""
}

// unsupportedCounter counts structures an adapter recognized as valid but
// has no mapping for, so they are reported as UNSUPPORTED with a reason
// instead of disappearing.
type unsupportedCounter map[string]int

func (u unsupportedCounter) add(res *LoadResult, what string) {
	u[what]++
	res.Skipped++
}

// flush writes one operator-facing line per unsupported structure.
func (u unsupportedCounter) flush(res *LoadResult, reason string) {
	keys := make([]string, 0, len(u))
	for k := range u {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		res.note(fmt.Sprintf("UNSUPPORTED: %d %s record(s): %s", u[k], k, reason))
	}
}

// containerIDRe finds a container id in a /proc/<pid>/cgroup style path
// or a runtime-prefixed id: docker-<id>.scope, /docker/<id>,
// cri-containerd-<id>.scope, crio-<id>.scope, libpod-<id>.scope,
// /kubepods/.../<id>, containerd://<id>, docker://<id>, cri-o://<id>.
var containerIDRe = regexp.MustCompile(`(?:docker|cri-containerd|crio|libpod|containerd|cri-o)(?:-|://|/)([0-9a-f]{64})|/kubepods[^\s]*/([0-9a-f]{64})`)

// ContainerIDFromCgroup returns the full container id named by a cgroup
// path or a runtime-prefixed id, or "" when it names none.
func ContainerIDFromCgroup(s string) string {
	m := containerIDRe.FindStringSubmatch(strings.ToLower(s))
	if m == nil {
		return ""
	}
	return firstNonEmpty(m[1], m[2])
}

// normContainerID strips a runtime scheme (containerd://, docker://).
func normContainerID(s string) string {
	s = strings.TrimSpace(s)
	if id := ContainerIDFromCgroup(s); id != "" {
		return id
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	switch strings.ToLower(s) {
	case "", "host", "<na>", "null":
		return ""
	}
	return s
}

// num reads a JSON number (or numeric string) as an int, bounded.
func num(v any) int {
	switch t := v.(type) {
	case float64:
		if t >= -1<<31 && t < 1<<31 {
			return int(t)
		}
	case string:
		var n int
		if _, err := fmt.Sscanf(t, "%d", &n); err == nil {
			return n
		}
	}
	return 0
}

// unum reads a JSON number as an unsigned namespace inode.
func unum(v any) uint64 {
	if f, ok := v.(float64); ok && f > 0 && f < 1<<53 {
		return uint64(f)
	}
	return 0
}

// strList renders a JSON array of strings space-separated, bounded.
func strList(v any) string {
	arr, ok := v.([]any)
	if !ok {
		return ""
	}
	var out []string
	for i, x := range arr {
		if i >= 64 {
			break
		}
		if s := anyStr(x); s != "" {
			out = append(out, s)
		}
	}
	return strings.Join(out, " ")
}
