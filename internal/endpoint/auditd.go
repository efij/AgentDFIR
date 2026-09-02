package endpoint

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Linux auditd (/var/log/audit/audit.log). One kernel event spans several
// records sharing msg=audit(<epoch>.<ms>:<serial>): SYSCALL (pid/ppid/exe/
// uid/success), EXECVE (argv, hex-encoded when it has spaces/specials),
// CWD, PATH (nametype=CREATE/DELETE/NORMAL), SOCKADDR (saddr hex).

var (
	auditHdrRe = regexp.MustCompile(`^type=(\S+) msg=audit\((\d+)\.(\d+):(\d+)\):\s*(.*)$`)
	kvRe       = regexp.MustCompile(`(\w+)=("(?:[^"\\]|\\.)*"|\S+)`)
)

type auditEvent struct {
	ts      time.Time
	serial  string
	syscall map[string]string
	execve  map[string]string
	cwd     string
	paths   []map[string]string
	saddr   string
	line    int
}

func loadAuditd(path string) (*LoadResult, error) {
	res := &LoadResult{}
	events := map[string]*auditEvent{}
	var order []string
	err := scanLines(path, func(line string, n int) {
		m := auditHdrRe.FindStringSubmatch(line)
		if m == nil {
			if strings.TrimSpace(line) != "" {
				res.problem(fmt.Sprintf("line %d: not an audit record", n))
			}
			return
		}
		typ, sec, ms, serial, body := m[1], m[2], m[3], m[4], m[5]
		key := sec + ":" + serial
		ev, ok := events[key]
		if !ok {
			s, _ := strconv.ParseInt(sec, 10, 64)
			f, _ := strconv.ParseInt(ms, 10, 64)
			// The fraction is milliseconds (three digits) in every auditd build.
			ev = &auditEvent{ts: time.Unix(s, f*int64(time.Millisecond)).UTC(), serial: serial, line: n}
			events[key] = ev
			order = append(order, key)
		}
		fields := parseKV(body)
		switch typ {
		case "SYSCALL":
			ev.syscall = fields
		case "EXECVE":
			ev.execve = fields
		case "CWD":
			ev.cwd = unq(fields["cwd"])
		case "PATH":
			ev.paths = append(ev.paths, fields)
		case "SOCKADDR":
			ev.saddr = fields["saddr"]
		}
	})
	if err != nil {
		return nil, err
	}
	for _, key := range order {
		ev := events[key]
		ref := fmt.Sprintf("audit.log:%d (serial %s)", ev.line, ev.serial)
		pid, _ := strconv.Atoi(ev.syscall["pid"])
		ppid, _ := strconv.Atoi(ev.syscall["ppid"])
		exe := unq(ev.syscall["exe"])
		user := ev.syscall["auid"]
		if u := ev.syscall["uid"]; u != "" {
			user = u
		}
		switch {
		case ev.execve != nil:
			argc, _ := strconv.Atoi(ev.execve["argc"])
			var argv []string
			for i := 0; i < argc || (argc == 0 && i < 64); i++ {
				v, ok := ev.execve["a"+strconv.Itoa(i)]
				if !ok {
					if argc == 0 {
						break
					}
					continue
				}
				argv = append(argv, decodeAuditArg(v))
			}
			res.Records = append(res.Records, Record{Time: ev.ts, Kind: "process", PID: pid, PPID: ppid, Exe: exe,
				Cmdline: strings.Join(argv, " "), User: user, Source: "auditd", Ref: ref})
		case ev.saddr != "":
			ip, port := decodeSaddr(ev.saddr)
			if ip != "" {
				res.Records = append(res.Records, Record{Time: ev.ts, Kind: "network", PID: pid, PPID: ppid, Exe: exe,
					Cmdline: unq(ev.syscall["comm"]), DestIP: ip, DestPort: port, User: user, Source: "auditd", Ref: ref})
			}
		case len(ev.paths) > 0:
			for _, p := range ev.paths {
				op := ""
				switch strings.ToUpper(p["nametype"]) {
				case "CREATE":
					op = "create"
				case "DELETE":
					op = "delete"
				case "NORMAL":
					if ev.syscall["syscall"] != "" && isWriteSyscall(ev.syscall) {
						op = "modify"
					}
				}
				if op == "" {
					continue
				}
				name := unq(p["name"])
				if !strings.HasPrefix(name, "/") && ev.cwd != "" {
					name = strings.TrimSuffix(ev.cwd, "/") + "/" + name
				}
				res.Records = append(res.Records, Record{Time: ev.ts, Kind: "file", PID: pid, PPID: ppid, Exe: exe,
					Cmdline: unq(ev.syscall["comm"]), FilePath: name, FileOp: op, User: user, Source: "auditd", Ref: ref})
			}
		}
	}
	sort.SliceStable(res.Records, func(i, j int) bool { return res.Records[i].Time.Before(res.Records[j].Time) })
	return res, nil
}

// isWriteSyscall: open/openat with write flags (a1/a2 contain O_WRONLY|O_RDWR|O_CREAT|O_TRUNC).
func isWriteSyscall(sc map[string]string) bool {
	name := sc["syscall"]
	flagsHex := ""
	switch name {
	case "2", "open":
		flagsHex = sc["a1"]
	case "257", "openat", "437", "openat2":
		flagsHex = sc["a2"]
	default:
		return false
	}
	v, err := strconv.ParseUint(strings.TrimPrefix(flagsHex, "0x"), 16, 64)
	if err != nil {
		return false
	}
	return v&0x3 != 0 || v&0x40 != 0 || v&0x200 != 0 // O_WRONLY/O_RDWR, O_CREAT, O_TRUNC
}

func parseKV(body string) map[string]string {
	out := map[string]string{}
	for _, m := range kvRe.FindAllStringSubmatch(body, -1) {
		out[m[1]] = m[2]
	}
	return out
}

func unq(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return strings.ReplaceAll(s[1:len(s)-1], `\"`, `"`)
	}
	return s
}

// decodeAuditArg: quoted args are literal; unquoted args are hex-encoded
// (auditd does this when the value contains spaces or control characters).
func decodeAuditArg(v string) string {
	if strings.HasPrefix(v, `"`) {
		return unq(v)
	}
	if b, err := hex.DecodeString(v); err == nil && len(v)%2 == 0 && len(v) > 0 {
		return string(b)
	}
	return v
}

// decodeSaddr parses the SOCKADDR hex blob: family (LE uint16), then for
// AF_INET port (BE) + 4-byte address; AF_INET6 port (BE), flowinfo, 16-byte
// address.
func decodeSaddr(h string) (string, int) {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) < 2 {
		return "", 0
	}
	fam := int(b[0]) | int(b[1])<<8
	switch fam {
	case 2: // AF_INET
		if len(b) < 8 {
			return "", 0
		}
		port := int(b[2])<<8 | int(b[3])
		return fmt.Sprintf("%d.%d.%d.%d", b[4], b[5], b[6], b[7]), port
	case 10: // AF_INET6
		if len(b) < 24 {
			return "", 0
		}
		port := int(b[2])<<8 | int(b[3])
		var parts []string
		for i := 8; i < 24; i += 2 {
			parts = append(parts, fmt.Sprintf("%x", int(b[i])<<8|int(b[i+1])))
		}
		return strings.Join(parts, ":"), port
	}
	return "", 0
}
