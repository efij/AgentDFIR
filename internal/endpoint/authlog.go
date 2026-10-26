package endpoint

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Linux authentication logs (/var/log/auth.log on Debian/Ubuntu,
// /var/log/secure on RHEL/Fedora) and the systemd journal exported with
// `journalctl -o json`.
//
//   - sudo:  dev : TTY=pts/0 ; PWD=/home/dev ; USER=root ; COMMAND=/usr/bin/rm -rf /tmp/x
//     → a process record: the command sudo was asked to run (and whether it refused)
//   - sshd:  Accepted publickey for dev from 10.0.0.5 port 50522 ssh2 / Failed password for …
//     → an auth record
//   - su:    pam_unix(su:session): session opened for user root by dev(uid=1000)
//     → an auth record
//
// The journal adds _CMDLINE: the command line of every process that wrote
// to it, one process record per pid and command line.

var (
	sudoCmdRe   = regexp.MustCompile(`^\s*(\S+) : (?:([^;=]+?) ; )?(?:TTY=(\S+) ; )?PWD=(\S*) ; USER=(\S+) ;(?: [A-Z]+=\S* ;)* COMMAND=(.*)$`)
	sshAcceptRe = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port (\d+)`)
	sshFailRe   = regexp.MustCompile(`^Failed (\S+) for (?:invalid user )?(\S+) from (\S+) port (\d+)`)
	sshInvalRe  = regexp.MustCompile(`^Invalid user (\S*) from (\S+)`)
	suOpenRe    = regexp.MustCompile(`pam_unix\(su(?:-l)?:session\): session opened for user (\S+?)(?:\(uid=\d+\))? by (\S*?)(?:\(uid=\d+\))?$`)
	suOKRe      = regexp.MustCompile(`^(?:\(to (\S+)\) (\S+) on \S+|Successful su for (\S+) by (\S+))`)
	suFailRe    = regexp.MustCompile(`^(?:FAILED SU \(to (\S+)\) (\S+) on \S+|FAILED su for (\S+) by (\S+))`)
)

var authProgs = map[string]bool{"sshd": true, "sudo": true, "su": true, "pkexec": true, "login": true, "systemd-logind": true, "polkitd": true, "passwd": true, "useradd": true, "usermod": true, "groupadd": true, "chpasswd": true}

// isAuthLine: a syslog-shaped line from an authentication program.
func isAuthLine(l string) bool {
	_, rest, ok := lineTime(l, time.Time{})
	if !ok {
		return false
	}
	m := syslogProgRe.FindStringSubmatch(rest)
	if m == nil {
		return false
	}
	return authProgs[strings.ToLower(m[2])] || strings.Contains(m[4], "pam_unix(")
}

func loadAuthLog(path string) (*LoadResult, error) {
	res := &LoadResult{}
	ref := modTime(path)
	base := baseName(path)
	err := scanLines(path, func(line string, n int) {
		if strings.TrimSpace(line) == "" {
			return
		}
		at := fmt.Sprintf("%s:%d", base, n)
		t, rest, ok := lineTime(line, ref)
		if !ok {
			res.problem(at + ": no recognizable timestamp")
			return
		}
		m := syslogProgRe.FindStringSubmatch(rest)
		if m == nil {
			res.problem(at + ": not a syslog line")
			return
		}
		pid, _ := strconv.Atoi(m[3])
		if rs := authRecords(strings.ToLower(m[2]), m[4], pid, t, at, "authlog"); len(rs) > 0 {
			res.Records = append(res.Records, rs...)
		} else {
			res.ignore()
		}
	})
	return res, err
}

// authRecord maps one authentication message.
func authRecord(prog, msg string, pid int, t time.Time, at, source string) (Record, bool) {
	msg = strings.TrimSpace(msg)
	switch {
	case prog == "sudo":
		m := sudoCmdRe.FindStringSubmatch(msg)
		if m == nil {
			return Record{}, false
		}
		r := Record{Time: t, Kind: "process", PID: pid, User: m[1], Cmdline: strings.TrimSpace(m[6]), Resource: "USER=" + m[5], Source: source, Ref: at,
			Cwd: m[4], TTY: m[3], PrivFrom: m[1], PrivTo: m[5]}
		r.Exe = firstField(r.Cmdline)
		if m[2] != "" { // "command not allowed", "3 incorrect password attempts"
			r.Failed = m[2]
		}
		return r, r.Cmdline != ""
	case prog == "sshd":
		if m := sshAcceptRe.FindStringSubmatch(msg); m != nil {
			return Record{Time: t, Kind: "auth", PID: pid, Operation: "ssh-accept " + m[1], User: m[2], SourceIP: m[3], Source: source, Ref: at}, true
		}
		if m := sshFailRe.FindStringSubmatch(msg); m != nil {
			return Record{Time: t, Kind: "auth", PID: pid, Operation: "ssh-fail " + m[1], User: m[2], SourceIP: m[3], Failed: "authentication failed", Source: source, Ref: at}, true
		}
		if m := sshInvalRe.FindStringSubmatch(msg); m != nil {
			return Record{Time: t, Kind: "auth", PID: pid, Operation: "ssh-invalid-user", User: m[1], SourceIP: m[2], Failed: "invalid user", Source: source, Ref: at}, true
		}
	case strings.HasPrefix(prog, "su"):
		if m := suOpenRe.FindStringSubmatch(msg); m != nil {
			return Record{Time: t, Kind: "auth", PID: pid, Operation: "su", Resource: m[1], User: m[2], PrivFrom: m[2], PrivTo: m[1], Source: source, Ref: at}, true
		}
		if m := suFailRe.FindStringSubmatch(msg); m != nil {
			to, by := firstNonEmpty(m[1], m[3]), firstNonEmpty(m[2], m[4])
			return Record{Time: t, Kind: "auth", PID: pid, Operation: "su", Resource: to, User: by, PrivFrom: by, PrivTo: to, Failed: "su failed", Source: source, Ref: at}, true
		}
		if m := suOKRe.FindStringSubmatch(msg); m != nil {
			to, by := firstNonEmpty(m[1], m[3]), firstNonEmpty(m[2], m[4])
			return Record{Time: t, Kind: "auth", PID: pid, Operation: "su", Resource: to, User: by, PrivFrom: by, PrivTo: to, Source: source, Ref: at}, true
		}
	}
	return Record{}, false
}

func firstField(s string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return f[0]
	}
	return ""
}

// loadJournal reads `journalctl -o json` (one object per line; also
// accepts a JSON array). MESSAGE may be a byte array for binary payloads.
func loadJournal(path string) (*LoadResult, error) {
	res := &LoadResult{}
	seen := map[string]bool{}
	err := forEachJSONDoc(path, res, nil, func(doc map[string]any, ref string) {
		usec, err := strconv.ParseInt(leaf(doc, "__REALTIME_TIMESTAMP"), 10, 64)
		if err != nil || usec <= 0 {
			res.problem(ref + ": no __REALTIME_TIMESTAMP")
			return
		}
		t := time.UnixMicro(usec).UTC()
		pid, _ := strconv.Atoi(leaf(doc, "_PID"))
		msg := journalMessage(doc["MESSAGE"])
		prog := strings.ToLower(firstNonEmpty(leaf(doc, "SYSLOG_IDENTIFIER"), leaf(doc, "_COMM")))
		emitted := false
		n0 := len(res.Records)
		host := leaf(doc, "_HOSTNAME")
		// __SEQNUM counts entries within one journal (__SEQNUM_ID). A
		// filtered export (journalctl -u …) skips numbers by design, so a
		// journal export is only HEALTHY when it is unfiltered; journal
		// records are corroborate-only either way.
		domain := ""
		if sn, err := strconv.ParseUint(leaf(doc, "__SEQNUM"), 10, 64); err == nil && sn > 0 {
			domain = "journald/" + firstNonEmpty(leaf(doc, "__SEQNUM_ID"), host, baseName(path))
			res.seqObserve(domain, sn, t, true)
			defer func() {
				for i := n0; i < len(res.Records); i++ {
					res.Records[i].Seq, res.Records[i].SeqDomain = sn, domain
					res.seqKind(domain, res.Records[i].Kind)
				}
			}()
		}
		defer func() {
			for i := n0; i < len(res.Records); i++ {
				res.Records[i].Host = host
			}
		}()
		if rs := authRecords(prog, msg, pid, t, ref, "journald"); len(rs) > 0 {
			res.Records = append(res.Records, rs...)
			emitted = true
		}
		if cmd := strings.TrimSpace(leaf(doc, "_CMDLINE")); cmd != "" {
			key := strconv.Itoa(pid) + "\x00" + cmd
			if !seen[key] {
				seen[key] = true
				res.Records = append(res.Records, Record{Time: t, Kind: "process", PID: pid, Exe: leaf(doc, "_EXE"), Cmdline: cmd,
					User: leaf(doc, "_UID"), Source: "journald", Ref: ref})
				emitted = true
			}
		}
		if !emitted {
			res.ignore()
		}
	})
	return res, err
}

func journalMessage(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []any: // non-UTF-8 payloads are exported as byte arrays
		b := make([]byte, 0, len(t))
		for _, x := range t {
			if f, ok := x.(float64); ok && f >= 0 && f < 256 {
				b = append(b, byte(f))
			}
		}
		return string(b)
	}
	return ""
}
