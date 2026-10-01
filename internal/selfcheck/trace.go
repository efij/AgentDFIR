package selfcheck

import (
	"bufio"
	"os"
	"regexp"
	"strings"
)

// parseTrace reads an strace -f output and returns the network dials,
// extra execs and out-of-tree writes it shows. allowed is the set of path
// prefixes a write may land under.
//
// The parse is deliberately narrow: a connect/sendto/sendmsg to anything
// that is not loopback or an AF_UNIX socket, any execve after the first
// (the subject itself), and any open-for-write of a path outside the
// allowed prefixes. A rule that tries to be clever is one nobody can audit.
func parseTrace(path string, allowed []string) (dials, execs, writes []string) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 128<<10), 8<<20)
	firstExec := false
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.Contains(line, "execve("):
			if !firstExec {
				firstExec = true
				continue
			}
			if m := execArgRe.FindStringSubmatch(line); m != nil {
				if !strings.Contains(line, "= -1") { // a failed exec is the sandbox working
					execs = append(execs, m[1])
				}
			}
		case strings.Contains(line, "connect(") || strings.Contains(line, "sendto(") || strings.Contains(line, "sendmsg("):
			if addr, ok := remoteAddr(line); ok {
				dials = append(dials, strings.TrimSpace(verbOf(line))+" "+addr)
			}
		case openForWrite(line):
			if p, ok := pathArg(line); ok && !underAny(p, allowed) && !systemWrite(p) {
				writes = append(writes, p)
			}
		}
	}
	return dedupe(dials), dedupe(execs), dedupe(writes)
}

var (
	execArgRe = regexp.MustCompile(`execve\("([^"]+)"`)
	pathArgRe = regexp.MustCompile(`open(?:at)?\((?:[^,]+,\s*)?"([^"]+)"`)
	inetRe    = regexp.MustCompile(`sin_addr=inet_addr\("([0-9.]+)"\)|inet_pton\([^,]+,\s*"([0-9a-fA-F:.]+)"|sin6_addr=inet_pton\([^,]+,\s*"([0-9a-fA-F:.]+)"`)
	portRe    = regexp.MustCompile(`sin6?_port=htons\((\d+)\)`)
)

func verbOf(line string) string {
	if i := strings.Index(line, "("); i >= 0 {
		head := line[:i]
		if j := strings.LastIndexAny(head, " \t"); j >= 0 {
			return head[j+1:]
		}
		return head
	}
	return "connect"
}

// remoteAddr returns the dotted address of a connect/sendto, and whether
// it is a non-loopback, non-unix destination worth reporting.
func remoteAddr(line string) (string, bool) {
	if strings.Contains(line, "AF_UNIX") || strings.Contains(line, "sun_path") {
		return "", false
	}
	if strings.Contains(line, "AF_NETLINK") || strings.Contains(line, "AF_LOCAL") {
		return "", false
	}
	m := inetRe.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	ip := firstNonEmpty(m[1:])
	if ip == "" {
		return "", false
	}
	if strings.HasPrefix(ip, "127.") || ip == "::1" || ip == "0.0.0.0" || ip == "::" {
		return "", false
	}
	addr := ip
	if p := portRe.FindStringSubmatch(line); p != nil {
		addr += ":" + p[1]
	}
	return addr, true
}

func openForWrite(line string) bool {
	if !strings.Contains(line, "open") {
		return false
	}
	return strings.Contains(line, "O_WRONLY") || strings.Contains(line, "O_RDWR") || strings.Contains(line, "O_CREAT")
}

func pathArg(line string) (string, bool) {
	m := pathArgRe.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	return m[1], true
}

func underAny(p string, prefixes []string) bool {
	for _, pre := range prefixes {
		if pre != "" && strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// systemWrite ignores writes the Go runtime and libc make that are not
// evidence of exfiltration or tampering: tty, the loader cache, /proc and
// /dev pseudo-files, and the shared temp the runtime may touch.
func systemWrite(p string) bool {
	for _, pre := range []string{"/dev/", "/proc/", "/sys/", "/tmp/go-", "/private/var/folders/", "/var/folders/"} {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return p == "" || !strings.HasPrefix(p, "/")
}

func firstNonEmpty(ss []string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
