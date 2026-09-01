package correlate

import (
	"bufio"
	"os"
	"strings"
)

// ShellHistoryAdapter reads a shell history file (bash/zsh) as an
// independent endpoint evidence source. Commands an agent reported
// running should also appear here if they actually executed in an
// interactive-ish shell context.
//
// Hostile input: bounded line size, no execution, values sanitized by
// downstream display. This is a reference adapter demonstrating the
// external-evidence extension point (plan §16).
type ShellHistoryAdapter struct {
	Path string
}

func (s *ShellHistoryAdapter) Name() string { return "shell_history" }

func (s *ShellHistoryAdapter) Observations() ([]Observation, error) {
	f, err := os.Open(s.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Observation
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		cmd := parseHistLine(sc.Text())
		if cmd == "" {
			continue
		}
		out = append(out, Observation{
			Source: "shell_history",
			Kind:   "command",
			Value:  cmd,
			Ref:    s.Path + ":" + itoa(line),
		})
	}
	return out, sc.Err()
}

// parseHistLine strips zsh extended-history metadata (": <ts>:<dur>;cmd").
func parseHistLine(l string) string {
	l = strings.TrimSpace(l)
	if l == "" {
		return ""
	}
	if strings.HasPrefix(l, ": ") {
		if i := strings.Index(l, ";"); i >= 0 {
			return strings.TrimSpace(l[i+1:])
		}
	}
	return l
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
