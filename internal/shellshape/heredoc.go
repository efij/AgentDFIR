package shellshape

import (
	"regexp"
	"strings"
)

var heredocRe = regexp.MustCompile(`<<(-?)\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?`)

// StripHeredocs removes heredoc bodies that are data and keeps everything
// else, quotes included. A file an agent writes with `cat > x <<'EOF' …
// EOF` is data; a body fed to a shell or interpreter (`bash <<EOF`,
// `python3 - <<EOF`) is code and stays. `<<` inside quotes or arithmetic
// is not a heredoc. Strip is the stronger form (quoted prose emptied too).
func StripHeredocs(cmd string) string { return stripHeredocs(cmd, false) }

// StripAllHeredocs removes every heredoc body, including one fed to an
// interpreter. For signature rules: `python3 - <<'EOF'` edit scripts are
// string literals being written into files, and on a real machine they were
// most of the HIGH false positives (a Go test mentioning a reverse shell,
// a plan that names ~/.aws/credentials).
func StripAllHeredocs(cmd string) string { return stripHeredocs(cmd, true) }

func stripHeredocs(cmd string, all bool) string {
	if !strings.Contains(cmd, "<<") {
		return cmd
	}
	lines := strings.Split(cmd, "\n")
	var out []string
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		out = append(out, l)
		for _, m := range heredocRe.FindAllStringSubmatchIndex(l, -1) {
			if strings.HasPrefix(l[m[0]:], "<<<") || (m[0] > 0 && l[m[0]-1] == '<') {
				continue // here-string
			}
			before := l[:m[0]]
			if inQuotes(before) || strings.Contains(before, "$((") || (m[0] > 0 && isDigit(l[m[0]-1])) {
				continue // a shift or a quoted "<<", not a heredoc
			}
			marker, tabs := l[m[4]:m[5]], l[m[2]:m[3]] == "-"
			keep := !all && feedsInterpreter(before)
			for i+1 < len(lines) {
				i++
				t := lines[i]
				if tabs {
					t = strings.TrimLeft(t, "\t")
				}
				if strings.TrimRight(t, " \r") == marker {
					if keep {
						out = append(out, lines[i])
					}
					break
				}
				if keep {
					out = append(out, lines[i])
				}
			}
		}
	}
	return strings.Join(out, "\n")
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// inQuotes reports whether the end of s is inside an unclosed quote.
func inQuotes(s string) bool {
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q == 0 && (c == '\'' || c == '"'):
			q = c
		case q != 0 && c == q && (q == '\'' || i == 0 || s[i-1] != '\\'):
			q = 0
		}
	}
	return q != 0
}

var interpreters = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "fish": true, "python": true, "python3": true,
	"node": true, "perl": true, "ruby": true, "php": true, "pwsh": true, "powershell": true, "osascript": true, "deno": true, "bun": true, "eval": true, "source": true, ".": true}

// feedsInterpreter: the stage the heredoc is attached to runs its stdin.
func feedsInterpreter(before string) bool {
	st := Stages(before)
	if len(st) == 0 {
		return false
	}
	v := Verb(st[len(st)-1].Text)
	if strings.HasPrefix(v, "python") {
		v = "python"
	}
	return interpreters[v] || v == "sudo" && strings.Contains(before, "sh")
}

// searchVerbs only read, search or print their arguments: a string that
// appears as their argument was looked for, not used.
var searchVerbs = map[string]bool{"grep": true, "egrep": true, "fgrep": true, "rg": true, "ag": true, "ack": true, "echo": true, "printf": true,
	"cat": true, "sed": true, "awk": true, "jq": true, "head": true, "tail": true, "less": true, "more": true, "wc": true, "ls": true, "test": true,
	"stat": true, "file": true, "git": false, "strings": true, "diff": true, "sort": true, "uniq": true, "cut": true, "tr": true, "xxd": false}

// IsSearchVerb reports whether a stage's verb only reads or prints.
func IsSearchVerb(verb string) bool { return searchVerbs[verb] }
