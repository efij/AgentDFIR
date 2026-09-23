// Package shellshape answers shape questions about a shell command line
// that several detection rules share: what the shell would actually run
// once heredoc bodies and quoted strings are set aside, which paths are
// scratch space, and which evidence paths belong to agentdfir itself.
//
// Rules that match a verb or a pipe anywhere in the line saw `curl … | sh`
// inside a `git commit -m "…"` message, a URL inside a Python docstring
// written through a heredoc, and `.claude.json` under a test fixture in a
// scratchpad, and reported each as the agent doing the thing. The helpers
// here give those rules the command as the shell sees it.
package shellshape

import (
	"path"
	"regexp"
	"strings"
)

// Strip returns cmd with heredoc bodies removed and the contents of quoted
// prose emptied, so that shell-shape regexes see only what the shell itself
// parses as commands, pipes, flags and arguments. A quoted token with no
// whitespace (a URL, a path) is an argument and is kept; a quoted script
// handed to a shell with -c (`bash -c '…'`) is a command line and is kept.
func Strip(cmd string) string {
	var b strings.Builder
	b.Grow(len(cmd))
	rs := []rune(cmd)
	n := len(rs)
	for i := 0; i < n; {
		c := rs[i]
		switch {
		case c == '<' && i+1 < n && rs[i+1] == '<':
			// Heredoc: <<TAG, <<-TAG, <<'TAG', <<"TAG". Keep the marker,
			// drop everything through the terminator line.
			j := i + 2
			if j < n && rs[j] == '-' {
				j++
			}
			for j < n && rs[j] == ' ' {
				j++
			}
			quote := rune(0)
			if j < n && (rs[j] == '\'' || rs[j] == '"') {
				quote = rs[j]
				j++
			}
			start := j
			for j < n && (rs[j] == '_' || rs[j] == '-' || isAlnum(rs[j])) {
				j++
			}
			tag := string(rs[start:j])
			if quote != 0 && j < n && rs[j] == quote {
				j++
			}
			if tag == "" {
				b.WriteRune(c)
				i++
				continue
			}
			b.WriteString("<<" + tag)
			// Rest of the current line stays (e.g. `<<EOF > file`).
			for j < n && rs[j] != '\n' {
				b.WriteRune(rs[j])
				j++
			}
			// Skip lines until the terminator.
			for j < n {
				j++ // past '\n'
				ls := j
				for j < n && rs[j] != '\n' {
					j++
				}
				if strings.TrimSpace(string(rs[ls:j])) == tag {
					break
				}
			}
			i = j
		case c == '\'' || c == '"':
			j := i + 1
			for j < n && rs[j] != c {
				if c == '"' && rs[j] == '\\' && j+1 < n {
					j++
				}
				j++
			}
			// A quoted token without whitespace is an argument (a URL, a
			// path, a header value), not prose; keep it so `curl "https://…"`
			// still shows its destination. Prose and scripts are emptied,
			// except a script handed to a shell with -c.
			body := ""
			inner := string(rs[i+1 : min(j, n)])
			if shellDashC(b.String()) || !strings.ContainsAny(inner, " \t\n") {
				body = inner
			}
			b.WriteRune(c)
			b.WriteString(body)
			b.WriteRune(c)
			i = j + 1
		default:
			b.WriteRune(c)
			i++
		}
	}
	return b.String()
}

// shellDashC reports whether the text so far ends with a shell verb's -c
// flag, i.e. the quoted string that follows is itself a command line.
func shellDashC(prefix string) bool {
	f := strings.Fields(prefix)
	if len(f) < 2 || f[len(f)-1] != "-c" {
		return false
	}
	v := f[len(f)-2]
	if i := strings.LastIndex(v, "/"); i >= 0 {
		v = v[i+1:]
	}
	switch v {
	case "sh", "bash", "zsh", "dash", "ksh":
		return true
	}
	return false
}

var assignRe = regexp.MustCompile(`(?m)^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=("([^"]*)"|'([^']*)'|(\S+))`)

// ExpandVars substitutes the simple `VAR=value` assignments a command line
// makes into its later `$VAR` / `${VAR}` uses. Test harnesses write
// `S=/tmp/…/scratchpad` once and then build fixtures under `$S`; without
// expansion a rule sees `$S/victim-home/.claude.json` and cannot tell it
// is scratch space.
func ExpandVars(cmd string) string {
	vals := map[string]string{}
	for _, m := range assignRe.FindAllStringSubmatch(cmd, -1) {
		v := m[3]
		if v == "" {
			v = m[4]
		}
		if v == "" {
			v = m[5]
		}
		vals[m[1]] = v
	}
	if len(vals) == 0 {
		return cmd
	}
	out := cmd
	for k, v := range vals {
		if strings.Contains(v, "$") {
			continue
		}
		out = strings.ReplaceAll(out, "${"+k+"}", v)
		out = strings.ReplaceAll(out, "$"+k+"/", v+"/")
		out = strings.ReplaceAll(out, "$"+k+" ", v+" ")
		if strings.HasSuffix(out, "$"+k) {
			out = strings.TrimSuffix(out, "$"+k) + v
		}
	}
	return out
}

// IsScratchPath reports whether a path is a temporary or build location,
// where deletion and writing are routine rather than notable.
func IsScratchPath(p string) bool {
	l := strings.ToLower(p)
	for _, frag := range []string{"/tmp/", "/private/tmp/", "/var/folders/", "scratchpad",
		"node_modules", "/dist/", "/build/", "/.cache/", "/target/", "/.next/", "/coverage/"} {
		if strings.Contains(l, frag) {
			return true
		}
	}
	return strings.HasPrefix(l, "/tmp") || strings.HasSuffix(l, "/dist") || strings.HasSuffix(l, "/build")
}

// SelfReferentialPath reports whether an evidence path belongs to
// agentdfir's own rules, fixtures or development, where the phrases and
// markers the rules look for appear because someone was writing the rule.
func SelfReferentialPath(p string) bool {
	l := strings.ToLower(p)
	for _, frag := range []string{
		"signatures", "/rules/", "rule-pack", "rulepack", "prompt-injection",
		"/detect/", "/fixtures/", "/testdata/", "_test.", "agentdfir", "runwall",
	} {
		if strings.Contains(l, frag) {
			return true
		}
	}
	return false
}

// Stages splits a command line into the units the shell runs in order:
// on newlines, `;`, `&&`, `||` and `|`. Pipe boundaries are reported so a
// caller can tell `… | nc host 9` (data leaves) from `nc -z host 9`.
type Stage struct {
	Text  string
	Piped bool // this stage reads the previous stage's output
}

func Stages(cmd string) []Stage {
	var out []Stage
	cur := strings.Builder{}
	piped := false
	flush := func(nextPiped bool) {
		if strings.TrimSpace(cur.String()) != "" {
			out = append(out, Stage{Text: strings.TrimSpace(cur.String()), Piped: piped})
		}
		cur.Reset()
		piped = nextPiped
	}
	rs := []rune(cmd)
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		two := ""
		if i+1 < len(rs) {
			two = string(rs[i : i+2])
		}
		switch {
		case two == "&&" || two == "||":
			flush(false)
			i++
		case c == '|':
			flush(true)
		case c == ';' || c == '\n':
			flush(false)
		default:
			cur.WriteRune(c)
		}
	}
	flush(false)
	return out
}

// Verb returns the program a stage runs, without env assignments or a
// directory prefix.
func Verb(stage string) string {
	for _, f := range strings.Fields(stage) {
		if strings.Contains(f, "=") && !strings.HasPrefix(f, "-") {
			continue
		}
		if i := strings.LastIndex(f, "/"); i >= 0 && !strings.HasPrefix(f, "./") {
			f = f[i+1:]
		}
		return f
	}
	return ""
}

// DownloadThenExecute reports whether a command line downloads a file and
// then, in a later stage, runs or marks executable that same file. Any
// interpreter after any download is not enough: `curl -o paper.pdf … &&
// python3 -c "count pages"` runs unrelated code and the payload never
// executes.
func DownloadThenExecute(cmd string) bool {
	stages := Stages(Strip(ExpandVars(cmd)))
	downloaded := map[string]bool{}
	for _, st := range stages {
		f := strings.Fields(st.Text)
		if len(f) == 0 {
			continue
		}
		v := Verb(st.Text)
		switch v {
		case "curl", "wget":
			for i, a := range f {
				switch {
				case a == "-o" || a == "--output" || a == "-O" && v == "wget":
					if i+1 < len(f) {
						downloaded[path.Base(strings.Trim(f[i+1], `"'`))] = true
					}
				case strings.HasPrefix(a, "--output="):
					downloaded[path.Base(strings.TrimPrefix(a, "--output="))] = true
				case a == "-O" && v == "curl", v == "wget" && strings.Contains(a, "://") && !hasFlag(f, "-O", "-o", "--output"):
					// Saved under the URL's basename.
					for _, u := range f {
						if strings.Contains(u, "://") {
							downloaded[path.Base(strings.Trim(u, `"'`))] = true
						}
					}
				}
			}
			continue
		}
		if len(downloaded) == 0 {
			continue
		}
		exec := false
		switch {
		case v == "chmod":
			exec = hasFlag(f, "+x")
		case v == "sh", v == "bash", v == "zsh", v == "dash", v == "source", v == ".",
			v == "perl", v == "node", v == "ruby", v == "php", strings.HasPrefix(v, "python"):
			exec = true
		case strings.HasPrefix(v, "./"):
			if downloaded[path.Base(v)] {
				return true
			}
		}
		if !exec {
			continue
		}
		for _, a := range f[1:] {
			if downloaded[path.Base(strings.Trim(a, `"'`))] {
				return true
			}
		}
	}
	return false
}

func hasFlag(fields []string, flags ...string) bool {
	for _, f := range fields {
		for _, fl := range flags {
			if f == fl {
				return true
			}
		}
	}
	return false
}

func isAlnum(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
}
