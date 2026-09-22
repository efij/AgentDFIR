package detect

import "strings"

// Shell-shape helpers shared by the precision-sensitive rules.
//
// Several rules matched a verb anywhere in a command and a path anywhere in
// the same command, and called that a write. On real transcripts that
// turned `ls ~/.claude/skills; sed -n 61,140p SKILL.md` into "the agent
// modified its own configuration", and
// `rm -rf $S/perf && mkdir -p $S/perf/.claude/projects/-big` into "agent
// logs targeted for deletion" — the log path belonged to the mkdir.
//
// These helpers answer the narrower question the rules actually mean:
// which paths does this command *write to*, and which does a *particular*
// command in the pipeline act on.

// readOnlyVerbs never modify their arguments.
var readOnlyVerbs = map[string]bool{
	"ls": true, "cat": true, "head": true, "tail": true, "grep": true, "rg": true,
	"find": true, "stat": true, "file": true, "wc": true, "diff": true, "less": true,
	"more": true, "awk": true, "jq": true, "du": true, "tree": true, "pwd": true, "which": true,
}

// segments splits a command line into pipeline/sequence segments, so a rule
// can ask about one command rather than the whole line.
func segments(cmd string) []string {
	var out []string
	cur := strings.Builder{}
	runes := []rune(cmd)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		two := ""
		if i+1 < len(runes) {
			two = string(runes[i : i+2])
		}
		switch {
		case two == "&&" || two == "||":
			out = append(out, cur.String())
			cur.Reset()
			i++
		case c == ';' || c == '|' || c == '\n':
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(c)
		}
	}
	out = append(out, cur.String())
	return out
}

// verbOf returns the first word of a segment, without env assignments.
func verbOf(seg string) string {
	for _, f := range strings.Fields(seg) {
		if strings.Contains(f, "=") && !strings.HasPrefix(f, "-") {
			continue // VAR=value prefix
		}
		if i := strings.LastIndex(f, "/"); i >= 0 {
			f = f[i+1:]
		}
		return f
	}
	return ""
}

// IsReadOnlyCommand reports whether every segment of a command is a
// read-only inspection. `sed -n …p` prints; `sed -i` edits.
func IsReadOnlyCommand(cmd string) bool {
	any := false
	for _, seg := range segments(cmd) {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		if strings.ContainsAny(seg, ">") {
			return false
		}
		v := verbOf(seg)
		switch {
		case readOnlyVerbs[v]:
		case v == "sed" && !strings.Contains(seg, "-i"):
		case v == "":
			continue
		default:
			return false
		}
		any = true
	}
	return any
}

// WriteTargets returns the paths a command writes to: redirect targets,
// tee arguments, and the destination of cp/mv. It deliberately returns
// nothing for read-only commands, however many paths they mention.
func WriteTargets(cmd string) []string {
	var out []string
	for _, seg := range segments(cmd) {
		fields := strings.Fields(seg)
		for i, f := range fields {
			switch {
			case f == ">" || f == ">>":
				if i+1 < len(fields) {
					out = append(out, strings.Trim(fields[i+1], `"'`))
				}
			case strings.HasPrefix(f, ">>") && len(f) > 2:
				out = append(out, strings.Trim(f[2:], `"'`))
			case strings.HasPrefix(f, ">") && len(f) > 1:
				out = append(out, strings.Trim(f[1:], `"'`))
			}
		}
		switch verbOf(seg) {
		case "tee":
			for _, f := range fields[1:] {
				if !strings.HasPrefix(f, "-") {
					out = append(out, strings.Trim(f, `"'`))
				}
			}
		case "cp", "mv", "rsync", "install":
			var args []string
			for _, f := range fields[1:] {
				if !strings.HasPrefix(f, "-") {
					args = append(args, strings.Trim(f, `"'`))
				}
			}
			if len(args) >= 2 {
				out = append(out, args[len(args)-1])
			}
		}
	}
	return out
}

// DeleteTargets returns the arguments of delete-shaped commands only, so a
// log path mentioned by a later mkdir in the same line does not count.
func DeleteTargets(cmd string) []string {
	var out []string
	for _, seg := range segments(cmd) {
		switch verbOf(seg) {
		case "rm", "shred", "unlink", "srm":
			for _, f := range strings.Fields(seg)[1:] {
				if !strings.HasPrefix(f, "-") {
					out = append(out, strings.Trim(f, `"'`))
				}
			}
		case "truncate":
			for _, f := range strings.Fields(seg)[1:] {
				if !strings.HasPrefix(f, "-") && !strings.Contains(f, "=") {
					out = append(out, strings.Trim(f, `"'`))
				}
			}
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
