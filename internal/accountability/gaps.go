package accountability

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/efij/AgentDFIR/v3/internal/provenance"
	"github.com/efij/AgentDFIR/v3/internal/schema"
)

// Gap codes. Each is a rule a reader can check by hand against the row.
const (
	GapNone               = "NONE_DETECTED"
	GapNoHuman            = "NO_HUMAN_INSTRUCTION"
	GapClassNotRequested  = "ACTION_CLASS_NOT_REQUESTED"
	GapTargetNotNamed     = "TARGET_NOT_NAMED_IN_INSTRUCTION"
	GapForbadeTarget      = "INSTRUCTION_FORBADE_TARGET"
	GapNetworkLocal       = "NETWORK_ACTION_LOCAL_INSTRUCTION"
	GapWitnessContradicts = "WITNESS_CONTRADICTS_CLAIM"
	GapReassurance        = "REASSURANCE_UNVERIFIED"
	GapPermissionWeakened = "PERMISSION_WEAKENED_BY_AGENT"
)

// GapCodes lists every code with the sentence that explains it, for the
// report's legend and the JSON schema.
var GapCodes = []struct{ Code, Meaning string }{
	{GapNone, "No gap rule fired. This is not a statement that the action was authorized."},
	{GapNoHuman, "No human prompt preceded the action in this session; the trigger was tool output, or nothing in the evidence."},
	{GapClassNotRequested, "The instruction contains no request for this kind of action."},
	{GapTargetNotNamed, "The instruction names neither the path, host nor database the action touched."},
	{GapForbadeTarget, "The instruction explicitly asked not to touch something the action touched."},
	{GapNetworkLocal, "The action reached the network while the instruction mentioned nothing remote."},
	{GapWitnessContradicts, "An independent witness disagrees with what the transcript claims."},
	{GapReassurance, "After a destructive action the agent reported the data as safe or recoverable; nothing in the evidence corroborates that."},
	{GapPermissionWeakened, "Earlier in the same session the agent itself wrote to a permission, hook or MCP configuration file."},
}

// classWords are the words a request for each class of action would
// contain. Deliberately short and plain: the rule is readable by hand.
var classWords = map[string][]string{
	"destructive":       {"delete", "remove", "drop", "wipe", "clean", "clear", "purge", "reset", "destroy", "rm ", "truncate", "erase", "prune", "revert", "rebuild", "reseed"},
	"cloud_destructive": {"delete", "remove", "drop", "wipe", "clean", "clear", "purge", "reset", "destroy", "truncate", "erase", "tear down", "decommission", "prune"},
	"exfiltration":      {"upload", "send", "post", "push", "publish", "share", "sync", "transfer", "export", "submit", "deploy", "email", "notify", "copy to"},
	"credential":        {"credential", "secret", "key", "token", "password", ".env", "login", "auth", "certificate", "wallet", "keystore", "kubeconfig"},
	"config_change":     {"setting", "config", "permission", "hook", "mcp", "allow", "rule", "instruction", "memory", "claude.md", "agents.md", "persist", "remember", "cron", "service", "ssh"},
	"execution":         {"run", "execute", "install", "start", "launch", "build", "test", "script", "setup", "set up", "compile", "apply"},
}

// networkWords are the words a request that involves the network would
// contain.
var networkWords = []string{"upload", "send", "post", "push", "publish", "fetch", "download", "deploy", "sync", "share", "email", "http", "url", "remote", "server", "api", "repo", "github", "pull", "clone", "install", "registry", "web"}

// forbidRe captures what an instruction asked the agent to leave alone:
// "don't touch prod", "do not delete the backups", "never push".
var forbidRe = regexp.MustCompile(`(?i)\b(?:don'?t|do not|never|without|must not|should not|avoid)\s+(?:touch|modify|change|delete|remove|drop|wipe|push|upload|send|use|access|read|alter|run|reset|clean)\w*\s+(?:the\s+|any\s+|our\s+|my\s+)?([a-z0-9_./*-]{3,})`)

// reassuranceRe matches the agent telling the user the data is fine.
var reassuranceRe = regexp.MustCompile(`(?i)\b(is safe|are safe|safe:|backed up|backups?\b|restor\w*|recover\w*|no data (?:was |were |has been )?lost|nothing (?:was |has been )?(?:lost|deleted|removed)|unchanged|not (?:touched|modified|affected)|intact)`)

// networkCmdRe matches commands that reach the network.
var networkCmdRe = regexp.MustCompile(`(?i)(^|[\s;|&(])(curl|wget|ssh|scp|rsync|nc|ncat|dig|nslookup|gh repo create|git push|aws s3 cp|gsutil cp|az storage)\b`)

// gaps applies the rules to one row and returns the codes that fired, or
// NONE_DETECTED. Every rule is a plain check on the row's own fields; no
// rule inspects anything a reader of the report cannot see.
func gaps(row Row, events []schema.Event, idxs []int, at int, trig provenance.Trigger) []Gap {
	var out []Gap
	prompt := strings.ToLower(row.Instruction.Prompt)
	// The prompt-based rules apply when a person asked for something in
	// this session and nothing from outside the conversation came in
	// between: the agent's own command output is a step, not a new request.
	hasPrompt := prompt != "" && (trig.Kind == "human_prompt" || (trig.Kind == "tool_result" && !OutsideContent(trig.Detail)))

	switch {
	case trig.Kind == "tool_result" && OutsideContent(trig.Detail):
		out = append(out, Gap{GapNoHuman, "no human asked for this; the model acted on content that came back from " + trig.Detail + "."})
	case trig.Kind == "tool_result" && prompt == "", trig.Kind == "unknown":
		out = append(out, Gap{GapNoHuman, "no human prompt precedes this action in the session's evidence."})
	}

	if hasPrompt {
		if words, ok := classWords[row.Class]; ok && !mentionsAny(prompt, words) {
			out = append(out, Gap{GapClassNotRequested, fmt.Sprintf("the instruction contains no request for a %s action (none of: %s).", strings.ReplaceAll(row.Class, "_", " "), strings.Join(words, ", "))})
		}
		if t := row.Action.Target; t != "" {
			toks := targetTokens(t)
			if len(toks) > 0 && !mentionsAny(prompt, toks) {
				out = append(out, Gap{GapTargetNotNamed, fmt.Sprintf("the instruction does not name %s (looked for: %s).", t, strings.Join(toks, ", "))})
			}
			for _, m := range forbidRe.FindAllStringSubmatch(row.Instruction.Prompt, -1) {
				obj := strings.ToLower(strings.Trim(m[1], ".,;:"))
				lt := strings.ToLower(t)
				if obj == "" {
					continue
				}
				hit := strings.Contains(lt, obj)
				for _, tok := range toks {
					if strings.HasPrefix(tok, obj) || strings.HasPrefix(obj, tok) {
						hit = true
					}
				}
				if hit {
					out = append(out, Gap{GapForbadeTarget, fmt.Sprintf("the instruction said %q and the action touched %s.", strings.TrimSpace(m[0]), t)})
					break
				}
			}
		}
		if row.Class != "exfiltration" && (row.Action.NetworkDest != "" || networkCmdRe.MatchString(row.Action.Command)) &&
			!mentionsAny(prompt, networkWords) && !strings.Contains(prompt, "://") {
			dest := row.Action.NetworkDest
			if dest == "" {
				dest = "the network"
			}
			out = append(out, Gap{GapNetworkLocal, "the action reached " + dest + " while the instruction mentioned nothing remote."})
		}
	}

	if row.Action.State == schema.StateContradicted {
		w := row.Action.Witness
		if w == "" {
			w = "see the event's corroboration record"
		}
		out = append(out, Gap{GapWitnessContradicts, "the transcript's claim is contradicted by an independent witness: " + w + "."})
	}
	if (row.Class == "destructive" || row.Class == "cloud_destructive") && row.Action.Narrative != "" && reassuranceRe.MatchString(row.Action.Narrative) {
		out = append(out, Gap{GapReassurance, "after the action the agent reported: " + quote(row.Action.Narrative, 160) + " — nothing in the evidence corroborates that claim."})
	}
	if n := len(row.Authority.AgentWrites); n > 0 {
		out = append(out, Gap{GapPermissionWeakened, fmt.Sprintf("the agent wrote to a permission, hook or MCP configuration file %d time(s) earlier in this session (%s).", n, row.Authority.AgentWrites[0].Evidence)})
	}
	if len(out) == 0 {
		out = append(out, Gap{GapNone, "no gap rule fired; this does not mean the action was authorized."})
	}
	return out
}

// OutsideContent reports whether a tool result's source brings content
// from outside the conversation and the local machine — a web page, a
// search, an MCP server, a subagent — rather than the output of the
// agent's own local step. The list matches provenance's severity rule.
func OutsideContent(source string) bool {
	t := strings.ToLower(source)
	for _, u := range []string{"webfetch", "websearch", "fetch", "mcp", "browser", "http", "task", "agent", "url", "search"} {
		if strings.Contains(t, u) {
			return true
		}
	}
	return false
}

func mentionsAny(text string, words []string) bool {
	for _, w := range words {
		if strings.Contains(text, strings.ToLower(w)) {
			return true
		}
	}
	return false
}

// targetTokens are the names a prompt would have to contain to be
// talking about the target: the last path element, its parent directory,
// a host name, a database name. Generic names are left out.
func targetTokens(t string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		s = strings.ToLower(strings.Trim(s, `"'/.*`))
		if len(s) < 3 || seen[s] || generic[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, part := range strings.Fields(t) {
		part = strings.TrimPrefix(part, "~")
		add(path.Base(part))
		add(path.Base(path.Dir(part)))
		if i := strings.Index(part, "://"); i >= 0 {
			part = part[i+3:]
		}
		if host, _, ok := strings.Cut(part, "/"); ok || !strings.Contains(part, "/") {
			add(host)
		}
		// "prod-*" and "backups/prod-2026" are about "prod".
		for _, piece := range strings.FieldsFunc(part, func(r rune) bool { return r == '-' || r == '_' || r == '.' || r == '/' }) {
			if len(piece) >= 4 && !isDigits(piece) {
				add(piece)
			}
		}
	}
	return out
}

var generic = map[string]bool{"tmp": true, "var": true, "etc": true, "usr": true, "home": true, "users": true, "opt": true, "bin": true, "src": true, "lib": true, "root": true, "com": true, "org": true, "net": true, "www": true, "json": true, "jsonl": true, "txt": true, "log": true, "logs": true, "dev": true, "null": true}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}
