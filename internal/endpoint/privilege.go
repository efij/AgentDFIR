package endpoint

import (
	"regexp"
	"strings"
	"time"
)

// Privilege changes in auth.log / secure / the journal, as kind auth
// records with PrivFrom → PrivTo. They sit beside the records authRecord
// already produces and never replace them:
//
//   - sudo COMMAND= lines keep their process record (it corroborates the
//     command) and add an auth record Operation "sudo" carrying the user
//     change, TTY, working directory and command
//   - su session-opened / FAILED SU lines are already kind auth; authRecord
//     sets PrivFrom (by) and PrivTo (target) on them
//   - pam_unix(<service>:auth): authentication failure → Operation
//     "pam-auth-fail <service>" (sshd excluded: its "Failed password" line
//     is already an auth record)
//   - pkexec "Executing command" / "Error executing command" → a process
//     record (the command, like sudo) and an auth record Operation "pkexec"
//   - polkitd "Operator of … authenticated as unix-user:X to gain …
//     authorization for action A" → Operation "polkit <action>"

var (
	pamFailRe   = regexp.MustCompile(`pam_unix\(([^:)]+):auth\): authentication failure;(.*)$`)
	pamKVRe     = regexp.MustCompile(`(\w+)=(\S*)`)
	pkexecRe    = regexp.MustCompile(`^(\S+): (?:Executing command|Error executing command as another user: ([^\[]*?)) \[USER=([^\]]*)\] \[TTY=([^\]]*)\] \[CWD=([^\]]*)\] \[COMMAND=(.*)\]$`)
	polkitOpsRe = regexp.MustCompile(`^Operator of (\S+) (successfully authenticated|FAILED to authenticate) as unix-user:(\S+) to gain (\S+) authorization for action (\S+)`)
)

// authRecords maps one authentication message to every record it yields.
func authRecords(prog, msg string, pid int, t time.Time, at, source string) []Record {
	msg = strings.TrimSpace(msg)
	var out []Record
	if r, ok := authRecord(prog, msg, pid, t, at, source); ok {
		out = append(out, r)
		if prog == "sudo" && r.Kind == "process" {
			out = append(out, Record{Time: t, Kind: "auth", PID: pid, Operation: "sudo", User: r.PrivFrom, PrivFrom: r.PrivFrom, PrivTo: r.PrivTo,
				Cmdline: r.Cmdline, Cwd: r.Cwd, TTY: r.TTY, Failed: r.Failed, Source: source, Ref: at})
		}
		return out
	}
	if m := pamFailRe.FindStringSubmatch(msg); m != nil && m[1] != "sshd" {
		kv := map[string]string{}
		for _, p := range pamKVRe.FindAllStringSubmatch(m[2], -1) {
			kv[p[1]] = p[2]
		}
		from := firstNonEmpty(kv["ruser"], kv["logname"])
		return []Record{{Time: t, Kind: "auth", PID: pid, Operation: "pam-auth-fail " + m[1], User: from, PrivFrom: from, PrivTo: kv["user"],
			TTY: kv["tty"], SourceIP: kv["rhost"], Failed: "authentication failure", Source: source, Ref: at}}
	}
	switch prog {
	case "pkexec":
		if m := pkexecRe.FindStringSubmatch(msg); m != nil {
			cmd := strings.TrimSpace(m[6])
			p := Record{Time: t, Kind: "process", PID: pid, User: m[1], Cmdline: cmd, Exe: firstField(cmd), Resource: "USER=" + m[3],
				Cwd: m[5], TTY: m[4], PrivFrom: m[1], PrivTo: m[3], Failed: strings.TrimSpace(m[2]), Source: source, Ref: at}
			a := p
			a.Kind, a.Operation, a.Resource, a.Exe = "auth", "pkexec", "", ""
			if p.Cmdline == "" {
				return []Record{a}
			}
			return []Record{p, a}
		}
	case "polkitd":
		if m := polkitOpsRe.FindStringSubmatch(msg); m != nil {
			r := Record{Time: t, Kind: "auth", PID: pid, Operation: "polkit " + m[5], Resource: m[1], PrivTo: m[3], Source: source, Ref: at}
			if strings.HasPrefix(m[2], "FAILED") {
				r.Failed = "authentication failed"
			}
			return []Record{r}
		}
	}
	return nil
}
