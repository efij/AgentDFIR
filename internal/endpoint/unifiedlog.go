package endpoint

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// The macOS unified log exported with
//
//	log show --style ndjson [--last 1h | --start … --end …] [--predicate …]
//	log show --style json   (one JSON array)
//
// No root is needed for the default store; private message arguments
// show as <private> unless the host enables them. The unified log does
// not carry exec argv and is not exhaustive process telemetry, so its
// records are a partial-coverage witness (IsSighting): they corroborate,
// never contradict, never widen coverage.
//
// The mapping is deliberately small:
//
//	auth     sshd messages Accepted/Failed/Invalid user (same parser as
//	         auth.log); otherwise any message from opendirectoryd, authd,
//	         loginwindow, sshd/sshd-session, sudo, su or login, kept raw
//	tcc      tccd (subsystem com.apple.TCC); the kTCCService… name when
//	         the message carries one, otherwise the raw message only
//	log      everything else, raw, for the timeline. sudo COMMAND= lines
//	         are kept as log (operation sudo-command, command line in
//	         Cmdline): a log line is not execution telemetry and never
//	         corroborates.
//
// A sender is genuine only when processImagePath is that binary's exact
// path and the subsystem is one it uses (see ulSenders); anything else,
// including a look-alike basename or a borrowed subsystem name, is log.
//
// Fields come only from the export: processImagePath, processID,
// userID, subsystem, category, eventMessage. Nothing is inferred.

// FormatUnifiedLog names the unified log adapter.
const FormatUnifiedLog Format = "unifiedlog"

// ulMaxLogRecords bounds the kind-log records kept from one export; a
// busy Mac writes thousands of messages a second. Mapped kinds (process,
// auth, tcc) are not bounded by it.
const ulMaxLogRecords = 200_000

// ulSenders is the mapping table: a message maps to auth or tcc only when
// processImagePath is the exact path of the system binary that writes
// it AND the subsystem is one that binary uses. Any process can write to
// the unified log under any subsystem name, and a basename is free to
// choose (/tmp/sudo), so neither alone is trusted. Everything else is
// kind log.
var ulSenders = map[string]struct {
	prog       string
	subsystems []string
}{
	"/usr/bin/sudo":               {"sudo", []string{"", "com.apple.sudo"}},
	"/usr/bin/su":                 {"su", []string{"", "com.apple.su"}},
	"/usr/bin/login":              {"login", []string{"", "com.apple.login"}},
	"/usr/sbin/sshd":              {"sshd", []string{"", "com.openssh.sshd"}},
	"/usr/libexec/sshd-session":   {"sshd", []string{"", "com.openssh.sshd"}},
	"/usr/libexec/opendirectoryd": {"opendirectoryd", []string{"com.apple.opendirectoryd"}},
	"/System/Library/Frameworks/Security.framework/Versions/A/MachServices/authd.xpc/Contents/MacOS/authd": {"authd", []string{"com.apple.Authorization"}},
	"/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow":                              {"loginwindow", []string{"com.apple.loginwindow.logging"}},
	"/System/Library/PrivateFrameworks/TCC.framework/Support/tccd":                                         {"tccd", []string{"com.apple.TCC"}},
}

// ulSender returns the program name of a genuine sender, or "".
func ulSender(image, subsystem string) string {
	s, ok := ulSenders[image]
	if !ok {
		return ""
	}
	for _, sub := range s.subsystems {
		if sub == subsystem {
			return s.prog
		}
	}
	return ""
}

var tccServiceRe = regexp.MustCompile(`\bkTCCService[A-Za-z0-9_]+`)

type ulEntry struct {
	Timestamp        string          `json:"timestamp"`
	EventType        string          `json:"eventType"`
	MessageType      string          `json:"messageType"`
	EventMessage     *string         `json:"eventMessage"`
	Subsystem        string          `json:"subsystem"`
	Category         string          `json:"category"`
	ProcessImagePath string          `json:"processImagePath"`
	ProcessID        int             `json:"processID"`
	UserID           json.RawMessage `json:"userID"`
	Finished         *int            `json:"finished"`
	Count            *int            `json:"count"`
}

type ulParser struct {
	res    *LoadResult
	logs   int
	losses int
	capped bool
}

func loadUnifiedLog(path string) (*LoadResult, error) {
	p := &ulParser{res: &LoadResult{}}
	base := baseName(path)
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	br := bufio.NewReader(f)
	first, _ := br.Peek(4096)
	first = bytes.TrimLeft(first, "\xef\xbb\xbf \t\r\n")
	if bytes.HasPrefix(first, []byte("[")) {
		err = p.array(br, base)
	} else {
		err = scanLines(path, func(line string, n int) {
			line = strings.TrimSpace(line)
			if line == "" {
				return
			}
			var e ulEntry
			if err := json.Unmarshal([]byte(line), &e); err != nil {
				p.res.problem(fmt.Sprintf("line %d: %v", n, err))
				return
			}
			p.entry(e, fmt.Sprintf("%s:%d", base, n))
		})
	}
	p.finish()
	return p.res, err
}

// array streams a `log show --style json` array element by element.
// Each element is cut out by a bounded scanner and decoded on its own, so
// one oversized element costs that element (maxLineBytes, like a line in
// ndjson), never unbounded memory.
func (p *ulParser) array(r *bufio.Reader, base string) error {
	if err := skipTo(r, '['); err != nil {
		return fmt.Errorf("unified log json array: %w", err)
	}
	for i := 0; ; i++ {
		elem, over, end, err := nextElement(r, maxLineBytes)
		if end {
			return nil
		}
		if over {
			p.res.problem(fmt.Sprintf("%s[%d]: element exceeds %d bytes, not read", base, i, maxLineBytes))
		} else if len(elem) > 0 {
			var e ulEntry
			if jerr := json.Unmarshal(elem, &e); jerr != nil {
				p.res.problem(fmt.Sprintf("%s[%d]: %v", base, i, jerr))
			} else {
				p.entry(e, fmt.Sprintf("%s[%d]", base, i))
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) || len(elem) > 0 || over {
				p.res.problem(fmt.Sprintf("%s[%d]: array ends early (%v); rest not read", base, i, err))
			}
			return nil
		}
	}
}

// skipTo consumes input up to and including the byte c, past whitespace
// and a UTF-8 BOM only.
func skipTo(r *bufio.Reader, c byte) error {
	for {
		b, err := r.ReadByte()
		if err != nil {
			return err
		}
		switch b {
		case c:
			return nil
		case ' ', '\t', '\r', '\n', 0xef, 0xbb, 0xbf:
		default:
			return fmt.Errorf("unexpected byte %q before %q", b, c)
		}
	}
}

// nextElement reads one array element (an object or scalar) up to the
// comma or bracket that ends it. end reports the closing bracket with no
// element; over reports an element longer than max, which is consumed but
// not returned. Strings and nesting are tracked so commas inside them do
// not split.
func nextElement(r *bufio.Reader, max int) (elem []byte, over, end bool, err error) {
	depth, inStr, esc, started := 0, false, false, false
	var buf []byte
	for {
		b, rerr := r.ReadByte()
		if rerr != nil {
			if over {
				return nil, true, false, rerr
			}
			return buf, false, false, rerr
		}
		if !started {
			switch b {
			case ' ', '\t', '\r', '\n', ',':
				continue
			case ']':
				return nil, false, true, nil
			}
			started = true
		}
		if !inStr && depth == 0 && (b == ',' || b == ']') {
			if b == ']' {
				_ = r.UnreadByte()
			}
			if over {
				return nil, true, false, nil
			}
			return buf, false, false, nil
		}
		switch {
		case inStr && esc:
			esc = false
		case inStr && b == '\\':
			esc = true
		case inStr && b == '"':
			inStr = false
		case !inStr && b == '"':
			inStr = true
		case !inStr && (b == '{' || b == '['):
			depth++
		case !inStr && (b == '}' || b == ']'):
			depth--
		}
		if !over {
			if len(buf) >= max {
				over, buf = true, nil
			} else {
				buf = append(buf, b)
			}
		}
	}
}

func (p *ulParser) entry(e ulEntry, ref string) {
	if e.EventMessage == nil && e.Timestamp == "" && e.Finished != nil {
		return // the {"count":N,"finished":1} trailer `log show` writes
	}
	t, ok := parseTime(e.Timestamp)
	if !ok {
		p.res.problem(ref + ": no recognizable timestamp")
		return
	}
	msg := ""
	if e.EventMessage != nil {
		msg = *e.EventMessage
	}
	if e.EventType == "lossEvent" {
		p.losses++
	}
	sender := ulSender(e.ProcessImagePath, e.Subsystem)
	r := Record{Time: t, Source: "unifiedlog", Ref: ref, PID: e.ProcessID, Exe: clip(e.ProcessImagePath, esMaxText)}
	if uid := strings.Trim(strings.TrimSpace(string(e.UserID)), `"`); uid != "" && uid != "null" {
		r.UID = clip(uid, 16)
	}
	switch {
	case sender == "tccd":
		r.Kind, r.Operation = KindTCC, strings.TrimSpace("tcc "+e.Category)
		r.Resource = tccServiceRe.FindString(msg)
		r.Message = clip(msg, esMaxText)
	case sender != "":
		if ar, ok := authRecord(sender, msg, e.ProcessID, t, ref, "unifiedlog"); ok {
			// The sender's own image stays the record's Exe; a value parsed
			// from the message never replaces it.
			ar.Exe, ar.UID, ar.Message = r.Exe, r.UID, clip(msg, esMaxText)
			if ar.Kind == "process" {
				// A log line naming a command is not execution telemetry:
				// kept as a log record that never corroborates.
				ar.Kind, ar.Operation = KindLog, "sudo-command"
			}
			r = ar
			break
		}
		r.Kind, r.Operation, r.Message = "auth", ulOperation(e, sender), clip(msg, esMaxText)
	default:
		if p.logs >= ulMaxLogRecords {
			if !p.capped {
				p.capped = true
				p.res.note(fmt.Sprintf("unified log: messages past %d kind-log records not kept (bound); mapped auth/tcc records still read", ulMaxLogRecords))
			}
			p.res.ignore()
			return
		}
		p.logs++
		r.Kind, r.Operation, r.Message = KindLog, ulOperation(e, baseName(e.ProcessImagePath)), clip(msg, esMaxText)
	}
	p.res.Records = append(p.res.Records, r)
}

// ulOperation names where a message came from: subsystem/category, or
// the process when the message has no subsystem.
func ulOperation(e ulEntry, prog string) string {
	switch {
	case e.Subsystem != "" && e.Category != "":
		return clip(e.Subsystem+"/"+e.Category, 256)
	case e.Subsystem != "":
		return clip(e.Subsystem, 256)
	}
	return clip(prog, 256)
}

func (p *ulParser) finish() {
	if p.losses > 0 {
		p.res.notice(strconv.Itoa(p.losses) + " unified log lossEvent record(s): the log itself reports dropped messages in this range")
	}
}

// sniffUnifiedLog: `log show` ndjson or json output.
func sniffUnifiedLog(head []byte) bool {
	if !bytes.HasPrefix(head, []byte("{")) && !bytes.HasPrefix(head, []byte("[")) {
		return false
	}
	return bytes.Contains(head, []byte(`"eventMessage"`)) && bytes.Contains(head, []byte(`"processImagePath"`))
}
