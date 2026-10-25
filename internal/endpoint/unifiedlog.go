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
//	process  sudo messages with a COMMAND= line (same parser as auth.log)
//	auth     sshd messages Accepted/Failed/Invalid user (same parser as
//	         auth.log); otherwise any message from opendirectoryd, authd,
//	         loginwindow, sshd/sshd-session, sudo, su or login, or from the
//	         subsystems com.apple.opendirectoryd, com.apple.Authorization,
//	         com.apple.loginwindow.logging, com.openssh.sshd, kept raw
//	tcc      subsystem com.apple.TCC; the kTCCService… name when the
//	         message carries one, otherwise the raw message only
//	log      everything else, raw, for the timeline
//
// Fields come only from the export: processImagePath, processID,
// userID, subsystem, category, eventMessage. Nothing is inferred.

// FormatUnifiedLog names the unified log adapter.
const FormatUnifiedLog Format = "unifiedlog"

// ulMaxLogRecords bounds the kind-log records kept from one export; a
// busy Mac writes thousands of messages a second. Mapped kinds (process,
// auth, tcc) are not bounded by it.
const ulMaxLogRecords = 200_000

var (
	ulAuthProcs = map[string]bool{"opendirectoryd": true, "authd": true, "loginwindow": true, "sshd": true,
		"sshd-session": true, "sudo": true, "su": true, "login": true}
	ulAuthSubsystems = map[string]bool{"com.apple.opendirectoryd": true, "com.apple.Authorization": true,
		"com.apple.loginwindow.logging": true, "com.openssh.sshd": true}
	tccServiceRe = regexp.MustCompile(`\bkTCCService[A-Za-z0-9_]+`)
)

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
func (p *ulParser) array(r io.Reader, base string) error {
	dec := json.NewDecoder(r)
	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("unified log json array: %w", err)
	}
	for i := 0; dec.More(); i++ {
		var e ulEntry
		if err := dec.Decode(&e); err != nil {
			var se *json.SyntaxError
			if errors.As(err, &se) || errors.Is(err, io.ErrUnexpectedEOF) {
				p.res.problem(fmt.Sprintf("%s[%d]: %v (rest of the array not read)", base, i, err))
				return nil
			}
			p.res.problem(fmt.Sprintf("%s[%d]: %v", base, i, err))
			continue
		}
		p.entry(e, fmt.Sprintf("%s[%d]", base, i))
	}
	return nil
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
	prog := baseName(e.ProcessImagePath)
	r := Record{Time: t, Source: "unifiedlog", Ref: ref, PID: e.ProcessID, Exe: clip(e.ProcessImagePath, esMaxText)}
	if uid := strings.Trim(strings.TrimSpace(string(e.UserID)), `"`); uid != "" && uid != "null" {
		r.UID = clip(uid, 16)
	}
	switch {
	case e.Subsystem == "com.apple.TCC":
		r.Kind, r.Operation = KindTCC, strings.TrimSpace("tcc "+e.Category)
		r.Resource = tccServiceRe.FindString(msg)
		r.Message = clip(msg, esMaxText)
	case ulAuthProcs[prog] || ulAuthSubsystems[e.Subsystem]:
		name := strings.ToLower(prog)
		if name == "sshd-session" {
			name = "sshd"
		}
		if ar, ok := authRecord(name, msg, e.ProcessID, t, ref, "unifiedlog"); ok {
			ar.Exe, ar.UID, ar.Message = r.Exe, r.UID, clip(msg, esMaxText)
			if ar.Kind == "process" {
				ar.Exe = firstField(ar.Cmdline)
			}
			r = ar
			break
		}
		r.Kind, r.Operation, r.Message = "auth", ulOperation(e, prog), clip(msg, esMaxText)
	default:
		if p.logs >= ulMaxLogRecords {
			if !p.capped {
				p.capped = true
				p.res.note(fmt.Sprintf("unified log: messages past %d kind-log records not kept (bound); mapped auth/tcc/process records still read", ulMaxLogRecords))
			}
			p.res.ignore()
			return
		}
		p.logs++
		r.Kind, r.Operation, r.Message = KindLog, ulOperation(e, prog), clip(msg, esMaxText)
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
