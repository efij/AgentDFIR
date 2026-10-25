package endpoint

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// macOS Endpoint Security telemetry as written by Apple's own ES client,
// /usr/bin/eslogger (macOS 13+; running it needs root and Full Disk
// Access for the launching terminal, no entitlement on our side):
//
//	eslogger exec fork exit open create close rename unlink ... --format json
//
// One JSON object per line. Every message carries schema_version,
// version (the ES message version), time, seq_num (per event type),
// global_seq_num (stream-wide), the acting process (es_process_t) and an
// "event" object with exactly one key, the event type name. The numeric
// event_type is ignored: the key is the type and does not shift between
// macOS releases.
//
// Mapping (kind ← ES event types):
//
//	process        exec (the new image: target, args, cwd)
//	process-fork   fork (child pid, parent pid)
//	process-exit   exit
//	file           open, create, write, close (only when modified), rename,
//	               unlink, truncate, clone, link
//	auth           authentication, openssh_login/logout, login_login/logout,
//	               lw_session_*, screensharing_attach/detach, sudo, su
//	persistence    btm_launch_item_add, btm_launch_item_remove
//	tcc            tcc_modify (macOS 15+)
//	av             xp_malware_detected, xp_malware_remediated
//	ipc            uipc_connect, uipc_bind (UNIX-domain sockets)
//	signal         signal, proc_suspend_resume
//
// Endpoint Security has no generic IP network event: eslogger shows
// UNIX-domain socket connects, not TCP/UDP connections, so it is never a
// network witness and never yields kind network. Every other event type
// is counted in LoadResult.Unsupported and reported as UNSUPPORTED, never
// dropped silently.

// FormatESLogger names the eslogger adapter.
const FormatESLogger Format = "eslogger"

// Kinds the macOS adapters add.
const (
	KindProcessFork = "process-fork"
	KindProcessExit = "process-exit"
	KindPersistence = "persistence"
	KindTCC         = "tcc"
	KindAV          = "av"
	KindIPC         = "ipc"
	KindSignal      = "signal"
	KindLog         = "log"
)

// Bounds on what one eslogger message may put into a Record.
const (
	esMaxArgs    = 256
	esMaxArg     = 4096
	esMaxCmdline = 32 << 10
	esMaxPIDMap  = 1 << 16
	esMaxText    = 1024
)

// esKnownSchema is the eslogger JSON schema_version this adapter was
// written against.
const esKnownSchema = 1

type esFile struct {
	Path      string `json:"path"`
	Truncated bool   `json:"truncated"`
}

type esToken struct {
	PID        int  `json:"pid"`
	PIDVersion int  `json:"pidversion"`
	EUID       *int `json:"euid"`
	RUID       *int `json:"ruid"`
	AUID       *int `json:"auid"`
	ASID       *int `json:"asid"`
}

type esProcess struct {
	AuditToken       esToken         `json:"audit_token"`
	ParentToken      *esToken        `json:"parent_audit_token"`
	ResponsibleToken *esToken        `json:"responsible_audit_token"`
	PPID             int             `json:"ppid"`
	OriginalPPID     int             `json:"original_ppid"`
	Executable       esFile          `json:"executable"`
	SigningID        *string         `json:"signing_id"`
	TeamID           *string         `json:"team_id"`
	CDHash           json.RawMessage `json:"cdhash"`
	IsPlatformBinary bool            `json:"is_platform_binary"`
	SessionID        int             `json:"session_id"`
	TTY              *esFile         `json:"tty"`
}

type esMessage struct {
	SchemaVersion *int                       `json:"schema_version"`
	Version       *int                       `json:"version"`
	Time          string                     `json:"time"`
	SeqNum        *uint64                    `json:"seq_num"`
	GlobalSeqNum  *uint64                    `json:"global_seq_num"`
	Process       *esProcess                 `json:"process"`
	Event         map[string]json.RawMessage `json:"event"`
}

// esUID is a uid as eslogger writes it: a bare number, or {"uid": n}.
type esUID struct{ v *int }

func (u *esUID) UnmarshalJSON(b []byte) error {
	var n int
	if json.Unmarshal(b, &n) == nil {
		u.v = &n
		return nil
	}
	var o struct {
		UID *int `json:"uid"`
	}
	if json.Unmarshal(b, &o) == nil {
		u.v = o.UID
	}
	return nil
}

func (u esUID) String() string {
	if u.v == nil {
		return ""
	}
	return strconv.Itoa(*u.v)
}

// ESParser turns eslogger JSON lines into Records. It keeps state across
// lines (the image last seen for each pid, version and type counts), so
// one parser reads one stream: a file, or `monitor --es` live output.
type ESParser struct {
	res      *LoadResult
	exeOf    map[int]string // pid → executable last seen for it in this stream
	types    map[string]int
	schemas  map[int]int
	versions map[int]int
	ignored  int // close events without modification
}

// NewESParser starts a parser.
func NewESParser() *ESParser {
	return &ESParser{res: &LoadResult{Format: FormatESLogger, Unsupported: map[string]int{}},
		exeOf: map[int]string{}, types: map[string]int{}, schemas: map[int]int{}, versions: map[int]int{}}
}

func loadESLogger(path string) (*LoadResult, error) {
	p := NewESParser()
	base := baseName(path)
	err := scanLines(path, func(line string, n int) {
		p.Line([]byte(line), fmt.Sprintf("%s:%d", base, n))
	})
	return p.Finish(), err
}

// Line parses one eslogger line. It returns the Record it produced, if
// any; problems and unsupported types are accounted in the result.
func (p *ESParser) Line(line []byte, ref string) (rec Record, ok bool) {
	defer func() {
		if r := recover(); r != nil { // hostile input must never take the reader down
			p.res.problem(fmt.Sprintf("%s: unreadable eslogger message (%v)", ref, r))
			rec, ok = Record{}, false
		}
	}()
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return Record{}, false
	}
	var m esMessage
	if err := json.Unmarshal(line, &m); err != nil {
		p.res.problem(fmt.Sprintf("%s: %v", ref, err))
		return Record{}, false
	}
	if len(m.Event) != 1 {
		p.res.problem(fmt.Sprintf("%s: not an eslogger message (event object has %d keys, want 1)", ref, len(m.Event)))
		return Record{}, false
	}
	var typ string
	var body json.RawMessage
	for k, v := range m.Event {
		typ, body = k, v
	}
	if m.SchemaVersion != nil {
		p.schemas[*m.SchemaVersion]++
	}
	if m.Version != nil {
		p.versions[*m.Version]++
	}
	p.types[typ]++
	ts, tok := parseTime(m.Time)
	if !tok {
		p.res.problem(ref + ": no recognizable timestamp")
		return Record{}, false
	}
	if m.Process != nil && m.Process.AuditToken.PID != 0 && m.Process.Executable.Path != "" {
		p.remember(m.Process.AuditToken.PID, m.Process.Executable.Path)
	}
	r := Record{Time: ts, Source: "eslogger", Ref: ref, Operation: typ}
	if m.SeqNum != nil {
		r.Seq, r.SeqDomain = *m.SeqNum, "eslogger/"+typ
	}
	if m.GlobalSeqNum != nil {
		r.GlobalSeq = *m.GlobalSeqNum
	}
	if m.Process != nil {
		setActor(&r, m.Process)
	}
	mapped, keep := p.mapEvent(&r, typ, body, ref)
	if !mapped {
		p.res.Unsupported[typ]++
		p.res.Skipped++
		return Record{}, false
	}
	if !keep {
		return Record{}, false
	}
	p.res.Records = append(p.res.Records, r)
	return r, true
}

// remember records the image of a pid, bounded.
func (p *ESParser) remember(pid int, exe string) {
	if _, ok := p.exeOf[pid]; ok || len(p.exeOf) < esMaxPIDMap {
		p.exeOf[pid] = exe
	}
}

// setActor fills a record's process identity from an es_process_t.
func setActor(r *Record, pr *esProcess) {
	r.PID = pr.AuditToken.PID
	r.PPID = pr.PPID
	r.OrigPPID = pr.OriginalPPID
	if pr.ResponsibleToken != nil && pr.ResponsibleToken.PID != r.PID {
		r.RespPID = pr.ResponsibleToken.PID
	}
	r.Exe = clip(pr.Executable.Path, esMaxText)
	r.AuditToken = tokenString(pr.AuditToken)
	r.SigningID = clip(strOf(pr.SigningID), esMaxText)
	r.TeamID = clip(strOf(pr.TeamID), 64)
	r.CDHash = cdhashOf(pr.CDHash)
	r.PlatformBinary = pr.IsPlatformBinary
	r.UID, r.EUID = intStr(pr.AuditToken.RUID), intStr(pr.AuditToken.EUID)
	r.ProcSession = pr.SessionID
	r.TTY = ""
	if pr.TTY != nil {
		r.TTY = clip(pr.TTY.Path, esMaxText)
	}
}

// mapEvent maps one event body onto r. mapped=false: an event type this
// adapter does not import (counted as unsupported). keep=false: a mapped
// type whose instance carries nothing to import (an unmodified close).
func (p *ESParser) mapEvent(r *Record, typ string, body json.RawMessage, ref string) (mapped, keep bool) {
	dec := func(v any) bool {
		if err := json.Unmarshal(body, v); err != nil {
			p.res.problem(fmt.Sprintf("%s: %s event: %v", ref, typ, err))
			return false
		}
		return true
	}
	switch typ {
	case "exec":
		var e struct {
			Target *esProcess `json:"target"`
			Args   []string   `json:"args"`
			Cwd    *esFile    `json:"cwd"`
		}
		if !dec(&e) {
			return true, false
		}
		if e.Target == nil {
			p.res.problem(ref + ": exec event without target")
			return true, false
		}
		setActor(r, e.Target)
		r.Kind = "process"
		r.Cmdline = joinArgs(e.Args)
		if r.Cmdline == "" {
			r.Cmdline = r.Exe
		}
		if e.Cwd != nil {
			r.Cwd = clip(e.Cwd.Path, esMaxText)
		}
		// The parent's image, as last seen for that pid in this stream.
		r.ParentExe = p.exeOf[r.PPID]
		if r.PID != 0 && r.Exe != "" {
			p.remember(r.PID, r.Exe)
		}
		return true, true
	case "fork":
		var e struct {
			Child *esProcess `json:"child"`
		}
		if !dec(&e) {
			return true, false
		}
		if e.Child == nil {
			p.res.problem(ref + ": fork event without child")
			return true, false
		}
		parentExe := r.Exe
		setActor(r, e.Child)
		r.Kind, r.ParentExe = KindProcessFork, parentExe
		if r.PID != 0 && r.Exe != "" {
			p.remember(r.PID, r.Exe)
		}
		return true, true
	case "exit":
		var e struct {
			Stat *int `json:"stat"`
		}
		if !dec(&e) {
			return true, false
		}
		r.Kind = KindProcessExit
		if e.Stat != nil {
			r.Resource = "stat=" + strconv.Itoa(*e.Stat)
		}
		return true, true
	case "open", "write", "truncate":
		var e struct {
			File   *esFile `json:"file"`
			Target *esFile `json:"target"`
		}
		if !dec(&e) {
			return true, false
		}
		f := e.File
		if f == nil {
			f = e.Target
		}
		op := "modify"
		if typ == "open" {
			op = "open"
		}
		return true, fileRec(p, r, f, op, ref)
	case "close":
		var e struct {
			Modified bool    `json:"modified"`
			Target   *esFile `json:"target"`
		}
		if !dec(&e) {
			return true, false
		}
		if !e.Modified {
			p.ignored++
			return true, false
		}
		return true, fileRec(p, r, e.Target, "modify", ref)
	case "create":
		var e struct {
			Destination struct {
				ExistingFile *esFile `json:"existing_file"`
				NewPath      *struct {
					Dir      *esFile `json:"dir"`
					Filename string  `json:"filename"`
				} `json:"new_path"`
			} `json:"destination"`
		}
		if !dec(&e) {
			return true, false
		}
		f := e.Destination.ExistingFile
		if np := e.Destination.NewPath; f == nil && np != nil && np.Dir != nil {
			f = &esFile{Path: joinPath(np.Dir.Path, np.Filename)}
		}
		return true, fileRec(p, r, f, "create", ref)
	case "rename":
		var e struct {
			Source      *esFile `json:"source"`
			Destination struct {
				ExistingFile *esFile `json:"existing_file"`
				NewPath      *struct {
					Dir      *esFile `json:"dir"`
					Filename string  `json:"filename"`
				} `json:"new_path"`
			} `json:"destination"`
		}
		if !dec(&e) {
			return true, false
		}
		f := e.Destination.ExistingFile
		if np := e.Destination.NewPath; f == nil && np != nil && np.Dir != nil {
			f = &esFile{Path: joinPath(np.Dir.Path, np.Filename)}
		}
		if e.Source != nil {
			r.Resource = "from " + clip(e.Source.Path, esMaxText)
		}
		return true, fileRec(p, r, f, "rename", ref)
	case "unlink":
		var e struct {
			Target *esFile `json:"target"`
		}
		if !dec(&e) {
			return true, false
		}
		return true, fileRec(p, r, e.Target, "delete", ref)
	case "clone", "link":
		var e struct {
			Source     *esFile `json:"source"`
			TargetDir  *esFile `json:"target_dir"`
			TargetName string  `json:"target_name"`
			TargetFile string  `json:"target_filename"`
		}
		if !dec(&e) {
			return true, false
		}
		var f *esFile
		if e.TargetDir != nil {
			f = &esFile{Path: joinPath(e.TargetDir.Path, firstNonEmpty(e.TargetName, e.TargetFile))}
		}
		if e.Source != nil {
			r.Resource = "from " + clip(e.Source.Path, esMaxText)
		}
		return true, fileRec(p, r, f, "create", ref)
	case "authentication":
		var e struct {
			Success bool                       `json:"success"`
			Type    json.RawMessage            `json:"type"`
			Data    map[string]json.RawMessage `json:"data"`
		}
		if !dec(&e) {
			return true, false
		}
		r.Kind = "auth"
		for k, v := range e.Data { // od | touchid | token | auto_unlock: one key
			r.Operation = "authentication " + k
			var d struct {
				RecordName string     `json:"record_name"`
				Username   string     `json:"username"`
				Instigator *esProcess `json:"instigator"`
			}
			if json.Unmarshal(v, &d) == nil {
				r.User = clip(firstNonEmpty(d.RecordName, d.Username), 256)
				if d.Instigator != nil {
					setActor(r, d.Instigator)
				}
			}
		}
		if !e.Success {
			r.Failed = "authentication failed"
		}
		return true, true
	case "openssh_login", "openssh_logout", "login_login", "login_logout",
		"lw_session_login", "lw_session_logout", "lw_session_lock", "lw_session_unlock",
		"screensharing_attach", "screensharing_detach":
		var e struct {
			Success        *bool  `json:"success"`
			Username       string `json:"username"`
			SourceAddress  string `json:"source_address"`
			FailureMessage string `json:"failure_message"`
			UID            esUID  `json:"uid"`
			ViewerAppleID  string `json:"authentication_username"`
		}
		if !dec(&e) {
			return true, false
		}
		r.Kind = "auth"
		r.User = clip(firstNonEmpty(e.Username, e.ViewerAppleID), 256)
		r.SourceIP = clip(e.SourceAddress, 128)
		if s := e.UID.String(); s != "" {
			r.Resource = "uid=" + s
		}
		if e.Success != nil && !*e.Success {
			r.Failed = firstNonEmpty(clip(e.FailureMessage, 256), "login failed")
		}
		return true, true
	case "sudo":
		var e struct {
			Success      bool            `json:"success"`
			RejectInfo   json.RawMessage `json:"reject_info"`
			FromUsername string          `json:"from_username"`
			FromUID      esUID           `json:"from_uid"`
			ToUsername   string          `json:"to_username"`
			ToUID        esUID           `json:"to_uid"`
			Command      string          `json:"command"`
		}
		if !dec(&e) {
			return true, false
		}
		r.Kind = "auth"
		r.User = clip(firstNonEmpty(e.FromUsername, e.FromUID.String()), 256)
		r.Resource = "USER=" + firstNonEmpty(e.ToUsername, e.ToUID.String())
		r.Cmdline = clip(e.Command, esMaxCmdline)
		if !e.Success {
			r.Failed = "sudo refused"
		}
		return true, true
	case "su":
		var e struct {
			Success        bool     `json:"success"`
			FailureMessage string   `json:"failure_message"`
			FromUsername   string   `json:"from_username"`
			FromUID        esUID    `json:"from_uid"`
			ToUsername     string   `json:"to_username"`
			ToUID          esUID    `json:"to_uid"`
			Argv           []string `json:"argv"`
		}
		if !dec(&e) {
			return true, false
		}
		r.Kind = "auth"
		r.User = clip(firstNonEmpty(e.FromUsername, e.FromUID.String()), 256)
		r.Resource = "USER=" + firstNonEmpty(e.ToUsername, e.ToUID.String())
		r.Cmdline = joinArgs(e.Argv)
		if !e.Success {
			r.Failed = firstNonEmpty(clip(e.FailureMessage, 256), "su failed")
		}
		return true, true
	case "btm_launch_item_add", "btm_launch_item_remove":
		var e struct {
			Instigator *esProcess `json:"instigator"`
			App        *esProcess `json:"app"`
			Item       *struct {
				ItemType json.RawMessage `json:"item_type"`
				Legacy   bool            `json:"legacy"`
				Managed  bool            `json:"managed"`
				UID      esUID           `json:"uid"`
				ItemURL  string          `json:"item_url"`
				AppURL   string          `json:"app_url"`
			} `json:"item"`
			ExecutablePath string `json:"executable_path"`
		}
		if !dec(&e) {
			return true, false
		}
		r.Kind = KindPersistence
		if e.Instigator != nil {
			setActor(r, e.Instigator)
		}
		if e.Item == nil {
			p.res.problem(ref + ": " + typ + " without item")
			return true, false
		}
		r.FilePath = clip(fileURLPath(e.Item.ItemURL), esMaxText)
		var parts []string
		if t := strings.Trim(string(e.Item.ItemType), `"`); t != "" && t != "null" {
			parts = append(parts, "item_type="+clip(t, 32))
		}
		if e.ExecutablePath != "" {
			parts = append(parts, "executable="+clip(e.ExecutablePath, esMaxText))
		}
		if e.Item.AppURL != "" {
			parts = append(parts, "app="+clip(fileURLPath(e.Item.AppURL), esMaxText))
		}
		if e.Item.Legacy {
			parts = append(parts, "legacy")
		}
		if e.Item.Managed {
			parts = append(parts, "managed")
		}
		r.Resource = strings.Join(parts, " ")
		return true, true
	case "tcc_modify":
		var e struct {
			Service      string          `json:"service"`
			Identity     string          `json:"identity"`
			IdentityType json.RawMessage `json:"identity_type"`
			UpdateType   json.RawMessage `json:"update_type"`
			Right        json.RawMessage `json:"right"`
			Reason       json.RawMessage `json:"reason"`
			Instigator   *esProcess      `json:"instigator"`
			Responsible  *esProcess      `json:"responsible"`
		}
		if !dec(&e) {
			return true, false
		}
		r.Kind = KindTCC
		switch {
		case e.Instigator != nil:
			setActor(r, e.Instigator)
		case e.Responsible != nil:
			setActor(r, e.Responsible)
		}
		r.Resource = clip(e.Service, 256)
		r.Message = clip(strings.TrimSpace(fmt.Sprintf("identity=%s right=%s update_type=%s reason=%s",
			e.Identity, rawText(e.Right), rawText(e.UpdateType), rawText(e.Reason))), esMaxText)
		return true, true
	case "xp_malware_detected", "xp_malware_remediated":
		var e struct {
			MalwareIdentifier  string `json:"malware_identifier"`
			DetectedPath       string `json:"detected_path"`
			RemediatedPath     string `json:"remediated_path"`
			IncidentIdentifier string `json:"incident_identifier"`
			ActionType         string `json:"action_type"`
			Success            *bool  `json:"success"`
		}
		if !dec(&e) {
			return true, false
		}
		r.Kind = KindAV
		r.FilePath = clip(firstNonEmpty(e.DetectedPath, e.RemediatedPath), esMaxText)
		r.Resource = clip(e.MalwareIdentifier, 256)
		if e.Success != nil && !*e.Success {
			r.Failed = "remediation failed"
		}
		return true, true
	case "uipc_connect", "uipc_bind":
		var e struct {
			File *esFile `json:"file"`
			Dir  *esFile `json:"dir"`
			Name string  `json:"filename"`
		}
		if !dec(&e) {
			return true, false
		}
		r.Kind = KindIPC
		switch {
		case e.File != nil:
			r.FilePath = clip(e.File.Path, esMaxText)
		case e.Dir != nil:
			r.FilePath = clip(joinPath(e.Dir.Path, e.Name), esMaxText)
		}
		return true, true
	case "signal", "proc_suspend_resume":
		var e struct {
			Sig    *int            `json:"sig"`
			Type   json.RawMessage `json:"type"`
			Target *esProcess      `json:"target"`
		}
		if !dec(&e) {
			return true, false
		}
		r.Kind = KindSignal
		var parts []string
		if e.Sig != nil {
			parts = append(parts, "sig="+strconv.Itoa(*e.Sig))
		}
		if t := rawText(e.Type); t != "" {
			parts = append(parts, "type="+t)
		}
		if e.Target != nil {
			parts = append(parts, fmt.Sprintf("target_pid=%d target=%s", e.Target.AuditToken.PID, clip(e.Target.Executable.Path, esMaxText)))
		}
		r.Resource = strings.Join(parts, " ")
		return true, true
	}
	return false, false
}

// fileRec completes a file record, or reports a file event without a path.
func fileRec(p *ESParser, r *Record, f *esFile, op, ref string) bool {
	if f == nil || f.Path == "" {
		p.res.problem(ref + ": " + r.Operation + " event without a file path")
		return false
	}
	r.Kind, r.FileOp, r.FilePath = "file", op, clip(f.Path, esMaxText)
	if f.Truncated {
		r.FilePath += " (truncated by Endpoint Security)"
	}
	return true
}

// Finish closes the stream and writes the operator summary: event type
// counts, schema and message versions, and every UNSUPPORTED type.
func (p *ESParser) Finish() *LoadResult {
	res := p.res
	for v, n := range p.schemas {
		if v != esKnownSchema {
			res.note(fmt.Sprintf("UNSUPPORTED eslogger schema_version %d on %d message(s) (this build reads %d); fields read best-effort", v, n, esKnownSchema))
		}
	}
	if len(p.types) > 0 {
		res.notice("eslogger: " + countList(p.types) + versionSpan(p.versions))
	}
	if p.ignored > 0 {
		res.notice(fmt.Sprintf("eslogger: %d close event(s) without modification not imported", p.ignored))
	}
	if len(res.Unsupported) > 0 {
		msg := "UNSUPPORTED eslogger event type(s), counted and not mapped: " + countList(res.Unsupported)
		res.notice(msg)
		res.note(msg)
	}
	return res
}

func countList(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s %d", k, m[k]))
	}
	return strings.Join(parts, ", ")
}

func versionSpan(v map[int]int) string {
	if len(v) == 0 {
		return ""
	}
	lo, hi := 1<<30, -1
	for k := range v {
		lo, hi = minInt(lo, k), maxInt(hi, k)
	}
	if lo == hi {
		return fmt.Sprintf(" (message version %d)", lo)
	}
	return fmt.Sprintf(" (message versions %d-%d)", lo, hi)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// joinArgs renders an argv, bounded in count and size.
func joinArgs(args []string) string {
	var b strings.Builder
	for i, a := range args {
		if i == esMaxArgs {
			fmt.Fprintf(&b, " …(%d more args)", len(args)-i)
			break
		}
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(clip(a, esMaxArg))
		if b.Len() > esMaxCmdline {
			return clip(b.String(), esMaxCmdline)
		}
	}
	return b.String()
}

func joinPath(dir, name string) string {
	if name == "" {
		return dir
	}
	return strings.TrimRight(dir, "/") + "/" + name
}

// clip bounds a string at n bytes on a rune boundary.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && n < len(s) && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n] + "…"
}

func strOf(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func intStr(p *int) string {
	if p == nil {
		return ""
	}
	return strconv.Itoa(*p)
}

func tokenString(t esToken) string {
	if t.PID == 0 && t.PIDVersion == 0 {
		return ""
	}
	s := fmt.Sprintf("pid=%d pidversion=%d", t.PID, t.PIDVersion)
	if t.EUID != nil {
		s += " euid=" + strconv.Itoa(*t.EUID)
	}
	if t.RUID != nil {
		s += " ruid=" + strconv.Itoa(*t.RUID)
	}
	if t.AUID != nil {
		s += " auid=" + strconv.Itoa(*t.AUID)
	}
	if t.ASID != nil {
		s += " asid=" + strconv.Itoa(*t.ASID)
	}
	return s
}

// cdhashOf renders a code-directory hash written as a hex string or as a
// byte array.
func cdhashOf(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return clip(strings.ToUpper(s), 128)
	}
	var b []byte
	var nums []int
	if json.Unmarshal(raw, &nums) == nil && len(nums) <= 64 {
		for _, n := range nums {
			b = append(b, byte(n))
		}
		return strings.ToUpper(hex.EncodeToString(b))
	}
	return ""
}

// rawText renders a JSON scalar (number, string, bool) as text.
func rawText(raw json.RawMessage) string {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" {
		return ""
	}
	return clip(strings.Trim(s, `"`), 64)
}

// fileURLPath turns file:///a%20b into /a b; anything else is kept.
func fileURLPath(u string) string {
	if strings.HasPrefix(u, "file://") {
		if p, err := url.Parse(u); err == nil && p.Path != "" {
			return p.Path
		}
	}
	return u
}

// sniffESLogger: the first line is an eslogger message.
func sniffESLogger(head []byte) bool {
	first := head
	if i := bytes.IndexByte(head, '\n'); i >= 0 {
		first = head[:i]
	}
	var probe struct {
		SchemaVersion *int                       `json:"schema_version"`
		Event         map[string]json.RawMessage `json:"event"`
		Process       json.RawMessage            `json:"process"`
		Time          string                     `json:"time"`
	}
	if json.Unmarshal(bytes.TrimSpace(first), &probe) != nil {
		// A first line longer than the sniff buffer: fall back to keys
		// only eslogger writes together.
		return bytes.HasPrefix(head, []byte("{")) && bytes.Contains(first, []byte(`"schema_version":`)) &&
			bytes.Contains(first, []byte(`"mach_time":`)) && bytes.Contains(first, []byte(`"event":{`))
	}
	return probe.SchemaVersion != nil && len(probe.Event) == 1 && len(probe.Process) > 0 && probe.Time != ""
}
