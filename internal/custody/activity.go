// Package custody is the chain of custody of a case as a whole: the sealed
// custody log the acquisition wrote (chain-of-custody.jsonl, covered by
// SHA256SUMS) plus the activity log that records what was done with the
// case after it was sealed — reports generated, custody packages
// exported, an authorization recorded, verification runs.
//
// The sealed log cannot take another line without breaking the seal, and
// re-sealing a case because someone generated a report would make the
// seal mean less, not more. So post-seal activity goes to
// <pkg>/custody/activity.jsonl: a hash chain of its own, outside the
// sealed zone, where every record names the seal digest it was made
// against. A record that cites a seal digest the case no longer has, or a
// chain that no longer links, is visible to anyone who reads the file.
package custody

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/casepkg"
	"github.com/efij/AgentDFIR/v4/internal/hashchain"
	"github.com/efij/AgentDFIR/v4/internal/version"
)

// Activity file inside a package (outside the sealed zone).
const (
	Dir  = "custody"
	File = "activity.jsonl"
)

// Events the activity log records.
const (
	EventReportGenerated = "report_generated"
	EventCustodyExported = "custody_exported"
	EventAuthorized      = "acquisition_authorized"
	EventVerified        = "verify_run"
	// EventProductionGenerated records an eDiscovery production set made
	// from the case (export --production).
	EventProductionGenerated = "production_generated"
)

// Record is one activity line, decoded. Fields holds the event-specific
// keys verbatim.
type Record struct {
	Seq        int            `json:"seq"`
	TS         string         `json:"ts_utc"`
	Prev       string         `json:"prev"`
	Event      string         `json:"event"`
	CaseID     string         `json:"case_id"`
	OSUser     string         `json:"actor_os_user"`
	Host       string         `json:"actor_host"`
	ToolVer    string         `json:"tool_version"`
	BinarySHA  string         `json:"tool_binary_sha256,omitempty"`
	LocalTime  string         `json:"local_time"`
	Timezone   string         `json:"timezone"`
	SealDigest string         `json:"seal_digest,omitempty"`
	Round      int            `json:"round,omitempty"`
	Fields     map[string]any `json:"-"`
}

// reserved are the keys Append sets itself; fields with these names are
// refused rather than silently overwritten.
var reserved = map[string]bool{"seq": true, "ts_utc": true, "prev": true, "event": true, "case_id": true,
	"actor_os_user": true, "actor_host": true, "tool_version": true, "tool_binary_sha256": true,
	"local_time": true, "timezone": true, "seal_digest": true, "round": true}

// Path is the activity file of a package.
func Path(pkg string) string { return filepath.Join(pkg, Dir, File) }

// SealDigest is the sha256 of the package's current SHA256SUMS, or "" when
// the package has none.
func SealDigest(pkg string) string {
	data, err := os.ReadFile(filepath.Join(pkg, "SHA256SUMS"))
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Append records one post-seal activity on the case. The record carries
// who (OS user, host, tool version, binary hash), when (UTC and local)
// and against which seal, plus the caller's fields.
func Append(pkg, event string, fields map[string]any) (Record, error) {
	for k := range fields {
		if reserved[k] {
			return Record{}, fmt.Errorf("custody: field %q is set by the log itself", k)
		}
	}
	ci, err := casepkg.ReadCaseInfo(pkg)
	if err != nil {
		return Record{}, fmt.Errorf("custody: %s is not a sealed case: %w", pkg, err)
	}
	if err := os.MkdirAll(filepath.Join(pkg, Dir), 0o700); err != nil {
		return Record{}, err
	}
	path := Path(pkg)
	var w *hashchain.Writer
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		w, err = hashchain.NewWriter(path)
		if err != nil {
			return Record{}, err
		}
	} else if w, err = hashchain.NewAppender(path); err != nil {
		return Record{}, fmt.Errorf("custody activity log: %w", err)
	}
	now := time.Now()
	zone, _ := now.Zone()
	rec := map[string]any{
		"event": event, "case_id": ci.CaseID,
		"actor_os_user": osUser(), "actor_host": hostname(),
		"tool_version": version.Version, "tool_binary_sha256": selfHash(),
		"local_time": now.Format(time.RFC3339), "timezone": zone,
		"seal_digest": SealDigest(pkg), "round": len(ci.Rounds),
	}
	for k, v := range fields {
		rec[k] = v
	}
	if err := w.Append(rec); err != nil {
		w.Close()
		return Record{}, err
	}
	if err := w.Close(); err != nil {
		return Record{}, err
	}
	recs, _, err := Read(pkg)
	if err != nil || len(recs) == 0 {
		return Record{}, err
	}
	return recs[len(recs)-1], nil
}

// Read returns every activity record in order and the chain's state: an
// empty error string when every link holds, otherwise the first break.
// A missing file is an empty log, not an error.
func Read(pkg string) ([]Record, string, error) {
	f, err := os.Open(Path(pkg))
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	return decode(f)
}

// decode parses an activity stream and verifies its chain.
func decode(r io.Reader) ([]Record, string, error) {
	data, err := io.ReadAll(io.LimitReader(r, 64<<20))
	if err != nil {
		return nil, "", err
	}
	chainErr := ""
	if _, err := hashchain.Verify(strings.NewReader(string(data))); err != nil {
		chainErr = err.Error()
	}
	var out []Record
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20)
	for sc.Scan() {
		line := sc.Bytes()
		var rec Record
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		var all map[string]any
		if json.Unmarshal(line, &all) == nil {
			rec.Fields = map[string]any{}
			for k, v := range all {
				if !reserved[k] {
					rec.Fields[k] = v
				}
			}
		}
		out = append(out, rec)
	}
	return out, chainErr, sc.Err()
}

// SortedFieldKeys lists a record's event-specific keys in a fixed order.
func (r Record) SortedFieldKeys() []string {
	keys := make([]string, 0, len(r.Fields))
	for k := range r.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// FieldString returns a field as text ("" when absent).
func (r Record) FieldString(k string) string {
	switch v := r.Fields[k].(type) {
	case string:
		return v
	case nil:
		return ""
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

// Authorizations returns the acquisition_authorized records, oldest first.
func Authorizations(recs []Record) []Record {
	var out []Record
	for _, r := range recs {
		if r.Event == EventAuthorized {
			out = append(out, r)
		}
	}
	return out
}

func osUser() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}

// selfHash hashes the running binary (best effort), the same value the
// sealed custody log records for the collector.
func selfHash() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	f, err := os.Open(exe)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// FileSHA256 hashes a file on disk.
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
