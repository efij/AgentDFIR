package recorder

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v5/internal/journal"
)

// Retention bounds what the recorder keeps on disk. Only capture files are
// ever deleted, oldest first; journal records are never pruned, and every
// deletion is journaled before it happens.
type Retention struct {
	Spec     string        // as given (e.g. "7d,2GB")
	MaxAge   time.Duration // 0 = no age bound
	MaxBytes int64         // 0 = no size bound
}

// RetentionState is the retention part of status.json.
type RetentionState struct {
	Policy       string   `json:"policy"`
	MaxAgeSec    int64    `json:"max_age_sec,omitempty"`
	MaxBytes     int64    `json:"max_bytes,omitempty"`
	Files        int      `json:"files"`
	Bytes        int64    `json:"bytes"`
	PrunedFiles  int      `json:"pruned_files"`
	PrunedBytes  int64    `json:"pruned_bytes"`
	LastPruneUTC string   `json:"last_prune_utc,omitempty"`
	LastReason   string   `json:"last_reason,omitempty"`
	Problems     []string `json:"problems,omitempty"`
}

// ParseRetention reads "7d", "12h", "2GB", "500MB" or both comma-separated
// ("7d,2GB"). Sizes are binary (1 GB = 2^30 bytes); ages take s, m, h, d
// and w suffixes.
func ParseRetention(spec string) (Retention, error) {
	r := Retention{Spec: spec}
	for _, part := range strings.Split(spec, ",") {
		p := strings.ToUpper(strings.TrimSpace(part))
		if p == "" {
			continue
		}
		if n, ok := parseSize(p); ok {
			if n <= 0 {
				return r, fmt.Errorf("retain: size %q must be positive", part)
			}
			r.MaxBytes = n
			continue
		}
		d, err := parseAge(p)
		if err != nil {
			return r, fmt.Errorf("retain: %q is neither an age (7d, 12h) nor a size (2GB, 500MB)", part)
		}
		if d <= 0 {
			return r, fmt.Errorf("retain: age %q must be positive", part)
		}
		r.MaxAge = d
	}
	if r.MaxAge == 0 && r.MaxBytes == 0 {
		return r, fmt.Errorf("retain: empty policy %q", spec)
	}
	return r, nil
}

func parseSize(p string) (int64, bool) {
	units := []struct {
		suf string
		mul int64
	}{{"TIB", 1 << 40}, {"GIB", 1 << 30}, {"MIB", 1 << 20}, {"KIB", 1 << 10},
		{"TB", 1 << 40}, {"GB", 1 << 30}, {"MB", 1 << 20}, {"KB", 1 << 10}, {"T", 1 << 40}, {"G", 1 << 30}, {"K", 1 << 10}, {"B", 1}}
	for _, u := range units {
		if strings.HasSuffix(p, u.suf) {
			v, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimSuffix(p, u.suf)), 64)
			if err != nil || v > float64(1<<62)/float64(u.mul) {
				return 0, false
			}
			return int64(v * float64(u.mul)), true
		}
	}
	return 0, false
}

func parseAge(p string) (time.Duration, error) {
	p = strings.ToLower(p)
	for suf, mul := range map[string]time.Duration{"d": 24 * time.Hour, "w": 7 * 24 * time.Hour} {
		if strings.HasSuffix(p, suf) {
			v, err := strconv.ParseFloat(strings.TrimSuffix(p, suf), 64)
			if err != nil || v > 1e6 {
				return 0, fmt.Errorf("bad age")
			}
			return time.Duration(v * float64(mul)), nil
		}
	}
	return time.ParseDuration(p)
}

// Pruned is one deletion.
type Pruned struct {
	Path   string
	Size   int64
	SHA256 string
	Reason string
}

// mtimeSlack is how far a capture's mtime may precede its creation stamp
// before it is reported as backdated (clock granularity, not tampering).
const mtimeSlack = 5 * time.Second

// CaptureStamp returns the creation time encoded in a capture file name.
func CaptureStamp(base string) (time.Time, bool) {
	m := captureRe.FindStringSubmatch(base)
	if m == nil {
		return time.Time{}, false
	}
	t, err := time.Parse("20060102T150405Z", m[2])
	return t, err == nil
}

// Prune applies the policy to the capture files in dir that the journal
// recorded (known: path → first journal record). Look-alike files the
// journal never recorded are neither counted nor deleted, only reported.
// Age is taken from the creation stamp in the file name (or the first
// journal record, if earlier), never from the forgeable mtime; a capture
// whose mtime is earlier than both is reported as backdated. Files in
// active (still being written) are never touched. Each deletion is hashed
// and journaled first; without a journal nothing is deleted.
func (r Retention) Prune(dir string, known map[string]journal.JournaledFile, active map[string]bool, jn Journal, now time.Time) ([]Pruned, []string) {
	if jn == nil {
		return nil, []string{"retention needs the journal; nothing pruned"}
	}
	type cand struct {
		path      string
		size      int64
		created   time.Time
		journaled int64
	}
	var all []cand
	var total int64
	var problems []string
	for _, p := range CaptureFiles(dir) {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		jf, ok := known[p]
		first := jf.First
		if !ok {
			problems = append(problems, filepath.Base(p)+": capture-named file the journal never recorded; not counted or pruned")
			continue
		}
		created, _ := CaptureStamp(filepath.Base(p))
		if !first.IsZero() && (created.IsZero() || first.Before(created)) {
			created = first
		}
		if created.IsZero() {
			problems = append(problems, filepath.Base(p)+": no creation time; not pruned")
			continue
		}
		if fi.ModTime().Before(created.Add(-mtimeSlack)) {
			problems = append(problems, fmt.Sprintf("%s: mtime %s is earlier than its creation %s (backdated)", filepath.Base(p), fi.ModTime().UTC().Format(time.RFC3339), created.UTC().Format(time.RFC3339)))
		}
		jsz := jf.Size
		if n, ok := jn.JournaledSize(p); ok {
			jsz = n // journaled in this session: the live journal knows best
		}
		all = append(all, cand{p, fi.Size(), created, jsz})
		total += fi.Size()
	}
	sort.SliceStable(all, func(i, j int) bool {
		if !all[i].created.Equal(all[j].created) {
			return all[i].created.Before(all[j].created)
		}
		return all[i].path < all[j].path
	})
	var out []Pruned
	for _, c := range all {
		if active[c.path] {
			continue
		}
		reason := ""
		switch {
		case r.MaxAge > 0 && now.Sub(c.created) > r.MaxAge:
			reason = fmt.Sprintf("retention: created %s ago, older than %s", now.Sub(c.created).Round(time.Second), r.MaxAge)
		case r.MaxBytes > 0 && total > r.MaxBytes:
			reason = fmt.Sprintf("retention: captures total %d bytes, over the %d-byte bound", total, r.MaxBytes)
		default:
			continue
		}
		sha, prefixSHA, err := hashWithPrefix(c.path, c.journaled)
		if err != nil {
			problems = append(problems, "cannot hash "+c.path+": "+err.Error()+"; not pruned")
			continue
		}
		jn.Prune(c.path, c.size, sha, c.journaled, prefixSHA, reason)
		if err := os.Remove(c.path); err != nil {
			jn.PruneFailed(c.path, err.Error())
			problems = append(problems, "prune "+c.path+": "+err.Error())
			continue
		}
		total -= c.size
		out = append(out, Pruned{Path: c.path, Size: c.size, SHA256: sha, Reason: reason})
	}
	return out, problems
}

// hashWithPrefix hashes a whole file and, in the same pass, its first
// prefix bytes ("" when prefix is 0 or the file is shorter).
func hashWithPrefix(p string, prefix int64) (string, string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	whole := sha256.New()
	pre := sha256.New()
	var preSum string
	if prefix > 0 {
		n, err := io.Copy(io.MultiWriter(whole, pre), io.LimitReader(f, prefix))
		if err != nil {
			return "", "", err
		}
		if n == prefix {
			preSum = hex.EncodeToString(pre.Sum(nil))
		}
	}
	if _, err := io.Copy(whole, f); err != nil {
		return "", "", err
	}
	return hex.EncodeToString(whole.Sum(nil)), preSum, nil
}
