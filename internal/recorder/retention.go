package recorder

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
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

// Prune applies the policy to the capture files in dir. Files in active
// (still being written) are never touched. Each deletion is hashed and
// journaled first; without a journal nothing is deleted.
func (r Retention) Prune(dir string, active map[string]bool, jn Journal, now time.Time) ([]Pruned, []string) {
	files := CaptureFiles(dir)
	type cand struct {
		path  string
		size  int64
		mtime time.Time
	}
	var all []cand
	var total int64
	for _, p := range files {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		all = append(all, cand{p, fi.Size(), fi.ModTime()})
		total += fi.Size()
	}
	sort.SliceStable(all, func(i, j int) bool {
		if !all[i].mtime.Equal(all[j].mtime) {
			return all[i].mtime.Before(all[j].mtime)
		}
		return all[i].path < all[j].path
	})
	var out []Pruned
	var problems []string
	for _, c := range all {
		if active[c.path] {
			continue
		}
		reason := ""
		switch {
		case r.MaxAge > 0 && now.Sub(c.mtime) > r.MaxAge:
			reason = fmt.Sprintf("retention: last written %s ago, older than %s", now.Sub(c.mtime).Round(time.Second), r.MaxAge)
		case r.MaxBytes > 0 && total > r.MaxBytes:
			reason = fmt.Sprintf("retention: captures total %d bytes, over the %d-byte bound", total, r.MaxBytes)
		default:
			continue
		}
		if jn == nil {
			problems = append(problems, "retention needs the journal; nothing pruned")
			break
		}
		sha, note := hashFile(c.path, 0)
		if note != "" {
			problems = append(problems, note)
			continue
		}
		jn.Prune(c.path, c.size, sha, reason)
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
