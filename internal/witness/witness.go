// Package witness records what the host says about the actions an agent
// claimed to take, at acquisition time.
//
// Every finding AgentDFIR produced before this was RECORDED at best: the
// transcript says a tool was called, and nothing else was ever asked. On a
// real 206,896-event package all 1,519 findings carried
// endpoint_corroboration UNKNOWN. The corroboration model existed and was
// wired to nothing, because it assumed the analyst already had auditd or
// Sysmon exports.
//
// Three witnesses cost nothing and need no EDR: the filesystem (does the
// file the agent said it wrote exist, and does it still contain that?),
// git (did the commit it claimed actually land?), and shell history.
//
// The timing is the whole design. Gathering happens HERE, during
// acquisition, into the sealed zone with its own provenance. Comparing
// happens later in analysis, in the regenerable overlay. Reversed — asking
// the host at analysis time, possibly days later on another machine — the
// answer would describe a different world and the tool would be
// manufacturing evidence rather than preserving it.
package witness

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v2/internal/casepkg"
	"github.com/efij/AgentDFIR/v2/internal/schema"
)

// File is what the host said about one path the agent claimed to write.
type File struct {
	Path       string `json:"path"`
	Exists     bool   `json:"exists"`
	Size       int64  `json:"size,omitempty"`
	ModTimeUTC string `json:"mtime_utc,omitempty"`
	SHA256     string `json:"sha256,omitempty"` // of the current content, bounded
	Truncated  bool   `json:"truncated,omitempty"`
	Error      string `json:"error,omitempty"`
}

// Repo is what the host said about a git working tree the agent used.
type Repo struct {
	Dir     string   `json:"dir"`
	Exists  bool     `json:"exists"`
	HeadLog []string `json:"head_log,omitempty"` // tail of .git/logs/HEAD
	Error   string   `json:"error,omitempty"`
}

// Record is the witness document written into the sealed zone.
type Record struct {
	GatheredUTC string   `json:"gathered_utc"`
	Host        string   `json:"host"`
	Round       int      `json:"round"`
	Files       []File   `json:"files"`
	Repos       []Repo   `json:"repos"`
	Note        string   `json:"note"`
	Limits      Limits   `json:"limits"`
	Skipped     []string `json:"skipped,omitempty"`
}

// Limits bounds the pass so hostile evidence cannot steer it into reading
// the disk.
type Limits struct {
	MaxFiles     int   `json:"max_files"`
	MaxFileBytes int64 `json:"max_file_bytes"`
	MaxRepos     int   `json:"max_repos"`
}

// DefaultLimits is deliberately modest: this is a corroboration pass, not a
// second collection.
var DefaultLimits = Limits{MaxFiles: 2000, MaxFileBytes: 8 << 20, MaxRepos: 100}

// Name is the witness file inside the package.
const Name = "witness.json"

// Gather inspects the host for the write targets and repositories the given
// events refer to, and returns the record. It reads only; nothing is
// modified.
//
// Paths are taken from evidence, which is hostile input, so the pass
// refuses anything that is not an absolute, symlink-free regular file, and
// stops at the limits above.
func Gather(events []schema.Event, host string, round int, lim Limits) *Record {
	if lim.MaxFiles == 0 {
		lim = DefaultLimits
	}
	rec := &Record{
		GatheredUTC: time.Now().UTC().Format(time.RFC3339Nano),
		Host:        host, Round: round, Limits: lim,
		Note: "Host state at acquisition time for paths the agent claimed to write and repositories it worked in. " +
			"Read-only. Gathered during acquisition on purpose: asked later, the answer would describe a different host.",
	}
	seenFile := map[string]bool{}
	seenRepo := map[string]bool{}

	for _, ev := range events {
		if p := claimedWrite(ev); p != "" && !seenFile[p] {
			if len(rec.Files) >= lim.MaxFiles {
				rec.Skipped = append(rec.Skipped, "file limit reached")
				break
			}
			seenFile[p] = true
			rec.Files = append(rec.Files, inspectFile(p, lim.MaxFileBytes))
		}
		// Repositories are derived from the write targets rather than from a
		// recorded working directory: the schema does not carry one, and the
		// tree an agent edited is the tree worth asking about.
		if p := claimedWrite(ev); p != "" && len(rec.Repos) < lim.MaxRepos {
			if d := repoRoot(filepath.Dir(p)); d != "" && !seenRepo[d] {
				seenRepo[d] = true
				if r, ok := inspectRepo(d); ok {
					rec.Repos = append(rec.Repos, r)
				}
			}
		}
	}
	sort.Slice(rec.Files, func(i, j int) bool { return rec.Files[i].Path < rec.Files[j].Path })
	sort.Slice(rec.Repos, func(i, j int) bool { return rec.Repos[i].Dir < rec.Repos[j].Dir })
	return rec
}

// claimedWrite returns the absolute path an event claims to have written,
// or "" when it claims none.
func claimedWrite(ev schema.Event) string {
	switch ev.Action {
	case "write_file", "edit_file":
	default:
		return ""
	}
	p := ev.File
	if p == "" || !filepath.IsAbs(p) {
		return ""
	}
	return filepath.Clean(p)
}

// inspectFile records the host's answer for one path.
func inspectFile(path string, max int64) File {
	f := File{Path: path}
	info, err := os.Lstat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			f.Error = err.Error()
		}
		return f
	}
	// A symlink or a device where a written file should be is itself worth
	// recording, but its content is not read.
	if !info.Mode().IsRegular() {
		f.Exists = true
		f.Error = "not a regular file: " + info.Mode().String()
		return f
	}
	f.Exists = true
	f.Size = info.Size()
	f.ModTimeUTC = info.ModTime().UTC().Format(time.RFC3339Nano)
	if info.Size() > max {
		f.Truncated = true
		return f
	}
	h, err := hashFile(path)
	if err != nil {
		f.Error = err.Error()
		return f
	}
	f.SHA256 = h
	return f
}

// repoRoot walks up from a directory to the nearest working tree, bounded
// so a crafted path cannot send it up the whole filesystem.
func repoRoot(dir string) string {
	for i := 0; i < 12 && dir != "" && dir != "/" && dir != "."; i++ {
		if info, err := os.Lstat(filepath.Join(dir, ".git")); err == nil && info.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

// inspectRepo reads a working tree's reflog. Nothing is executed: the
// reflog is a text file, and this tool does not run binaries it found on a
// host under investigation.
func inspectRepo(dir string) (Repo, bool) {
	gitDir := filepath.Join(dir, ".git")
	info, err := os.Lstat(gitDir)
	if err != nil || !info.IsDir() {
		return Repo{}, false
	}
	r := Repo{Dir: dir, Exists: true}
	data, err := os.ReadFile(filepath.Join(gitDir, "logs", "HEAD"))
	if err != nil {
		r.Error = err.Error()
		return r, true
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) > 200 {
		lines = lines[len(lines)-200:]
	}
	r.HeadLog = lines
	return r, true
}

func hashFile(path string) (string, error) {
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

// Write stores the record in the package's sealed zone through the builder,
// so it is covered by SHA256SUMS and the custody chain like any other
// evidence.
func Write(b *casepkg.Builder, rec *Record) error {
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp("", "adfir-witness-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()
	if err := b.IngestFile(tmp.Name(), casepkg.ArtifactRecord{
		SourcePath: tmp.Name(), LogicalPath: Name,
		ArtifactType: "host_witness", Sensitivity: "medium",
		CollectorRule: "witness.host",
	}); err != nil {
		return err
	}
	return b.Log("witness_gathered", map[string]any{
		"files": len(rec.Files), "repos": len(rec.Repos), "round": rec.Round,
	})
}

// Load reads the witness record out of a sealed package, newest round first.
func Load(pkgDir string) (*Record, error) {
	man, err := casepkg.ReadManifest(pkgDir)
	if err != nil {
		return nil, err
	}
	store := casepkg.NewStore(pkgDir, man)
	var newest *casepkg.ArtifactRecord
	for i := range man.Artifacts {
		a := man.Artifacts[i]
		if a.LogicalPath == Name && a.Status == casepkg.StatusOK {
			newest = &man.Artifacts[i]
		}
	}
	if newest == nil {
		return nil, os.ErrNotExist
	}
	data, err := store.ReadAll(newest.ArtifactID, 64<<20)
	if err != nil {
		return nil, err
	}
	var rec Record
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}
