// Package hostpersist acquires Linux persistence state at collection
// time: the places a process that wants to survive a reboot or a new
// login writes to. Read-only, and it never executes anything.
//
//   - systemd units and timers: /etc/systemd/system, ~/.config/systemd/user
//   - cron: /etc/crontab, /etc/cron.d, /etc/cron.{hourly,daily,weekly,monthly},
//     /var/spool/cron (crontabs/ on Debian, per-user files on RHEL)
//   - shell init: ~/.bashrc, ~/.bash_profile, ~/.bash_login, ~/.profile,
//     ~/.zshrc, ~/.zprofile, ~/.zshenv, /etc/profile, /etc/profile.d,
//     /etc/bash.bashrc
//   - /etc/ld.so.preload
//   - ~/.ssh/authorized_keys, authorized_keys2
//
// Two things go into the package. The files themselves, through the
// ordinary manifest collector (so symlinks are recorded and never
// followed, irregular files are skipped, and an unreadable file or
// directory is an ACCESS_DENIED record with the error, not a silent gap).
// And host/linux-persistence.json, an inventory that says what each file
// does: ExecStart/OnCalendar lines of units and timers, crontab entries,
// ld.so.preload entries, and each authorized key by type, SHA256
// fingerprint and comment. Paths that could not be read are listed in it
// with the reason.
package hostpersist

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/casepkg"
	"github.com/efij/AgentDFIR/v4/internal/collector"
	"github.com/efij/AgentDFIR/v4/internal/products"
)

// Product is the product id the records carry.
const Product = "linux-persistence"

// InventoryPath is the inventory's logical path inside the package.
const InventoryPath = "host/linux-persistence.json"

const (
	maxItems     = 4096
	maxReadBytes = 1 << 20
	maxDetail    = 64
)

type place struct {
	category string
	root     string // "profile" or "system"
	rel      string
	tree     bool // a directory to walk
}

var places = []place{
	{"systemd", "system", "etc/systemd/system", true},
	{"systemd", "profile", ".config/systemd/user", true},
	{"cron", "system", "etc/crontab", false},
	{"cron", "system", "etc/anacrontab", false},
	{"cron", "system", "etc/cron.d", true},
	{"cron", "system", "etc/cron.hourly", true},
	{"cron", "system", "etc/cron.daily", true},
	{"cron", "system", "etc/cron.weekly", true},
	{"cron", "system", "etc/cron.monthly", true},
	{"cron", "system", "var/spool/cron", true},
	{"shell_init", "profile", ".bashrc", false},
	{"shell_init", "profile", ".bash_profile", false},
	{"shell_init", "profile", ".bash_login", false},
	{"shell_init", "profile", ".profile", false},
	{"shell_init", "profile", ".zshrc", false},
	{"shell_init", "profile", ".zprofile", false},
	{"shell_init", "profile", ".zshenv", false},
	{"shell_init", "system", "etc/profile", false},
	{"shell_init", "system", "etc/profile.d", true},
	{"shell_init", "system", "etc/bash.bashrc", false},
	{"ld_preload", "system", "etc/ld.so.preload", false},
	{"authorized_keys", "profile", ".ssh/authorized_keys", false},
	{"authorized_keys", "profile", ".ssh/authorized_keys2", false},
}

// Applies reports whether persistence collection runs: on a live Linux
// host (systemRoot "/"), or on an offline tree that is a Linux root.
func Applies(systemRoot string) bool {
	if systemRoot == "/" || systemRoot == "" {
		return runtime.GOOS == "linux"
	}
	_, err := os.Lstat(filepath.Join(systemRoot, "etc", "os-release"))
	return err == nil
}

// Manifest is the collector manifest for the places above.
func Manifest() *products.CollectorManifest {
	m := &products.CollectorManifest{Product: Product}
	for _, p := range places {
		root := "${SYSTEM_ROOT}/"
		if p.root == "profile" {
			root = "${PROFILE_ROOT}/"
		}
		path := root + p.rel
		if p.tree {
			path += "/**"
		}
		sens := "medium"
		if p.category == "cron" || p.category == "authorized_keys" {
			sens = "high"
		}
		m.Entries = append(m.Entries, products.ManifestEntry{ID: "linux." + p.category + "." + strings.NewReplacer("/", "_", ".", "").Replace(p.rel),
			Platforms: []string{"linux"}, Paths: []string{path}, Category: "host_persistence", Sensitivity: sens})
	}
	return m
}

// Key is one authorized_keys entry.
type Key struct {
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"` // SHA256:<base64>, as ssh-keygen -l prints it
	Comment     string `json:"comment,omitempty"`
	Options     string `json:"options,omitempty"`
}

// Item is one persistence file.
type Item struct {
	Category      string   `json:"category"`
	Path          string   `json:"path"`
	Size          int64    `json:"size"`
	Mode          string   `json:"mode"`
	ModTimeUTC    string   `json:"mtime_utc"`
	SHA256        string   `json:"sha256,omitempty"`
	SymlinkTarget string   `json:"symlink_target,omitempty"`
	Detail        []string `json:"detail,omitempty"`
	Keys          []Key    `json:"keys,omitempty"`
	Truncated     bool     `json:"truncated,omitempty"` // only the first 1 MiB was read
}

// Skip is a path that could not be read, with the reason.
type Skip struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// Inventory is the host/linux-persistence.json document.
type Inventory struct {
	CollectedUTC string `json:"collected_utc"`
	ProfileRoot  string `json:"profile_root"`
	SystemRoot   string `json:"system_root"`
	Items        []Item `json:"items"`
	Skipped      []Skip `json:"skipped,omitempty"`
	Absent       int    `json:"absent"`                  // places checked that do not exist
	ItemsLimited bool   `json:"items_limited,omitempty"` // stopped at maxItems
}

// Build reads the places under the given roots.
func Build(profileRoot, systemRoot string) *Inventory {
	inv := &Inventory{CollectedUTC: time.Now().UTC().Format(time.RFC3339Nano), ProfileRoot: profileRoot, SystemRoot: systemRoot}
	for _, p := range places {
		root := systemRoot
		if p.root == "profile" {
			root = profileRoot
		}
		if root == "" {
			continue
		}
		base := filepath.Join(root, filepath.FromSlash(p.rel))
		if _, err := os.Lstat(base); err != nil {
			if os.IsNotExist(err) {
				inv.Absent++
			} else {
				inv.Skipped = append(inv.Skipped, Skip{base, err.Error()})
			}
			continue
		}
		if !p.tree {
			inv.add(p.category, base)
			continue
		}
		_ = filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				inv.Skipped = append(inv.Skipped, Skip{path, err.Error()})
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if len(inv.Items) >= maxItems {
				inv.ItemsLimited = true
				return fs.SkipAll
			}
			if !d.IsDir() {
				inv.add(p.category, path)
			}
			return nil
		})
	}
	return inv
}

func (inv *Inventory) add(category, path string) {
	if len(inv.Items) >= maxItems {
		inv.ItemsLimited = true
		return
	}
	fi, err := os.Lstat(path)
	if err != nil {
		inv.Skipped = append(inv.Skipped, Skip{path, err.Error()})
		return
	}
	it := Item{Category: category, Path: path, Size: fi.Size(), Mode: fi.Mode().String(), ModTimeUTC: fi.ModTime().UTC().Format(time.RFC3339Nano)}
	switch {
	case fi.Mode()&os.ModeSymlink != 0:
		// Recorded, never followed. The target is a Linux path; Readlink on
		// Windows (an offline root) hands it back with backslashes.
		t, _ := os.Readlink(path)
		it.SymlinkTarget = filepath.ToSlash(t)
		inv.Items = append(inv.Items, it)
		return
	case !fi.Mode().IsRegular():
		inv.Skipped = append(inv.Skipped, Skip{path, "not a regular file (" + fi.Mode().Type().String() + ")"})
		return
	}
	f, err := os.Open(path)
	if err != nil {
		inv.Skipped = append(inv.Skipped, Skip{path, err.Error()})
		return
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxReadBytes+1))
	if err != nil {
		inv.Skipped = append(inv.Skipped, Skip{path, err.Error()})
		return
	}
	if len(data) > maxReadBytes {
		data, it.Truncated = data[:maxReadBytes], true
	} else {
		sum := sha256.Sum256(data)
		it.SHA256 = hex.EncodeToString(sum[:])
	}
	switch category {
	case "systemd":
		it.Detail = matchLines(data, func(l string) bool {
			for _, k := range []string{"ExecStart", "ExecStop=", "ExecReload=", "OnCalendar=", "OnBootSec=", "OnStartupSec=", "OnActiveSec=", "OnUnitActiveSec=", "Unit=", "WantedBy=", "User="} {
				if strings.HasPrefix(l, k) {
					return true
				}
			}
			return false
		})
	case "cron", "ld_preload":
		it.Detail = matchLines(data, func(string) bool { return true })
	case "authorized_keys":
		it.Keys = parseAuthorizedKeys(data)
	}
	inv.Items = append(inv.Items, it)
}

// matchLines returns the non-comment, non-blank lines keep accepts.
func matchLines(data []byte, keep func(string) bool) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 0, 4096), maxReadBytes)
	for sc.Scan() && len(out) < maxDetail {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, ";") || !keep(l) {
			continue
		}
		if len(l) > 300 {
			l = l[:300]
		}
		out = append(out, l)
	}
	return out
}

// parseAuthorizedKeys lists each key by type, fingerprint and comment.
// The options field may contain quoted spaces; the key type is the first
// field that names a known key algorithm.
func parseAuthorizedKeys(data []byte) []Key {
	var out []Key
	for _, line := range matchLines(data, func(string) bool { return true }) {
		f := splitKeyLine(line)
		for i, tok := range f {
			if !isKeyType(tok) || i+1 >= len(f) {
				continue
			}
			k := Key{Type: tok, Options: strings.Join(f[:i], " "), Comment: strings.Join(f[i+2:], " ")}
			if blob, err := base64.StdEncoding.DecodeString(f[i+1]); err == nil {
				sum := sha256.Sum256(blob)
				k.Fingerprint = "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
			} else {
				k.Fingerprint = "unparseable key data"
			}
			out = append(out, k)
			break
		}
	}
	return out
}

func isKeyType(s string) bool {
	return strings.HasPrefix(s, "ssh-") || strings.HasPrefix(s, "ecdsa-sha2-") || strings.HasPrefix(s, "sk-")
}

// splitKeyLine splits on spaces outside double quotes.
func splitKeyLine(l string) []string {
	var out []string
	var cur strings.Builder
	inQ := false
	for i := 0; i < len(l); i++ {
		switch c := l[i]; {
		case c == '"':
			inQ = !inQ
			cur.WriteByte(c)
		case (c == ' ' || c == '\t') && !inQ:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// Collect acquires the persistence files and the inventory into an open
// package. base supplies the roots, host, user and bounds.
func Collect(b *casepkg.Builder, base collector.Options) (*collector.Stats, error) {
	opts := base
	opts.Product = Product
	opts.ConfigRoot = base.ProfileRoot
	start := time.Now()
	_ = b.Log("collection_run_started", map[string]any{"product": Product, "profile_root": opts.ProfileRoot, "system_root": opts.SystemRoot})
	st, err := collector.Run(b, Manifest(), opts)
	if err != nil {
		return st, err
	}
	inv := Build(opts.ProfileRoot, opts.SystemRoot)
	sort.SliceStable(inv.Skipped, func(i, j int) bool { return inv.Skipped[i].Path < inv.Skipped[j].Path })
	data, err := json.MarshalIndent(inv, "", "  ")
	if err != nil {
		return st, err
	}
	tmp, err := os.CreateTemp("", "adfir-persist-*.json")
	if err != nil {
		return st, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return st, err
	}
	tmp.Close()
	rec := casepkg.ArtifactRecord{SourcePath: "computed:" + InventoryPath, LogicalPath: InventoryPath, Host: opts.Host, User: opts.User,
		Product: Product, CollectorRule: "linux.persistence_inventory", ArtifactType: "host_persistence", Sensitivity: "high"}
	if err := b.IngestFile(tmp.Name(), rec); err != nil {
		return st, fmt.Errorf("persistence inventory: %w", err)
	}
	st.Acquired++
	_ = b.Log("collection_run_finished", map[string]any{"product": Product, "acquired": st.Acquired, "skipped": st.Skipped,
		"failed": st.Failed, "inventory_items": len(inv.Items), "inventory_skipped": len(inv.Skipped), "duration_ms": time.Since(start).Milliseconds()})
	return st, nil
}
