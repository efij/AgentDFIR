// Package extinv inventories the code an editor or an agent loads on its
// own: IDE extensions (VS Code and its forks), agent plugins with their
// hooks, plugin marketplaces and skills — and raises heuristic findings on
// what that code does.
//
// The October 2025 GlassWorm worm spread through Open VSX and VS Code
// extensions, hiding its loader in characters a reviewer cannot see, and
// stole the tokens of everyone who installed an infected version. Agent
// plugins and skills are the same shape of supply chain: a hook runs at
// session start, a skill's markdown is read by the model as trusted
// instructions. Neither is visible to a dependency scanner.
//
// Read-only by construction: manifests and entry files are read with size
// bounds, hashed, and pattern-matched. Nothing is executed, resolved,
// installed or contacted. No indicator values (extension IDs, hashes,
// domains) ship with this package; known-bad lists come from the user
// through `agentdfir hunt --iocs`.
//
// Works on a live (or offline-mounted) home directory and on a sealed
// .adfir package, through the same tree abstraction.
package extinv

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v5/internal/casepkg"
)

// Bounds for hostile input.
const (
	MaxManifestBytes = 4 << 20   // package.json, plugin.json, hooks.json, a skill file
	MaxRegistryBytes = 16 << 20  // extensions.json, installed_plugins.json
	MaxCodeBytes     = 32 << 20  // an entry file scanned by the code heuristics
	MaxHashBytes     = 256 << 20 // a file hashed in full on a live host
	MaxExtensionDirs = 5000      // per editor
	MaxPluginDirs    = 2000
	MaxSkillFiles    = 5000
)

// Extension is one installed IDE extension.
type Extension struct {
	Editor      string `json:"editor"` // vscode | vscode-insiders | vscodium | cursor | windsurf | kiro | trae | positron | *-server
	ID          string `json:"id"`     // publisher.name, lowercased
	Publisher   string `json:"publisher,omitempty"`
	Name        string `json:"name,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Version     string `json:"version,omitempty"`
	Dir         string `json:"dir"` // evidence path of the extension directory
	// InstalledAt is metadata.installedTimestamp from the editor's
	// registry (or the older package.json __metadata), RFC 3339 UTC.
	InstalledAt          string `json:"installed_at,omitempty"`
	PublisherDisplayName string `json:"publisher_display_name,omitempty"`
	// Source is what the editor recorded: gallery (its configured
	// marketplace), vsix (installed from a file), resource, or "" when the
	// editor recorded nothing.
	Source string `json:"source,omitempty"`
	// Registry is the marketplace the editor uses by default: vs-marketplace
	// for Microsoft builds, open-vsx-or-vendor for forks (Open VSX or the
	// vendor's own mirror). It is the editor's default, not proof of where
	// this extension came from.
	Registry   string `json:"registry"`
	PreRelease bool   `json:"pre_release,omitempty"`
	// Registered: listed in the editor's extensions.json. A directory the
	// registry does not list was dropped in by hand or left behind.
	Registered bool `json:"registered"`
	Present    bool `json:"present"` // directory exists in the evidence
	Obsolete   bool `json:"obsolete,omitempty"`
	// ActivationEvents as declared; StartupActivation when "*" or
	// onStartupFinished: the code runs whenever the editor starts.
	ActivationEvents  []string    `json:"activation_events,omitempty"`
	StartupActivation bool        `json:"startup_activation,omitempty"`
	Contributes       Contributes `json:"contributes"`
	Main              string      `json:"main,omitempty"`    // entry file, evidence path
	Browser           string      `json:"browser,omitempty"` // web entry file, evidence path
	MainSize          int64       `json:"main_size,omitempty"`
	MainSHA256        string      `json:"main_sha256,omitempty"`
	PackageSHA256     string      `json:"package_json_sha256,omitempty"`
	// CodeScanned is false when the entry file was absent, not collected
	// or not readable: the code heuristics did not run on this extension.
	CodeScanned bool     `json:"code_scanned"`
	Notes       []string `json:"notes,omitempty"`

	signals       codeSignals
	registryKnown bool // the editor's extensions.json was read
}

// Contributes summarizes what an extension adds to the editor that an
// agent can reach.
type Contributes struct {
	Commands int `json:"commands"`
	// MCPServerProviders: contributes.mcpServerDefinitionProviders — the
	// extension can hand the editor's agent MCP servers at run time.
	MCPServerProviders []string `json:"mcp_server_providers,omitempty"`
	ChatParticipants   []string `json:"chat_participants,omitempty"`
	LanguageModelTools []string `json:"language_model_tools,omitempty"`
}

// Hook is one command an agent plugin registers on a lifecycle event.
type Hook struct {
	Event   string `json:"event"`
	Command string `json:"command"`
	File    string `json:"file,omitempty"` // the hooks file (or plugin.json) that declares it
}

// Plugin is one agent plugin (Claude Code plugin, Codex plugin, Gemini CLI
// extension).
type Plugin struct {
	Host        string   `json:"host"` // claude-code | codex-cli | gemini-cli
	Name        string   `json:"name"`
	Marketplace string   `json:"marketplace,omitempty"`
	Version     string   `json:"version,omitempty"`
	Scope       string   `json:"scope,omitempty"`
	InstalledAt string   `json:"installed_at,omitempty"`
	LastUpdated string   `json:"last_updated,omitempty"`
	GitCommit   string   `json:"git_commit,omitempty"`
	Dir         string   `json:"dir"`
	Registered  bool     `json:"registered"` // listed in the host's install registry
	Present     bool     `json:"present"`
	Hooks       []Hook   `json:"hooks,omitempty"`
	Commands    []string `json:"commands,omitempty"`
	Agents      []string `json:"agents,omitempty"`
	Skills      []string `json:"skills,omitempty"`
	MCPServers  []string `json:"mcp_servers,omitempty"`
	ManifestSHA string   `json:"manifest_sha256,omitempty"`
	Notes       []string `json:"notes,omitempty"`

	tr  tree   // where the plugin's files are, for reading hook scripts
	rel string // plugin directory inside tr
}

// Marketplace is a plugin source the host was told to trust.
type Marketplace struct {
	Host     string `json:"host"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`              // github | git | url | directory | file | unknown
	Location string `json:"location"`          // repo, URL or path as recorded
	Default  bool   `json:"default"`           // the host's built-in marketplace
	Updated  string `json:"updated,omitempty"` // lastUpdated as recorded
	Evidence string `json:"evidence"`
}

// Skill is one markdown file an agent loads as a skill, sub-agent or
// command definition.
type Skill struct {
	Host   string `json:"host"`
	Kind   string `json:"kind"` // skill | agent | command
	Name   string `json:"name"`
	Plugin string `json:"plugin,omitempty"`
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256,omitempty"`

	hidden hiddenSignals
}

// Inventory is the normalized view of one home or package.
type Inventory struct {
	Source       string        `json:"source"`
	Mode         string        `json:"mode"` // live | package
	Extensions   []Extension   `json:"extensions"`
	Plugins      []Plugin      `json:"plugins"`
	Marketplaces []Marketplace `json:"marketplaces"`
	Skills       []Skill       `json:"skills"`
	RootsSeen    []string      `json:"roots_seen"`
	Problems     []string      `json:"problems,omitempty"`    // unreadable or malformed input, never silent
	Unsupported  []string      `json:"unsupported,omitempty"` // what was present but could not be analyzed, and why
}

// ---- tree: one read-only view over a live home or a sealed package

type entry struct {
	name  string
	dir   bool
	link  bool
	size  int64
	mtime string
}

type tree interface {
	// read returns at most max bytes; truncated reports that more exist.
	read(rel string, max int64) (data []byte, truncated bool, err error)
	list(rel string) []entry
	stat(rel string) (entry, bool)
	sha256(rel string) string
	ref(rel string) string // evidence reference for a finding or the inventory
	// fromSource maps a path recorded on the source machine (an
	// installPath, a location) to a tree path.
	fromSource(p string) (string, bool)
}

var errNotRegular = errors.New("not a regular file")

// liveTree reads a directory on this machine. Links are never followed and
// only regular files are opened (a FIFO would block forever).
type liveTree struct{ root string }

func (t liveTree) abs(rel string) string { return filepath.Join(t.root, filepath.FromSlash(rel)) }

func (t liveTree) read(rel string, max int64) ([]byte, bool, error) {
	p := t.abs(rel)
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, false, err
	}
	if !fi.Mode().IsRegular() {
		return nil, false, errNotRegular
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(b)) > max {
		return b[:max], true, nil
	}
	return b, false, nil
}

func (t liveTree) list(rel string) []entry {
	des, err := os.ReadDir(t.abs(rel))
	if err != nil {
		return nil
	}
	out := make([]entry, 0, len(des))
	for _, d := range des {
		e := entry{name: d.Name(), dir: d.IsDir(), link: d.Type()&os.ModeSymlink != 0}
		if fi, err := d.Info(); err == nil {
			e.size = fi.Size()
			e.mtime = fi.ModTime().UTC().Format(time.RFC3339)
		}
		out = append(out, e)
	}
	return out
}

func (t liveTree) stat(rel string) (entry, bool) {
	fi, err := os.Lstat(t.abs(rel))
	if err != nil {
		return entry{}, false
	}
	return entry{name: fi.Name(), dir: fi.IsDir(), link: fi.Mode()&os.ModeSymlink != 0, size: fi.Size(),
		mtime: fi.ModTime().UTC().Format(time.RFC3339)}, true
}

func (t liveTree) sha256(rel string) string {
	p := t.abs(rel)
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() {
		return ""
	}
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, MaxHashBytes+1))
	if err != nil || n > MaxHashBytes {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (t liveTree) ref(rel string) string { return t.abs(rel) }

func (t liveTree) fromSource(p string) (string, bool) {
	p = filepath.Clean(p)
	if r, err := filepath.Rel(t.root, p); err == nil && !strings.HasPrefix(r, "..") && !filepath.IsAbs(r) {
		return filepath.ToSlash(r), true
	}
	return fromSourceMarkers(p)
}

// fromSourceMarkers maps an absolute source-machine path onto the home
// layout by its known directory marker (…/.claude/plugins/… → .claude/plugins/…).
func fromSourceMarkers(p string) (string, bool) {
	s := strings.ReplaceAll(p, `\`, "/")
	for _, m := range sourceMarkers {
		if i := strings.Index(s, "/"+m); i >= 0 {
			return path.Clean(s[i+1:]), true
		}
	}
	return "", false
}

var sourceMarkers = []string{".claude/plugins/", ".codex/plugins/", ".gemini/extensions/"}

// pkgTree is a sealed package's artifacts under one home prefix.
type pkgTree struct {
	prefix   string // logical-path prefix of this home ("" or "C/Users/alice/")
	store    *casepkg.Store
	files    map[string]casepkg.ArtifactRecord
	children map[string]map[string]bool // dir → child name → isDir
}

func newPkgTree(prefix string, store *casepkg.Store, recs []casepkg.ArtifactRecord) *pkgTree {
	t := &pkgTree{prefix: prefix, store: store, files: map[string]casepkg.ArtifactRecord{}, children: map[string]map[string]bool{}}
	for _, a := range recs {
		lp := strings.ReplaceAll(a.LogicalPath, `\`, "/")
		if !strings.HasPrefix(lp, prefix) {
			continue
		}
		rel := strings.TrimPrefix(lp, prefix)
		if rel == "" || strings.Contains("/"+rel+"/", "/../") {
			continue
		}
		t.files[rel] = a
		// Every ancestor is a directory.
		for p := rel; ; {
			dir, name := path.Split(p)
			dir = strings.TrimSuffix(dir, "/")
			if t.children[dir] == nil {
				t.children[dir] = map[string]bool{}
			}
			isDir := p != rel
			t.children[dir][name] = t.children[dir][name] || isDir
			if dir == "" {
				break
			}
			p = dir
		}
	}
	return t
}

func (t *pkgTree) read(rel string, max int64) ([]byte, bool, error) {
	a, ok := t.files[rel]
	if !ok {
		return nil, false, os.ErrNotExist
	}
	if a.Status != casepkg.StatusOK || a.ArtifactID == "" {
		return nil, false, fmt.Errorf("artifact status %s", a.Status)
	}
	rc, err := t.store.Open(a.ArtifactID)
	if err != nil {
		return nil, false, err
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, max+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(b)) > max {
		return b[:max], true, nil
	}
	return b, false, nil
}

func (t *pkgTree) list(rel string) []entry {
	kids := t.children[rel]
	out := make([]entry, 0, len(kids))
	for name, isDir := range kids {
		e := entry{name: name, dir: isDir}
		if !isDir {
			child := name
			if rel != "" {
				child = rel + "/" + name
			}
			a := t.files[child]
			e.size, e.mtime = a.Size, a.ModTimeUTC
			e.link = a.SymlinkTarget != ""
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

func (t *pkgTree) stat(rel string) (entry, bool) {
	if a, ok := t.files[rel]; ok {
		return entry{name: path.Base(rel), size: a.Size, mtime: a.ModTimeUTC, link: a.SymlinkTarget != ""}, true
	}
	if _, ok := t.children[rel]; ok {
		return entry{name: path.Base(rel), dir: true}, true
	}
	return entry{}, false
}

func (t *pkgTree) sha256(rel string) string {
	if a, ok := t.files[rel]; ok && a.Status == casepkg.StatusOK {
		return a.ArtifactID // content address = SHA-256 of the plaintext
	}
	return ""
}

func (t *pkgTree) ref(rel string) string {
	if a, ok := t.files[rel]; ok && a.ArtifactID != "" {
		return fmt.Sprintf("%s (artifact %.12s)", t.prefix+rel, a.ArtifactID)
	}
	return t.prefix + rel
}

func (t *pkgTree) fromSource(p string) (string, bool) { return fromSourceMarkers(p) }

// ---- entry points

// ScanHome inventories a live or offline-mounted home directory.
func ScanHome(root string) *Inventory {
	inv := &Inventory{Source: root, Mode: "live"}
	scanTree(inv, liveTree{root: root})
	finish(inv)
	return inv
}

// homeMarkers locate a home inside a package: any logical path containing
// one of these directories belongs to the home that precedes it.
var homeMarkers = func() []string {
	var m []string
	for _, e := range editors {
		m = append(m, e.dir+"/")
	}
	return append(m, ".claude/plugins/", ".claude/skills/", ".claude/agents/", ".claude/commands/",
		".codex/skills/", ".codex/plugins/", ".gemini/extensions/", ".kiro/skills/")
}()

// ScanPackage inventories what a sealed package collected.
func ScanPackage(pkgDir string) (*Inventory, error) {
	man, err := casepkg.ReadManifest(pkgDir)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	inv := &Inventory{Source: pkgDir, Mode: "package"}
	recs := man.Current()
	prefixes := map[string]bool{}
	for _, a := range recs {
		lp := strings.ReplaceAll(a.LogicalPath, `\`, "/")
		for _, m := range homeMarkers {
			if strings.HasPrefix(lp, m) {
				prefixes[""] = true
			} else if i := strings.Index(lp, "/"+m); i >= 0 {
				prefixes[lp[:i+1]] = true
			}
		}
	}
	keys := make([]string, 0, len(prefixes))
	for p := range prefixes {
		keys = append(keys, p)
	}
	sort.Strings(keys)
	store := casepkg.NewStore(pkgDir, man)
	for _, p := range keys {
		scanTree(inv, newPkgTree(p, store, recs))
	}
	finish(inv)
	return inv, nil
}

func scanTree(inv *Inventory, t tree) {
	scanEditors(inv, t)
	scanClaudePlugins(inv, t)
	scanSkills(inv, t)
	scanGeminiExtensions(inv, t)
	scanCodexPlugins(inv, t)
}

func finish(inv *Inventory) {
	sort.SliceStable(inv.Extensions, func(i, j int) bool {
		a, b := inv.Extensions[i], inv.Extensions[j]
		if a.Editor != b.Editor {
			return a.Editor < b.Editor
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		return a.Version < b.Version
	})
	sort.SliceStable(inv.Plugins, func(i, j int) bool {
		a, b := inv.Plugins[i], inv.Plugins[j]
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		return a.Name+"@"+a.Marketplace < b.Name+"@"+b.Marketplace
	})
	sort.SliceStable(inv.Skills, func(i, j int) bool { return inv.Skills[i].Path < inv.Skills[j].Path })
	sort.Strings(inv.RootsSeen)
	if inv.Extensions == nil {
		inv.Extensions = []Extension{}
	}
	if inv.Plugins == nil {
		inv.Plugins = []Plugin{}
	}
	if inv.Marketplaces == nil {
		inv.Marketplaces = []Marketplace{}
	}
	if inv.Skills == nil {
		inv.Skills = []Skill{}
	}
}

// join builds a tree path.
func join(parts ...string) string {
	var keep []string
	for _, p := range parts {
		if p != "" {
			keep = append(keep, p)
		}
	}
	return path.Join(keep...)
}

// inside reports whether a relative reference stays inside its base (no
// "..", no absolute path): a manifest cannot point the scan elsewhere.
func inside(ref string) (string, bool) {
	r := strings.ReplaceAll(ref, `\`, "/")
	if r == "" || strings.HasPrefix(r, "/") || (len(r) > 1 && r[1] == ':') {
		return "", false
	}
	c := path.Clean(r)
	if c == "." || c == ".." || strings.HasPrefix(c, "../") {
		return "", false
	}
	return c, true
}

func msTime(ms float64) string {
	if ms <= 0 || ms > 1e14 {
		return ""
	}
	return time.UnixMilli(int64(ms)).UTC().Format(time.RFC3339)
}
