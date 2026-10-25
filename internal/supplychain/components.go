package supplychain

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/efij/AgentDFIR/v4/internal/casepkg"
	"github.com/efij/AgentDFIR/v4/internal/extinv"
	"github.com/efij/AgentDFIR/v4/internal/mcpaudit"
)

// maxBlob bounds one evidence file read for settings, git metadata and
// cached manifests.
const maxBlob = 4 << 20

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// evidencePath turns an inventory reference ("a/b (artifact 0123…)") into
// the logical path it names.
func evidencePath(ref string) string {
	if i := strings.Index(ref, " (artifact "); i >= 0 {
		ref = ref[:i]
	}
	return normPath(strings.TrimSpace(ref))
}

func (b *builder) readBlob(a casepkg.ArtifactRecord) ([]byte, error) {
	if b.in.Store == nil {
		return nil, fmt.Errorf("no evidence store")
	}
	if a.Size > maxBlob {
		return nil, fmt.Errorf("%d bytes exceeds the %d byte bound", a.Size, maxBlob)
	}
	return b.in.Store.ReadAll(a.ArtifactID, maxBlob)
}

// components lists everything the inventories found, plus the settings
// hooks, instruction files and settings files the manifest holds.
func (b *builder) components() {
	if b.in.Ext != nil {
		b.extComponents(b.in.Ext)
		for _, u := range b.in.Ext.Unsupported {
			b.unsupported("extension inventory: %s", u)
		}
	} else {
		b.note("no extension/plugin/skill inventory: plugins, skills and IDE extensions are not listed")
	}
	if b.in.MCP != nil {
		for _, s := range b.in.MCP.Servers {
			b.mcpComponent(s)
		}
	} else {
		b.note("no MCP inventory: configured MCP servers are not listed")
	}
	b.fileComponents()
}

func pluginID(p extinv.Plugin) string {
	id := "plugin:" + p.Host + ":" + p.Name
	if p.Marketplace != "" {
		id += "@" + p.Marketplace
	}
	return id
}

func (b *builder) extComponents(inv *extinv.Inventory) {
	mkts := map[string]extinv.Marketplace{}
	for _, m := range inv.Marketplaces {
		mkts[m.Host+"\x00"+m.Name] = m
		c := Component{ID: "marketplace:" + m.Host + ":" + m.Name, Kind: KindMarketplace, Name: m.Name, Host: m.Host,
			Origin: Origin{Type: m.Kind, Trust: trustOf(m.Default), Location: safeURL(m.Location), Basis: "marketplace registry " + m.Evidence}}
		if m.Kind == "github" || m.Kind == "git" {
			c.Origin.GitRemote = safeURL(m.Location)
		}
		if t, ok := parseTS(m.Updated); ok {
			c.LastSeen = &Stamp{Time: rfc(t), Source: TimeInstall, Detail: "marketplace lastUpdated", Ref: m.Evidence}
		}
		if p := evidencePath(m.Evidence); p != "" {
			c.Paths = []string{p}
		}
		b.add(c)
	}
	for _, p := range inv.Plugins {
		dir := evidencePath(p.Dir)
		o := Origin{Type: "marketplace", Trust: "unknown", Marketplace: p.Marketplace, Version: p.Version, GitCommit: p.GitCommit,
			Basis: "plugin install registry"}
		if m, ok := mkts[p.Host+"\x00"+p.Marketplace]; ok {
			o.Trust = trustOf(m.Default)
			o.Location = safeURL(m.Location)
			if m.Kind == "github" || m.Kind == "git" {
				o.GitRemote = safeURL(m.Location)
			}
			if m.Kind == "directory" || m.Kind == "file" {
				o.LocalPath = m.Location
			}
		} else if p.Marketplace == "" {
			o.Type = "unknown"
		}
		if !p.Registered {
			o.Trust = "unregistered"
			o.Basis = "plugin directory present without an install registry entry"
		}
		c := Component{ID: pluginID(p), Kind: KindPlugin, Name: p.Name, Host: p.Host, Origin: o, SHA256: p.ManifestSHA,
			HashBasis: "plugin manifest content"}
		if dir != "" {
			c.Paths = []string{dir}
		}
		if t, ok := parseTS(p.InstalledAt); ok {
			c.FirstSeen = &Stamp{Time: rfc(t), Source: TimeInstall, Detail: "installedAt"}
		}
		if t, ok := parseTS(p.LastUpdated); ok {
			c.LastSeen = &Stamp{Time: rfc(t), Source: TimeInstall, Detail: "lastUpdated"}
		}
		pc := b.add(c)
		pid := pc.ID
		if p.Marketplace != "" {
			if _, ok := mkts[p.Host+"\x00"+p.Marketplace]; ok {
				b.relate(Relation{From: pid, To: "marketplace:" + p.Host + ":" + p.Marketplace, Type: "installed_from", Class: Verified,
					Basis: "the host's plugin install registry names this marketplace", Refs: []Ref{{Path: dir}}})
			}
		}
		for _, h := range p.Hooks {
			hid := "hook:" + strings.TrimPrefix(pid, "plugin:") + ":" + h.Event + ":" + short(sha(h.Command))
			hc := Component{ID: hid, Kind: KindHook, Name: h.Event + " hook", Host: p.Host, Parent: pid, Origin: o,
				SHA256: sha(h.Command), HashBasis: "declared command string", cmd: h.Command, event: h.Event}
			hc.Origin.Basis = "declared by plugin " + p.Name
			if f := evidencePath(h.File); f != "" {
				hc.Paths = []string{f}
			}
			b.add(hc)
			b.relate(Relation{From: pid, To: hid, Type: "contains", Class: Verified, Basis: "the plugin's hooks declaration lists this hook",
				Label: trim(h.Command, 160), Refs: []Ref{{Path: evidencePath(h.File)}}})
		}
	}
	// A plugin's skills are matched to it by directory, never by name alone.
	type pdir struct{ dir, id string }
	var pdirs []pdir
	for _, p := range inv.Plugins {
		if d := evidencePath(p.Dir); d != "" {
			pdirs = append(pdirs, pdir{d + "/", pluginID(p)})
		}
	}
	sort.Slice(pdirs, func(i, j int) bool { return len(pdirs[i].dir) > len(pdirs[j].dir) })
	for _, s := range inv.Skills {
		kind := map[string]string{"skill": KindSkill, "agent": KindSubagent, "command": KindCommand, "context": KindInstruction}[s.Kind]
		if kind == "" {
			kind = KindSkill
		}
		p := evidencePath(s.Path)
		name := s.Name
		var parent string
		for _, d := range pdirs {
			if strings.HasPrefix(p, d.dir) {
				parent = d.id
				break
			}
		}
		id := kind + ":" + s.Host + ":"
		if s.Plugin != "" {
			id += s.Plugin + ":"
		}
		id += name
		c := Component{ID: id, Kind: kind, Name: name, Host: s.Host, Parent: parent, SHA256: s.SHA256, HashBasis: "file content",
			Paths: []string{p}}
		if parent != "" {
			if pc := b.comp(parent); pc != nil {
				c.Origin = pc.Origin
				c.Origin.Basis = "file inside plugin " + pc.Name
			}
		} else {
			c.Origin = b.localOrigin(p)
		}
		if s.Plugin != "" {
			// The host invokes a plugin skill as <plugin>:<skill>; the
			// inventory labels the plugin <plugin>@<marketplace>.
			c.Name = strings.SplitN(s.Plugin, "@", 2)[0] + ":" + name
		}
		b.add(c)
		if parent != "" {
			b.relate(Relation{From: parent, To: id, Type: "contains", Class: Verified, Basis: "the file is inside the plugin's directory",
				Refs: []Ref{{Path: p}}})
		}
	}
	for _, x := range inv.Extensions {
		o := Origin{Type: "unknown", Trust: "unknown", Package: x.ID, Version: x.Version, Basis: "editor extension registry"}
		switch {
		case x.Source == "gallery":
			o.Type, o.Trust, o.Location = "gallery", "default", x.Registry
		case x.Source == "vsix":
			o.Type, o.Trust = "vsix", "third_party"
		case !x.Registered:
			o.Trust = "unregistered"
			o.Basis = "extension directory present without a registry entry"
		}
		c := Component{ID: "ide_extension:" + x.Editor + ":" + x.ID, Kind: KindExtension, Name: x.ID, Host: x.Editor, Origin: o,
			SHA256: firstNonEmpty(x.MainSHA256, x.PackageSHA256), HashBasis: "extension entry file content"}
		if x.MainSHA256 == "" {
			c.HashBasis = "extension package.json content"
		}
		if d := evidencePath(x.Dir); d != "" {
			c.Paths = append(c.Paths, d)
		}
		if t, ok := parseTS(x.InstalledAt); ok {
			c.FirstSeen = &Stamp{Time: rfc(t), Source: TimeInstall, Detail: "installedTimestamp"}
		}
		b.add(c)
	}
}

func trustOf(def bool) string {
	if def {
		return "default"
	}
	return "third_party"
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// localOrigin is the origin of a file that no install registry names: a
// repository when git metadata for an enclosing directory was collected,
// otherwise a local file.
func (b *builder) localOrigin(p string) Origin {
	if remote, commit, gitDir, ok := b.gitFor(p); ok {
		return Origin{Type: "repository", Trust: "repository", GitRemote: remote, GitCommit: commit, LocalPath: path.Dir(gitDir),
			Basis: "git metadata collected at " + gitDir}
	}
	return Origin{Type: "local", Trust: "local", LocalPath: p, Basis: "no install record names it; a local file"}
}

var remoteURLRe = regexp.MustCompile(`(?m)^\s*url\s*=\s*(\S+)`)

// gitFor walks up from a logical path to the nearest directory whose
// .git/config was collected, and reads its remote and HEAD commit.
func (b *builder) gitFor(p string) (remote, commit, gitDir string, ok bool) {
	dir := path.Dir(p)
	for hop := 0; hop < 64 && dir != "." && dir != "/" && dir != ""; hop++ {
		cfg, has := b.current[dir+"/.git/config"]
		if has {
			gitDir = dir + "/.git"
			if data, err := b.readBlob(cfg); err == nil {
				if m := remoteURLRe.FindSubmatch(data); m != nil {
					remote = safeURL(string(m[1]))
				}
			}
			commit = b.gitHead(gitDir)
			return remote, commit, gitDir, true
		}
		dir = path.Dir(dir)
	}
	return "", "", "", false
}

var hexCommitRe = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

func (b *builder) gitHead(gitDir string) string {
	head, ok := b.current[gitDir+"/HEAD"]
	if !ok {
		return ""
	}
	data, err := b.readBlob(head)
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(data))
	if hexCommitRe.MatchString(s) {
		return s
	}
	ref := strings.TrimSpace(strings.TrimPrefix(s, "ref:"))
	if ref == s || strings.Contains(ref, "..") {
		return ""
	}
	if r, ok := b.current[gitDir+"/"+ref]; ok {
		if d, err := b.readBlob(r); err == nil {
			if c := strings.TrimSpace(string(d)); hexCommitRe.MatchString(c) {
				return c
			}
		}
	}
	if r, ok := b.current[gitDir+"/packed-refs"]; ok {
		if d, err := b.readBlob(r); err == nil {
			sc := bufio.NewScanner(bytes.NewReader(d))
			for sc.Scan() {
				f := strings.Fields(sc.Text())
				if len(f) == 2 && f[1] == ref && hexCommitRe.MatchString(f[0]) {
					return f[0]
				}
			}
		}
	}
	return ""
}

func mcpID(s mcpaudit.Server) string { return "mcp_server:" + s.Key() }

// defHash fingerprints what a server is: how it is launched or reached,
// its env (by the audit's value fingerprint, never the values), and the
// resolved binary when one was hashed.
func defHash(s mcpaudit.Server) string {
	return sha(s.Identity() + "\x00" + s.EnvSHA256 + "\x00" + s.SHA256 + "\x00" + strings.Join(s.HeaderKeys, ","))
}

func (b *builder) mcpComponent(s mcpaudit.Server) {
	o := Origin{Type: "local", Trust: "local", Basis: "MCP configuration " + s.ConfigPath}
	switch {
	case strings.Contains(s.Package, "git+") || strings.HasPrefix(s.Package, "github:"):
		o.Type, o.Trust, o.Package = "git", "third_party", safeURL(s.Package)
		o.GitRemote = safeURL(strings.TrimPrefix(s.Package, "git+"))
	case s.Package != "":
		o.Type, o.Trust, o.Package = "npm", "registry", s.Package
		switch s.PackageMgr {
		case "uvx", "pipx":
			o.Type = "pypi"
		}
		o.Package, o.Version = splitPkgVersion(s.Package)
	case s.URL != "":
		o.Type, o.Trust, o.URL = "url", "remote", safeURL(s.URL)
	case s.Command != "":
		o.LocalPath = s.Command
	default:
		o.Type, o.Trust = "unknown", "unknown"
	}
	c := Component{ID: mcpID(s), Kind: KindMCP, Name: s.Name, Host: s.Host, Origin: o, SHA256: defHash(s),
		HashBasis: "server definition (command/args or URL, env fingerprint, header names, resolved binary)",
		Paths:     []string{normPath(s.ConfigPath)}}
	for _, t := range s.Tools {
		c.Tools = append(c.Tools, t.Name)
	}
	b.add(c)
}

// splitPkgVersion splits "@scope/name@1.2.3" / "name==1.2" into name and version.
func splitPkgVersion(p string) (string, string) {
	if i := strings.Index(p, "=="); i > 0 {
		return p[:i], p[i+2:]
	}
	if i := strings.LastIndex(p, "@"); i > 0 {
		return p[:i], p[i+1:]
	}
	return p, ""
}

// instructionRe names standing-instruction files (the same set
// correlate-cases compares by content hash).
var instructionRe = regexp.MustCompile(`(?i)(^|/)(CLAUDE(\.local)?\.md|AGENTS?\.md|GEMINI\.md|\.cursorrules|\.windsurfrules|\.clinerules|copilot-instructions\.md|instructions\.md|memory\.md)$|(^|/)\.cursor/rules/|(^|/)\.github/instructions/|(^|/)\.claude/(agents|commands|skills)/`)

// settingsRe names agent settings files whose permission rules, hooks and
// MCP switches are compared across rounds.
var settingsRe = regexp.MustCompile(`(?i)(^|/)\.claude/settings(\.local)?\.json$|(^|/)managed-settings\.json$|(^|/)\.gemini/settings\.json$`)

// fileComponents adds the components that are files the inventories do
// not cover: instruction files, settings files and the hooks settings
// declare. Every path ever collected counts, so a file removed in a later
// round still shows its history.
func (b *builder) fileComponents() {
	claimed := map[string]bool{}
	for _, c := range b.rep.Components {
		for _, p := range c.Paths {
			claimed[p] = true
		}
	}
	paths := make([]string, 0, len(b.recs))
	for p := range b.recs {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		switch {
		case settingsRe.MatchString(p) || mcpaudit.IsConfigPath(p):
			c := Component{ID: "agent_settings:" + p, Kind: KindAgentSetting, Name: path.Base(p), Paths: []string{p},
				Origin: b.localOrigin(p), HashBasis: "file content"}
			if rs := b.recs[p]; len(rs) > 0 {
				c.Host = rs[len(rs)-1].Product
			}
			if settingsRe.MatchString(p) {
				b.settingsHooks(p)
			}
			b.add(c)
		case instructionRe.MatchString(p) && !claimed[p]:
			c := Component{ID: "instruction_file:" + p, Kind: KindInstruction, Name: path.Base(p), Paths: []string{p},
				Origin: b.localOrigin(p), HashBasis: "file content"}
			if rs := b.recs[p]; len(rs) > 0 {
				c.Host = rs[len(rs)-1].Product
			}
			b.add(c)
		}
	}
}

// settingsHooks adds the hooks a settings file declares now.
func (b *builder) settingsHooks(p string) {
	a, ok := b.current[p]
	if !ok {
		return
	}
	data, err := b.readBlob(a)
	if err != nil {
		b.note("%s: not read: %v", p, err)
		return
	}
	sv, err := parseSettings(data)
	if err != nil {
		b.note("%s: %v", p, err)
		return
	}
	o := b.localOrigin(p)
	o.Basis = "declared in " + p
	for _, ev := range sortedKeys(sv.Hooks) {
		for _, cmd := range sv.Hooks[ev] {
			id := "hook:settings:" + p + ":" + ev + ":" + short(sha(cmd))
			b.add(Component{ID: id, Kind: KindHook, Name: ev + " hook", Host: a.Product, Parent: "agent_settings:" + p, Origin: o,
				SHA256: sha(cmd), HashBasis: "declared command string", Paths: []string{p}, cmd: cmd, event: ev})
			b.relate(Relation{From: "agent_settings:" + p, To: id, Type: "contains", Class: Verified,
				Basis: "the settings file declares this hook", Label: trim(cmd, 160), Refs: []Ref{{ArtifactID: a.ArtifactID, Path: p}}})
		}
	}
}

// settingsView is the part of an agent settings file that grants or runs
// something.
type settingsView struct {
	Allow, Deny, Ask []string
	DefaultMode      string
	Hooks            map[string][]string // event → commands
	EnableAllProject bool
	EnabledMCPJSON   []string
	MCPServers       []string
}

func parseSettings(data []byte) (settingsView, error) {
	var sv settingsView
	var doc struct {
		Permissions struct {
			Allow       []string `json:"allow"`
			Deny        []string `json:"deny"`
			Ask         []string `json:"ask"`
			DefaultMode string   `json:"defaultMode"`
		} `json:"permissions"`
		Hooks          map[string]json.RawMessage `json:"hooks"`
		EnableAll      bool                       `json:"enableAllProjectMcpServers"`
		EnabledMCPJSON []string                   `json:"enabledMcpjsonServers"`
		MCPServers     map[string]json.RawMessage `json:"mcpServers"`
	}
	if err := json.Unmarshal(mcpaudit.StripJSONC(data), &doc); err != nil {
		return sv, fmt.Errorf("settings are not valid JSON: %v", err)
	}
	sv.Allow, sv.Deny, sv.Ask, sv.DefaultMode = doc.Permissions.Allow, doc.Permissions.Deny, doc.Permissions.Ask, doc.Permissions.DefaultMode
	sv.EnableAllProject, sv.EnabledMCPJSON = doc.EnableAll, doc.EnabledMCPJSON
	sv.MCPServers = sortedKeys(doc.MCPServers)
	sv.Hooks = map[string][]string{}
	for ev, raw := range doc.Hooks {
		// {"Event": [{"matcher": "...", "hooks": [{"type": "command", "command": "..."}]}]}
		var groups []struct {
			Hooks []struct {
				Command string `json:"command"`
			} `json:"hooks"`
		}
		if json.Unmarshal(raw, &groups) != nil {
			continue
		}
		for _, g := range groups {
			for _, h := range g.Hooks {
				if h.Command != "" && len(sv.Hooks[ev]) < 200 {
					sv.Hooks[ev] = append(sv.Hooks[ev], h.Command)
				}
			}
		}
	}
	return sv, nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
