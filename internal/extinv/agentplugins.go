package extinv

import (
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/efij/AgentDFIR/v5/internal/mcpaudit"
)

const (
	claudePlugins = ".claude/plugins"
	// defaultMarketplaceRepo is the marketplace Claude Code ships with.
	// Anything else was added by the user, a project, or managed settings.
	defaultMarketplaceRepo = "anthropics/claude-plugins-official"
	defaultMarketplaceName = "claude-plugins-official"
)

// installRecord is one install in installed_plugins.json (v1 stores one
// object per plugin, v2 a list per plugin keyed by scope).
type installRecord struct {
	Scope        string `json:"scope"`
	InstallPath  string `json:"installPath"`
	Version      string `json:"version"`
	InstalledAt  string `json:"installedAt"`
	LastUpdated  string `json:"lastUpdated"`
	GitCommitSha string `json:"gitCommitSha"`
	ProjectPath  string `json:"projectPath"`
}

func scanClaudePlugins(inv *Inventory, t tree) {
	if e, ok := t.stat(claudePlugins); !ok || !e.dir {
		scanClaudeSettingsMarketplaces(inv, t)
		return
	}
	inv.RootsSeen = append(inv.RootsSeen, t.ref(claudePlugins))
	scanMarketplaces(inv, t)
	scanClaudeSettingsMarketplaces(inv, t)

	registered := map[string]bool{} // tree dir of every registered install
	regPath := join(claudePlugins, "installed_plugins.json")
	haveRegistry := false
	if b, trunc, err := t.read(regPath, MaxRegistryBytes); err == nil {
		switch {
		case trunc:
			inv.Problems = append(inv.Problems, t.ref(regPath)+": exceeds size bound, not parsed")
		default:
			var doc struct {
				Version int                        `json:"version"`
				Plugins map[string]json.RawMessage `json:"plugins"`
			}
			if err := json.Unmarshal(b, &doc); err != nil {
				inv.Problems = append(inv.Problems, t.ref(regPath)+": invalid JSON: "+err.Error())
				break
			}
			if doc.Version > 2 {
				inv.Unsupported = append(inv.Unsupported, fmt.Sprintf("%s: registry version %d is newer than the versions this build reads (1, 2); parsed best-effort", t.ref(regPath), doc.Version))
			}
			haveRegistry = true
			keys := make([]string, 0, len(doc.Plugins))
			for k := range doc.Plugins {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				var recs []installRecord
				if err := json.Unmarshal(doc.Plugins[k], &recs); err != nil {
					var one installRecord
					if err := json.Unmarshal(doc.Plugins[k], &one); err != nil {
						inv.Problems = append(inv.Problems, t.ref(regPath)+": plugin "+k+": unrecognized install record")
						continue
					}
					recs = []installRecord{one}
				}
				name, mk := k, ""
				if i := strings.LastIndex(k, "@"); i > 0 {
					name, mk = k[:i], k[i+1:]
				}
				for _, r := range recs {
					p := Plugin{Host: "claude-code", Name: name, Marketplace: mk, Version: r.Version, Scope: r.Scope,
						InstalledAt: r.InstalledAt, LastUpdated: r.LastUpdated, GitCommit: r.GitCommitSha, Registered: true}
					if r.ProjectPath != "" {
						p.Notes = append(p.Notes, "project: "+r.ProjectPath)
					}
					dir, ok := t.fromSource(r.InstallPath)
					if !ok {
						p.Dir = r.InstallPath
						p.Notes = append(p.Notes, "install path outside the plugin store; not read")
						inv.Plugins = append(inv.Plugins, p)
						continue
					}
					registered[dir] = true
					readClaudePlugin(inv, t, dir, &p)
					inv.Plugins = append(inv.Plugins, p)
				}
			}
		}
	}

	// Plugin directories in the cache the registry does not list: old
	// versions, failed installs, or something dropped in by hand.
	cache := join(claudePlugins, "cache")
	n := 0
	for _, mk := range t.list(cache) {
		if !mk.dir || strings.HasPrefix(mk.name, "temp_git_") {
			continue
		}
		for _, pl := range t.list(join(cache, mk.name)) {
			if !pl.dir {
				continue
			}
			for _, ver := range t.list(join(cache, mk.name, pl.name)) {
				if !ver.dir {
					continue
				}
				dir := join(cache, mk.name, pl.name, ver.name)
				if registered[dir] || !looksLikePlugin(t, dir) {
					continue
				}
				if n++; n > MaxPluginDirs {
					inv.Problems = append(inv.Problems, fmt.Sprintf("%s: more than %d plugin directories, the rest were not read", t.ref(cache), MaxPluginDirs))
					return
				}
				p := Plugin{Host: "claude-code", Name: pl.name, Marketplace: mk.name, Version: ver.name}
				if haveRegistry {
					p.Notes = append(p.Notes, "in the plugin cache but not in installed_plugins.json (an old version, or not installed through the host)")
				} else {
					p.Notes = append(p.Notes, "installed_plugins.json not in the evidence: registration state unknown")
				}
				readClaudePlugin(inv, t, dir, &p)
				inv.Plugins = append(inv.Plugins, p)
			}
		}
	}
}

func looksLikePlugin(t tree, dir string) bool {
	for _, f := range []string{".claude-plugin/plugin.json", "hooks/hooks.json", ".mcp.json"} {
		if _, ok := t.stat(join(dir, f)); ok {
			return true
		}
	}
	for _, d := range []string{"commands", "agents", "skills"} {
		if e, ok := t.stat(join(dir, d)); ok && e.dir {
			return true
		}
	}
	return false
}

// readClaudePlugin fills in what a plugin directory registers: hooks,
// MCP servers, commands, agents, skills.
func readClaudePlugin(inv *Inventory, t tree, dir string, p *Plugin) {
	p.Dir = t.ref(dir)
	p.tr, p.rel = t, dir
	if e, ok := t.stat(dir); !ok || !e.dir {
		p.Notes = append(p.Notes, "plugin directory not in the evidence")
		return
	}
	p.Present = true
	var hooksRef, mcpRef json.RawMessage
	manifest := join(dir, ".claude-plugin/plugin.json")
	if b, trunc, err := t.read(manifest, MaxManifestBytes); err == nil && !trunc {
		p.ManifestSHA = t.sha256(manifest)
		var m struct {
			Name       string          `json:"name"`
			Version    string          `json:"version"`
			Hooks      json.RawMessage `json:"hooks"`
			MCPServers json.RawMessage `json:"mcpServers"`
		}
		if err := json.Unmarshal(mcpaudit.StripJSONC(b), &m); err != nil {
			inv.Problems = append(inv.Problems, t.ref(manifest)+": invalid JSON: "+err.Error())
		} else {
			if p.Name == "" {
				p.Name = m.Name
			}
			if p.Version == "" {
				p.Version = m.Version
			}
			hooksRef, mcpRef = m.Hooks, m.MCPServers
		}
	} else if trunc {
		inv.Problems = append(inv.Problems, t.ref(manifest)+": exceeds size bound, not parsed")
	}

	// Hooks: hooks/hooks.json, plus whatever plugin.json declares inline
	// or by path.
	hookFiles := []string{join(dir, "hooks/hooks.json")}
	if len(hooksRef) > 0 {
		var ref string
		if json.Unmarshal(hooksRef, &ref) == nil {
			if r, ok := inside(strings.TrimPrefix(ref, "${CLAUDE_PLUGIN_ROOT}/")); ok {
				hookFiles = append(hookFiles, join(dir, r))
			}
		} else {
			p.Hooks = append(p.Hooks, hooksFrom(hooksRef, t.ref(manifest))...)
		}
	}
	seenHookFile := map[string]bool{}
	for _, hf := range hookFiles {
		if seenHookFile[hf] {
			continue
		}
		seenHookFile[hf] = true
		b, trunc, err := t.read(hf, MaxManifestBytes)
		if err != nil {
			continue
		}
		if trunc {
			inv.Problems = append(inv.Problems, t.ref(hf)+": exceeds size bound, not parsed")
			continue
		}
		var doc map[string]json.RawMessage
		if err := json.Unmarshal(mcpaudit.StripJSONC(b), &doc); err != nil {
			inv.Problems = append(inv.Problems, t.ref(hf)+": invalid JSON: "+err.Error())
			continue
		}
		raw := doc["hooks"]
		if raw == nil {
			raw, _ = json.Marshal(doc)
		}
		p.Hooks = append(p.Hooks, hooksFrom(raw, t.ref(hf))...)
	}

	// MCP servers: .mcp.json in the plugin root, or plugin.json mcpServers.
	if b, trunc, err := t.read(join(dir, ".mcp.json"), MaxManifestBytes); err == nil && !trunc {
		p.MCPServers = append(p.MCPServers, serverNames(b)...)
	}
	if len(mcpRef) > 0 {
		var ref string
		if json.Unmarshal(mcpRef, &ref) != nil {
			var m map[string]json.RawMessage
			if json.Unmarshal(mcpRef, &m) == nil {
				for k := range m {
					p.MCPServers = append(p.MCPServers, k)
				}
			}
		}
	}
	sort.Strings(p.MCPServers)

	// Definitions the model reads.
	for _, e := range t.list(join(dir, "commands")) {
		if !e.dir && strings.HasSuffix(strings.ToLower(e.name), ".md") {
			p.Commands = append(p.Commands, strings.TrimSuffix(e.name, path.Ext(e.name)))
		}
	}
	for _, e := range t.list(join(dir, "agents")) {
		if !e.dir && strings.HasSuffix(strings.ToLower(e.name), ".md") {
			p.Agents = append(p.Agents, strings.TrimSuffix(e.name, path.Ext(e.name)))
		}
	}
	for _, e := range t.list(join(dir, "skills")) {
		if e.dir {
			p.Skills = append(p.Skills, e.name)
		}
	}
	label := p.Name
	if p.Marketplace != "" {
		label += "@" + p.Marketplace
	}
	addSkillDir(inv, t, "claude-code", "command", join(dir, "commands"), label, 3)
	addSkillDir(inv, t, "claude-code", "agent", join(dir, "agents"), label, 2)
	addSkillDir(inv, t, "claude-code", "skill", join(dir, "skills"), label, 4)
}

func serverNames(b []byte) []string {
	var doc map[string]json.RawMessage
	if json.Unmarshal(mcpaudit.StripJSONC(b), &doc) != nil {
		return nil
	}
	raw := doc["mcpServers"]
	if raw == nil {
		raw = doc["servers"]
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// hooksFrom reads {"Event": [{"matcher": …, "hooks": [{"command": …}]}]}.
func hooksFrom(raw json.RawMessage, file string) []Hook {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	events := make([]string, 0, len(m))
	for k := range m {
		events = append(events, k)
	}
	sort.Strings(events)
	var out []Hook
	for _, ev := range events {
		for _, c := range commandsUnder(m[ev], 0) {
			out = append(out, Hook{Event: ev, Command: c, File: file})
			if len(out) >= 256 {
				return out
			}
		}
	}
	return out
}

// commandsUnder collects command strings at any depth (bounded).
func commandsUnder(v any, depth int) []string {
	if depth > 8 {
		return nil
	}
	var out []string
	switch t := v.(type) {
	case map[string]any:
		for _, k := range []string{"command", "cmd", "bash", "powershell"} {
			if c, ok := t[k].(string); ok && c != "" {
				out = append(out, c)
			}
			if arr, ok := t[k].([]any); ok {
				var parts []string
				for _, p := range arr {
					if ps, ok := p.(string); ok {
						parts = append(parts, ps)
					}
				}
				if len(parts) > 0 {
					out = append(out, strings.Join(parts, " "))
				}
			}
		}
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			switch k {
			case "command", "cmd", "bash", "powershell":
				continue
			}
			out = append(out, commandsUnder(t[k], depth+1)...)
		}
	case []any:
		for _, e := range t {
			out = append(out, commandsUnder(e, depth+1)...)
		}
	}
	return out
}

// ---- marketplaces

type mkSource struct {
	Source string `json:"source"`
	Repo   string `json:"repo"`
	URL    string `json:"url"`
	Path   string `json:"path"`
}

func scanMarketplaces(inv *Inventory, t tree) {
	p := join(claudePlugins, "known_marketplaces.json")
	b, trunc, err := t.read(p, MaxRegistryBytes)
	if err != nil {
		return
	}
	if trunc {
		inv.Problems = append(inv.Problems, t.ref(p)+": exceeds size bound, not parsed")
		return
	}
	var doc map[string]struct {
		Source      mkSource `json:"source"`
		LastUpdated string   `json:"lastUpdated"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		inv.Problems = append(inv.Problems, t.ref(p)+": invalid JSON: "+err.Error())
		return
	}
	names := make([]string, 0, len(doc))
	for n := range doc {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		inv.Marketplaces = append(inv.Marketplaces, marketplace(n, doc[n].Source, doc[n].LastUpdated, t.ref(p)))
	}
}

// scanClaudeSettingsMarketplaces reads extraKnownMarketplaces from the
// user's settings: a marketplace can be declared there before any plugin
// from it is installed.
func scanClaudeSettingsMarketplaces(inv *Inventory, t tree) {
	for _, sp := range []string{".claude/settings.json", ".claude/settings.local.json"} {
		b, trunc, err := t.read(sp, MaxManifestBytes)
		if err != nil || trunc {
			continue
		}
		var doc struct {
			Extra map[string]struct {
				Source mkSource `json:"source"`
			} `json:"extraKnownMarketplaces"`
		}
		if json.Unmarshal(mcpaudit.StripJSONC(b), &doc) != nil {
			continue // settings parse errors are the MCP audit's to report
		}
		names := make([]string, 0, len(doc.Extra))
		for n := range doc.Extra {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			m := marketplace(n, doc.Extra[n].Source, "", t.ref(sp))
			dup := false
			for _, k := range inv.Marketplaces {
				dup = dup || (k.Host == m.Host && k.Name == m.Name && strings.EqualFold(k.Location, m.Location))
			}
			if !dup {
				inv.Marketplaces = append(inv.Marketplaces, m)
			}
		}
	}
}

func marketplace(name string, s mkSource, updated, evidence string) Marketplace {
	m := Marketplace{Host: "claude-code", Name: name, Kind: strings.ToLower(s.Source), Updated: updated, Evidence: evidence}
	m.Location = firstNonEmpty(s.Repo, s.URL, s.Path)
	if m.Kind == "" {
		m.Kind = "unknown"
	}
	m.Default = name == defaultMarketplaceName && m.Kind == "github" && strings.EqualFold(s.Repo, defaultMarketplaceRepo)
	return m
}

// ---- skills and other markdown definitions

func scanSkills(inv *Inventory, t tree) {
	for _, s := range []struct{ host, kind, dir string }{
		{"claude-code", "skill", ".claude/skills"},
		{"claude-code", "agent", ".claude/agents"},
		{"claude-code", "command", ".claude/commands"},
		{"codex-cli", "skill", ".codex/skills"},
		{"kiro", "skill", ".kiro/skills"},
	} {
		if e, ok := t.stat(s.dir); ok && e.dir {
			inv.RootsSeen = append(inv.RootsSeen, t.ref(s.dir))
			addSkillDir(inv, t, s.host, s.kind, s.dir, "", 4)
		}
	}
}

// addSkillDir records every markdown file under dir (to maxDepth) and
// reads it for hidden content.
func addSkillDir(inv *Inventory, t tree, host, kind, dir, plugin string, maxDepth int) {
	var walk func(d string, depth int)
	walk = func(d string, depth int) {
		if depth > maxDepth {
			return
		}
		for _, e := range t.list(d) {
			p := join(d, e.name)
			if e.link {
				continue
			}
			if e.dir {
				switch strings.ToLower(e.name) {
				case "node_modules", ".git", "tests", "test", "__tests__":
					continue
				}
				walk(p, depth+1)
				continue
			}
			ln := strings.ToLower(e.name)
			if !strings.HasSuffix(ln, ".md") && !strings.HasSuffix(ln, ".mdc") {
				continue
			}
			if countSkills(inv) >= MaxSkillFiles {
				inv.Problems = append(inv.Problems, fmt.Sprintf("more than %d skill/agent/command files; the rest were not read", MaxSkillFiles))
				return
			}
			s := Skill{Host: host, Kind: kind, Plugin: plugin, Path: t.ref(p), Size: e.size, Name: skillName(dir, p)}
			b, trunc, err := t.read(p, MaxManifestBytes)
			if err != nil {
				inv.Problems = append(inv.Problems, t.ref(p)+": "+err.Error())
				inv.Skills = append(inv.Skills, s)
				continue
			}
			s.SHA256 = t.sha256(p)
			s.hidden = scanHidden(string(b), p)
			if trunc {
				inv.Problems = append(inv.Problems, fmt.Sprintf("%s: larger than %d bytes; the first %d were read", t.ref(p), MaxManifestBytes, MaxManifestBytes))
			}
			inv.Skills = append(inv.Skills, s)
		}
	}
	walk(dir, 1)
}

func countSkills(inv *Inventory) int { return len(inv.Skills) }

// skillName: the skill's directory (skills/<name>/SKILL.md), otherwise the
// file's base name.
func skillName(root, p string) string {
	rel := strings.TrimPrefix(strings.TrimPrefix(p, root), "/")
	if i := strings.Index(rel, "/"); i > 0 {
		return rel[:i]
	}
	return strings.TrimSuffix(rel, path.Ext(rel))
}

// ---- Gemini CLI extensions and Codex plugins

func scanGeminiExtensions(inv *Inventory, t tree) {
	root := ".gemini/extensions"
	if e, ok := t.stat(root); !ok || !e.dir {
		return
	}
	inv.RootsSeen = append(inv.RootsSeen, t.ref(root))
	n := 0
	for _, e := range t.list(root) {
		if !e.dir {
			continue
		}
		if n++; n > MaxPluginDirs {
			inv.Problems = append(inv.Problems, fmt.Sprintf("%s: more than %d extensions, the rest were not read", t.ref(root), MaxPluginDirs))
			return
		}
		dir := join(root, e.name)
		p := Plugin{Host: "gemini-cli", Name: e.name, Dir: t.ref(dir), Present: true}
		mf := join(dir, "gemini-extension.json")
		b, trunc, err := t.read(mf, MaxManifestBytes)
		if err != nil || trunc {
			p.Notes = append(p.Notes, "gemini-extension.json not readable")
			inv.Unsupported = append(inv.Unsupported, t.ref(dir)+": no readable gemini-extension.json; extension not analyzed")
			inv.Plugins = append(inv.Plugins, p)
			continue
		}
		p.ManifestSHA = t.sha256(mf)
		var m struct {
			Name            string          `json:"name"`
			Version         string          `json:"version"`
			ContextFileName json.RawMessage `json:"contextFileName"`
		}
		if err := json.Unmarshal(mcpaudit.StripJSONC(b), &m); err != nil {
			inv.Problems = append(inv.Problems, t.ref(mf)+": invalid JSON: "+err.Error())
		} else {
			p.Name = firstNonEmpty(m.Name, e.name)
			p.Version = m.Version
		}
		p.MCPServers = serverNames(b)
		// Install record: where the extension came from (git URL, local
		// path, link), when the CLI wrote one.
		if ib, trunc, err := t.read(join(dir, ".gemini-extension-install.json"), MaxManifestBytes); err == nil && !trunc {
			var ir struct {
				Source string `json:"source"`
				Type   string `json:"type"`
			}
			if json.Unmarshal(ib, &ir) == nil {
				p.Marketplace = ir.Source
				p.Registered = true
				if ir.Type != "" {
					p.Notes = append(p.Notes, "install type: "+ir.Type)
				}
			}
		}
		// Context files the CLI loads into every session.
		ctx := []string{"GEMINI.md"}
		var one string
		var many []string
		if json.Unmarshal(m.ContextFileName, &one) == nil && one != "" {
			ctx = []string{one}
		} else if json.Unmarshal(m.ContextFileName, &many) == nil && len(many) > 0 {
			ctx = many
		}
		for _, c := range ctx {
			r, ok := inside(c)
			if !ok {
				continue
			}
			cp := join(dir, r)
			st, ok := t.stat(cp)
			if !ok || st.dir {
				continue
			}
			if cb, _, err := t.read(cp, MaxManifestBytes); err == nil {
				inv.Skills = append(inv.Skills, Skill{Host: "gemini-cli", Kind: "context", Name: r, Plugin: p.Name,
					Path: t.ref(cp), Size: st.size, SHA256: t.sha256(cp), hidden: scanHidden(string(cb), cp)})
			}
		}
		addSkillDir(inv, t, "gemini-cli", "command", join(dir, "commands"), p.Name, 3)
		inv.Plugins = append(inv.Plugins, p)
	}
}

// scanCodexPlugins records that a Codex plugin store exists. Its on-disk
// layout is not documented well enough to parse without guessing, so it is
// reported as UNSUPPORTED rather than half-read.
func scanCodexPlugins(inv *Inventory, t tree) {
	root := ".codex/plugins"
	if e, ok := t.stat(root); ok && e.dir && len(t.list(root)) > 0 {
		inv.RootsSeen = append(inv.RootsSeen, t.ref(root))
		inv.Unsupported = append(inv.Unsupported, t.ref(root)+": Codex plugin store present; its layout is not parsed by this build (UNSUPPORTED). The files are in the evidence for manual review.")
	}
}
