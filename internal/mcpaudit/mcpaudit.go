// Package mcpaudit inventories every MCP server an agent host is
// configured to load and raises supply-chain / configuration findings.
//
// Read-only by construction: it parses configuration files, stats and
// hashes referenced binaries, and never launches, resolves packages over
// the network, or contacts a server. It works on a live profile root
// (pre-incident hygiene) and on a sealed .adfir package (post-incident).
package mcpaudit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/efij/AgentDFIR/internal/detect"
)

func secretKind(v string) (string, bool)   { return detect.SecretKind(v) }
func lookPath(name string) (string, error) { return exec.LookPath(name) }

// Server is one normalized MCP server definition.
type Server struct {
	Name       string   `json:"name"`
	Host       string   `json:"host"`        // product that loads it (claude-code, cursor-cli, vscode, …)
	ConfigPath string   `json:"config_path"` // file it came from
	Scope      string   `json:"scope"`       // user | project | managed
	Project    string   `json:"project,omitempty"`
	Transport  string   `json:"transport"` // stdio | sse | http | streamable-http | ws | unknown
	Command    string   `json:"command,omitempty"`
	Args       []string `json:"args,omitempty"`
	URL        string   `json:"url,omitempty"`
	Package    string   `json:"package,omitempty"` // npm/pypi ref when launched via npx/uvx/pipx/bunx
	PackageMgr string   `json:"package_manager,omitempty"`
	Pinned     bool     `json:"pinned"`
	Resolved   string   `json:"resolved_path,omitempty"`
	SHA256     string   `json:"resolved_sha256,omitempty"`
	EnvKeys    []string `json:"env_keys,omitempty"` // names only — values are never recorded
	HeaderKeys []string `json:"header_keys,omitempty"`
	SecretEnv  []string `json:"secret_env,omitempty"` // env keys whose inline value matches a credential pattern
	AutoAllow  []string `json:"auto_allow,omitempty"` // autoApprove / alwaysAllow / trust lists
	Disabled   bool     `json:"disabled"`
	Tools      []Tool   `json:"tools,omitempty"` // declared/cached tool descriptions, when present
}

// Tool is a declared or cached MCP tool.
type Tool struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// HostSettings captures host-level MCP trust switches (not per server).
type HostSettings struct {
	Host                   string   `json:"host"`
	ConfigPath             string   `json:"config_path"`
	EnableAllProjectMCP    bool     `json:"enable_all_project_mcp_servers,omitempty"`
	EnabledProjectServers  []string `json:"enabled_mcpjson_servers,omitempty"`
	WildcardMCPPermissions []string `json:"wildcard_mcp_permissions,omitempty"` // e.g. mcp__* allow entries
}

// Inventory is the audit's normalized view of a host or package.
type Inventory struct {
	Source   string         `json:"source"` // profile root or package dir
	Mode     string         `json:"mode"`   // live | package
	Servers  []Server       `json:"servers"`
	Settings []HostSettings `json:"host_settings,omitempty"`
	Configs  []string       `json:"configs_seen"`
	Problems []string       `json:"problems,omitempty"` // unreadable/unparsable configs (never silent)
}

// Key identifies a server across configs for collision/baseline checks.
func (s Server) Key() string { return s.Host + "/" + s.Scope + "/" + s.Name }

// Identity is what a server "is": command+args or url. Two servers with
// the same name but different identities collide.
func (s Server) Identity() string {
	if s.URL != "" {
		return "url:" + s.URL
	}
	return "cmd:" + s.Command + " " + strings.Join(s.Args, " ")
}

// ---- location table ----

// format names the config dialect.
type format int

const (
	fmtMCPServers     format = iota // {"mcpServers": {name: {...}}}  (Claude, Cursor, Gemini, Cline/Roo, Copilot CLI, Claude Desktop)
	fmtServers                      // {"servers": {name: {...}}}     (VS Code mcp.json)
	fmtClaudeJSON                   // ~/.claude.json: mcpServers at top level AND under projects.<path>.mcpServers
	fmtClaudeSettings               // settings.json: permissions.allow, enableAllProjectMcpServers, enabledMcpjsonServers
	fmtOpenCode                     // opencode.json: {"mcp": {name: {"type":"local|remote","command":[...],"url":...}}}
	fmtCodexTOML                    // config.toml: [mcp_servers.name] command="…" args=[…] url="…"
)

type location struct {
	host   string
	rel    []string // relative to profile root; globs allowed
	format format
	scope  string
}

// locations lists where each MCP host keeps its server definitions.
// Platform-specific directories are all listed; absent paths are skipped.
var locations = []location{
	{"claude-code", []string{".claude.json"}, fmtClaudeJSON, "user"},
	{"claude-code", []string{".claude/settings.json", ".claude/settings.local.json"}, fmtClaudeSettings, "user"},
	{"claude-code", []string{"Library/Application Support/ClaudeCode/managed-settings.json", "/etc/claude-code/managed-settings.json"}, fmtClaudeSettings, "managed"},
	{"claude-desktop", []string{
		"Library/Application Support/Claude/claude_desktop_config.json",
		"AppData/Roaming/Claude/claude_desktop_config.json",
		".config/Claude/claude_desktop_config.json"}, fmtMCPServers, "user"},
	{"cursor-cli", []string{".cursor/mcp.json"}, fmtMCPServers, "user"},
	{"vscode", []string{
		"Library/Application Support/Code/User/mcp.json",
		".config/Code/User/mcp.json",
		"AppData/Roaming/Code/User/mcp.json"}, fmtServers, "user"},
	{"copilot-cli", []string{".copilot/mcp-config.json"}, fmtMCPServers, "user"},
	{"cline", []string{
		"Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
		".config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
		"AppData/Roaming/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"}, fmtMCPServers, "user"},
	{"roo-code", []string{
		"Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json",
		".config/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json",
		"AppData/Roaming/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json"}, fmtMCPServers, "user"},
	{"gemini-cli", []string{".gemini/settings.json"}, fmtMCPServers, "user"},
	{"opencode", []string{".config/opencode/opencode.json", ".config/opencode/config.json"}, fmtOpenCode, "user"},
	{"codex-cli", []string{".codex/config.toml"}, fmtCodexTOML, "user"},
}

// projectFiles are repo-scoped MCP configs; matched by basename anywhere
// in a package (they travel with the project, not the user).
var projectFiles = map[string]struct {
	host   string
	format format
}{
	".mcp.json":               {"claude-code", fmtMCPServers},
	"mcp.json":                {"vscode-or-cursor", fmtServersOrMCP},
	"opencode.json":           {"opencode", fmtOpenCode},
	"cline_mcp_settings.json": {"cline", fmtMCPServers},
	"mcp_settings.json":       {"roo-code", fmtMCPServers},
}

// fmtServersOrMCP accepts either wrapper key (project mcp.json may be
// VS Code "servers" or Cursor "mcpServers").
const fmtServersOrMCP format = 100

// MaxConfigBytes bounds a config read (hostile evidence).
const MaxConfigBytes = 4 << 20

// ---- live profile scan ----

// ScanProfile audits a live (or offline-mounted) profile root.
func ScanProfile(root string) *Inventory {
	inv := &Inventory{Source: root, Mode: "live"}
	for _, loc := range locations {
		for _, rel := range loc.rel {
			path := rel
			if !filepath.IsAbs(rel) {
				path = filepath.Join(root, filepath.FromSlash(rel))
			}
			matches, _ := filepath.Glob(path)
			for _, m := range matches {
				data, ok := readBounded(m, inv)
				if !ok {
					continue
				}
				inv.Configs = append(inv.Configs, m)
				parseInto(inv, loc.host, loc.scope, m, "", loc.format, data)
			}
		}
	}
	finish(inv)
	return inv
}

// ParseConfigFile parses one config with an explicit dialect (package mode
// and tests). host/scope/project annotate the resulting servers.
func ParseConfigFile(inv *Inventory, host, scope, path, logical string, f format, data []byte) {
	parseInto(inv, host, scope, path, logical, f, data)
}

func readBounded(path string, inv *Inventory) ([]byte, bool) {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return nil, false
	}
	if fi.Size() > MaxConfigBytes {
		inv.Problems = append(inv.Problems, path+": exceeds size bound, not parsed")
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		inv.Problems = append(inv.Problems, path+": "+err.Error())
		return nil, false
	}
	return data, true
}

func finish(inv *Inventory) {
	sort.SliceStable(inv.Servers, func(i, j int) bool {
		if inv.Servers[i].Host != inv.Servers[j].Host {
			return inv.Servers[i].Host < inv.Servers[j].Host
		}
		return inv.Servers[i].Name < inv.Servers[j].Name
	})
	sort.Strings(inv.Configs)
}

// ---- parsing ----

func parseInto(inv *Inventory, host, scope, path, logical string, f format, data []byte) {
	display := path
	if logical != "" {
		display = logical
	}
	switch f {
	case fmtCodexTOML:
		servers, err := parseCodexTOML(data)
		if err != nil {
			inv.Problems = append(inv.Problems, display+": "+err.Error())
			return
		}
		for i := range servers {
			servers[i].Host, servers[i].Scope, servers[i].ConfigPath = host, scope, display
			enrich(&servers[i], inv.Mode == "live")
			inv.Servers = append(inv.Servers, servers[i])
		}
		return
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(stripJSONC(data), &doc); err != nil {
		inv.Problems = append(inv.Problems, display+": invalid JSON: "+err.Error())
		return
	}
	switch f {
	case fmtMCPServers:
		addServerMap(inv, doc["mcpServers"], host, scope, display, "")
	case fmtServers:
		addServerMap(inv, doc["servers"], host, scope, display, "")
	case fmtServersOrMCP:
		if raw, ok := doc["mcpServers"]; ok {
			addServerMap(inv, raw, "cursor-cli", scope, display, "")
		}
		if raw, ok := doc["servers"]; ok {
			addServerMap(inv, raw, "vscode", scope, display, "")
		}
	case fmtClaudeJSON:
		addServerMap(inv, doc["mcpServers"], host, scope, display, "")
		var projects map[string]struct {
			MCPServers json.RawMessage `json:"mcpServers"`
		}
		if raw, ok := doc["projects"]; ok && json.Unmarshal(raw, &projects) == nil {
			keys := make([]string, 0, len(projects))
			for k := range projects {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				addServerMap(inv, projects[k].MCPServers, host, "project", display, k)
			}
		}
	case fmtClaudeSettings:
		hs := HostSettings{Host: host, ConfigPath: display}
		var b bool
		if raw, ok := doc["enableAllProjectMcpServers"]; ok && json.Unmarshal(raw, &b) == nil {
			hs.EnableAllProjectMCP = b
		}
		_ = json.Unmarshal(doc["enabledMcpjsonServers"], &hs.EnabledProjectServers)
		var perms struct {
			Allow []string `json:"allow"`
		}
		if raw, ok := doc["permissions"]; ok && json.Unmarshal(raw, &perms) == nil {
			for _, a := range perms.Allow {
				if strings.HasPrefix(a, "mcp__") && strings.Contains(a, "*") || a == "mcp__*" {
					hs.WildcardMCPPermissions = append(hs.WildcardMCPPermissions, a)
				}
			}
		}
		inv.Settings = append(inv.Settings, hs)
		// settings.json may also embed mcpServers in some builds.
		addServerMap(inv, doc["mcpServers"], host, scope, display, "")
	case fmtOpenCode:
		var m map[string]struct {
			Type    string            `json:"type"`
			Command []string          `json:"command"`
			URL     string            `json:"url"`
			Env     map[string]string `json:"environment"`
			Headers map[string]string `json:"headers"`
			Enabled *bool             `json:"enabled"`
		}
		if raw, ok := doc["mcp"]; ok && json.Unmarshal(raw, &m) == nil {
			names := make([]string, 0, len(m))
			for n := range m {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				e := m[n]
				s := Server{Name: n, Host: host, Scope: scope, ConfigPath: display, URL: e.URL}
				if len(e.Command) > 0 {
					s.Command, s.Args = e.Command[0], e.Command[1:]
				}
				s.EnvKeys, s.SecretEnv = envKeys(e.Env)
				s.HeaderKeys = sortedKeys(e.Headers)
				s.Disabled = e.Enabled != nil && !*e.Enabled
				enrich(&s, inv.Mode == "live")
				inv.Servers = append(inv.Servers, s)
			}
		}
	}
}

// genericServer is the tolerant union of per-server JSON shapes.
type genericServer struct {
	Command      string            `json:"command"`
	Args         []string          `json:"args"`
	URL          string            `json:"url"`
	ServerURL    string            `json:"serverUrl"`
	HTTPURL      string            `json:"httpUrl"`
	Type         string            `json:"type"`
	Transport    string            `json:"transport"`
	Env          map[string]string `json:"env"`
	Headers      map[string]string `json:"headers"`
	Disabled     bool              `json:"disabled"`
	AutoApprove  []string          `json:"autoApprove"`
	AlwaysAllow  []string          `json:"alwaysAllow"`
	Trust        bool              `json:"trust"`
	Tools        []Tool            `json:"tools"`
	ToolsCache   []Tool            `json:"toolsCache"`
	Capabilities struct {
		Tools []Tool `json:"tools"`
	} `json:"capabilities"`
}

func addServerMap(inv *Inventory, raw json.RawMessage, host, scope, display, project string) {
	if len(raw) == 0 {
		return
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		inv.Problems = append(inv.Problems, display+": server map is not an object")
		return
	}
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		var g genericServer
		if err := json.Unmarshal(m[n], &g); err != nil {
			inv.Problems = append(inv.Problems, display+": server "+n+": "+err.Error())
			continue
		}
		s := Server{Name: n, Host: host, Scope: scope, ConfigPath: display, Project: project,
			Command: g.Command, Args: g.Args, Disabled: g.Disabled}
		s.URL = firstNonEmpty(g.URL, g.ServerURL, g.HTTPURL)
		s.Transport = strings.ToLower(firstNonEmpty(g.Type, g.Transport))
		s.EnvKeys, s.SecretEnv = envKeys(g.Env)
		s.HeaderKeys = sortedKeys(g.Headers)
		s.AutoAllow = append(append([]string{}, g.AutoApprove...), g.AlwaysAllow...)
		if g.Trust {
			s.AutoAllow = append(s.AutoAllow, "*")
		}
		s.Tools = append(append(append([]Tool{}, g.Tools...), g.ToolsCache...), g.Capabilities.Tools...)
		enrich(&s, inv.Mode == "live")
		inv.Servers = append(inv.Servers, s)
	}
}

var (
	pkgMgrs   = map[string]bool{"npx": true, "uvx": true, "pipx": true, "bunx": true, "pnpx": true, "dlx": true}
	npmPinRe  = regexp.MustCompile(`^(@?[^@\s]+)@([^@\s]+)$`)
	pypiPinRe = regexp.MustCompile(`^([A-Za-z0-9_.-]+)(==|@)([^\s]+)$`)
)

// enrich derives transport, package reference and pinning. Binary
// resolution/hashing only happens on a live host (live=true); a package
// is analyzed on a different machine where PATH means nothing.
func enrich(s *Server, live bool) {
	switch {
	case s.Transport == "":
		if s.URL != "" {
			switch {
			case strings.Contains(s.URL, "/sse"):
				s.Transport = "sse"
			case strings.HasPrefix(s.URL, "ws"):
				s.Transport = "ws"
			default:
				s.Transport = "http"
			}
		} else if s.Command != "" {
			s.Transport = "stdio"
		} else {
			s.Transport = "unknown"
		}
	case s.Transport == "local":
		s.Transport = "stdio"
	case s.Transport == "remote":
		s.Transport = "http"
	}
	if s.Command == "" {
		return
	}
	base := strings.ToLower(filepath.Base(s.Command))
	base = strings.TrimSuffix(base, ".exe")
	if base == "npm" || base == "pnpm" || base == "yarn" || base == "bun" {
		// npm exec <pkg> / pnpm dlx <pkg> / bunx via bun x
		for i, a := range s.Args {
			if (a == "exec" || a == "dlx" || a == "x") && i+1 < len(s.Args) {
				s.PackageMgr = base
				s.Package, s.Pinned = packageRef(base, s.Args[i+1:])
				return
			}
		}
	}
	if pkgMgrs[base] {
		s.PackageMgr = base
		s.Package, s.Pinned = packageRef(base, s.Args)
		return
	}
	// Direct binary/script: pinned by definition (a concrete file). Resolve
	// and hash when it exists — never execute.
	s.Pinned = true
	if !live {
		return
	}
	target := s.Command
	if !filepath.IsAbs(target) {
		if p, err := lookPath(target); err == nil {
			target = p
		}
	}
	// Interpreters: hash the script argument instead of the interpreter.
	if base == "node" || base == "python" || base == "python3" || base == "sh" || base == "bash" {
		for _, a := range s.Args {
			if !strings.HasPrefix(a, "-") {
				target = a
				break
			}
		}
	}
	if fi, err := os.Stat(target); err == nil && fi.Mode().IsRegular() {
		s.Resolved = target
		s.SHA256 = fileSHA256(target)
	}
}

// packageRef extracts the package spec from package-runner args and
// reports whether it is pinned to an exact version.
func packageRef(mgr string, args []string) (string, bool) {
	for _, a := range args {
		if strings.HasPrefix(a, "-") || a == "" {
			continue
		}
		// first non-flag token is the package
		switch mgr {
		case "uvx", "pipx":
			if m := pypiPinRe.FindStringSubmatch(a); m != nil {
				return a, isExactVersion(m[3])
			}
			return a, false
		default:
			if m := npmPinRe.FindStringSubmatch(a); m != nil {
				return a, isExactVersion(m[2])
			}
			return a, false
		}
	}
	return "", false
}

func isExactVersion(v string) bool {
	v = strings.TrimPrefix(v, "v")
	if v == "latest" || v == "next" || v == "canary" || v == "" {
		return false
	}
	if strings.ContainsAny(v, "^~*xX><|") {
		return false
	}
	return regexp.MustCompile(`^\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$`).MatchString(v)
}

func envKeys(env map[string]string) (keys, secret []string) {
	keys = sortedKeys(env)
	for _, k := range keys {
		if kind, ok := secretKind(env[k]); ok {
			secret = append(secret, k+" ("+kind+")")
		}
	}
	return
}

func sortedKeys(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func fileSHA256(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, 256<<20)); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// stripJSONC removes // and /* */ comments outside strings (VS Code and
// Cursor configs are JSONC). Trailing commas are also tolerated.
func stripJSONC(b []byte) []byte {
	var out []byte
	inStr, esc := false, false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inStr {
			out = append(out, c)
			if esc {
				esc = false
			} else if c == '\\' {
				esc = true
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		switch {
		case c == '"':
			inStr = true
			out = append(out, c)
		case c == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
			out = append(out, '\n')
		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			i += 2
			for i+1 < len(b) && !(b[i] == '*' && b[i+1] == '/') {
				i++
			}
			i++
		default:
			out = append(out, c)
		}
	}
	// trailing commas: ", }" or ", ]"
	re := regexp.MustCompile(`,(\s*[}\]])`)
	return re.ReplaceAll(out, []byte("$1"))
}

func injectionPhrase(text string) (string, bool) { return detect.InjectionPhrase(text) }
