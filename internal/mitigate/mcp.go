package mitigate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// MCP fixes are the one place a finding disappears on the next scan: they
// are about what a config file says right now. Two are safe to make
// without asking what the server is for:
//
//   - pin: `npx pkg@latest` (or no version) runs whatever was published
//     last night. The version to pin to is the one already running on this
//     machine, read from the npx cache. Nothing is executed and nothing is
//     fetched; when the cache has no copy, it is a recommendation instead.
//   - noauto: an auto-approve list lets the server's tools run without the
//     person seeing the call. Emptying it brings the prompt back.
//
// Disabling or removing a server changes what the person can do, so it is
// only ever recommended.

// mcpFiles are the JSON MCP configs this package can edit, relative to home.
var mcpFiles = []struct{ product, rel string }{
	{"claude-code", ".claude.json"},
	{"cursor", ".cursor/mcp.json"},
	{"kiro", ".kiro/settings/mcp.json"},
	{"gemini-cli", ".gemini/settings.json"},
	{"copilot-cli", ".copilot/mcp-config.json"},
	{"claude-desktop", "Library/Application Support/Claude/claude_desktop_config.json"},
	{"claude-desktop", ".config/Claude/claude_desktop_config.json"},
	{"claude-desktop", "AppData/Roaming/Claude/claude_desktop_config.json"},
}

type mcpFile struct {
	product, path string
	items         []Item
}

var npmRefRe = regexp.MustCompile(`^(@[^/@\s]+/[^@\s]+|[^@\s][^@\s]*)(?:@([^@\s]+))?$`)
var exactVerRe = regexp.MustCompile(`^\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$`)

func scanMCP(env Env) []mcpFile {
	var out []mcpFile
	for _, f := range mcpFiles {
		p := env.path(f.rel)
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		v, err := ParseJSON(data)
		if err != nil {
			continue
		}
		root, ok := v.(*Obj)
		if !ok {
			continue
		}
		mf := mcpFile{product: f.product, path: p}
		walkServers(root, func(path []string, srv *Obj) {
			key, _ := json.Marshal(path)
			if _, _, _, ref, ok := unpinned(srv); ok {
				if ver := cachedVersion(env.Home, ref); ver != "" {
					mf.items = append(mf.items, Item{Kind: "pin", Key: string(key), Value: ref + "@" + ver})
				}
			}
			for _, k := range []string{"autoApprove", "alwaysAllow"} {
				if l, err := srv.List(k); err == nil && len(l) > 0 {
					mf.items = append(mf.items, Item{Kind: "noauto", Key: string(key), Value: path[len(path)-1]})
					break
				}
			}
		})
		if len(mf.items) > 0 {
			out = append(out, mf)
		}
	}
	return out
}

// MCPRecommendations lists unpinned servers that have no cached version,
// so the plan can say what to do by hand.
func MCPRecommendations(env Env) []string {
	var out []string
	for _, f := range mcpFiles {
		p := env.path(f.rel)
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		v, err := ParseJSON(data)
		if err != nil {
			continue
		}
		root, ok := v.(*Obj)
		if !ok {
			continue
		}
		walkServers(root, func(path []string, srv *Obj) {
			if cmd, _, _, ref, ok := unpinned(srv); ok && cachedVersion(env.Home, ref) == "" {
				out = append(out, fmt.Sprintf("MCP server %q in %s runs %s %s without a version and no copy is cached here. Pin it by hand: `npm view %s version`, then use %s@<that version>.",
					path[len(path)-1], p, cmd, ref, ref, ref))
			}
		})
	}
	return out
}

// walkServers visits every server object under mcpServers, at the top level
// and under projects.<dir>.mcpServers (Claude Code keeps per-project ones).
func walkServers(root *Obj, fn func(path []string, srv *Obj)) {
	visit := func(prefix []string, o *Obj) {
		ms, ok := o.Vals["mcpServers"].(*Obj)
		if !ok {
			return
		}
		for _, name := range ms.Keys {
			if s, ok := ms.Vals[name].(*Obj); ok {
				fn(append(append([]string{}, prefix...), "mcpServers", name), s)
			}
		}
	}
	visit(nil, root)
	if projs, ok := root.Vals["projects"].(*Obj); ok {
		for _, dir := range projs.Keys {
			if po, ok := projs.Vals[dir].(*Obj); ok {
				visit([]string{"projects", dir}, po)
			}
		}
	}
}

// unpinned reports an npx-style server whose package has no exact version.
func unpinned(srv *Obj) (cmd string, args []any, idx int, ref string, ok bool) {
	c, _ := srv.Vals["command"].(string)
	base := strings.TrimSuffix(filepath.Base(filepath.ToSlash(c)), ".cmd")
	if base != "npx" && base != "bunx" && base != "pnpx" {
		return "", nil, 0, "", false
	}
	args, _ = srv.Vals["args"].([]any)
	for i, a := range args {
		s, isStr := a.(string)
		if !isStr || s == "" || strings.HasPrefix(s, "-") {
			continue
		}
		m := npmRefRe.FindStringSubmatch(s)
		if m == nil {
			return "", nil, 0, "", false
		}
		if exactVerRe.MatchString(strings.TrimPrefix(m[2], "v")) {
			return "", nil, 0, "", false
		}
		return base, args, i, m[1], true
	}
	return "", nil, 0, "", false
}

// cachedVersion reads the version npx actually runs from its cache:
// ~/.npm/_npx/<hash>/node_modules/<pkg>/package.json. The most recently
// written copy wins. Nothing is executed and nothing is fetched.
func cachedVersion(home, pkg string) string {
	matches, _ := filepath.Glob(filepath.Join(home, ".npm", "_npx", "*", "node_modules", filepath.FromSlash(pkg), "package.json"))
	sort.Slice(matches, func(i, j int) bool {
		a, _ := os.Stat(matches[i])
		b, _ := os.Stat(matches[j])
		return a != nil && b != nil && a.ModTime().After(b.ModTime())
	})
	for _, m := range matches {
		data, err := os.ReadFile(m)
		if err != nil || len(data) > 1<<20 {
			continue
		}
		var pj struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if json.Unmarshal(data, &pj) == nil && pj.Name == pkg && exactVerRe.MatchString(pj.Version) {
			return pj.Version
		}
	}
	return ""
}

func serverAt(root *Obj, key string) (*Obj, error) {
	var path []string
	if err := json.Unmarshal([]byte(key), &path); err != nil {
		return nil, err
	}
	o := root
	for _, k := range path {
		n, ok := o.Vals[k].(*Obj)
		if !ok {
			return nil, errors.New("server no longer in the file")
		}
		o = n
	}
	return o, nil
}

func renderMCP(cur []byte, items []Item) ([]byte, error) {
	root, st, err := loadObj(cur)
	if err != nil {
		return nil, err
	}
	changed := false
	for _, it := range items {
		srv, err := serverAt(root, it.Key)
		if err != nil {
			continue // removed since the plan: nothing to fix
		}
		switch it.Kind {
		case "pin":
			_, args, idx, ref, ok := unpinned(srv)
			if !ok || !strings.HasPrefix(it.Value, ref+"@") {
				continue
			}
			args[idx] = it.Value
			srv.Vals["args"] = args
			changed = true
		case "noauto":
			for _, k := range []string{"autoApprove", "alwaysAllow"} {
				if l, err := srv.List(k); err == nil && len(l) > 0 {
					srv.Set(k, []any{})
					changed = true
				}
			}
		}
	}
	if !changed {
		return cur, nil
	}
	return MarshalJSON(root, st)
}
