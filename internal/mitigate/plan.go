// Package mitigate turns findings into guardrails on the machine: it
// edits the AI agents' own permission files so what was found cannot
// happen again, fixes config that is unsafe right now, records every
// change in a hash-chained ledger with a byte-exact backup, and can put
// every file back.
//
// This is the only part of AgentDFIR that writes to the host, so it is
// fenced: nothing here runs inside `run` or `serve`; every change is
// planned and shown before it is made; only files owned by the current
// user are touched, never symlinks, never managed or root-owned settings;
// no agent binary is executed; each file is written once, atomically,
// after a backup.
package mitigate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Env is the machine being protected.
type Env struct {
	Home         string // profile root whose agent configs are edited
	StateDir     string // ledger and backups (default ~/.agentdfir/mitigations)
	GuardCommand string // hook command for the log guard; empty = no hook
}

// Selection is what the person chose.
type Selection struct {
	Packs []string
	Fix   bool            // include the fix-now changes (MCP pins, auto-approve)
	Deny  map[string]bool // ask packs raised to deny
}

// Item is one guardrail inside a file.
type Item struct {
	Kind  string `json:"kind"` // deny | ask | setting | hook | codex | pin | noauto
	Key   string `json:"key"`
	Value string `json:"value,omitempty"`
	Pack  string `json:"pack,omitempty"`
}

// Change is everything planned for one file.
type Change struct {
	Product string   `json:"product"`
	Kind    string   `json:"kind"` // claude-settings | cursor-cli | codex-rules | mcp
	Target  string   `json:"target"`
	Items   []Item   `json:"items"`
	Existed bool     `json:"existed"`
	Before  []byte   `json:"-"`
	After   []byte   `json:"-"`
	Diff    string   `json:"diff"`
	Summary []string `json:"summary"`
}

// Plan is the full set of changes plus what can only be recommended.
type Plan struct {
	Changes   []*Change `json:"changes"`
	InPlace   []string  `json:"in_place"`  // targets that already have everything selected
	Recommend []string  `json:"recommend"` // what a person or admin has to do
	Refused   []string  `json:"refused"`   // targets left alone, and why
}

// Kinds of target.
const (
	KindClaude = "claude-settings"
	KindCursor = "cursor-cli"
	KindCodex  = "codex-rules"
	KindMCP    = "mcp"
)

func (e Env) path(rel string) string { return filepath.Join(e.Home, filepath.FromSlash(rel)) }

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// BuildPlan computes every change for the selection. It reads files and
// writes nothing.
func BuildPlan(env Env, sel Selection) (*Plan, error) {
	if env.Home == "" {
		return nil, errors.New("mitigate: no home directory")
	}
	var packs []Pack
	for _, id := range sel.Packs {
		p, ok := PackByID(id)
		if !ok {
			return nil, fmt.Errorf("unknown pack %q (known: %s)", id, strings.Join(PackIDs(), ", "))
		}
		if sel.Deny[id] {
			p.Level = Deny
		}
		packs = append(packs, p)
	}
	pl := &Plan{}
	var want = map[string]*Change{}
	add := func(product, kind, target string, it Item) {
		c := want[target]
		if c == nil {
			c = &Change{Product: product, Kind: kind, Target: target}
			want[target] = c
		}
		for _, x := range c.Items {
			if x.Kind == it.Kind && x.Key == it.Key {
				return
			}
		}
		c.Items = append(c.Items, it)
	}

	claude := dirExists(env.path(".claude"))
	cursorCfg := env.path(".cursor/cli-config.json")
	_, cursorErr := os.Stat(cursorCfg)
	codex := dirExists(env.path(".codex"))

	for _, p := range packs {
		if claude {
			t := env.path(".claude/settings.json")
			for _, pat := range p.Claude {
				add("claude-code", KindClaude, t, Item{Kind: string(p.Level), Key: pat, Pack: p.ID})
			}
			if p.ClaudeHook && env.GuardCommand != "" {
				add("claude-code", KindClaude, t, Item{Kind: "hook", Key: "log-guard", Value: env.GuardCommand, Pack: p.ID})
			}
			if p.Setting != nil {
				add("claude-code", KindClaude, t, Item{Kind: "setting", Key: strings.Join(p.Setting.Path, "."), Value: p.Setting.Value, Pack: p.ID})
			}
		}
		if len(p.Cursor) > 0 && cursorErr == nil {
			if p.Level == Deny {
				for _, pat := range p.Cursor {
					add("cursor-cli", KindCursor, cursorCfg, Item{Kind: "deny", Key: pat, Pack: p.ID})
				}
			} else {
				pl.Recommend = append(pl.Recommend, fmt.Sprintf("Cursor CLI has no ask list, so %q is not written there. Keep those commands out of permissions.allow in %s, or pass --deny %s to block them.", p.ID, cursorCfg, p.ID))
			}
		}
		if len(p.Codex) > 0 && codex {
			t := env.path(".codex/rules/agentdfir.rules")
			dec := "prompt"
			if p.Level == Deny {
				dec = "forbidden"
			}
			for _, r := range p.Codex {
				for _, pat := range expandCodex(env.Home, r.Pattern) {
					add("codex-cli", KindCodex, t, Item{Kind: "codex", Key: strings.Join(pat, "\x1f"), Value: dec, Pack: p.ID})
				}
			}
		}
		if p.ID == "secret-paths" && codex {
			pl.Recommend = append(pl.Recommend, "Codex CLI has no per-path read rule. Keep sandbox_mode = \"workspace-write\" in ~/.codex/config.toml so the sandbox, not the prompt, decides what it can reach.")
		}
		if p.ID == "no-bypass" && codex {
			pl.Recommend = append(pl.Recommend, "Codex: do not run with approval_policy = \"never\" together with sandbox_mode = \"danger-full-access\"; that is Codex's equivalent of skipping every permission check.")
		}
	}
	if sel.Fix {
		for _, f := range scanMCP(env) {
			for _, it := range f.items {
				add(f.product, KindMCP, f.path, it)
			}
		}
	}

	targets := make([]string, 0, len(want))
	for t := range want {
		targets = append(targets, t)
	}
	sort.Strings(targets)
	for _, t := range targets {
		c := want[t]
		if why := refuse(t); why != "" {
			pl.Refused = append(pl.Refused, t+": "+why)
			continue
		}
		cur, err := os.ReadFile(t)
		if err == nil {
			c.Existed = true
			c.Before = cur
		} else if !errors.Is(err, os.ErrNotExist) {
			pl.Refused = append(pl.Refused, t+": "+err.Error())
			continue
		}
		after, err := Render(c.Kind, cur, c.Items)
		if err != nil {
			pl.Refused = append(pl.Refused, t+": "+err.Error())
			continue
		}
		if bytes.Equal(after, cur) {
			pl.InPlace = append(pl.InPlace, t)
			continue
		}
		c.After = after
		c.Diff = UnifiedDiff(t, cur, after)
		c.Summary = summarize(c)
		pl.Changes = append(pl.Changes, c)
	}
	return pl, nil
}

// PackIDs lists every pack id in order.
func PackIDs() []string {
	out := make([]string, 0, len(Packs))
	for _, p := range Packs {
		out = append(out, p.ID)
	}
	return out
}

// refuse returns why a target must not be edited, or "".
func refuse(target string) string {
	fi, err := os.Lstat(target)
	if errors.Is(err, os.ErrNotExist) {
		// A new file: its directory must be ours and not a link.
		dir := filepath.Dir(target)
		if di, derr := os.Lstat(dir); derr == nil {
			if di.Mode()&os.ModeSymlink != 0 {
				return "its directory is a symlink"
			}
			if !ownedByMe(di) {
				return "its directory belongs to another user"
			}
		}
		return ""
	}
	if err != nil {
		return err.Error()
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return "is a symlink (never followed)"
	}
	if !fi.Mode().IsRegular() {
		return "is not a regular file"
	}
	if !ownedByMe(fi) {
		return "belongs to another user (managed settings are an administrator's change: see --export managed)"
	}
	return ""
}

// expandCodex returns the pattern as written plus, when it names a path
// under the home directory, the absolute form: Codex compares argv tokens
// literally and an agent writes either.
func expandCodex(home string, pat []string) [][]string {
	out := [][]string{pat}
	var abs []string
	changed := false
	for _, t := range pat {
		if strings.HasPrefix(t, "~/") {
			abs = append(abs, filepath.ToSlash(filepath.Join(home, t[2:])))
			changed = true
		} else {
			abs = append(abs, t)
		}
	}
	if changed {
		out = append(out, abs)
	}
	return out
}

// Render applies items to the current bytes of a target. Pure.
func Render(kind string, cur []byte, items []Item) ([]byte, error) {
	switch kind {
	case KindClaude, KindCursor:
		return renderPermissions(kind, cur, items)
	case KindCodex:
		return renderCodex(cur, items), nil
	case KindMCP:
		return renderMCP(cur, items)
	}
	return nil, fmt.Errorf("unknown target kind %q", kind)
}

// Missing returns the items not (or no longer) present in cur: what Verify
// reports as drift.
func Missing(kind string, cur []byte, items []Item) []Item {
	var miss []Item
	for _, it := range items {
		after, err := Render(kind, cur, []Item{it})
		if err != nil || !bytes.Equal(after, cur) {
			miss = append(miss, it)
		}
	}
	return miss
}

func loadObj(cur []byte) (*Obj, Style, error) {
	st := DetectStyle(cur)
	if len(bytes.TrimSpace(cur)) == 0 {
		return NewObj(), st, nil
	}
	v, err := ParseJSON(cur)
	if err != nil {
		return nil, st, fmt.Errorf("not valid JSON (%v); left alone", err)
	}
	o, ok := v.(*Obj)
	if !ok {
		return nil, st, errors.New("top level is not a JSON object; left alone")
	}
	return o, st, nil
}

func renderPermissions(kind string, cur []byte, items []Item) ([]byte, error) {
	root, st, err := loadObj(cur)
	if err != nil {
		return nil, err
	}
	changed := false
	perms := func() (*Obj, error) { return root.Child("permissions") }
	for _, it := range items {
		switch it.Kind {
		case "deny", "ask":
			p, err := perms()
			if err != nil {
				return nil, err
			}
			l, err := p.List(it.Kind)
			if err != nil {
				return nil, err
			}
			if !contains(stringsIn(l), it.Key) {
				p.Set(it.Kind, append(l, it.Key))
				changed = true
			}
		case "setting":
			path := strings.Split(it.Key, ".")
			o := root
			for _, k := range path[:len(path)-1] {
				if o, err = o.Child(k); err != nil {
					return nil, err
				}
			}
			last := path[len(path)-1]
			if v, ok := o.Get(last); !ok || v != it.Value {
				o.Set(last, it.Value)
				changed = true
			}
		case "hook":
			if kind != KindClaude {
				continue
			}
			ok, err := addGuardHook(root, it.Value)
			if err != nil {
				return nil, err
			}
			changed = changed || ok
		}
	}
	if !changed {
		return cur, nil
	}
	return MarshalJSON(root, st)
}

// addGuardHook adds one PreToolUse entry running the guard, unless an
// agentdfir guard hook is already there.
func addGuardHook(root *Obj, command string) (bool, error) {
	hooks, err := root.Child("hooks")
	if err != nil {
		return false, err
	}
	pre, err := hooks.List("PreToolUse")
	if err != nil {
		return false, err
	}
	for _, e := range pre {
		eo, ok := e.(*Obj)
		if !ok {
			continue
		}
		inner, _ := eo.List("hooks")
		for _, h := range inner {
			if ho, ok := h.(*Obj); ok {
				if c, _ := ho.Get("command"); isGuardCommand(c) {
					return false, nil
				}
			}
		}
	}
	h := NewObj()
	h.Set("type", "command")
	h.Set("command", command)
	entry := NewObj()
	entry.Set("matcher", "Bash|Write|Edit|MultiEdit")
	entry.Set("hooks", []any{h})
	hooks.Set("PreToolUse", append(pre, entry))
	return true, nil
}

func isGuardCommand(v any) bool {
	s, ok := v.(string)
	return ok && strings.Contains(s, "agentdfir") && strings.Contains(s, "guard log")
}

const codexHeader = "# Written by `agentdfir mitigate`. Every rule here came from a guardrail pack;\n# `agentdfir mitigate --status` shows them, `--revert-all` removes this file.\n"

var codexRuleRe = regexp.MustCompile(`^prefix_rule\(pattern = (\[.*\]), decision = "(\w+)"`)

// renderCodex rewrites the file agentdfir owns: the rules it already has
// plus the new ones. Codex's own default.rules is never touched.
func renderCodex(cur []byte, items []Item) []byte {
	type rule struct {
		pat      []string
		dec, why string
	}
	var rules []rule
	seen := map[string]bool{}
	for _, line := range strings.Split(string(cur), "\n") {
		m := codexRuleRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		var pat []string
		if json.Unmarshal([]byte(m[1]), &pat) != nil {
			continue
		}
		k := strings.Join(pat, "\x1f")
		if seen[k] {
			continue
		}
		seen[k] = true
		rules = append(rules, rule{pat, m[2], ""})
	}
	changed := false
	for _, it := range items {
		if it.Kind != "codex" || seen[it.Key] {
			continue
		}
		seen[it.Key] = true
		rules = append(rules, rule{strings.Split(it.Key, "\x1f"), it.Value, it.Pack})
		changed = true
	}
	if !changed && len(cur) > 0 {
		return cur
	}
	var b strings.Builder
	b.WriteString(codexHeader)
	for _, r := range rules {
		p, _ := json.Marshal(r.pat)
		why := "agentdfir guardrail"
		if r.why != "" {
			why = "agentdfir " + r.why
		}
		fmt.Fprintf(&b, "prefix_rule(pattern = %s, decision = %q, justification = %q)\n", strings.ReplaceAll(string(p), ",", ", "), r.dec, why)
	}
	return []byte(b.String())
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func summarize(c *Change) []string {
	var out []string
	for _, it := range c.Items {
		switch it.Kind {
		case "deny":
			out = append(out, "block  "+it.Key)
		case "ask":
			out = append(out, "ask    "+it.Key)
		case "setting":
			out = append(out, "set    "+it.Key+" = "+it.Value)
		case "hook":
			out = append(out, "hook   PreToolUse → "+it.Value)
		case "codex":
			out = append(out, fmt.Sprintf("%-6s %s", map[string]string{"forbidden": "block", "prompt": "ask"}[it.Value], strings.ReplaceAll(it.Key, "\x1f", " ")))
		case "pin":
			out = append(out, "pin    "+it.Value)
		case "noauto":
			out = append(out, "clear  auto-approve on "+it.Value)
		}
	}
	return out
}

// SHA256 of a byte slice, hex.
func SHA256(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
