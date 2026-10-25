package extinv

import (
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/efij/AgentDFIR/v4/internal/mcpaudit"
)

// editor is one VS Code-family product and where it keeps extensions.
type editor struct {
	id       string
	dir      string // relative to the home
	registry string
}

const (
	regMicrosoft = "vs-marketplace"
	regOpen      = "open-vsx-or-vendor"
)

// editors lists every extension root the inventory reads. The *-server
// roots are the remote-development hosts (SSH, containers, WSL): the
// extension runs on the machine being investigated, not on the laptop.
var editors = []editor{
	{"vscode", ".vscode/extensions", regMicrosoft},
	{"vscode-insiders", ".vscode-insiders/extensions", regMicrosoft},
	{"vscode-server", ".vscode-server/extensions", regMicrosoft},
	{"vscode-server-insiders", ".vscode-server-insiders/extensions", regMicrosoft},
	{"vscodium", ".vscode-oss/extensions", regOpen},
	{"vscodium-server", ".vscodium-server/extensions", regOpen},
	{"cursor", ".cursor/extensions", regOpen},
	{"cursor-server", ".cursor-server/extensions", regOpen},
	{"windsurf", ".windsurf/extensions", regOpen},
	{"windsurf-server", ".windsurf-server/extensions", regOpen},
	{"kiro", ".kiro/extensions", regOpen},
	{"trae", ".trae/extensions", regOpen},
	{"positron", ".positron/extensions", regOpen},
}

// registryEntry is one element of an editor's extensions.json.
type registryEntry struct {
	Identifier struct {
		ID string `json:"id"`
	} `json:"identifier"`
	Version  string `json:"version"`
	Location struct {
		Path   string `json:"path"`
		FsPath string `json:"fsPath"`
	} `json:"location"`
	RelativeLocation string   `json:"relativeLocation"`
	Metadata         metadata `json:"metadata"`
}

// metadata is the install record VS Code keeps per extension (in
// extensions.json, or in package.json __metadata on older builds).
type metadata struct {
	InstalledTimestamp   float64 `json:"installedTimestamp"`
	Source               string  `json:"source"`
	PublisherDisplayName string  `json:"publisherDisplayName"`
	IsPreReleaseVersion  bool    `json:"isPreReleaseVersion"`
	PreRelease           bool    `json:"preRelease"`
}

// packageJSON is the subset of an extension manifest the inventory reads.
type packageJSON struct {
	Name             string          `json:"name"`
	Publisher        string          `json:"publisher"`
	Version          string          `json:"version"`
	DisplayName      string          `json:"displayName"`
	Main             string          `json:"main"`
	Browser          string          `json:"browser"`
	ActivationEvents []string        `json:"activationEvents"`
	Contributes      json.RawMessage `json:"contributes"`
	Metadata         *metadata       `json:"__metadata"`
}

// parsePackageJSON decodes field by field: a manifest with one field of
// the wrong type (hostile or just sloppy) still yields everything else.
func parsePackageJSON(b []byte) (packageJSON, []string, error) {
	var m packageJSON
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(mcpaudit.StripJSONC(b), &raw); err != nil {
		return m, nil, err
	}
	var bad []string
	field := func(name string, dst any) {
		if v, ok := raw[name]; ok && json.Unmarshal(v, dst) != nil {
			bad = append(bad, name)
		}
	}
	field("name", &m.Name)
	field("publisher", &m.Publisher)
	field("version", &m.Version)
	field("displayName", &m.DisplayName)
	field("main", &m.Main)
	field("browser", &m.Browser)
	field("activationEvents", &m.ActivationEvents)
	field("__metadata", &m.Metadata)
	m.Contributes = raw["contributes"]
	return m, bad, nil
}

func scanEditors(inv *Inventory, t tree) {
	for _, ed := range editors {
		if e, ok := t.stat(ed.dir); !ok || !e.dir {
			continue
		}
		inv.RootsSeen = append(inv.RootsSeen, t.ref(ed.dir))
		scanEditor(inv, t, ed)
	}
}

func scanEditor(inv *Inventory, t tree, ed editor) {
	// The registry: what the editor believes is installed.
	regPath := join(ed.dir, "extensions.json")
	byDir := map[string]registryEntry{}
	haveRegistry := false
	if b, trunc, err := t.read(regPath, MaxRegistryBytes); err == nil {
		if trunc {
			inv.Problems = append(inv.Problems, t.ref(regPath)+": exceeds size bound, not parsed")
		} else {
			var list []registryEntry
			if err := json.Unmarshal(mcpaudit.StripJSONC(b), &list); err != nil {
				inv.Problems = append(inv.Problems, t.ref(regPath)+": invalid JSON: "+err.Error())
			} else {
				haveRegistry = true
				for _, r := range list {
					d := r.RelativeLocation
					if d == "" {
						p := r.Location.Path
						if p == "" {
							p = r.Location.FsPath
						}
						d = path.Base(strings.ReplaceAll(p, `\`, "/"))
					}
					if d == "" || d == "." || d == "/" {
						d = strings.ToLower(r.Identifier.ID) + "-" + r.Version
					}
					byDir[d] = r
				}
			}
		}
	}
	// .obsolete: directories the editor has marked for removal.
	obsolete := map[string]bool{}
	if b, _, err := t.read(join(ed.dir, ".obsolete"), MaxManifestBytes); err == nil {
		_ = json.Unmarshal(b, &obsolete)
	}

	seen := map[string]bool{}
	n := 0
	for _, e := range t.list(ed.dir) {
		if !e.dir || strings.HasPrefix(e.name, ".") {
			if e.link {
				inv.Problems = append(inv.Problems, t.ref(join(ed.dir, e.name))+": symbolic link, not followed")
			}
			continue
		}
		if n++; n > MaxExtensionDirs {
			inv.Problems = append(inv.Problems, fmt.Sprintf("%s: more than %d extension directories, the rest were not read", t.ref(ed.dir), MaxExtensionDirs))
			break
		}
		seen[e.name] = true
		r, registered := byDir[e.name]
		x := readExtension(inv, t, ed, e.name, registered, r)
		x.Registered = registered
		x.registryKnown = haveRegistry
		if !haveRegistry {
			x.Notes = append(x.Notes, "editor registry extensions.json not present: registration state unknown")
		}
		x.Obsolete = obsolete[e.name]
		inv.Extensions = append(inv.Extensions, x)
	}
	// Listed but absent: the editor thinks it is installed; the evidence
	// does not have it (removed, or not collected).
	dirs := make([]string, 0, len(byDir))
	for d := range byDir {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	for _, d := range dirs {
		if seen[d] {
			continue
		}
		r := byDir[d]
		x := Extension{Editor: ed.id, Registry: ed.registry, Registered: true, Dir: t.ref(join(ed.dir, d)),
			ID: strings.ToLower(r.Identifier.ID), Version: r.Version}
		applyMetadata(&x, &r.Metadata)
		x.Publisher, x.Name = splitID(x.ID)
		x.Notes = append(x.Notes, "listed in extensions.json but the directory is not in the evidence")
		inv.Extensions = append(inv.Extensions, x)
	}
}

func splitID(id string) (string, string) {
	if i := strings.Index(id, "."); i > 0 {
		return id[:i], id[i+1:]
	}
	return "", id
}

func applyMetadata(x *Extension, m *metadata) {
	if m == nil {
		return
	}
	if x.InstalledAt == "" {
		x.InstalledAt = msTime(m.InstalledTimestamp)
	}
	if x.Source == "" {
		x.Source = strings.ToLower(m.Source)
	}
	if x.PublisherDisplayName == "" {
		x.PublisherDisplayName = m.PublisherDisplayName
	}
	x.PreRelease = x.PreRelease || m.IsPreReleaseVersion || m.PreRelease
}

func readExtension(inv *Inventory, t tree, ed editor, dirName string, registered bool, r registryEntry) Extension {
	dir := join(ed.dir, dirName)
	x := Extension{Editor: ed.id, Registry: ed.registry, Dir: t.ref(dir), Present: true}
	if registered {
		x.ID = strings.ToLower(r.Identifier.ID)
		x.Version = r.Version
		applyMetadata(&x, &r.Metadata)
	}
	pj := join(dir, "package.json")
	b, trunc, err := t.read(pj, MaxManifestBytes)
	switch {
	case err != nil:
		x.Notes = append(x.Notes, "package.json not readable: "+err.Error())
		inv.Unsupported = append(inv.Unsupported, t.ref(dir)+": no readable package.json; extension not analyzed")
		if x.ID == "" {
			x.ID = strings.ToLower(dirName)
		}
		return x
	case trunc:
		inv.Problems = append(inv.Problems, t.ref(pj)+": exceeds size bound, not parsed")
		if x.ID == "" {
			x.ID = strings.ToLower(dirName)
		}
		return x
	}
	x.PackageSHA256 = t.sha256(pj)
	m, badFields, err := parsePackageJSON(b)
	for _, f := range badFields {
		x.Notes = append(x.Notes, "package.json field "+f+" has an unexpected type; ignored")
	}
	if err != nil {
		inv.Problems = append(inv.Problems, t.ref(pj)+": invalid JSON: "+err.Error())
		if x.ID == "" {
			x.ID = strings.ToLower(dirName)
		}
		return x
	}
	x.Publisher, x.Name, x.DisplayName = m.Publisher, m.Name, m.DisplayName
	if x.ID == "" {
		if m.Publisher != "" && m.Name != "" {
			x.ID = strings.ToLower(m.Publisher + "." + m.Name)
		} else {
			x.ID = strings.ToLower(dirName)
		}
	}
	if x.Version == "" {
		x.Version = m.Version
	} else if m.Version != "" && m.Version != x.Version {
		x.Notes = append(x.Notes, fmt.Sprintf("registry says version %s, package.json says %s", x.Version, m.Version))
	}
	if x.Publisher == "" {
		x.Publisher, _ = splitID(x.ID)
	}
	applyMetadata(&x, m.Metadata)
	x.ActivationEvents = capStrings(m.ActivationEvents, 64)
	for _, a := range m.ActivationEvents {
		if a == "*" || a == "onStartupFinished" {
			x.StartupActivation = true
		}
	}
	x.Contributes = parseContributes(m.Contributes)

	// Entry files: resolved inside the extension directory only.
	var mainCode, browserCode []byte
	if m.Main != "" {
		if rel, ok := resolveEntry(t, dir, m.Main); ok {
			x.Main = t.ref(rel)
			if e, ok := t.stat(rel); ok {
				x.MainSize = e.size
			}
			x.MainSHA256 = t.sha256(rel)
			mainCode = readCode(inv, t, rel, &x)
		} else {
			x.Notes = append(x.Notes, fmt.Sprintf("entry file %q not present in the evidence", m.Main))
		}
	}
	if m.Browser != "" {
		if rel, ok := resolveEntry(t, dir, m.Browser); ok {
			x.Browser = t.ref(rel)
			browserCode = readCode(inv, t, rel, &x)
		}
	}
	switch {
	case mainCode != nil || browserCode != nil:
		x.CodeScanned = true
		x.signals = scanCode(mainCode)
		x.signals.merge(scanCode(browserCode))
	case m.Main == "" && m.Browser == "":
		// Declarative extensions (themes, grammars, snippets) have no code.
		x.CodeScanned = true
	default:
		inv.Unsupported = append(inv.Unsupported, x.Dir+": entry file not available; code heuristics not run")
	}
	return x
}

func readCode(inv *Inventory, t tree, rel string, x *Extension) []byte {
	b, trunc, err := t.read(rel, MaxCodeBytes)
	if err != nil {
		x.Notes = append(x.Notes, "entry file not readable: "+err.Error())
		return nil
	}
	if trunc {
		x.Notes = append(x.Notes, fmt.Sprintf("entry file larger than %d bytes: the first %d bytes were scanned", MaxCodeBytes, MaxCodeBytes))
	}
	return b
}

// resolveEntry applies Node's resolution for a manifest "main": the path,
// then .js/.cjs/.mjs, then index.js inside it.
func resolveEntry(t tree, dir, ref string) (string, bool) {
	r, ok := inside(ref)
	if !ok {
		return "", false
	}
	base := join(dir, r)
	for _, cand := range []string{base, base + ".js", base + ".cjs", base + ".mjs", base + "/index.js"} {
		if e, ok := t.stat(cand); ok && !e.dir && !e.link {
			return cand, true
		}
	}
	return "", false
}

func parseContributes(raw json.RawMessage) Contributes {
	var c Contributes
	if len(raw) == 0 {
		return c
	}
	var m struct {
		Commands           []json.RawMessage `json:"commands"`
		MCPServerProviders []struct {
			ID    string `json:"id"`
			Label string `json:"label"`
		} `json:"mcpServerDefinitionProviders"`
		ChatParticipants []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"chatParticipants"`
		LanguageModelTools []struct {
			Name string `json:"name"`
		} `json:"languageModelTools"`
	}
	if json.Unmarshal(raw, &m) != nil {
		return c
	}
	c.Commands = len(m.Commands)
	for _, p := range m.MCPServerProviders {
		c.MCPServerProviders = append(c.MCPServerProviders, firstNonEmpty(p.ID, p.Label))
	}
	for _, p := range m.ChatParticipants {
		c.ChatParticipants = append(c.ChatParticipants, firstNonEmpty(p.ID, p.Name))
	}
	for _, p := range m.LanguageModelTools {
		c.LanguageModelTools = append(c.LanguageModelTools, p.Name)
	}
	c.MCPServerProviders = capStrings(c.MCPServerProviders, 64)
	c.ChatParticipants = capStrings(c.ChatParticipants, 64)
	c.LanguageModelTools = capStrings(c.LanguageModelTools, 256)
	return c
}

func capStrings(s []string, n int) []string {
	if len(s) > n {
		return append(s[:n:n], fmt.Sprintf("… %d more", len(s)-n))
	}
	return s
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
