package ioc

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/efij/AgentDFIR/v3/internal/casepkg"
	"github.com/efij/AgentDFIR/v3/internal/netdest"
	"github.com/efij/AgentDFIR/v3/internal/schema"
	"github.com/efij/AgentDFIR/v3/internal/shellshape"
)

// PkgRef is a package the case says is installed or configured.
type PkgRef struct {
	Ecosystem string // npm | pypi
	Name      string
	Version   string // "" when unknown
	Evidence  string // where the reference was found
}

// Inputs is what one hunt looks at. Every surface is optional; the verdict
// names the surfaces that were actually searched.
type Inputs struct {
	Events   []schema.Event
	Manifest *casepkg.Manifest
	Store    *casepkg.Store
	Packages []PkgRef // MCP inventory
	// RawTranscripts also scans transcript bytes (tool outputs, text the
	// parsers do not keep). One read per transcript; `hunt` sets it, the
	// analyze stage does not.
	RawTranscripts bool
	// Path is a directory to walk for lockfiles, installed files and shell
	// rc files (hunt --path).
	Path string
	// Simulated marks a case built by `agentdfir simulate`.
	Simulated bool
}

// Hit is one indicator seen in one place (aggregated).
type Hit struct {
	Indicator Indicator
	Where     string // OBSERVED | SEEN_IN_OUTPUT | MENTIONED
	Surface   string // command | file | tool_output | config | shell_history | transcript | mcp_inventory | lockfile | filesystem | artifact_hash
	Evidence  string // first evidence reference
	Count     int
	FirstSeen string
	LastSeen  string
	TimeSrc   string // transcript | file_mtime | "" (current state)
	InWindow  string // yes | no | "" (unknown)
	State     string // corroboration state of the event, when from an event
}

// Verdict is the answer for one incident.
type Verdict struct {
	Incident Incident
	Status   string // HIT | SIMULATED | NO_EVIDENCE | INCONCLUSIVE
	Reason   string
	Window   string // evidence window searched
	Surfaces []string
	Hits     []Hit // OBSERVED and SEEN_IN_OUTPUT
	Mentions []Hit
	// Context: low-confidence indicators (shared infrastructure that
	// legitimate software also uses) that were seen. Never a HIT alone.
	Context []Hit
	Notes   []string
}

type hitKey struct {
	ind   string
	where string
	surf  string
}

type collector struct {
	inc  Incident
	hits map[hitKey]*Hit
	ord  []hitKey
}

func (c *collector) add(ind Indicator, where, surf, evidence, ts, tsrc, state string) {
	k := hitKey{ind.Label(), where, surf}
	h, ok := c.hits[k]
	if !ok {
		h = &Hit{Indicator: ind, Where: where, Surface: surf, Evidence: evidence, TimeSrc: tsrc, State: state}
		c.hits[k] = h
		c.ord = append(c.ord, k)
	}
	h.Count++
	if ts != "" {
		if h.FirstSeen == "" || ts < h.FirstSeen {
			h.FirstSeen = ts
		}
		if ts > h.LastSeen {
			h.LastSeen = ts
		}
	}
}

var pkgTokRe = regexp.MustCompile(`(?:^|[\s"'(=,])((?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*)@v?(\d+\.\d+\.\d+[0-9a-z.+-]*)`)

// Hunt evaluates incidents against the inputs.
func Hunt(incs []Incident, in Inputs) []Verdict {
	cols := make([]*collector, len(incs))
	for i, inc := range incs {
		cols[i] = &collector{inc: inc, hits: map[hitKey]*Hit{}}
	}
	var surfaces []string
	oldest, newest := "", ""

	// ---- normalized events
	if len(in.Events) > 0 {
		surfaces = append(surfaces, "agent tool calls and results")
	}
	callTool := map[string]string{}
	for _, ev := range in.Events {
		if ev.EventType == schema.EventToolCall && ev.ToolCallID != "" {
			callTool[ev.ToolCallID] = ev.Tool
		}
	}
	for _, ev := range in.Events {
		ts := ev.Timestamp
		if len(ts) >= 10 && ev.TimestampSrc != "database" {
			if oldest == "" || ts < oldest {
				oldest = ts
			}
			if ts > newest {
				newest = ts
			}
		}
		ref := fmt.Sprintf("%s:%d (artifact %.12s)", ev.SourcePath, ev.SourceLine, ev.SourceArtifact)
		// Each event becomes (text, where, surface) pieces.
		type piece struct{ text, where, surf string }
		var pieces []piece
		switch ev.EventType {
		case schema.EventToolCall:
			if cmd := ev.FullCommand(); cmd != "" {
				// A heredoc body is a file being written; a search or print
				// stage is looking for the string, not using it.
				// Stages of the command as the shell parses it: quoted prose
				// (an echo'd sentence, a commit message) is not a command.
				for _, st := range shellshape.Stages(shellshape.Strip(cmd)) {
					w := WhereObserved
					if shellshape.IsSearchVerb(shellshape.Verb(st.Text)) {
						w = WhereMentioned
					}
					pieces = append(pieces, piece{st.Text, w, "command"})
				}
			}
			if ev.File != "" {
				pieces = append(pieces, piece{ev.File, WhereObserved, "file"})
			}
		case schema.EventToolResult:
			// Output of a shell is what the host holds; output of a web
			// fetch, a search or a file read is what the agent read about.
			w := WhereMentioned
			if shellTool(callTool[ev.ToolCallID]) || shellTool(ev.Tool) {
				w = WhereOutput
			}
			pieces = append(pieces, piece{ev.Summary, w, "tool_output"})
		case schema.EventHumanPrompt, schema.EventModelResponse:
			pieces = append(pieces, piece{ev.Summary, WhereMentioned, "conversation"})
		default:
			continue
		}
		for _, pc := range pieces {
			if strings.TrimSpace(pc.text) == "" {
				continue
			}
			low := strings.ToLower(pc.text)
			pkgs := pkgTokRe.FindAllStringSubmatch(low, 32)
			var hosts []string
			if pc.surf == "command" {
				for _, d := range netdest.Extract(pc.text) {
					hosts = append(hosts, netdest.Host(d))
				}
			}
			for _, c := range cols {
				for _, ind := range c.inc.Indicators {
					hit := false
					switch ind.Kind {
					case KindPackage:
						for _, m := range pkgs {
							if ind.MatchPackage(ind.Ecosystem, m[1], m[2]) {
								hit = true
							}
						}
						if !hit && len(ind.Versions) == 0 && ind.FromVersion == "" && installsPackage(low, ind.Value) {
							hit = true
						}
					case KindSHA256:
					default:
						hit = ind.MatchText(low)
						for _, h := range hosts {
							hit = hit || ind.MatchHost(h)
						}
					}
					if hit {
						c.add(ind, pc.where, pc.surf, ref, ts, "transcript", ev.Corroboration)
					}
				}
			}
		}
	}

	// ---- MCP inventory
	if len(in.Packages) > 0 {
		surfaces = append(surfaces, "MCP server packages")
	}
	for _, p := range in.Packages {
		for _, c := range cols {
			for _, ind := range c.inc.Indicators {
				if ind.MatchPackage(p.Ecosystem, p.Name, p.Version) {
					c.add(ind, WhereObserved, "mcp_inventory", p.Evidence, "", "", schema.StateObserved)
				}
			}
		}
	}

	// ---- collected artifacts
	if in.Manifest != nil && in.Store != nil {
		cur := in.Manifest.Current()
		surfaces = append(surfaces, "collected configs, instructions and shell history", "collected file hashes and paths")
		if in.RawTranscripts {
			surfaces = append(surfaces, "raw transcript bytes")
		}
		for _, a := range cur {
			if a.Status != casepkg.StatusOK {
				continue
			}
			ref := fmt.Sprintf("%s (artifact %.12s)", a.LogicalPath, a.ArtifactID)
			for _, c := range cols {
				for _, ind := range c.inc.Indicators {
					switch {
					case ind.Kind == KindSHA256 && ind.Value == a.ArtifactID:
						c.add(ind, WhereObserved, "artifact_hash", ref, a.ModTimeUTC, "file_mtime", schema.StateObserved)
					case ind.Kind == KindPath && pathMatch(a.LogicalPath, ind.Value):
						c.add(ind, WhereObserved, "filesystem", ref, a.ModTimeUTC, "file_mtime", schema.StateObserved)
					}
				}
			}
			if shellshape.SelfReferentialPath(a.LogicalPath) {
				continue // agentdfir's own rules and fixtures name every indicator
			}
			switch a.ArtifactType {
			case "product_config", "managed_config", "agent_instructions", "shell_state":
				if !in.Store.IsText(a) {
					continue
				}
				data, err := in.Store.ReadAll(a.ArtifactID, 16<<20)
				if err != nil {
					continue
				}
				surf := "config"
				if a.ArtifactType == "shell_state" {
					surf = "shell_history"
				}
				scanText(cols, strings.ToLower(string(data)), WhereObserved, surf, ref, a.ModTimeUTC, "file_mtime")
			case "agent_session", "prompt_history":
				if in.RawTranscripts && in.Store.IsText(a) {
					scanTranscript(cols, in.Store, a, ref)
				}
			}
		}
	}

	// ---- a directory on disk
	var walkNotes []string
	if in.Path != "" {
		surfaces = append(surfaces, "lockfiles, installed files and shell rc files under "+in.Path)
		walkNotes = walkPath(cols, in.Path)
	}

	window := ""
	if oldest != "" {
		window = oldest[:10] + ".." + newest[:10]
	}
	var out []Verdict
	for _, c := range cols {
		v := Verdict{Incident: c.inc, Window: window, Surfaces: surfaces, Notes: walkNotes}
		for _, k := range c.ord {
			h := *c.hits[k]
			h.InWindow = inWindow(h, c.inc)
			if h.Where == WhereMentioned {
				v.Mentions = append(v.Mentions, h)
				continue
			}
			if h.Indicator.Confidence == "low" {
				v.Context = append(v.Context, h)
				continue
			}
			v.Hits = append(v.Hits, h)
		}
		sort.SliceStable(v.Hits, func(i, j int) bool { return sevRank(v.Hits[i]) > sevRank(v.Hits[j]) })
		switch {
		case len(v.Hits) > 0 && in.Simulated:
			v.Status, v.Reason = "SIMULATED", "indicators found in a case built by `agentdfir simulate`; synthetic, not a compromise"
		case len(v.Hits) > 0:
			v.Status, v.Reason = "HIT", fmt.Sprintf("%d indicator(s) seen", len(v.Hits))
		case window != "" && c.inc.LastSeen != "" && window[:10] > c.inc.LastSeen:
			v.Status = "INCONCLUSIVE"
			v.Reason = fmt.Sprintf("agent activity in this case starts %s, after the incident (%s..%s); activity from then is not in the evidence (transcripts are routinely cleaned up). Current-state checks (packages, configs, files) found nothing.", window[:10], c.inc.FirstSeen, c.inc.LastSeen)
		case len(surfaces) == 0:
			v.Status, v.Reason = "INCONCLUSIVE", "nothing to search"
		default:
			v.Status, v.Reason = "NO_EVIDENCE", "no indicator found on the surfaces searched"
		}
		out = append(out, v)
	}
	return out
}

// shellTool: tools whose output is the host's own answer.
func shellTool(t string) bool {
	switch strings.ToLower(t) {
	case "bash", "shell", "container.exec", "exec_command", "local_shell", "execute_command", "run_terminal_cmd", "run_shell_command", "bashoutput", "terminal", "run_command":
		return true
	}
	return false
}

func sevRank(h Hit) int {
	switch h.Indicator.Severity(h.Where) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	}
	return 1
}

func inWindow(h Hit, inc Incident) string {
	if h.FirstSeen == "" || inc.FirstSeen == "" || len(h.FirstSeen) < 10 {
		return ""
	}
	d := h.FirstSeen[:10]
	last := inc.LastSeen
	if last == "" {
		last = "9999-12-31"
	}
	// installs and files keep acting after an incident is disclosed
	if d >= inc.FirstSeen {
		if d <= last {
			return "yes"
		}
		return "after"
	}
	return "no"
}

// installsPackage: an install command naming the package without a
// version (npm i keyv, pnpm add codexui-android).
func installsPackage(lowCmd, name string) bool {
	if !strings.Contains(lowCmd, name) {
		return false
	}
	re := regexp.MustCompile(`\b(npm|pnpm|yarn|bun)\s+(i|install|add)\b[^;&|\n]*(\s|^)` + regexp.QuoteMeta(name) + `(\s|$|@)`)
	return re.MatchString(lowCmd)
}

func pathMatch(p, frag string) bool {
	p = strings.ToLower(strings.ReplaceAll(p, `\`, "/"))
	f := strings.ToLower(frag)
	if strings.Contains(f, "/") {
		return strings.Contains(p, strings.TrimSuffix(f, "/"))
	}
	return path.Base(p) == f || strings.Contains(p, "/"+f+"/")
}

func scanText(cols []*collector, low, where, surf, ref, ts, tsrc string) {
	pkgs := pkgTokRe.FindAllStringSubmatch(low, 256)
	for _, c := range cols {
		for _, ind := range c.inc.Indicators {
			switch ind.Kind {
			case KindSHA256:
				continue
			case KindPackage:
				for _, m := range pkgs {
					if ind.MatchPackage(ind.Ecosystem, m[1], m[2]) {
						c.add(ind, where, surf, ref, ts, tsrc, schema.StateObserved)
						break
					}
				}
			default:
				if ind.MatchText(low) {
					c.add(ind, where, surf, ref, ts, tsrc, schema.StateObserved)
				}
			}
		}
	}
}

// scanTranscript reads a transcript once, in bounded chunks: a line longer
// than the buffer is scanned piece by piece (with overlap), so neither a
// multi-GB line nor padding hides an indicator or exhausts memory.
func scanTranscript(cols []*collector, store *casepkg.Store, a casepkg.ArtifactRecord, ref string) {
	f, err := store.Open(a.ArtifactID)
	if err != nil {
		return
	}
	defer f.Close()
	const overlap = 512
	r := bufio.NewReaderSize(f, 1<<20)
	var off int64
	lineStart := true
	skip := false // current line is a tool call (covered by the events)
	var carry []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(chunk) > 0 {
			low := strings.ToLower(string(chunk))
			if lineStart {
				skip = strings.Contains(low, `"tool_use"`) || strings.Contains(low, `"function_call"`) || strings.Contains(low, `"custom_tool_call"`)
				carry = carry[:0]
			}
			// Tool calls are covered, shell-aware, by the events. The raw
			// pass adds only what the parsers do not keep, and cannot tell a
			// shell's output from a web page's, so everything it finds is
			// context.
			if !skip {
				text := strings.ToLower(string(carry)) + low
				scanText(cols, text, WhereMentioned, "transcript", fmt.Sprintf("%s (artifact %.12s, byte offset %d)", a.LogicalPath, a.ArtifactID, off), "", "")
			}
			if len(chunk) > overlap {
				carry = append(carry[:0], chunk[len(chunk)-overlap:]...)
			} else {
				carry = append(carry, chunk...)
			}
			off += int64(len(chunk))
			lineStart = chunk[len(chunk)-1] == '\n'
		}
		if err != nil {
			if err == bufio.ErrBufferFull {
				continue
			}
			return
		}
	}
}

// ---- directory walk (hunt --path)

const (
	maxWalkEntries = 1000000
	maxWalkDepth   = 12
	maxHashBytes   = 16 << 20
)

var skipDirs = map[string]bool{".git": true, "Library": true, ".cache": true, ".Trash": true, "_cacache": true, ".rustup": true, ".cargo": true, "go": true, ".gradle": true, ".m2": true, "Pictures": true, "Movies": true, "Music": true}

var rcFiles = map[string]bool{".bashrc": true, ".zshrc": true, ".profile": true, ".bash_profile": true, ".zprofile": true, ".zshenv": true, ".bash_login": true}

func walkPath(cols []*collector, root string) []string {
	var notes []string
	hashNames := map[string]bool{}
	pathNames := map[string]bool{}
	for _, c := range cols {
		for _, ind := range c.inc.Indicators {
			if ind.Kind == KindSHA256 && ind.FileName != "" {
				hashNames[strings.ToLower(ind.FileName)] = true
			}
			if ind.Kind == KindPath && !strings.Contains(ind.Value, "/") {
				pathNames[strings.ToLower(ind.Value)] = true
			}
		}
	}
	entries := 0
	root = filepath.Clean(root)
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		entries++
		if entries > maxWalkEntries {
			notes = append(notes, fmt.Sprintf("walk stopped after %d entries under %s; point --path at a project or home subtree", maxWalkEntries, root))
			return filepath.SkipAll
		}
		rel, _ := filepath.Rel(root, p)
		depth := strings.Count(rel, string(filepath.Separator))
		name := d.Name()
		lname := strings.ToLower(name)
		if d.Type()&os.ModeSymlink != 0 {
			return nil // never follow links out of the tree
		}
		if d.IsDir() {
			if p != root && (skipDirs[name] || depth >= maxWalkDepth) {
				return filepath.SkipDir
			}
			if pathNames[lname] {
				for _, c := range cols {
					for _, ind := range c.inc.Indicators {
						if ind.Kind == KindPath && strings.EqualFold(ind.Value, name) {
							c.add(ind, WhereObserved, "filesystem", p, mtime(d), "file_mtime", schema.StateObserved)
						}
					}
				}
			}
			if name == "node_modules" {
				// Installed versions are in npm's hidden lockfile; do not
				// walk tens of thousands of package files.
				hidden := filepath.Join(p, ".package-lock.json")
				if _, err := os.Stat(hidden); err == nil {
					scanLockfile(cols, hidden)
				}
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		switch {
		case lname == "package-lock.json" || lname == "npm-shrinkwrap.json" || lname == "yarn.lock" || lname == "pnpm-lock.yaml" ||
			lname == "bun.lock" || lname == "poetry.lock" || lname == "uv.lock" || strings.HasPrefix(lname, "requirements") && strings.HasSuffix(lname, ".txt"):
			scanLockfile(cols, p)
		case depth == 0 && rcFiles[name]:
			if b, err := readCapped(p, 4<<20); err == nil {
				scanText(cols, strings.ToLower(string(b)), WhereObserved, "shell_rc", p, mtime(d), "file_mtime")
			}
		}
		if pathNames[lname] {
			for _, c := range cols {
				for _, ind := range c.inc.Indicators {
					if ind.Kind == KindPath && strings.EqualFold(ind.Value, name) {
						c.add(ind, WhereObserved, "filesystem", p, mtime(d), "file_mtime", schema.StateObserved)
					}
				}
			}
		}
		for _, c := range cols {
			for _, ind := range c.inc.Indicators {
				if ind.Kind == KindPath && strings.Contains(ind.Value, "/") && pathMatch(p, ind.Value) {
					c.add(ind, WhereObserved, "filesystem", p, mtime(d), "file_mtime", schema.StateObserved)
				}
			}
		}
		if hashNames[lname] {
			if sum := hashFile(p); sum != "" {
				for _, c := range cols {
					for _, ind := range c.inc.Indicators {
						if ind.Kind == KindSHA256 && ind.Value == sum {
							c.add(ind, WhereObserved, "artifact_hash", p, mtime(d), "file_mtime", schema.StateObserved)
						}
					}
				}
			}
		}
		return nil
	})
	return notes
}

func mtime(d os.DirEntry) string {
	if fi, err := d.Info(); err == nil {
		return fi.ModTime().UTC().Format("2006-01-02T15:04:05Z")
	}
	return ""
}

func readCapped(p string, n int64) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, n))
}

func hashFile(p string) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, maxHashBytes)); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}
