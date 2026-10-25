package supplychain

import (
	"bytes"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/efij/AgentDFIR/v4/internal/casepkg"
	"github.com/efij/AgentDFIR/v4/internal/detect"
	"github.com/efij/AgentDFIR/v4/internal/mcpaudit"
)

// Bounds on history work over hostile or very long-lived cases.
const (
	maxVersionsPerFile = 64
	maxCacheFiles      = 500
)

// fileVersion is one distinct content of a file, in collection order.
type fileVersion struct {
	rec    casepkg.ArtifactRecord // first record holding this content
	rounds []int
}

// versions returns the distinct consecutive contents a logical path held
// across the case's rounds (A A B A → A[1,2] B[3] A[4]).
func (b *builder) versions(p string) []fileVersion {
	var out []fileVersion
	for _, a := range b.recs[p] {
		r := roundOf(a)
		if n := len(out); n > 0 && out[n-1].rec.ArtifactID == a.ArtifactID {
			if out[n-1].rounds[len(out[n-1].rounds)-1] != r {
				out[n-1].rounds = append(out[n-1].rounds, r)
			}
			continue
		}
		if len(out) >= maxVersionsPerFile {
			b.omitted["file_versions"]++
			continue
		}
		out = append(out, fileVersion{rec: a, rounds: []int{r}})
	}
	return out
}

// primaryFile is the file whose content is a component's hash.
func (b *builder) primaryFile(c *Component) string {
	switch c.Kind {
	case KindSkill, KindSubagent, KindCommand, KindInstruction, KindAgentSetting:
		if len(c.Paths) > 0 {
			return c.Paths[0]
		}
	case KindPlugin, KindExtension:
		// The file under the component's directory whose content is the hash.
		if len(c.Paths) == 0 || c.SHA256 == "" {
			return ""
		}
		dir := c.Paths[0] + "/"
		for p, a := range b.current {
			if a.ArtifactID == c.SHA256 && strings.HasPrefix(p, dir) {
				return p
			}
		}
	}
	return ""
}

// history fills hash history and first/last-seen stamps from the manifest,
// then folds in the baselines.
func (b *builder) history() {
	for i := range b.rep.Components {
		c := &b.rep.Components[i]
		switch c.Kind {
		case KindMCP:
			b.mcpHistory(c)
			continue
		case KindHook, KindMarketplace:
			if len(c.Paths) > 0 {
				b.presence(c, c.Paths[0])
			}
			continue
		}
		p := b.primaryFile(c)
		if p == "" {
			continue
		}
		vs := b.versions(p)
		for _, v := range vs {
			c.addVersion(Version{SHA256: v.rec.ArtifactID, Source: "round", Label: roundsLabel(v.rounds), Rounds: v.rounds, Path: p, MTime: v.rec.ModTimeUTC})
		}
		if len(vs) == 0 {
			continue
		}
		if c.SHA256 == "" {
			c.SHA256 = vs[len(vs)-1].rec.ArtifactID
		}
		first, last := vs[0].rec, b.recs[p][len(b.recs[p])-1]
		c.seen(&Stamp{Time: first.ModTimeUTC, Source: TimeMTime, Detail: "mtime of the earliest collected copy", Ref: refOf(first)}, false)
		c.seen(&Stamp{Time: last.CollectedUTC, Source: TimeCollection, Detail: fmt.Sprintf("present when round %d was collected", roundOf(last)), Ref: refOf(last)}, true)
		if len(vs) > 1 {
			for k := 1; k < len(vs); k++ {
				b.timeline(TimelineEntry{Time: vs[k].rec.CollectedUTC, TimeSource: TimeCollection, Kind: "version", Component: c.ID, Class: Verified,
					Text: fmt.Sprintf("%s content changed: sha256 %s (round %d) → %s (round %d)", c.Name, short(vs[k-1].rec.ArtifactID),
						vs[k-1].rounds[len(vs[k-1].rounds)-1], short(vs[k].rec.ArtifactID), vs[k].rounds[0]), Ref: refOf(vs[k].rec)})
			}
		}
	}
	for _, pb := range b.in.Baselines {
		if pb.B == nil {
			continue
		}
		for i := range b.rep.Components {
			c := &b.rep.Components[i]
			p := b.primaryFile(c)
			if h, ok := pb.B.Artifacts[p]; ok && p != "" {
				c.addVersion(Version{SHA256: h, Source: "package_snapshot", Label: pb.Label + " (" + pb.B.CreatedUTC + ")", Path: p})
			}
		}
	}
	for i := range b.rep.Components {
		c := &b.rep.Components[i]
		if c.FirstSeen != nil {
			b.timeline(TimelineEntry{Time: c.FirstSeen.Time, TimeSource: c.FirstSeen.Source, Kind: "first_seen", Component: c.ID,
				Text: fmt.Sprintf("%s %s first seen (%s)", c.Kind, c.Name, c.FirstSeen.Detail), Ref: c.FirstSeen.Ref})
		}
	}
}

// presence records the rounds the file declaring a component was collected in.
func (b *builder) presence(c *Component, p string) {
	vs := b.versions(p)
	if len(vs) == 0 {
		return
	}
	var rounds []int
	for _, v := range vs {
		for _, r := range v.rounds {
			if len(rounds) == 0 || rounds[len(rounds)-1] != r {
				rounds = append(rounds, r)
			}
		}
	}
	if c.SHA256 != "" {
		c.addVersion(Version{SHA256: c.SHA256, Source: "round", Label: "declared in " + roundsLabel(rounds), Rounds: rounds, Path: p})
	}
	last := b.recs[p][len(b.recs[p])-1]
	c.seen(&Stamp{Time: vs[0].rec.ModTimeUTC, Source: TimeMTime, Detail: "mtime of the declaring file", Ref: refOf(vs[0].rec)}, false)
	c.seen(&Stamp{Time: last.CollectedUTC, Source: TimeCollection, Detail: fmt.Sprintf("declared when round %d was collected", roundOf(last)), Ref: refOf(last)}, true)
}

func (c *Component) addVersion(v Version) {
	for i := range c.History {
		h := &c.History[i]
		if h.SHA256 == v.SHA256 && h.Source == v.Source && h.Path == v.Path && h.Label == v.Label {
			return
		}
	}
	c.History = append(c.History, v)
}

// seen widens first_seen (last=false) or last_seen (last=true) when the
// stamp is earlier / later than what is recorded.
func (c *Component) seen(s *Stamp, last bool) {
	t, ok := parseTS(s.Time)
	if !ok {
		return
	}
	s.Time = rfc(t)
	if last {
		if c.LastSeen == nil {
			c.LastSeen = s
			return
		}
		if cur, ok := parseTS(c.LastSeen.Time); !ok || t.After(cur) {
			c.LastSeen = s
		}
		return
	}
	if c.FirstSeen == nil {
		c.FirstSeen = s
		return
	}
	if cur, ok := parseTS(c.FirstSeen.Time); !ok || t.Before(cur) {
		c.FirstSeen = s
	}
}

func refOf(a casepkg.ArtifactRecord) string {
	return fmt.Sprintf("%s (artifact %s, round %d)", a.LogicalPath, short(a.ArtifactID), roundOf(a))
}

func roundsLabel(rs []int) string {
	if len(rs) == 0 {
		return ""
	}
	if len(rs) == 1 {
		return fmt.Sprintf("round %d", rs[0])
	}
	parts := make([]string, len(rs))
	for i, r := range rs {
		parts[i] = fmt.Sprint(r)
	}
	return "rounds " + strings.Join(parts, ",")
}

// serverSnap is one server definition as one source recorded it.
type serverSnap struct {
	snap Snapshot
	s    mcpaudit.Server
}

// configSnaps parses every version of a server's config file and returns
// the server as each version defined it (absent versions are skipped).
func (b *builder) configSnaps(c *Component) []serverSnap {
	if len(c.Paths) == 0 {
		return nil
	}
	p := c.Paths[0]
	key := strings.TrimPrefix(c.ID, "mcp_server:")
	var out []serverSnap
	for _, v := range b.versions(p) {
		data, err := b.readBlob(v.rec)
		if err != nil {
			b.note("%s round %d: not read: %v", p, v.rounds[0], err)
			continue
		}
		inv, ok := mcpaudit.ParseArtifact(p, data)
		if !ok || inv == nil {
			continue
		}
		for _, s := range inv.Servers {
			if s.Key() == key {
				out = append(out, serverSnap{snap: Snapshot{Label: fmt.Sprintf("%s in %s", roundsLabel(v.rounds), p), Source: "round",
					Round: v.rounds[0], Time: v.rec.CollectedUTC, TimeSource: TimeCollection, SHA256: defHash(s), Ref: refOf(v.rec)}, s: s})
				break
			}
		}
	}
	return out
}

func (b *builder) mcpHistory(c *Component) {
	snaps := b.configSnaps(c)
	for _, ss := range snaps {
		c.addVersion(Version{SHA256: ss.snap.SHA256, Source: "round", Label: ss.snap.Label, Rounds: []int{ss.snap.Round}, Path: c.Paths[0]})
	}
	if len(c.Paths) > 0 {
		if rs := b.recs[c.Paths[0]]; len(rs) > 0 {
			if len(snaps) > 0 {
				c.seen(&Stamp{Time: snaps[0].snap.Time, Source: TimeCollection, Detail: "first collected definition (" + snaps[0].snap.Label + ")", Ref: snaps[0].snap.Ref}, false)
			}
			last := rs[len(rs)-1]
			c.seen(&Stamp{Time: last.CollectedUTC, Source: TimeCollection, Detail: fmt.Sprintf("configured when round %d was collected", roundOf(last)), Ref: refOf(last)}, true)
		}
	}
	key := strings.TrimPrefix(c.ID, "mcp_server:")
	for _, mb := range b.in.MCPBaselines {
		if mb.B == nil {
			continue
		}
		if s, ok := mb.B.Servers[key]; ok {
			c.addVersion(Version{SHA256: defHash(s), Source: "baseline", Label: mb.Label + " (" + mb.B.CreatedUTC + ")"})
		}
	}
}

// ---- drift

// drift compares consecutive snapshots of each MCP server (config rounds
// after any baselines; cached tool manifests; tool lists logged at session
// start) and of each settings file.
func (b *builder) drift() {
	for i := range b.rep.Components {
		c := &b.rep.Components[i]
		switch c.Kind {
		case KindMCP:
			var chain []serverSnap
			key := strings.TrimPrefix(c.ID, "mcp_server:")
			bl := append([]MCPBaseline(nil), b.in.MCPBaselines...)
			sort.SliceStable(bl, func(i, j int) bool { return bl[i].B != nil && bl[j].B != nil && bl[i].B.CreatedUTC < bl[j].B.CreatedUTC })
			for _, mb := range bl {
				if mb.B == nil {
					continue
				}
				if s, ok := mb.B.Servers[key]; ok {
					chain = append(chain, serverSnap{snap: Snapshot{Label: mb.Label, Source: "baseline", Time: mb.B.CreatedUTC, TimeSource: "baseline_created", SHA256: defHash(s)}, s: s})
				}
			}
			chain = append(chain, b.configSnaps(c)...)
			b.compareChain(c, chain, "the server definitions are read from sealed configuration files (hash-identified) and baselines")
		case KindAgentSetting:
			b.settingsDrift(c)
		}
	}
	b.cachedManifestDrift()
}

func (b *builder) compareChain(c *Component, chain []serverSnap, basis string) {
	for k := 1; k < len(chain); k++ {
		prev, cur := chain[k-1], chain[k]
		d := compareServers(prev.s, cur.s)
		if d == nil {
			continue
		}
		d.Component, d.Subject, d.From, d.To, d.Class, d.Basis = c.ID, c.Name, prev.snap, cur.snap, Verified, basis
		b.addDrift(*d)
	}
}

func (b *builder) addDrift(d Drift) {
	b.rep.Drift = append(b.rep.Drift, d)
	t, ts := d.To.Time, d.To.TimeSource
	text := fmt.Sprintf("%s drift in %s: %s → %s", d.Kind, d.Subject, d.From.Label, d.To.Label)
	if len(d.Expansion) > 0 {
		text += "; permission expansion: " + strings.Join(d.Expansion, "; ")
	}
	b.timeline(TimelineEntry{Time: t, TimeSource: ts, Kind: "drift", Component: d.Component, Class: d.Class, Session: d.To.Session, Text: trim(text, 400), Ref: d.To.Ref})
}

var pathArgRe = regexp.MustCompile(`^(/|~|[A-Za-z]:[\\/]|\\\\)`)

// compareServers reports what changed between two definitions of one
// server, or nil when nothing did.
func compareServers(old, cur mcpaudit.Server) *Drift {
	d := &Drift{Kind: "mcp_server_definition"}
	ot, ct := map[string]mcpaudit.Tool{}, map[string]mcpaudit.Tool{}
	for _, t := range old.Tools {
		ot[t.Name] = t
	}
	for _, t := range cur.Tools {
		ct[t.Name] = t
	}
	for _, n := range sortedKeys(ct) {
		o, had := ot[n]
		switch {
		case !had:
			d.Added = append(d.Added, "tool "+n)
			d.Expansion = append(d.Expansion, "new tool "+n)
		case o.DefSHA256 != "" && ct[n].DefSHA256 != "" && o.DefSHA256 != ct[n].DefSHA256:
			d.Changed = append(d.Changed, fmt.Sprintf("tool %s definition (sha256 %s → %s)", n, short(o.DefSHA256), short(ct[n].DefSHA256)))
		}
	}
	for _, n := range sortedKeys(ot) {
		if _, ok := ct[n]; !ok {
			d.Removed = append(d.Removed, "tool "+n)
		}
	}
	if len(d.Added)+len(d.Removed)+len(d.Changed) > 0 {
		d.Kind = "mcp_tool_definition"
	}
	if old.Command != cur.Command {
		d.Changed = append(d.Changed, fmt.Sprintf("command %q → %q", trim(old.Command, 80), trim(cur.Command, 80)))
	}
	if strings.Join(old.Args, "\x00") != strings.Join(cur.Args, "\x00") {
		d.Changed = append(d.Changed, fmt.Sprintf("args %q → %q", detect.MaskSecrets(trim(strings.Join(old.Args, " "), 120)), detect.MaskSecrets(trim(strings.Join(cur.Args, " "), 120))))
		had := map[string]bool{}
		for _, a := range old.Args {
			had[a] = true
		}
		for _, a := range cur.Args {
			if !had[a] && pathArgRe.MatchString(a) {
				d.Expansion = append(d.Expansion, "new filesystem path argument "+trim(a, 120))
			}
		}
	}
	if old.URL != cur.URL {
		d.Changed = append(d.Changed, fmt.Sprintf("url %q → %q", safeURL(old.URL), safeURL(cur.URL)))
	}
	if old.Transport != cur.Transport {
		d.Changed = append(d.Changed, fmt.Sprintf("transport %s → %s", old.Transport, cur.Transport))
	}
	for _, k := range newItems(old.EnvKeys, cur.EnvKeys) {
		d.Expansion = append(d.Expansion, "new env key "+k)
		d.Added = append(d.Added, "env "+k)
	}
	if old.EnvSHA256 != cur.EnvSHA256 {
		d.Changed = append(d.Changed, "env values (fingerprint changed; values are never recorded)")
	}
	for _, k := range newItems(old.HeaderKeys, cur.HeaderKeys) {
		d.Expansion = append(d.Expansion, "new header "+k)
		d.Added = append(d.Added, "header "+k)
	}
	for _, k := range newItems(old.AutoAllow, cur.AutoAllow) {
		d.Expansion = append(d.Expansion, "tool auto-approved: "+k)
		d.Added = append(d.Added, "auto-approve "+k)
	}
	if old.Disabled && !cur.Disabled {
		d.Expansion = append(d.Expansion, "server re-enabled")
		d.Changed = append(d.Changed, "disabled → enabled")
	}
	if old.SHA256 != cur.SHA256 && old.SHA256 != "" && cur.SHA256 != "" {
		d.Changed = append(d.Changed, fmt.Sprintf("resolved binary sha256 %s → %s", short(old.SHA256), short(cur.SHA256)))
	}
	if len(d.Added)+len(d.Removed)+len(d.Changed)+len(d.Expansion) == 0 {
		return nil
	}
	return d
}

func newItems(old, cur []string) []string {
	had := map[string]bool{}
	for _, x := range old {
		had[x] = true
	}
	var out []string
	for _, x := range cur {
		if !had[x] {
			out = append(out, x)
			had[x] = true
		}
	}
	return out
}

// settingsDrift compares consecutive versions of one settings or MCP
// configuration file, after the package snapshots that hold it.
func (b *builder) settingsDrift(c *Component) {
	p := c.Paths[0]
	vs := b.versions(p)
	for _, pb := range b.in.Baselines {
		if pb.B == nil || len(vs) == 0 {
			continue
		}
		if h, ok := pb.B.Artifacts[p]; ok && h != vs[0].rec.ArtifactID {
			b.addDrift(Drift{Kind: "agent_settings", Component: c.ID, Subject: p,
				From:    Snapshot{Label: pb.Label, Source: "package_snapshot", Time: pb.B.CreatedUTC, TimeSource: "baseline_created", SHA256: h},
				To:      Snapshot{Label: roundsLabel(vs[0].rounds), Source: "round", Round: vs[0].rounds[0], Time: vs[0].rec.CollectedUTC, TimeSource: TimeCollection, SHA256: vs[0].rec.ArtifactID, Ref: refOf(vs[0].rec)},
				Changed: []string{"file content differs from the snapshot (the snapshot holds hashes only; no field-level comparison)"},
				Class:   Verified, Basis: "content hashes differ"})
		}
	}
	if len(vs) < 2 {
		return
	}
	prev, prevOK := b.settingsAt(p, vs[0])
	for k := 1; k < len(vs); k++ {
		cur, ok := b.settingsAt(p, vs[k])
		if ok && prevOK {
			d := compareSettings(prev, cur)
			if d != nil {
				d.Component, d.Subject, d.Class = c.ID, p, Verified
				d.Basis = "both versions are sealed artifacts of this file; content hashes differ"
				d.From = Snapshot{Label: roundsLabel(vs[k-1].rounds), Source: "round", Round: vs[k-1].rounds[0], Time: vs[k-1].rec.CollectedUTC, TimeSource: TimeCollection, SHA256: vs[k-1].rec.ArtifactID, Ref: refOf(vs[k-1].rec)}
				d.To = Snapshot{Label: roundsLabel(vs[k].rounds), Source: "round", Round: vs[k].rounds[0], Time: vs[k].rec.CollectedUTC, TimeSource: TimeCollection, SHA256: vs[k].rec.ArtifactID, Ref: refOf(vs[k].rec)}
				b.addDrift(*d)
			}
		}
		prev, prevOK = cur, ok
	}
}

// settingsAt reads one version as settings plus the MCP servers it defines.
func (b *builder) settingsAt(p string, v fileVersion) (settingsView, bool) {
	data, err := b.readBlob(v.rec)
	if err != nil {
		b.note("%s %s: not read: %v", p, roundsLabel(v.rounds), err)
		return settingsView{}, false
	}
	sv, err := parseSettings(data)
	if err != nil && !strings.HasSuffix(p, ".toml") && !strings.HasSuffix(p, ".yaml") && !strings.HasSuffix(p, ".yml") {
		b.note("%s %s: %v", p, roundsLabel(v.rounds), err)
	}
	if inv, ok := mcpaudit.ParseArtifact(p, data); ok && inv != nil {
		names := map[string]bool{}
		for _, s := range inv.Servers {
			names[s.Name] = true
		}
		sv.MCPServers = sortedKeys(names)
	}
	return sv, err == nil || len(sv.MCPServers) > 0
}

func compareSettings(old, cur settingsView) *Drift {
	d := &Drift{Kind: "agent_settings"}
	for _, x := range newItems(old.Allow, cur.Allow) {
		d.Added = append(d.Added, "allow "+x)
		d.Expansion = append(d.Expansion, "new allow rule "+x)
	}
	for _, x := range newItems(cur.Allow, old.Allow) {
		d.Removed = append(d.Removed, "allow "+x)
	}
	for _, x := range newItems(cur.Deny, old.Deny) {
		d.Removed = append(d.Removed, "deny "+x)
		d.Expansion = append(d.Expansion, "deny rule removed "+x)
	}
	for _, x := range newItems(old.Deny, cur.Deny) {
		d.Added = append(d.Added, "deny "+x)
	}
	for _, x := range newItems(cur.Ask, old.Ask) {
		d.Removed = append(d.Removed, "ask "+x)
		d.Expansion = append(d.Expansion, "ask rule removed "+x)
	}
	for _, x := range newItems(old.Ask, cur.Ask) {
		d.Added = append(d.Added, "ask "+x)
	}
	if old.DefaultMode != cur.DefaultMode {
		d.Changed = append(d.Changed, fmt.Sprintf("defaultMode %q → %q", old.DefaultMode, cur.DefaultMode))
		if cur.DefaultMode == "bypassPermissions" || cur.DefaultMode == "acceptEdits" || cur.DefaultMode == "auto" {
			d.Expansion = append(d.Expansion, "defaultMode "+cur.DefaultMode)
		}
	}
	for _, ev := range sortedKeys(cur.Hooks) {
		for _, h := range newItems(old.Hooks[ev], cur.Hooks[ev]) {
			d.Added = append(d.Added, "hook "+ev+": "+trim(h, 120))
			d.Expansion = append(d.Expansion, "new "+ev+" hook "+trim(h, 120))
		}
	}
	for _, ev := range sortedKeys(old.Hooks) {
		for _, h := range newItems(cur.Hooks[ev], old.Hooks[ev]) {
			d.Removed = append(d.Removed, "hook "+ev+": "+trim(h, 120))
		}
	}
	if !old.EnableAllProject && cur.EnableAllProject {
		d.Changed = append(d.Changed, "enableAllProjectMcpServers false → true")
		d.Expansion = append(d.Expansion, "every project MCP server trusted (enableAllProjectMcpServers)")
	}
	for _, x := range newItems(old.EnabledMCPJSON, cur.EnabledMCPJSON) {
		d.Added = append(d.Added, "enabledMcpjsonServers "+x)
		d.Expansion = append(d.Expansion, "project MCP server enabled "+x)
	}
	for _, x := range newItems(old.MCPServers, cur.MCPServers) {
		d.Added = append(d.Added, "MCP server "+x)
		d.Expansion = append(d.Expansion, "new MCP server "+x)
	}
	for _, x := range newItems(cur.MCPServers, old.MCPServers) {
		d.Removed = append(d.Removed, "MCP server "+x)
	}
	if len(d.Added)+len(d.Removed)+len(d.Changed) == 0 {
		return nil
	}
	return d
}

// cachedManifestDrift compares the tool declarations each cached tool
// manifest file held across rounds, per server name.
func (b *builder) cachedManifestDrift() {
	if b.in.Store == nil {
		return
	}
	var files []string
	for p, rs := range b.recs {
		if len(rs) < 2 || mcpaudit.IsConfigPath(p) {
			continue
		}
		switch rs[0].ArtifactType {
		case "product_config", "product_state", "debug_logs", "managed_config":
			files = append(files, p)
		}
	}
	sort.Strings(files)
	if len(files) > maxCacheFiles {
		b.omitted["cached_manifest_files"] += len(files) - maxCacheFiles
		files = files[:maxCacheFiles]
	}
	for _, p := range files {
		vs := b.versions(p)
		if len(vs) < 2 {
			continue
		}
		type snap struct {
			v     fileVersion
			tools map[string][]mcpaudit.Tool
		}
		var snaps []snap
		for _, v := range vs {
			if v.rec.Size > maxBlob {
				continue
			}
			data, err := b.readBlob(v.rec)
			if err != nil || !bytes.Contains(data, []byte("inputSchema")) {
				continue
			}
			snaps = append(snaps, snap{v, mcpaudit.ServerTools(data)})
		}
		for k := 1; k < len(snaps); k++ {
			prev, cur := snaps[k-1], snaps[k]
			names := map[string]bool{}
			for n := range prev.tools {
				names[n] = true
			}
			for n := range cur.tools {
				names[n] = true
			}
			for _, n := range sortedKeys(names) {
				d := compareServers(mcpaudit.Server{Name: n, Tools: prev.tools[n]}, mcpaudit.Server{Name: n, Tools: cur.tools[n]})
				if d == nil {
					continue
				}
				subject := n
				if subject == "" {
					subject = path.Base(p)
				}
				cid := b.mcpByName(n)
				d.Component, d.Subject, d.Class = cid, subject, Verified
				d.Basis = "both versions are sealed artifacts of this cached tool manifest; definition hashes differ"
				d.From = Snapshot{Label: "cached manifest " + roundsLabel(prev.v.rounds), Source: "cached_manifest", Round: prev.v.rounds[0], Time: prev.v.rec.CollectedUTC, TimeSource: TimeCollection, SHA256: prev.v.rec.ArtifactID, Ref: refOf(prev.v.rec)}
				d.To = Snapshot{Label: "cached manifest " + roundsLabel(cur.v.rounds), Source: "cached_manifest", Round: cur.v.rounds[0], Time: cur.v.rec.CollectedUTC, TimeSource: TimeCollection, SHA256: cur.v.rec.ArtifactID, Ref: refOf(cur.v.rec)}
				b.addDrift(*d)
			}
		}
	}
}

// mcpByName returns the id of the single configured server with a name,
// or "" when none or several carry it.
func (b *builder) mcpByName(name string) string {
	id := ""
	for _, c := range b.rep.Components {
		if c.Kind == KindMCP && c.Name == name && !c.Observed {
			if id != "" {
				return ""
			}
			id = c.ID
		}
	}
	return id
}

// mcpCount is how many configured servers carry a name.
func (b *builder) mcpCount(name string) int {
	n := 0
	for _, c := range b.rep.Components {
		if c.Kind == KindMCP && c.Name == name && !c.Observed {
			n++
		}
	}
	return n
}
