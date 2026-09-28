package mcpaudit

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v3/internal/schema"
	"github.com/efij/AgentDFIR/v3/internal/version"
)

// Baseline is a known-good snapshot of the MCP inventory. Comparing a
// later audit against it converts "here is what's configured" into
// "here is what changed" — the question that matters after an incident.
type Baseline struct {
	CreatedUTC string            `json:"created_utc"`
	Tool       string            `json:"tool"`
	Source     string            `json:"source"`
	Servers    map[string]Server `json:"servers"` // by Key()
	Settings   []HostSettings    `json:"host_settings,omitempty"`
}

// WriteBaseline snapshots an inventory.
func WriteBaseline(inv *Inventory, path string) error {
	b := Baseline{CreatedUTC: time.Now().UTC().Format(time.RFC3339), Tool: "agentdfir " + version.Version,
		Source: inv.Source, Servers: map[string]Server{}, Settings: inv.Settings}
	for _, s := range inv.Servers {
		b.Servers[s.Key()] = s
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

// LoadBaseline reads a snapshot.
func LoadBaseline(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("baseline: %w", err)
	}
	return &b, nil
}

// Compare reports servers added, removed or changed since the baseline.
func Compare(inv *Inventory, b *Baseline) []schema.Finding {
	var out []schema.Finding
	now := map[string]Server{}
	for _, s := range inv.Servers {
		now[s.Key()] = s
	}
	keys := map[string]bool{}
	for k := range now {
		keys[k] = true
	}
	for k := range b.Servers {
		keys[k] = true
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	for _, k := range sorted {
		cur, inNow := now[k]
		old, inOld := b.Servers[k]
		switch {
		case inNow && !inOld:
			out = append(out, finding("MCP_SERVER_ADDED", "MEDIUM", "MCP Server Not in Baseline",
				fmt.Sprintf("Server %q (%s) is configured now but absent from the baseline of %s.", cur.Name, cur.Identity(), b.CreatedUTC),
				cur, "T1195.002", "AML.T0010", "Legitimate new tooling; confirm who added it and when."))
		case !inNow && inOld:
			out = append(out, finding("MCP_SERVER_REMOVED", "LOW", "Baseline MCP Server Missing",
				fmt.Sprintf("Server %q (%s) was in the baseline of %s and is no longer configured.", old.Name, old.Identity(), b.CreatedUTC),
				old, "", "", "Cleanup is normal; note it for the timeline."))
		default:
			var diffs []string
			if cur.Identity() != old.Identity() {
				diffs = append(diffs, "command/url: "+old.Identity()+" → "+cur.Identity())
			}
			if cur.SHA256 != "" && old.SHA256 != "" && cur.SHA256 != old.SHA256 {
				diffs = append(diffs, "binary sha256: "+short(old.SHA256)+" → "+short(cur.SHA256))
			}
			if cur.Package != old.Package {
				diffs = append(diffs, "package: "+old.Package+" → "+cur.Package)
			}
			if fmt.Sprint(cur.EnvKeys) != fmt.Sprint(old.EnvKeys) {
				diffs = append(diffs, fmt.Sprintf("env keys: %v → %v", old.EnvKeys, cur.EnvKeys))
			}
			if fmt.Sprint(cur.AutoAllow) != fmt.Sprint(old.AutoAllow) {
				diffs = append(diffs, fmt.Sprintf("auto-allow: %v → %v", old.AutoAllow, cur.AutoAllow))
			}
			if cur.EnvSHA256 != "" && old.EnvSHA256 != "" && cur.EnvSHA256 != old.EnvSHA256 && fmt.Sprint(cur.EnvKeys) == fmt.Sprint(old.EnvKeys) {
				diffs = append(diffs, "env values changed (same keys): "+short(old.EnvSHA256)+" → "+short(cur.EnvSHA256))
			}
			out = append(out, compareTools(cur, old, b.CreatedUTC)...)
			if len(diffs) == 0 {
				continue
			}
			sev := "HIGH"
			if len(diffs) == 1 && (len(cur.EnvKeys) != len(old.EnvKeys) || fmt.Sprint(cur.AutoAllow) != fmt.Sprint(old.AutoAllow)) {
				sev = "MEDIUM"
			}
			f := finding("MCP_SERVER_CHANGED", sev, "MCP Server Definition Changed Since Baseline",
				fmt.Sprintf("Server %q differs from the baseline of %s.", cur.Name, b.CreatedUTC),
				cur, "T1195.002", "AML.T0010", "Upgrades change binaries and packages; verify the change was intended.")
			f.Related = append(f.Related, diffs...)
			out = append(out, f)
		}
	}
	return out
}

// compareTools reports tool definitions that changed or appeared since the
// baseline — the MCP rug-pull: a server approved with one set of tool
// descriptions later serves another. Only definitions the host recorded
// can be compared; a baseline written before v2.8 has no fingerprints and
// yields nothing.
func compareTools(cur, old Server, created string) []schema.Finding {
	if len(old.Tools) == 0 && len(cur.Tools) == 0 {
		return nil
	}
	before := map[string]string{}
	hashed := false
	for _, t := range old.Tools {
		before[t.Name] = t.DefSHA256
		hashed = hashed || t.DefSHA256 != ""
	}
	if !hashed {
		return nil
	}
	var changed, added []string
	for _, t := range cur.Tools {
		h, ok := before[t.Name]
		switch {
		case !ok:
			added = append(added, t.Name)
		case h != "" && t.DefSHA256 != "" && h != t.DefSHA256:
			changed = append(changed, t.Name)
		}
	}
	var out []schema.Finding
	if len(changed) > 0 {
		f := finding("MCP_TOOL_DEFINITION_CHANGED", "HIGH", "MCP Tool Definition Changed Since Baseline",
			fmt.Sprintf("Server %q now declares %d tool(s) whose definition differs from the baseline of %s: %s. A tool approved once and changed later is the MCP rug-pull; read the new descriptions and parameter schemas.", cur.Name, len(changed), created, strings.Join(changed, ", ")),
			cur, "T1195.002", "AML.T0110", "Server upgrades legitimately reword tools; diff the definitions.")
		out = append(out, f)
	}
	if len(added) > 0 {
		out = append(out, finding("MCP_TOOL_ADDED", "LOW", "MCP Server Declares New Tools Since Baseline",
			fmt.Sprintf("Server %q declares tool(s) absent from the baseline of %s: %s.", cur.Name, created, strings.Join(added, ", ")),
			cur, "", "", "New server versions add tools; confirm the upgrade was intended."))
	}
	return out
}
