package mcpaudit

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/efij/AgentDFIR/internal/schema"
	"github.com/efij/AgentDFIR/internal/version"
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
