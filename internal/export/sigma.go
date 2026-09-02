package export

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/internal/rulepack"
)

// --- Sigma ---
//
// Declarative rule packs convert to Sigma YAML so detections travel to
// Splunk/Sentinel/Elastic/etc. through the converters SOCs already run.
//
//	match.type "command"   → logsource category process_creation, field CommandLine
//	                          (portable to EDR/Sysmon/auditd process telemetry)
//	match.type "summary"   → logsource product agentdfir / service transcript, field summary
//	match.type "config"    → logsource product agentdfir / service config, field content
//	match.type "transcript"→ logsource product agentdfir / service transcript, field content
//
// Built-in Go rules are stateful/multi-event and are not expressible as
// Sigma selections; only pack rules are exported (documented limitation).

var sigmaTagRe = regexp.MustCompile(`^(T\d{4})(?:\.(\d{3}))?$`)

// WriteSigmaDir writes one YAML file per rule into dir and returns the
// written paths in pack/rule order.
func WriteSigmaDir(packs []rulepack.Pack, dir string) ([]string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	var written []string
	for _, p := range packs {
		for _, r := range p.Rules {
			// Pack-prefixed so two packs sharing a rule ID never overwrite each other.
			name := strings.ToLower(p.Pack+"--"+strings.ReplaceAll(r.ID, "_", "-")) + ".yml"
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, []byte(SigmaYAML(p, r)), 0o600); err != nil {
				return written, err
			}
			written = append(written, path)
		}
	}
	return written, nil
}

// SigmaYAML renders one rule as a Sigma document.
func SigmaYAML(p rulepack.Pack, r rulepack.Rule) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }

	w("title: %s\n", yq(r.Title))
	w("id: %s\n", deterministicUUID("sigma", p.Pack, r.ID))
	w("name: %s\n", yq(r.ID))
	w("status: experimental\n")
	w("description: %s\n", yq(r.Description))
	if len(r.References) > 0 {
		w("references:\n")
		for _, ref := range r.References {
			w("  - %s\n", yq(ref))
		}
	}
	w("author: %s\n", yq("AgentDFIR rule pack "+p.Pack+" v"+p.Version))
	w("date: %s\n", time.Now().UTC().Format("2006-01-02"))
	tags := []string{"agentdfir." + strings.ToLower(r.Match.Type)}
	if m := sigmaTagRe.FindStringSubmatch(r.MitreATTACK); m != nil {
		tags = append(tags, "attack."+strings.ToLower(m[1]))
		if m[2] != "" {
			tags = append(tags, "attack."+strings.ToLower(m[1])+"."+m[2])
		}
	}
	if r.MitreATLAS != "" {
		tags = append(tags, "atlas."+strings.ToLower(strings.ReplaceAll(r.MitreATLAS, ".", "_")))
	}
	w("tags:\n")
	for _, t := range tags {
		w("  - %s\n", t)
	}

	w("logsource:\n")
	field := "content"
	switch r.Match.Type {
	case "command":
		w("  category: process_creation\n")
		w("  product: agentdfir\n")
		field = "CommandLine"
	case "summary":
		w("  product: agentdfir\n  service: transcript\n")
		field = "summary"
	case "config":
		w("  product: agentdfir\n  service: config\n")
	default:
		w("  product: agentdfir\n  service: transcript\n")
	}

	w("detection:\n  selection:\n")
	if len(r.Match.Contains) > 0 {
		w("    %s|contains:\n", field)
		for _, c := range r.Match.Contains {
			w("      - %s\n", yq(c))
		}
	}
	if r.Match.Regex != "" {
		w("    %s|re: %s\n", field, yq(r.Match.Regex))
	}
	w("  condition: selection\n")
	if r.FalsePositive != "" {
		w("falsepositives:\n  - %s\n", yq(r.FalsePositive))
	} else {
		w("falsepositives:\n  - Unknown\n")
	}
	w("level: %s\n", sigmaLevel(r.Severity))
	return b.String()
}

// yq renders a YAML double-quoted scalar. JSON string encoding is a
// valid YAML double-quoted scalar, which keeps evidence-derived text
// (quotes, backslashes, control characters) from breaking the document.
func yq(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func sigmaLevel(sev string) string {
	switch sev {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	default:
		return "informational"
	}
}
