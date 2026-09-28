package detect

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/efij/AgentDFIR/v3/internal/decode"
	"github.com/efij/AgentDFIR/v3/internal/netdest"
	"github.com/efij/AgentDFIR/v3/internal/schema"
	"github.com/efij/AgentDFIR/v3/internal/shellshape"
)

// githubRepoCreateRe: creating a repository or gist from the command line.
// Shai-Hulud, s1ngularity and the keyv wave all exfiltrated to repositories
// they created with a stolen token — and github.com is on every allowlist,
// so the destination check alone never fires on it.
var githubRepoCreateRe = regexp.MustCompile(`(?i)(\bgh\s+(repo\s+create|gist\s+create|api\s+[^|;&]*(user/repos|/gists|orgs/[^/\s]+/repos)[^|;&]*(-X\s*POST|--method\s+POST|-f\s|--field\s|-F\s))|\bcurl\b[^|;&]*api\.github\.com/(user/repos|gists|orgs/[^/\s"']+/repos)\b[^|;&]*(-X\s*POST|-d\b|--data|-F\b))`)

// egressFindings covers EGRESS_VIA_TRUSTED_SERVICE and
// GITHUB_EXFIL_REPO_CREATE for one tool call. sensitive says the session
// touched credentials or staged data earlier; seen dedupes per
// session+destination.
func egressFindings(ev schema.Event, sensitive bool, seen map[string]bool) []schema.Finding {
	cmd := ev.FullCommand()
	if cmd == "" {
		return nil
	}
	// The command as written, then whatever it decodes and runs: a
	// destination inside a base64+gzip payload is still where data went.
	cmd = shellshape.StripHeredocs(cmd)
	out := egressOne(ev, cmd, "", sensitive, seen)
	if decode.ExecutesDecoded(cmd) {
		for _, r := range decode.FindInCommand(cmd) {
			out = append(out, egressOne(ev, r.Text, " (inside a decoded "+r.ChainString()+" payload)", sensitive, seen)...)
		}
	}
	if githubRepoCreateRe.MatchString(shellshape.Strip(cmd)) {
		// On a real machine every repo creation was the user's own; the
		// signal is a public repo created in a session that touched secrets.
		sev := "LOW"
		if sensitive && strings.Contains(cmd, "--public") {
			sev = "MEDIUM"
		}
		out = append(out, schema.Finding{
			RuleID: "GITHUB_EXFIL_REPO_CREATE", Severity: sev,
			Title:       "Agent Created a GitHub Repository or Gist",
			Description: "Agent command creates a repository or gist. Shai-Hulud, s1ngularity and the keyv wave exfiltrated stolen secrets into repositories created this way; github.com is allowlisted, so only the action shows it.",
			SessionID:   ev.SessionID, AgentID: ev.AgentID, EvidenceRefs: []string{ref(ev)},
			Status: ev.Corroboration, Endpoint: schema.StateUnknown, MitreATTACK: "T1567.001", MitreATLAS: "AML.T0086",
			FalsePositive: "Creating a repo for a new project is normal when the user asked for it; check the prompt and the repo's contents.",
		})
	}
	return out
}

func egressOne(ev schema.Event, cmd, where string, sensitive bool, seen map[string]bool) []schema.Finding {
	var out []schema.Finding
	outbound := netdest.IsOutbound(cmd)
	upload := netdest.IsUpload(cmd)
	for _, d := range netdest.Extract(cmd) {
		cat := netdest.Category(d)
		if cat == "" || netdest.CoveredByPack(cat) || !outbound {
			continue
		}
		if cat == "serverless-edge" && !upload {
			continue // people deploy their own apps there; only data going up is interesting
		}
		if cat == "blockchain-rpc" && !sensitive {
			continue // web3 development calls RPC nodes all day; C2-over-contract matters after credential access
		}
		key := ev.SessionID + "\x00" + netdest.Host(d)
		if seen[key] {
			continue
		}
		seen[key] = true
		sev, tech := "MEDIUM", "T1102" // Web Service (C2 over a trusted service)
		why := "outbound request"
		if upload || sensitive {
			sev, tech = "HIGH", "T1567" // Exfiltration Over Web Service
			switch {
			case upload && sensitive:
				why = "upload-shaped request after credential access in the same session"
			case upload:
				why = "upload-shaped request"
			default:
				why = "request after credential access in the same session"
			}
		}
		out = append(out, schema.Finding{
			RuleID: "EGRESS_VIA_TRUSTED_SERVICE", Severity: sev,
			Title:       "Traffic Through a Trusted Service Used for Exfiltration",
			Description: fmt.Sprintf("Agent command sends an %s to %s (%s)%s. Services of this class carried exfiltration and C2 in 2025–2026 agent incidents because nothing blocks them.", why, netdest.Host(d), cat, where),
			SessionID:   ev.SessionID, AgentID: ev.AgentID, EvidenceRefs: []string{ref(ev)},
			Related: []string{"category: " + cat},
			Status:  ev.Corroboration, Endpoint: schema.StateUnknown, MitreATTACK: tech, MitreATLAS: "AML.T0086",
			FalsePositive: "Web3 developers call RPC nodes and people expand short links; read what was sent.",
		})
	}
	return out
}
