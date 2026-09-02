package mcpaudit

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/efij/AgentDFIR/internal/detect"
	"github.com/efij/AgentDFIR/internal/schema"
)

// Findings derived from the inventory. Rule IDs are distinct from the
// text-match rules in the community pack (MCP_UNPINNED_PACKAGE etc.) —
// these are structural, parse-based and lower-noise; the pack rules stay
// for Sigma export and hosts without the audit.

var (
	remoteFetchRe = regexp.MustCompile(`(?i)(curl|wget|iwr|invoke-webrequest|irm)\b.*(\||;|&&)\s*(sh|bash|zsh|node|python|pwsh|powershell)\b|\b(git\+https?|https?://[^\s"']+\.(sh|py|js|ps1))\b`)
	shellWrapRe   = regexp.MustCompile(`^(sh|bash|zsh|cmd(\.exe)?|powershell(\.exe)?|pwsh)$`)
	plainHTTPRe   = regexp.MustCompile(`(?i)^(http|ws)://`)
	loopbackRe    = regexp.MustCompile(`(?i)^(http|ws)://(localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)([:/]|$)`)
)

func ref(s Server) string {
	r := s.ConfigPath + " (server " + s.Name
	if s.Project != "" {
		r += ", project " + s.Project
	}
	return r + ")"
}

func finding(id, sev, title, desc string, s Server, attack, atlas, fp string) schema.Finding {
	return schema.Finding{
		RuleID: id, Severity: sev, Title: title, Description: desc,
		EvidenceRefs: []string{ref(s)},
		Status:       schema.StateObserved, // configuration on disk is observed fact
		Endpoint:     schema.StateUnknown,
		MitreATTACK:  attack, MitreATLAS: atlas, FalsePositive: fp,
		Related: []string{"host: " + s.Host, "transport: " + s.Transport},
	}
}

// Evaluate runs every structural rule over the inventory.
func Evaluate(inv *Inventory) []schema.Finding {
	var out []schema.Finding
	byName := map[string][]Server{}
	for _, s := range inv.Servers {
		byName[s.Name] = append(byName[s.Name], s)
		if s.Disabled {
			continue
		}
		if s.PackageMgr != "" && s.Package != "" && !s.Pinned {
			out = append(out, finding("UNPINNED_MCP_PACKAGE", "HIGH", "MCP Server Package Not Pinned",
				fmt.Sprintf("Server %q is launched with %s from package %q without an exact version. Every start resolves the newest publish; a compromised or hijacked package version runs with the agent's tool access.", s.Name, s.PackageMgr, s.Package),
				s, "T1195.002", "AML.T0010", "Pin an exact version (pkg@1.2.3) and hash-verify; many docs copy the unpinned form."))
		}
		if s.PackageMgr != "" && s.Package == "" {
			out = append(out, finding("UNPINNED_MCP_PACKAGE", "MEDIUM", "MCP Server Package Runner Without Recognizable Package",
				fmt.Sprintf("Server %q runs %s but no package reference could be parsed from its arguments (%v).", s.Name, s.PackageMgr, s.Args),
				s, "T1195.002", "", "Unusual invocation forms; inspect the args."))
		}
		if s.URL != "" && plainHTTPRe.MatchString(s.URL) && !loopbackRe.MatchString(s.URL) {
			out = append(out, finding("INSECURE_MCP_TRANSPORT", "HIGH", "MCP Server Over Plaintext Transport",
				fmt.Sprintf("Server %q is reached at %s. Tool calls, results and any auth headers cross the network unencrypted and can be read or altered in transit.", s.Name, s.URL),
				s, "T1557", "", "Trusted internal networks sometimes run plaintext; still verify — tool results are model context."))
		}
		if len(s.AutoAllow) > 0 {
			sev := "MEDIUM"
			for _, a := range s.AutoAllow {
				if a == "*" {
					sev = "HIGH"
				}
			}
			out = append(out, finding("MCP_AUTO_APPROVE", sev, "MCP Tools Auto-Approved Without Human Confirmation",
				fmt.Sprintf("Server %q has tools pre-approved (%s). A poisoned tool description or injected instruction can drive these tools with no prompt to the user.", s.Name, strings.Join(s.AutoAllow, ", ")),
				s, "T1548", "AML.T0053", "Deliberate for read-only tools in trusted setups; check what the approved tools can do."))
		}
		if len(s.SecretEnv) > 0 {
			out = append(out, finding("MCP_SECRET_IN_CONFIG", "MEDIUM", "Credential Material Inline in MCP Server Config",
				fmt.Sprintf("Server %q carries credential-shaped values in its environment (%s). Config files are collected, synced and backed up in the clear; values are not recorded by this audit.", s.Name, strings.Join(s.SecretEnv, ", ")),
				s, "T1552.001", "", "Some servers require inline tokens; prefer a secret manager or OS keychain reference."))
		}
		cmdline := s.Command + " " + strings.Join(s.Args, " ")
		if remoteFetchRe.MatchString(cmdline) {
			out = append(out, finding("MCP_REMOTE_FETCH_COMMAND", "CRITICAL", "MCP Server Command Fetches and Executes Remote Code",
				fmt.Sprintf("Server %q starts by downloading code at launch (%s). Whatever the remote host serves runs with the agent's privileges every session.", s.Name, trimCmd(cmdline)),
				s, "T1105", "AML.T0010", "Rare in legitimate configs; installers belong outside the MCP launch command."))
		} else if shellWrapRe.MatchString(strings.ToLower(baseOf(s.Command))) && len(s.Args) > 0 && (s.Args[0] == "-c" || strings.EqualFold(s.Args[0], "/c")) {
			out = append(out, finding("MCP_REMOTE_FETCH_COMMAND", "MEDIUM", "MCP Server Launched Through a Shell Wrapper",
				fmt.Sprintf("Server %q is launched via %s -c, hiding the real program behind shell parsing (%s).", s.Name, baseOf(s.Command), trimCmd(cmdline)),
				s, "T1059", "", "Used to set env or cd before exec; inspect the wrapped command."))
		}
		if s.Scope == "project" {
			out = append(out, finding("MCP_PROJECT_SCOPED_SERVER", "INFO", "Project-Scoped MCP Server",
				fmt.Sprintf("Server %q is defined by a project, not the user. Anyone who can commit to that repository controls what this agent loads.", s.Name),
				s, "T1195", "", "Normal for team repos; review who can change the file."))
		}
		for _, t := range s.Tools {
			if ph, ok := detect.InjectionPhrase(t.Description); ok {
				out = append(out, finding("MCP_TOOL_DESCRIPTION_POISONING", "CRITICAL", "Instruction Payload in MCP Tool Description",
					fmt.Sprintf("Tool %q of server %q carries an instruction-override phrase (%q) in its description. Tool descriptions are injected into the model's context on every session — this is the tool-poisoning delivery path, present before any call is made.", t.Name, s.Name, ph),
					s, "", "AML.T0053", "Tools that document prompt-injection defenses can match; read the full description."))
			}
		}
	}
	// Name collisions: same name, different identity, across configs/hosts.
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		list := byName[n]
		if len(list) < 2 {
			continue
		}
		ids := map[string]Server{}
		for _, s := range list {
			ids[s.Identity()] = s
		}
		if len(ids) < 2 {
			continue
		}
		var where []string
		for _, s := range list {
			where = append(where, fmt.Sprintf("%s:%s → %s", s.Host, s.ConfigPath, s.Identity()))
		}
		f := finding("MCP_NAME_COLLISION", "MEDIUM", "Same MCP Server Name Resolves to Different Programs",
			fmt.Sprintf("Server name %q is defined %d times with different commands/URLs. The agent's tools and the analyst's transcripts refer to the name only — one definition shadows or impersonates another.", n, len(list)),
			list[0], "T1036", "AML.T0053", "Project overrides of a user-level server are common; confirm both definitions are intended.")
		f.Related = where
		var refs []string
		for _, s := range list {
			refs = append(refs, ref(s))
		}
		f.EvidenceRefs = refs
		out = append(out, f)
	}
	// Host-level trust switches.
	for _, hs := range inv.Settings {
		base := Server{Host: hs.Host, ConfigPath: hs.ConfigPath, Name: "(host settings)", Transport: "-"}
		if hs.EnableAllProjectMCP {
			out = append(out, finding("MCP_ALL_PROJECT_SERVERS_TRUSTED", "HIGH", "All Project MCP Servers Auto-Trusted",
				"enableAllProjectMcpServers is true: any repository's .mcp.json is loaded without confirmation. Cloning a hostile repo installs its MCP servers into the agent.",
				base, "T1195", "AML.T0010", "Convenient in single-owner environments; dangerous wherever untrusted repos are opened."))
		}
		if len(hs.WildcardMCPPermissions) > 0 {
			out = append(out, finding("MCP_WILDCARD_TOOL_PERMISSION", "MEDIUM", "Wildcard Permission Grants MCP Tools Without Prompting",
				fmt.Sprintf("permissions.allow contains %s — MCP tools matching the pattern run without confirmation.", strings.Join(hs.WildcardMCPPermissions, ", ")),
				base, "T1548", "", "Teams allow specific trusted servers this way; the risk is the breadth of the pattern."))
		}
	}
	return out
}

func trimCmd(s string) string {
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > 200 {
		return string(r[:200]) + "…"
	}
	return s
}

func baseOf(cmd string) string {
	if i := strings.LastIndexAny(cmd, `/\`); i >= 0 {
		return cmd[i+1:]
	}
	return cmd
}
