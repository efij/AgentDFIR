package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/efij/AgentDFIR/v4/internal/extinv"
	"github.com/efij/AgentDFIR/v4/internal/overlay"
	"github.com/efij/AgentDFIR/v4/internal/sanitize"
	"github.com/efij/AgentDFIR/v4/internal/schema"
)

const extensionsUsage = `usage:
  agentdfir extensions [<package-dir>] [flags]   IDE extensions, agent plugins and skills in a sealed package
  agentdfir extensions --path <home> [flags]     the same on a live host or offline home directory
                                                  (default: current user's home)
flags:
  --json          machine-readable output (inventory + findings)
  --out <file>    write the JSON report here (package mode default: <pkg>/detections/extensions.json)

Reads VS Code, VS Code Insiders, VSCodium, Cursor, Windsurf, Kiro, Trae and Positron extension
directories (and their remote-server twins), Claude Code plugins, marketplaces and skills, Gemini CLI
extensions and Codex skills. Read-only: nothing is executed, installed or contacted.
Known-bad extension IDs are matched by: agentdfir hunt --iocs <feed with vscode_extension indicators>
`

type extensionsReport struct {
	Inventory *extinv.Inventory `json:"inventory"`
	Findings  []schema.Finding  `json:"findings"`
}

func cmdExtensions(args []string) int {
	fs := flag.NewFlagSet("extensions", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, extensionsUsage) }
	home := fs.String("path", "", "live/offline home directory")
	asJSON := fs.Bool("json", false, "JSON output")
	out := fs.String("out", "", "JSON report path")
	pkg, rest := splitPositional(args)
	if err := fs.Parse(rest); err != nil || (pkg != "" && fs.NArg() != 0) || fs.NArg() > 1 {
		if err == flag.ErrHelp {
			return 0
		}
		fmt.Fprint(os.Stderr, extensionsUsage)
		return 2
	}
	if pkg == "" && fs.NArg() == 1 {
		pkg = fs.Arg(0)
	}
	var inv *extinv.Inventory
	switch {
	case pkg != "":
		if *home != "" {
			fmt.Fprintln(os.Stderr, "use either a package or --path, not both")
			return 2
		}
		i, err := extinv.ScanPackage(pkg)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		inv = i
	default:
		root := *home
		if root == "" {
			h, err := os.UserHomeDir()
			if err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				return 1
			}
			root = h
		}
		if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
			fmt.Fprintf(os.Stderr, "home %s is not a directory\n", sanitize.Terminal(root))
			return 2
		}
		inv = extinv.ScanHome(root)
	}
	findings := extinv.Evaluate(inv)
	sortFindings(findings)
	rep := extensionsReport{Inventory: inv, Findings: findings}

	dest := *out
	inPkg := false
	if dest == "" && pkg != "" {
		dest = filepath.Join(pkg, "detections", "extensions.json")
		inPkg = true
	}
	if dest != "" {
		_ = os.MkdirAll(filepath.Dir(dest), 0o700)
		var wErr error
		if inPkg {
			wErr = overlay.WriteJSON(dest, rep)
		} else {
			data, _ := json.MarshalIndent(rep, "", "  ")
			wErr = os.WriteFile(dest, append(data, '\n'), 0o600)
		}
		if wErr != nil {
			fmt.Fprintln(os.Stderr, "error:", wErr)
			return 1
		}
	}
	if *asJSON {
		data, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(data))
		return exitFor(findings)
	}
	printExtensions(rep, dest)
	return exitFor(findings)
}

func printExtensions(rep extensionsReport, dest string) {
	inv := rep.Inventory
	fmt.Printf("Extensions, plugins and skills — %s (%s mode)\n", sanitize.Terminal(inv.Source), inv.Mode)
	fmt.Printf("IDE extensions: %d   Agent plugins: %d   Marketplaces: %d   Skill/agent/command files: %d\n\n",
		len(inv.Extensions), len(inv.Plugins), len(inv.Marketplaces), len(inv.Skills))
	if len(inv.Extensions) > 0 {
		fmt.Printf("  %-16s %-40s %-14s %-9s %-20s %s\n", "EDITOR", "EXTENSION", "VERSION", "SOURCE", "INSTALLED", "FLAGS")
		for _, x := range inv.Extensions {
			var flags []string
			if !x.Present {
				flags = append(flags, "[not present]")
			} else if !x.Registered {
				flags = append(flags, "[unregistered]")
			}
			if x.StartupActivation {
				flags = append(flags, "[startup]")
			}
			if len(x.Contributes.MCPServerProviders) > 0 {
				flags = append(flags, "[mcp-provider]")
			}
			if len(x.Contributes.ChatParticipants) > 0 {
				flags = append(flags, "[chat]")
			}
			if len(x.Contributes.LanguageModelTools) > 0 {
				flags = append(flags, "[lm-tools]")
			}
			if x.Present && !x.CodeScanned {
				flags = append(flags, "[code not scanned]")
			}
			src := x.Source
			if src == "" {
				src = "-"
			}
			fmt.Printf("  %-16s %-40s %-14s %-9s %-20s %s\n", x.Editor, trimTo(sanitize.Terminal(x.ID), 40), trimTo(sanitize.Terminal(x.Version), 14),
				trimTo(sanitize.Terminal(src), 9), x.InstalledAt, strings.Join(flags, " "))
		}
		fmt.Println()
	}
	if len(inv.Plugins) > 0 {
		fmt.Printf("  %-12s %-44s %-14s %-6s %-5s %s\n", "HOST", "PLUGIN", "VERSION", "HOOKS", "MCP", "INSTALLED")
		for _, p := range inv.Plugins {
			name := p.Name
			if p.Marketplace != "" {
				name += "@" + p.Marketplace
			}
			reg := ""
			if !p.Registered {
				reg = " [not in registry]"
			}
			fmt.Printf("  %-12s %-44s %-14s %-6d %-5d %s%s\n", p.Host, trimTo(sanitize.Terminal(name), 44), trimTo(sanitize.Terminal(p.Version), 14),
				len(p.Hooks), len(p.MCPServers), p.InstalledAt, reg)
		}
		fmt.Println()
	}
	for _, m := range inv.Marketplaces {
		def := ""
		if m.Default {
			def = " (default)"
		}
		fmt.Printf("  marketplace: %s — %s %s%s\n", sanitize.Terminal(m.Name), m.Kind, sanitize.Terminal(m.Location), def)
	}
	if len(inv.Marketplaces) > 0 {
		fmt.Println()
	}
	for _, p := range inv.Problems {
		fmt.Printf("  problem: %s\n", sanitize.Terminal(p))
	}
	for _, u := range inv.Unsupported {
		fmt.Printf("  UNSUPPORTED: %s\n", sanitize.Terminal(u))
	}
	fmt.Printf("%d finding(s):\n", len(rep.Findings))
	for _, f := range rep.Findings {
		fmt.Printf("%s — %s [%s]\n", f.Severity, f.Title, f.RuleID)
		fmt.Printf("  Finding: %s\n", sanitize.Terminal(f.Description))
		for _, e := range f.EvidenceRefs {
			fmt.Printf("  Evidence: %s\n", sanitize.Terminal(e))
		}
		if f.MitreATTACK != "" || f.MitreATLAS != "" {
			fmt.Printf("  MITRE: %s %s\n", f.MitreATTACK, f.MitreATLAS)
		}
	}
	if dest != "" {
		fmt.Printf("\nreport written to %s\n", dest)
	}
}
