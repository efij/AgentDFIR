package mcpaudit

import "testing"

func TestTyposquatOf(t *testing.T) {
	hits := map[string]string{
		"@modelcontextprotoco1/server-github":           "@modelcontextprotocol/server-github",
		"@modelcontextprotocol-org/server-memory@1.0.0": "@modelcontextprotocol/server-memory",
		"@evil/mcp-remote":                              "mcp-remote",
		"mcp-rernote":                                   "mcp-remote",
		"firecrawl-mpc":                                 "firecrawl-mcp",
		"@upstash/context7-mcp@1.0.0":                   "",
		"@playwright/mcp@latest":                        "",
		"mcp_server_fetch":                              "mcp-server-fetch",
		"mcp-server-fetch==2025.1.1":                    "",
		"@modelcontextprotocol/server-gitlab":           "", // sibling in the canonical scope
		"server-filesystem":                             "@modelcontextprotocol/server-filesystem",
		"my-company-mcp":                                "",
		"@acme/docs-mcp":                                "",
	}
	for spec, want := range hits {
		if got := typosquatOf(spec); got != want {
			t.Errorf("typosquatOf(%q) = %q, want %q", spec, got, want)
		}
	}
}

func TestPackageRefFlags(t *testing.T) {
	for args, want := range map[string]string{
		"--package=evil-pkg@1.0.0 legit":                 "evil-pkg@1.0.0",
		"-y -p evil legit":                               "evil",
		"--registry https://r.example -y some-mcp@2.0.0": "some-mcp@2.0.0",
	} {
		got, _ := packageRef("npx", splitArgs(args))
		if got != want {
			t.Errorf("npx %s → %q, want %q", args, got, want)
		}
	}
	got, pinned := packageRef("uvx", []string{"--from", "git+https://github.com/x/y", "tool"})
	if got != "git+https://github.com/x/y" || pinned {
		t.Errorf("uvx --from → %q pinned=%v", got, pinned)
	}
}

func splitArgs(s string) []string {
	var out []string
	cur := ""
	for _, c := range s + " " {
		if c == ' ' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(c)
	}
	return out
}

func TestGitPin(t *testing.T) {
	for spec, want := range map[string]bool{
		"git+https://user@github.com/org/a-very-long-repository-name-here.git":         false,
		"git+ssh://git@github.com/org/repo.git":                                        false,
		"git+https://github.com/org/repo.git#0123456789abcdef0123456789abcdef01234567": true,
	} {
		if _, got := pinOf("uvx", spec); got != want {
			t.Errorf("%s pinned=%v want %v", spec, got, want)
		}
	}
}
