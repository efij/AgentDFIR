package mcpaudit

import (
	"strings"
)

// wellKnownMCP lists widely installed MCP server packages. A package that is
// one of these, or lives in one of their scopes, never fires; a package
// that is almost one of these does.
//
// This catches the look-alike of an MCP server. It would not have caught
// SANDWORM_MODE (February 2026), which squatted general npm packages
// (`suport-color`, `claud-code`) and injected its MCP server afterwards —
// that campaign is covered by the incident IOC pack (`agentdfir hunt`).
var wellKnownMCP = []string{
	// npm
	"@modelcontextprotocol/server-filesystem", "@modelcontextprotocol/server-github", "@modelcontextprotocol/server-memory",
	"@modelcontextprotocol/server-everything", "@modelcontextprotocol/server-sequential-thinking", "@modelcontextprotocol/server-puppeteer",
	"@modelcontextprotocol/server-brave-search", "@modelcontextprotocol/server-postgres", "@modelcontextprotocol/server-slack",
	"@modelcontextprotocol/server-gdrive", "@modelcontextprotocol/server-google-maps", "@modelcontextprotocol/inspector",
	"@playwright/mcp", "@upstash/context7-mcp", "@supabase/mcp-server-supabase", "@stripe/mcp", "@notionhq/notion-mcp-server",
	"@browsermcp/mcp", "mcp-remote", "@sentry/mcp-server", "@cloudflare/mcp-server-cloudflare", "firecrawl-mcp", "exa-mcp-server",
	"@21st-dev/magic", "figma-developer-mcp", "chrome-devtools-mcp", "@executeautomation/playwright-mcp-server", "tavily-mcp",
	"@apify/actors-mcp-server", "@heroku/mcp-server", "@azure/mcp", "@shopify/dev-mcp",
	// PyPI (uvx / pipx)
	"mcp-server-fetch", "mcp-server-git", "mcp-server-time", "mcp-server-sqlite",
}

// canonicalScopes are npm scopes owned by the publishers above.
var canonicalScopes = func() map[string]bool {
	m := map[string]bool{}
	for _, p := range wellKnownMCP {
		if strings.HasPrefix(p, "@") {
			m[p[:strings.Index(p, "/")]] = true
		}
	}
	return m
}()

var knownSet = func() map[string]bool {
	m := map[string]bool{}
	for _, p := range wellKnownMCP {
		m[p] = true
	}
	return m
}()

// pkgName strips a version or range from a package spec.
func pkgName(spec string) string {
	s := strings.ToLower(strings.TrimSpace(spec))
	if i := strings.Index(s, "=="); i > 0 {
		s = s[:i]
	}
	if strings.HasPrefix(s, "@") {
		if i := strings.Index(s[1:], "@"); i >= 0 {
			s = s[:i+1]
		}
	} else if i := strings.Index(s, "@"); i > 0 {
		s = s[:i]
	}
	return s
}

func splitScope(n string) (scope, name string) {
	if strings.HasPrefix(n, "@") {
		if i := strings.Index(n, "/"); i > 0 {
			return n[:i], n[i+1:]
		}
	}
	return "", n
}

// fold normalizes the confusions typosquats rely on: separators, digit
// look-alikes, "rn" for "m", and PyPI's -_. equivalence.
func fold(s string) string {
	s = strings.NewReplacer("-", "", "_", "", ".", "", "0", "o", "1", "l", "rn", "m", "vv", "w").Replace(strings.ToLower(s))
	return s
}

// typosquatOf returns the well-known package spec looks like, or "".
func typosquatOf(spec string) string {
	n := pkgName(spec)
	if n == "" || knownSet[n] || strings.HasPrefix(n, "git+") || strings.Contains(n, "://") {
		return ""
	}
	scope, name := splitScope(n)
	if scope != "" && canonicalScopes[scope] {
		return ""
	}
	for _, k := range wellKnownMCP {
		ks, kn := splitScope(k)
		switch {
		case scope != ks && (name == kn || fold(name) == fold(kn)) && len(kn) >= 4:
			// same name, different (or dropped) scope: @modelcontextprotoco1/server-github,
			// modelcontextprotocol-server-github, @evil/mcp-remote
			return k
		case fold(n) == fold(k):
			return k
		case len(n) >= 6 && damerauLevenshtein(n, k) == 1:
			return k
		}
	}
	// Scope squats: @modelcontextprotocoI/…, @modelcontext-protocol/…
	if scope != "" {
		for s := range canonicalScopes {
			if fold(scope) == fold(s) || (len(scope) >= 6 && damerauLevenshtein(scope, s) == 1) {
				return s + "/" + name
			}
		}
	}
	return ""
}

// damerauLevenshtein is the optimal-string-alignment distance.
func damerauLevenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	if d := len(ra) - len(rb); d > 2 || d < -2 {
		return 3 // only distance 1 matters; skip the table
	}
	d := make([][]int, len(ra)+1)
	for i := range d {
		d[i] = make([]int, len(rb)+1)
		d[i][0] = i
	}
	for j := 0; j <= len(rb); j++ {
		d[0][j] = j
	}
	for i := 1; i <= len(ra); i++ {
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[len(ra)][len(rb)]
}
