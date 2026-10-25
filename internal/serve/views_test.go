package serve

import (
	"regexp"
	"strings"
	"testing"
)

// TestInvestigationViewsReachable: every view added for the investigation
// layer is in the navigation and in the Cmd/Ctrl+K palette, has its
// renderer wired, and degrades to a "not in this case" answer with the
// regenerate command instead of failing.
func TestInvestigationViewsReachable(t *testing.T) {
	ui := string(uiHTML)
	for _, want := range []string{
		// navigation
		`data-view="coverage"`, `id="v-coverage"`, `const VIEWS=['overview','findings','activity','coverage','protect','more'];`,
		`data-m="conversations"`, `data-m="extensions"`, `data-m="lineage"`, `data-m="bookmarks"`, `data-m="compare"`,
		// palette entries (MORE_TABS feeds "Go to"; coverage is a top-level view)
		`['conversations','AI conversations',`, `['extensions','Extensions & agent plugins',`, `['lineage','Who did what',`,
		`['bookmarks','Bookmarks',`, `['compare','Compare cases',`, `['coverage','Coverage',`, `group:'Saved filters'`,
		// renderers and their API routes
		"if(name==='coverage') renderCoverage();", "renderConversations(box)", "renderExtensions(box)", "renderBookmarks(box)", "renderCompare(box)",
		"api('/api/coverage')", "'/api/lineage?finding='+f.index", "'/api/lineage?session='", "api('/api/conversations')", "api('/api/extensions')", "api('/api/compare')", "'/api/witness?event='",
		// graceful degradation
		"function notInCase(", "d.regenerate",
		// bookmarks reuse the hash-chained case file; saved filters are per viewer and guarded
		"post('pin',key,", "localStorage.getItem('adfir-saved-filters')", "localStorage.setItem('adfir-saved-filters'",
		// evidence classes and branch markers are said in words
		"Browser history — visits only, no content", "Provider export", "Other branch — regenerated or edited away",
		// truncated lineage is announced
		"'Truncated: '",
	} {
		if !strings.Contains(ui, want) {
			t.Errorf("ui.html lost %q", want)
		}
	}
	// Every localStorage access sits inside a try block on the same line.
	for _, line := range strings.Split(ui, "\n") {
		if strings.Contains(line, "localStorage.") && !strings.Contains(line, "try{") {
			t.Errorf("unguarded localStorage access: %.120s", strings.TrimSpace(line))
		}
	}
}

// TestUIStaysSelfContained: no external resource, no inline event handler
// attribute, and the page's own CSP meta tag is intact.
func TestUIStaysSelfContained(t *testing.T) {
	ui := string(uiHTML)
	if !strings.Contains(ui, `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'">`) {
		t.Error("CSP meta tag changed")
	}
	// The only absolute URL the page may contain is the SVG namespace.
	for _, m := range regexp.MustCompile(`(?i)(?:https?:)?//[a-z0-9.-]+\.[a-z]{2,}[^\s'"<>)]*`).FindAllString(ui, -1) {
		if m != "http://www.w3.org/2000/svg" && !strings.HasPrefix(m, "//www.w3.org/2000/svg") {
			t.Errorf("external URL in ui.html: %s", m)
		}
	}
	for _, re := range []string{`(?i)<script[^>]+src=`, `(?i)<link[^>]+href=`, `(?i)<(?:img|iframe|object|embed)\b`, `(?i)\son[a-z]+\s*=\s*["']`, `(?i)@import`, `(?i)url\(\s*['"]?https?:`} {
		if loc := regexp.MustCompile(re).FindStringIndex(ui); loc != nil {
			t.Errorf("%s matched: %.80s", re, ui[loc[0]:])
		}
	}
	// Evidence reaches the page as text: no innerHTML/outerHTML/insertAdjacentHTML/document.write.
	for _, bad := range []string{".innerHTML", ".outerHTML", "insertAdjacentHTML", "document.write"} {
		if strings.Contains(ui, bad) {
			t.Errorf("ui.html uses %s", bad)
		}
	}
}
