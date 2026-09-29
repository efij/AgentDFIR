package serve

import (
	"strings"
	"testing"
)

// TestShortcutsMatchPhysicalKeys: Cmd/Ctrl+K and j/k must match e.code, not
// only e.key — on a Hebrew, Russian or Greek layout e.key is not "k" and the
// search shortcut was dead for those users.
func TestShortcutsMatchPhysicalKeys(t *testing.T) {
	ui := string(uiHTML)
	for _, want := range []string{"e.code==='Key'+ch.toUpperCase()", "isKey(e,'k')", "isKey(e,'j')", "t.nodeType===1"} {
		if !strings.Contains(ui, want) {
			t.Errorf("ui.html lost %q", want)
		}
	}
	if !strings.Contains(ui, "b.latest.localeCompare(a.latest)") {
		t.Error("findings groups are no longer ordered newest first within a tier")
	}
	if strings.Contains(ui, "e.key.toLowerCase()==='k'") {
		t.Error("layout-dependent Cmd+K check is back")
	}
}
