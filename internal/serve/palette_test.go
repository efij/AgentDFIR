package serve

import (
	"strings"
	"testing"
)

// TestCommandPalette: Cmd/Ctrl+K opens a real palette (a dialog with a
// combobox and a listbox), not just focus on the header box, and closing it
// takes focus out of the hidden input so later keys do not type into it.
func TestCommandPalette(t *testing.T) {
	ui := string(uiHTML)
	for _, want := range []string{
		`id="pal" role="dialog" aria-modal="true"`,
		`id="palq" type="text"`, `role="combobox"`, `aria-controls="pall"`, `id="pall" role="listbox"`,
		"isKey(e,'k')){e.preventDefault(); if(PAL.open) closePal(); else openPal('');",
		"e.key==='/'",
		"$('#palq').blur()",
		"scope:'events'",
		`id="palbtn"`,
	} {
		if !strings.Contains(ui, want) {
			t.Errorf("ui.html lost %q", want)
		}
	}
	if strings.Contains(ui, "g.focus(); g.select();") {
		t.Error("Cmd+K went back to only focusing the header box")
	}
}
