package correlate

import (
	"reflect"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v5/internal/endpoint"
	"github.com/efij/AgentDFIR/v5/internal/schema"
)

// Script blocks corroborate only on an exact match or the whole command
// at token boundaries; loose substring overlaps no longer count.
func TestScriptBlockMatchIsStrict(t *testing.T) {
	block := func(at, text string) endpoint.Record {
		return endpoint.Record{Time: ts(at), Kind: "script", Exe: "powershell.exe", Cmdline: text, Source: "powershell", Ref: "powershell:4104 (" + at + ")"}
	}
	events := []schema.Event{
		tc("exact", "2026-08-30T10:00:00Z", "Bash", "Remove-Item -Recurse -Force build"),
		tc("inside", "2026-08-30T10:01:00Z", "Bash", `Get-ChildItem -Path C:\proj -Recurse`),
		tc("prefix", "2026-08-30T10:02:00Z", "Bash", "Remove-Item -Recurse -Force build"), // block says "buildings"
		tc("short", "2026-08-30T10:03:00Z", "Bash", "ls"),
		tc("superset", "2026-08-30T10:04:00Z", "Bash", "Remove-Item -Recurse -Force build; rm x"), // block is only part of it
		tc("pastcap", "2026-08-30T10:05:00Z", "Bash", "Invoke-WebRequest -Uri http://x/a -OutFile a.exe"),
		tc("partial", "2026-08-30T10:06:00Z", "Bash", "Stop-Service -Name Spooler -Force"),
	}
	events[6].Corroboration = schema.StatePartial
	recs := []endpoint.Record{
		block("2026-08-30T10:00:01Z", "remove-item   -recurse -force build"),
		block("2026-08-30T10:01:01Z", "$x = 1\nGet-ChildItem -Path C:\\proj -Recurse | Out-Null"),
		block("2026-08-30T10:02:01Z", "Remove-Item -Recurse -Force buildings"),
		block("2026-08-30T10:03:01Z", "ls; whoami"),
		block("2026-08-30T10:04:01Z", "Remove-Item"),
		block("2026-08-30T10:05:01Z", strings.Repeat("#", 70<<10)+" Invoke-WebRequest -Uri http://x/a -OutFile a.exe"),
		block("2026-08-30T10:06:01Z", "Stop-Service -Name Spooler -Force"),
	}
	res, f := Endpoint(events, recs, EndpointOptions{})
	want := map[string]string{"exact": schema.StateCorroborated, "inside": schema.StateCorroborated, "prefix": schema.StateObserved,
		"short": schema.StateObserved, "superset": schema.StateObserved, "pastcap": schema.StateObserved, "partial": schema.StateCorroborated}
	for _, e := range events {
		if e.Corroboration != want[e.EventID] {
			t.Errorf("%s: got %s want %s (%s)", e.EventID, e.Corroboration, want[e.EventID], e.Summary)
		}
		if (e.Corroboration == schema.StateCorroborated) != strings.HasPrefix(e.WitnessNote, "script-block:") {
			t.Errorf("%s: witness note %q", e.EventID, e.WitnessNote)
		}
	}
	if res.ScriptCorroborated != 3 || len(f) != 0 {
		t.Fatalf("summary: %+v %+v", res, f)
	}
	if !strings.Contains(events[0].WitnessNote, "exact match") || !strings.Contains(events[1].WitnessNote, "whole command inside the block") {
		t.Fatalf("basis: %q / %q", events[0].WitnessNote, events[1].WitnessNote)
	}
}

// 4688 records without a command line partly corroborate by program
// name, never contradict and never widen coverage; 4688 records with a
// command line keep the normal process behaviour.
func TestProcessImageRecordsArePartialOnly(t *testing.T) {
	image := func(at, exe string) endpoint.Record {
		return endpoint.Record{Time: ts(at), Kind: endpoint.KindProcessImage, Exe: exe, Source: "security", Ref: "security:4688 (" + at + ")"}
	}
	full := func(at, exe, cmd string) endpoint.Record {
		return endpoint.Record{Time: ts(at), Kind: "process", Exe: exe, Cmdline: cmd, Source: "security", Ref: "security:4688 (" + at + ")"}
	}

	// Only image records: partial for the matching program, nothing contradicted, no coverage.
	events := []schema.Event{
		tc("git", "2026-08-30T10:00:00Z", "Bash", `cd C:\proj && git status`),
		tc("pytest", "2026-08-30T10:00:10Z", "Bash", "pytest -q"),
	}
	res, f := Endpoint(events, []endpoint.Record{image("2026-08-30T10:00:01Z", `C:\Program Files\Git\cmd\git.exe`), image("2026-08-30T10:00:11Z", `C:\Windows\System32\conhost.exe`)}, EndpointOptions{})
	if events[0].Corroboration != schema.StatePartial || !strings.HasPrefix(events[0].WitnessNote, "process-image:") || !strings.Contains(events[0].Summary, "partly corroborated by security process-image: git.exe") {
		t.Fatalf("git: %+v", events[0])
	}
	if events[1].Corroboration != schema.StateObserved || res.Contradicted != 0 || len(f) != 0 || !res.CoverageStart.IsZero() || res.ImagePartial != 1 {
		t.Fatalf("image-only must not contradict or create coverage: %+v %+v %+v", events[1], res, f)
	}

	// Mixed: full 4688 records keep normal behaviour (CORROBORATED / CONTRADICTED inside their
	// coverage); an image record far outside that coverage does not widen it.
	events = []schema.Event{
		tc("whoami", "2026-08-30T10:00:00Z", "Bash", "whoami /all"),
		tc("make", "2026-08-30T10:00:30Z", "Bash", "make test"),
		tc("late", "2026-08-30T12:00:00Z", "Bash", "git push"),
	}
	recs := []endpoint.Record{
		full("2026-08-30T10:00:00Z", `C:\Windows\System32\whoami.exe`, "whoami /all"),
		full("2026-08-30T10:01:00Z", `C:\Windows\System32\svchost.exe`, "svchost.exe -k netsvcs"),
		image("2026-08-30T12:00:01Z", `C:\Program Files\Git\cmd\git.exe`),
	}
	res, f = Endpoint(events, recs, EndpointOptions{})
	got := []string{events[0].Corroboration, events[1].Corroboration, events[2].Corroboration}
	if !reflect.DeepEqual(got, []string{schema.StateCorroborated, schema.StateContradicted, schema.StatePartial}) {
		t.Fatalf("mixed states: %v", got)
	}
	if !res.CoverageEnd.Equal(ts("2026-08-30T10:01:00Z")) || res.OutsideCover != 1 || len(f) != 1 || f[0].RuleID != "ENDPOINT_CONTRADICTED_COMMAND" {
		t.Fatalf("mixed: %+v %+v", res, f)
	}
}
