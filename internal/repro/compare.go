package repro

import (
	"fmt"
	"sort"
	"strings"

	"github.com/efij/AgentDFIR/v5/internal/schema"
)

// Difference is one way a reproduction's circumstances differ from the
// recorded analysis. Affects says whether the difference can change the
// findings (code, rules, evidence, options) or should not (toolchain,
// platform, time); a mismatch with only the latter is a determinism bug.
type Difference struct {
	Field    string `json:"field"`
	Recorded string `json:"recorded"`
	Now      string `json:"now"`
	Affects  bool   `json:"can_change_findings"`
	Explain  string `json:"explain"`
}

// Comparison is the result of reproducing a recorded analysis.
type Comparison struct {
	Reproduced  bool         `json:"reproduced"`
	Recorded    string       `json:"recorded_fingerprint"`
	Now         string       `json:"reproduced_fingerprint"`
	Differences []Difference `json:"differences"`
	// OnlyRecorded and OnlyNow are the findings, as readable keys, that
	// one side has and the other does not (bounded; the counts are exact).
	OnlyRecorded      []string `json:"only_in_recorded,omitempty"`
	OnlyNow           []string `json:"only_in_reproduction,omitempty"`
	OnlyRecordedCount int      `json:"only_in_recorded_count"`
	OnlyNowCount      int      `json:"only_in_reproduction_count"`
	Notes             []string `json:"notes,omitempty"`
}

const maxListedDiff = 25

// Readable renders a finding's fingerprinted fields for a person.
func Readable(f schema.Finding) string {
	refs := append([]string(nil), f.EvidenceRefs...)
	sort.Strings(refs)
	s := fmt.Sprintf("%s %s status=%s endpoint=%s", f.RuleID, f.Severity, f.Status, f.Endpoint)
	if f.SessionID != "" {
		s += " session=" + f.SessionID
	}
	if f.AgentID != "" {
		s += " agent=" + f.AgentID
	}
	if len(refs) > 0 {
		s += " evidence=" + refs[0]
		if len(refs) > 1 {
			s += fmt.Sprintf(" (+%d)", len(refs)-1)
		}
	}
	return s
}

// Compare explains how a reproduction relates to the recorded analysis.
// recordedFindings may be nil when the stored findings are unavailable
// or do not match the recorded fingerprint.
func Compare(rec, now *Manifest, recordedFindings, nowFindings []schema.Finding) *Comparison {
	c := &Comparison{Recorded: rec.FindingsFingerprint, Now: now.FindingsFingerprint, Differences: []Difference{}}
	c.Reproduced = rec.FindingsFingerprint != "" && rec.FindingsFingerprint == now.FindingsFingerprint
	add := func(field, a, b string, affects bool, explain string) {
		if a != b {
			c.Differences = append(c.Differences, Difference{Field: field, Recorded: a, Now: b, Affects: affects, Explain: explain})
		}
	}
	add("tool.version", rec.Tool.Version, now.Tool.Version, false,
		"a different release; it changes findings only if the analysis code differs (see tool.analysis_fingerprint)")
	add("tool.analysis_fingerprint", rec.Tool.AnalysisFingerprint, now.Tool.AnalysisFingerprint, true,
		"the code that turns evidence into findings differs (parsers, built-in rules or embedded packs); reproduce with agentdfir "+rec.Tool.Version)
	add("tool.go_version", rec.Tool.GoVersion, now.Tool.GoVersion, false, "a different Go toolchain; it should not change findings")
	add("tool.os/arch", rec.Tool.OS+"/"+rec.Tool.Arch, now.Tool.OS+"/"+now.Tool.Arch, false, "a different platform; it should not change findings")
	add("rule_set.builtin_packs", fmt.Sprint(rec.RuleSet.BuiltinPacks), fmt.Sprint(now.RuleSet.BuiltinPacks), true, "the embedded rule packs were switched on or off")
	add("rule_set.packs", packList(rec.RuleSet.Packs), packList(now.RuleSet.Packs), true, "a different set of rule packs, or packs with different content")
	add("rule_set.rules_dir_files", fileList(rec.RuleSet.RulesDirFiles), fileList(now.RuleSet.RulesDirFiles), true,
		"the files in the --rules directory are not the ones the analysis read")
	add("input.seal_sha256", rec.Input.SealSHA256, now.Input.SealSHA256, true,
		"the sealed evidence differs (a later collection round, or a different package)")
	add("input.inputs_digest", rec.Input.InputsDigest, now.Input.InputsDigest, true, "the records analysis reads differ")
	add("input.retired_sha256", rec.Input.RetiredSHA256, now.Input.RetiredSHA256, true,
		"a different set of records was retired from the scan set (normalized/retired.json)")
	ro, no := rec.Options, now.Options
	add("options.endpoint_logs", fileList(ro.EndpointLogs), fileList(no.EndpointLogs), true, "different endpoint logs (the second witness)")
	add("options.endpoint_format", ro.EndpointFormat, no.EndpointFormat, true, "a different endpoint log format")
	add("options.window_ms", fmt.Sprint(ro.WindowMS), fmt.Sprint(no.WindowMS), true, "a different correlation window")
	add("options.shell_history", optFile(ro.ShellHistory), optFile(no.ShellHistory), true, "a different shell history file")
	add("options.gateway_log", optFile(ro.GatewayLog), optFile(no.GatewayLog), true, "a different MCP gateway log")
	add("options.gateway_map", optFile(ro.GatewayMap), optFile(no.GatewayMap), true, "a different gateway field map")
	add("options.gateway_servers", strings.Join(ro.GatewayServers, ","), strings.Join(no.GatewayServers, ","), true, "different gateway-routed servers")
	add("options.no_builtin_packs", fmt.Sprint(ro.NoBuiltinPacks), fmt.Sprint(no.NoBuiltinPacks), true, "the embedded packs were switched on or off")
	add("options.spawn_threshold", fmt.Sprint(ro.SpawnThreshold), fmt.Sprint(no.SpawnThreshold), true, "a different AGENT_SPAWN_EXPLOSION threshold")
	add("options.known_destinations", strings.Join(ro.KnownDests, ","), strings.Join(no.KnownDests, ","), true, "a different destination allowlist")
	add("options.ioc_files", fileList(ro.IOCFiles), fileList(no.IOCFiles), true, "different IOC feeds")
	add("options.honeytokens", fmt.Sprint(ro.Honeytokens), fmt.Sprint(no.Honeytokens), true,
		"a different number of honeytokens (pass the original list with --honeytokens)")
	if ro.Honeytokens > 0 {
		c.Notes = append(c.Notes, "honeytokens: only their count is recorded, so the package cannot confirm the list passed to the reproduction is the one the analysis used")
	}
	if ro.ReusedCorrelation {
		c.Differences = append(c.Differences, Difference{Field: "options.reused_correlation", Recorded: fmt.Sprintf("%d finding(s)", ro.ReusedCorrelationFindings), Now: "not reusable",
			Affects: true, Explain: "the recorded analysis carried forward endpoint-correlation findings from an earlier run whose logs it did not read; " +
				"a reproduction starts from the sealed evidence and cannot include them — reproduce the run that read the logs (--endpoint)"})
	}
	if ro.OverlayReused {
		c.Differences = append(c.Differences, Difference{Field: "options.overlay_reused", Recorded: "true", Now: "false", Affects: true,
			Explain: "the recorded analysis reused normalized events an earlier run had built; evidence states that run added from inputs this one did not name (such as --shell-history) are not reproduced from the sealed evidence"})
	}
	if c.Reproduced {
		if len(c.Differences) > 0 {
			c.Notes = append(c.Notes, "the findings reproduced despite the differences listed")
		}
		return c
	}
	nowKeys := multiset(nowFindings)
	if recordedFindings == nil {
		c.Notes = append(c.Notes, "the stored findings are unavailable or do not match the recorded fingerprint, so the findings cannot be compared one by one")
	} else {
		recKeys := multiset(recordedFindings)
		c.OnlyRecorded, c.OnlyRecordedCount = minus(recKeys, nowKeys)
		c.OnlyNow, c.OnlyNowCount = minus(nowKeys, recKeys)
	}
	affecting := false
	for _, d := range c.Differences {
		affecting = affecting || d.Affects
	}
	if !affecting {
		c.Notes = append(c.Notes, "nothing that can change findings differs, yet the findings did: this is a determinism defect in the analysis — please report it with this output")
	}
	return c
}

func multiset(fs []schema.Finding) map[string][]string {
	m := map[string][]string{}
	for _, f := range fs {
		k := CanonicalEntry(f)
		m[k] = append(m[k], Readable(f))
	}
	return m
}

// minus lists what a has beyond b, counting duplicates.
func minus(a, b map[string][]string) ([]string, int) {
	keys := make([]string, 0, len(a))
	for k := range a {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []string
	n := 0
	for _, k := range keys {
		extra := len(a[k]) - len(b[k])
		for i := 0; i < extra; i++ {
			n++
			if len(out) < maxListedDiff {
				out = append(out, a[k][0])
			}
		}
	}
	return out, n
}

func packList(ps []Pack) string {
	var s []string
	for _, p := range ps {
		s = append(s, p.Pack+"@"+p.Version+":"+short(p.SHA256))
	}
	sort.Strings(s)
	return strings.Join(s, ", ")
}

func fileList(fs []FileRef) string {
	var s []string
	for _, f := range fs {
		s = append(s, optFile(&f))
	}
	return strings.Join(s, ", ")
}

func optFile(f *FileRef) string {
	if f == nil {
		return ""
	}
	if f.Error != "" {
		return f.Path + " (" + f.Error + ")"
	}
	return f.Path + ":" + short(f.SHA256)
}

func short(h string) string {
	if len(h) > 16 {
		return h[:16]
	}
	return h
}
