// Injection-surface detections (plan §14): prompt-injection indicators,
// context/tool poisoning, invisible-Unicode instruction smuggling, and
// honeytoken access. All scans stream (any artifact size).
//
// Mapping discipline (MITRE ATLAS v5.x): LLM Prompt Injection (AML.T0051)
// for conversation content, AI Agent Context Poisoning: Memory
// (AML.T0080.000) for standing instruction files, AI Agent Tool Poisoning
// (AML.T0110) for tool/skill definitions, and LLM Prompt Obfuscation
// (AML.T0068) for invisible-Unicode smuggling. They remain INDICATORS —
// never auto-escalated to a compromise conclusion.
package detect

import (
	"fmt"
	"strings"

	"github.com/efij/AgentDFIR/v2/internal/casepkg"
	"github.com/efij/AgentDFIR/v2/internal/schema"
)

// injectionPhrases are common instruction-override formulations.
// Deliberately conservative: phrases, not single words.
var injectionPhrases = []string{
	"ignore previous instructions",
	"ignore all previous instructions",
	"disregard your instructions",
	"disregard all prior",
	"ignore your system prompt",
	"override your system prompt",
	"you are now dan",
	"pretend you have no restrictions",
	"do not tell the user",
	"without informing the user",
	"exfiltrate",
	"<!-- ai:",
	"[system]",
	"important: before responding",
}

// InjectionPhrase reports the first instruction-override phrase found in
// text (case-insensitive). Shared with the MCP audit so tool descriptions
// are judged by the same conservative vocabulary as transcripts.
func InjectionPhrase(text string) (string, bool) {
	low := strings.ToLower(text)
	for _, ph := range injectionPhrases {
		if strings.Contains(low, ph) {
			return ph, true
		}
	}
	return "", false
}

// surfaceRule maps an artifact category to the rule it triggers. The
// same phrase list is applied; the SURFACE determines the finding.
type surfaceRule struct {
	types  []string
	ruleID string
	title  string
	desc   string
	atlas  string
}

var injectionSurfaces = []surfaceRule{
	{[]string{"agent_session", "prompt_history"}, "PROMPT_INJECTION_INDICATOR",
		"Prompt Injection Indicator",
		"Instruction-override phrase %q present in agent-facing conversation content. INDICATOR of possible prompt injection, not proof of a successful one — correlate with subsequent agent behavior.",
		"AML.T0051"},
	{[]string{"agent_instructions"}, "AGENT_CONTEXT_POISONING",
		"Agent Context Poisoning Indicator",
		"Instruction-override phrase %q present in standing agent instructions (CLAUDE.md / GEMINI.md / rules). Persistent context is a high-value poisoning target because it influences every session.",
		"AML.T0080.000"},
	{[]string{"agent_definitions"}, "TOOL_POISONING_INDICATOR",
		"Tool/Skill Definition Poisoning Indicator",
		"Instruction-override phrase %q present in a tool, skill, agent or plugin definition. Poisoned tool metadata is read by the model as trusted context.",
		"AML.T0110"},
}

func promptInjectionIndicator(man *casepkg.Manifest, pkgDir string) []schema.Finding {
	var out []schema.Finding
	store := casepkg.NewStore(pkgDir, man)
	for _, a := range man.Current() {
		if selfReferentialPath(a.LogicalPath) {
			continue
		}
		for _, sr := range injectionSurfaces {
			if !isType(a, sr.types...) {
				continue
			}
			phrase, off, ok := scanPhrases(blobReader{store, a.ArtifactID}, injectionPhrases)
			if !ok {
				continue
			}
			out = append(out, schema.Finding{
				RuleID:        sr.ruleID,
				Severity:      severityFor(sr.ruleID),
				Title:         sr.title,
				Description:   fmt.Sprintf(sr.desc, phrase),
				EvidenceRefs:  []string{artRef(a, off)},
				Status:        schema.StateObserved,
				Endpoint:      schema.StateUnknown,
				MitreATLAS:    sr.atlas,
				FalsePositive: "Security discussions, test fixtures and documentation legitimately contain these phrases; review the surrounding context at the referenced offset.",
			})
			break
		}
	}
	return out
}

func severityFor(rule string) string {
	switch rule {
	case "AGENT_CONTEXT_POISONING", "TOOL_POISONING_INDICATOR", "MCP_TOOL_POISONING":
		return "HIGH"
	default:
		return "MEDIUM"
	}
}

// INVISIBLE_UNICODE_INSTRUCTION — tag characters, bidi overrides and
// zero-width runs inside agent-facing content.
func invisibleUnicodeInstruction(man *casepkg.Manifest, pkgDir string) []schema.Finding {
	var out []schema.Finding
	store := casepkg.NewStore(pkgDir, man)
	for _, a := range man.Current() {
		if !isType(a, "agent_session", "prompt_history", "agent_instructions", "agent_definitions") {
			continue
		}
		tags, bidi, zw, firstOff := invisibleStats(blobReader{store, a.ArtifactID})
		if tags == 0 && bidi < 3 && zw < 8 {
			continue
		}
		// Severity follows which characters were found. Unicode tag
		// characters (U+E0000–U+E007F) have no legitimate use in prompts and
		// can carry a whole instruction invisibly. Bidi controls occur in
		// every right-to-left language and zero-width joiners in ordinary
		// emoji — on a real machine all 43 HIGH findings had tags == 0.
		sev := "INFO"
		switch {
		case tags > 0:
			sev = "HIGH"
		case bidi >= 3:
			sev = "MEDIUM"
		}
		out = append(out, schema.Finding{
			RuleID:   "INVISIBLE_UNICODE_INSTRUCTION",
			Severity: sev,
			Title:    "Invisible Unicode in Agent-Facing Content",
			Description: fmt.Sprintf("Invisible characters detected (tag: %d, bidi controls: %d, zero-width: %d). Unicode tag characters can smuggle instructions invisible to a human reviewer but readable by the model.",
				tags, bidi, zw),
			EvidenceRefs:  []string{artRef(a, firstOff)},
			Status:        schema.StateObserved,
			Endpoint:      schema.StateUnknown,
			MitreATLAS:    "AML.T0068", // LLM Prompt Obfuscation
			FalsePositive: "Bidi controls occur in legitimate RTL text; zero-width joiners in some scripts and emoji. Tag characters (U+E0000–U+E007F) have no legitimate use in prompts.",
		})
	}
	return out
}

// HoneytokenFindings flags planted canary markers appearing in agent
// conversations (killer feature #8).
func HoneytokenFindings(man *casepkg.Manifest, pkgDir string, markers []string) []schema.Finding {
	var out []schema.Finding
	store := casepkg.NewStore(pkgDir, man)
	for _, a := range man.Current() {
		if !isType(a, "agent_session", "prompt_history") {
			continue
		}
		_, off, ok := scanContains(blobReader{store, a.ArtifactID}, markers)
		if !ok {
			continue
		}
		out = append(out, schema.Finding{
			RuleID:        "SECRET_ACCESS",
			Severity:      "HIGH",
			Title:         "Honeytoken Accessed by Agent",
			Description:   "A planted canary marker appears inside an agent conversation. The agent read the bait content; treat any network activity in the same session as a potential transmission path. Marker value: [REDACTED]",
			EvidenceRefs:  []string{artRef(a, off)},
			Status:        schema.StateObserved,
			Endpoint:      schema.StateUnknown,
			MitreATTACK:   "T1552",
			MitreATLAS:    "AML.T0055", // Unsecured Credentials
			FalsePositive: "Low: honeytokens are planted precisely so that any access is signal. Verify the marker was not legitimately referenced by the operator.",
		})
	}
	return out
}

// selfReferentialPath reports whether an artifact is a security tool's own
// rule material, a test fixture or this project's own sources.
//
// Injection detection works by looking for injection phrases, so anything
// whose job is to detect or document them contains them by definition.
// On a real machine TOOL_POISONING_INDICATOR fired on a security plugin's
// SIGNATURES.md and on its prompt-injection-context.regex — the file that
// exists to catch exactly that phrase.
func selfReferentialPath(p string) bool {
	l := strings.ToLower(p)
	for _, frag := range []string{
		"signatures", "/rules/", "rule-pack", "rulepack", "prompt-injection",
		"/detect/", "/fixtures/", "/testdata/", "_test.", "agentdfir", "runwall",
	} {
		if strings.Contains(l, frag) {
			return true
		}
	}
	return false
}
