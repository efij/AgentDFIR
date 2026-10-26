package chain

import (
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v4/internal/redact"
	"github.com/efij/AgentDFIR/v4/internal/schema"
)

// A GitHub token shape the secret patterns know; built at run time so the
// source holds no literal token.
var testGHToken = "ghp_" + strings.Repeat("aB3dE5fG7h", 3) + "J9kL1m"

func testRedactor(t *testing.T) *redact.Redactor {
	t.Helper()
	red, err := redact.Parse("secrets")
	if err != nil || red == nil {
		t.Fatalf("redact.Parse: %v", err)
	}
	if got := red.String(testGHToken, "test"); strings.Contains(got, "ghp_") {
		t.Fatalf("redactor does not mask the test token: %q", got)
	}
	return red
}

// Regression: the shared value was shortened before redaction, so a token
// cut to 16 bytes no longer matched its pattern and leaked a prefix.
func TestLinkSentenceRedactsBeforeShortening(t *testing.T) {
	red := testRedactor(t)
	for _, kind := range []string{LinkToolCallID, LinkTarget, LinkNetDest, LinkSession} {
		got := linkSentence(red, kind, 1, 2, []string{testGHToken}, &Step{}, schema.Event{}, schema.Event{})
		if strings.Contains(got, "ghp_") || strings.Contains(got, "aB3dE5") {
			t.Errorf("%s: secret prefix leaked into link sentence: %q", kind, got)
		}
		if strings.Contains(got, "[REDACTED:") && !strings.Contains(got, "]") {
			t.Errorf("%s: split redaction marker: %q", kind, got)
		}
	}
}

// Regression: a VAR=value prefix holding '/' was taken for the program,
// so the value reached link_reason through method().
func TestMethodSkipsAnyEnvAssignment(t *testing.T) {
	cases := map[string]string{
		"TOKEN=abc/def curl https://x.example":            "bash:curl",
		"A=1 B=x/y/z sudo /usr/bin/rm -rf build":          "bash:rm",
		"_X=" + testGHToken + "/p env FOO=a/b python3 -c": "bash:python3",
		"--flag=a/b":  "bash:b",
		"1BAD=x/y ls": "bash:y",
	}
	for cmd, want := range cases {
		if got := method(schema.Event{Tool: "Bash", Command: cmd}); got != want {
			t.Errorf("method(%q) = %q, want %q", cmd, got, want)
		}
	}
}

// The whole sentence, method and agent text included, is redacted.
func TestLinkSentenceRedactsMethodAndAgent(t *testing.T) {
	red := testRedactor(t)
	prev := schema.Event{Tool: "Bash", Command: "ls", SessionID: "s1", AgentID: "a"}
	cur := schema.Event{Tool: "Bash", Command: "/opt/" + testGHToken + " run", SessionID: "s2", AgentID: testGHToken}
	got := linkSentence(red, "", 1, 2, nil, &Step{DifferentAgent: true, DifferentMethod: true}, prev, cur)
	if strings.Contains(got, "ghp_") || strings.Contains(got, "aB3dE5") {
		t.Fatalf("secret leaked through method/agent text: %q", got)
	}
}

func TestShortNeverSplitsRedactionMarker(t *testing.T) {
	m := redact.Marker("secret", testGHToken)
	s := "abcd" + m + "tail-text-after-the-marker"
	for n := 0; n < len(s); n++ {
		got := strings.TrimSuffix(short(s, n), "…")
		if strings.Contains(got, "[") && !strings.Contains(got, m) {
			t.Fatalf("short(%d) split the marker: %q", n, got)
		}
		if len(got) > n {
			t.Fatalf("short(%d) too long: %q", n, got)
		}
	}
	if got := short(s, 4+len(m)); got != "abcd"+m+"…" {
		t.Fatalf("whole marker should survive when it fits: %q", got)
	}
}
