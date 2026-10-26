package accountability_test

import (
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v5/internal/accountability"
)

func TestCertificationPrefillsFactsKeepsPlaceholders(t *testing.T) {
	pkg := build(t, "pocketos-wipe")
	cert, err := accountability.Certification(pkg, accountability.CertFields{Name: "Dana Lee", Title: "GCFA", Org: "CSIRT"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Dana Lee", "GCFA", "CSIRT", "902(13)", "902(14)", "Not legal advice", "ACC-pocketos-wipe"} {
		if !strings.Contains(cert, want) {
			t.Errorf("certification missing %q", want)
		}
	}
	// Human fields not supplied stay as placeholders; the tool never signs.
	if !strings.Contains(cert, "[[ date ]]") || !strings.Contains(cert, "[[ state the basis") {
		t.Error("human placeholders were filled in by the tool")
	}
	if strings.Contains(cert, "admissible") || strings.Contains(cert, "court-proof") {
		t.Error("certification over-claims (admissible/court-proof)")
	}
}
