package aiexport

import (
	"testing"

	"github.com/efij/AgentDFIR/v4/internal/parsers/suite"
)

// The suite reader parses the report.xml this planner seals; the rule
// string is defined in both packages and must not drift.
func TestUFDRRuleShared(t *testing.T) {
	if RuleUFDRReport != suite.RuleUFDRReport {
		t.Fatalf("%q != %q", RuleUFDRReport, suite.RuleUFDRReport)
	}
}
