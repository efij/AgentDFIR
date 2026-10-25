package benchmark

import (
	"fmt"
	"path/filepath"

	"github.com/efij/AgentDFIR/v4/internal/analysis"
	"github.com/efij/AgentDFIR/v4/internal/compat"
	"github.com/efij/AgentDFIR/v4/internal/integrity"
)

// Compat is the compatibility section: packages written by released
// binaries (internal/compat) checked by this one.
type Compat struct {
	Packages []CompatResult `json:"packages"`
	OK       int            `json:"ok"`
	Total    int            `json:"total"`
}

// CompatResult is one historical package.
type CompatResult struct {
	Version   string `json:"producer_version"`
	Verified  bool   `json:"verified"`
	Signature string `json:"signature"` // valid | unsigned | INVALID
	Analyzed  bool   `json:"analyzed"`
	Events    int    `json:"events"`
	Findings  int    `json:"findings"`
	Problem   string `json:"problem,omitempty"`
}

func runCompat(r *Report, work string) {
	c := &r.Compat
	for i, p := range compat.Packages() {
		res := CompatResult{Version: p.Version, Signature: "unsigned"}
		c.Total++
		dir, err := p.Extract(filepath.Join(work, fmt.Sprintf("p%d", i)))
		if err != nil {
			res.Problem = "extract: " + err.Error()
			r.fail("compatibility: %s package: %s", p.Version, res.Problem)
			c.Packages = append(c.Packages, res)
			continue
		}
		chk, err := integrity.VerifyPackage(dir, "")
		switch {
		case err != nil:
			res.Problem = "verify: " + err.Error()
		case len(chk.Package.Problems) > 0:
			res.Problem = "verify: " + chk.Package.Problems[0]
		default:
			res.Verified = true
		}
		if err == nil && chk.Signature != nil && chk.Signature.Present {
			res.Signature = "valid"
			if !chk.Signature.Valid {
				res.Signature = "INVALID"
			}
		}
		if ar, err := analysis.Run(dir, analysis.Options{}); err != nil {
			if res.Problem == "" {
				res.Problem = "analyze: " + err.Error()
			}
		} else {
			res.Analyzed, res.Events, res.Findings = true, ar.Events, len(ar.Findings)
		}
		if res.Verified && res.Analyzed && res.Events > 0 {
			c.OK++
		} else {
			r.fail("compatibility: %s package: %s", p.Version, res.Problem)
		}
		c.Packages = append(c.Packages, res)
	}
}
