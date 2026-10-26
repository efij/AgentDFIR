package proof

import (
	"fmt"
	"regexp"
	"time"

	"github.com/efij/AgentDFIR/v5/internal/correlate"
	"github.com/efij/AgentDFIR/v5/internal/endpoint"
	"github.com/efij/AgentDFIR/v5/internal/lineage"
	"github.com/efij/AgentDFIR/v5/internal/schema"
)

// The overlay the report reads is regenerable analysis output, not sealed
// evidence: a crafted one must not be able to put arbitrary text where a
// fixed vocabulary is expected, nor a short "hash" where a SHA-256 is.
// validate normalizes timestamps to RFC 3339, replaces values outside
// their vocabulary with "INVALID" and blanks malformed hashes, and says so
// in the notes. Free text is left as is and sanitized when rendered.

// Invalid replaces a value outside its vocabulary.
const Invalid = "INVALID"

var (
	hex64    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	kindLike = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	states   = set(schema.StateRequested, schema.StateReported, schema.StateObserved, schema.StateCorroborated, schema.StatePartial,
		schema.StateContradicted, schema.StateUnknown, "")
	coverages = set(correlate.CoverHealthy, correlate.CoverUnverified, correlate.CoverPartial, correlate.CoverNoKind, correlate.CoverOutside, "unknown")
	verdicts  = set(endpoint.HealthHealthy, endpoint.HealthPartial, endpoint.HealthUnknown)
	assurance = set(lineage.AssuranceVerified, lineage.AssuranceCorroborated, lineage.AssuranceInferred, "")
	corrConf  = set("HIGH", "MEDIUM", "LOW", "")
	signals   = set("rate-limit", "throttle", "lost-events", "log-clear", "context-bound", "daemon")
)

func set(v ...string) map[string]bool {
	m := map[string]bool{}
	for _, s := range v {
		m[s] = true
	}
	return m
}

type validator struct{ bad map[string]int }

func (v *validator) enum(field string, val *string, allowed map[string]bool) {
	if !allowed[*val] {
		v.bad[field]++
		*val = Invalid
	}
}

func (v *validator) pattern(field string, val *string, re *regexp.Regexp) {
	if *val != "" && !re.MatchString(*val) {
		v.bad[field]++
		*val = Invalid
	}
}

func (v *validator) hash(field string, val *string) {
	if *val != "" && !hex64.MatchString(*val) {
		v.bad[field]++
		*val = ""
	}
}

// normTS returns the timestamp in RFC 3339 (UTC), or "" when it does not
// parse.
func normTS(s string) (string, bool) {
	if s == "" {
		return "", true
	}
	t, ok := parseTS(s)
	if !ok {
		return "", false
	}
	return t.Format(time.RFC3339Nano), true
}

// validate checks the report in place and records what it changed.
func validate(r *Report) {
	v := &validator{bad: map[string]int{}}
	for i := range r.Telemetry.Sources {
		s := &r.Telemetry.Sources[i]
		v.enum("source verdict", &s.Verdict, verdicts)
		v.hash("source sha256", &s.SHA256)
		for j := range s.Drops {
			v.enum("drop signal", &s.Drops[j].Signal, signals)
		}
	}
	for i := range r.Telemetry.Coverage {
		c := &r.Telemetry.Coverage[i]
		v.enum("coverage health", &c.Health, verdicts)
		v.pattern("coverage kind", &c.Kind, kindLike)
	}
	for i := range r.Actions {
		a := &r.Actions[i]
		if ts, ok := normTS(a.Timestamp); ok {
			a.Timestamp = ts
		} else {
			v.bad["timestamp"]++
			a.Timestamp = Invalid
			a.Limitations = append(a.Limitations, "the recorded timestamp does not parse; coverage could not be placed in time")
		}
		v.enum("evidence state", &a.State, states)
		v.enum("confidence", &a.Confidence, assurance)
		for j := range a.Coverage {
			v.enum("coverage", &a.Coverage[j].Coverage, coverages)
			v.pattern("coverage kind", &a.Coverage[j].Kind, kindLike)
		}
		for j := range a.Chain {
			s := &a.Chain[j]
			v.pattern("node kind", &s.Role, kindLike)
			v.enum("evidence state", &s.State, states)
			v.enum("assurance", &s.Assurance, assurance)
			v.enum("correlation confidence", &s.Correlation, corrConf)
			for k := range s.Refs {
				v.hash("telemetry sha256", &s.Refs[k].TelemetrySHA256)
			}
		}
	}
	for _, f := range sortedKeysInt(v.bad) {
		r.Notes = append(r.Notes, fmt.Sprintf("%d %s value(s) in the analysis overlay were malformed and are shown as %s or left blank", v.bad[f], f, Invalid))
	}
}

func sortedKeysInt(m map[string]int) []string {
	b := map[string]bool{}
	for k := range m {
		b[k] = true
	}
	return sortedSet(b)
}
