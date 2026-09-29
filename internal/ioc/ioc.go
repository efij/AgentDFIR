// Package ioc answers "was this machine hit by X?" for named AI-agent and
// developer-supply-chain incidents.
//
// An incident pack lists indicators copied from the incident's primary
// write-ups — package versions, domains, file names, hashes, repository
// names — and the source each came from. Matching is offline and
// read-only; nothing is resolved, fetched or executed.
//
// Evidence discipline: a hit says WHERE the indicator was seen, because
// that decides what it proves. A command the agent ran is OBSERVED; the
// same string in a tool's output was SEEN_IN_OUTPUT; in a user's question
// or the model's prose it is only MENTIONED (an analyst asking the agent
// about the incident is not the incident).
package ioc

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/efij/AgentDFIR/v3/internal/sanitize"
)

// Indicator kinds.
const (
	KindPackage      = "package"       // Ecosystem/Value, optional Versions, FromVersion or BelowVersion
	KindDomain       = "domain"        // host or parent domain; IPs too
	KindURL          = "url"           // URL prefix without scheme
	KindPath         = "path"          // file name or path fragment
	KindSHA256       = "sha256"        // file content hash
	KindRepoName     = "repo_name"     // repository or owner/repo
	KindString       = "string"        // literal, ≥ 8 characters
	KindCommandRegex = "command_regex" // RE2 over command lines, ≤ 1 KiB
)

// Indicator is one observable.
type Indicator struct {
	Kind        string   `json:"kind"`
	Value       string   `json:"value"`
	Ecosystem   string   `json:"ecosystem,omitempty"`
	Versions    []string `json:"versions,omitempty"`
	FromVersion string   `json:"from_version,omitempty"`
	// BelowVersion marks every version before the fixed one as affected:
	// a vulnerable-version range rather than a list of malicious releases.
	BelowVersion string `json:"below_version,omitempty"`
	Confidence   string `json:"confidence,omitempty"` // high (default) | medium | low
	Note         string `json:"note,omitempty"`
	// FileName, for a sha256 indicator, names the file the hash belongs to,
	// so a directory walk hashes only files of that name.
	FileName string `json:"file_name,omitempty"`

	re *regexp.Regexp
}

// Incident is one named incident and its indicators.
type Incident struct {
	ID         string      `json:"id"`
	Title      string      `json:"title"`
	Summary    string      `json:"summary,omitempty"`
	FirstSeen  string      `json:"first_seen,omitempty"` // YYYY-MM-DD
	LastSeen   string      `json:"last_seen,omitempty"`
	Sources    []string    `json:"sources,omitempty"`
	Indicators []Indicator `json:"indicators"`
	Origin     string      `json:"-"` // embedded pack name or file path
}

// Pack is a file of incidents.
type Pack struct {
	Pack      string     `json:"pack"`
	Version   string     `json:"version"`
	Note      string     `json:"note,omitempty"`
	Incidents []Incident `json:"incidents"`
}

// Limits for untrusted feeds.
const (
	MaxFileBytes  = 16 << 20
	MaxIndicators = 50000
	MaxRegexLen   = 1024
	MinStringLen  = 8
)

//go:embed packs/*.json
var embedded embed.FS

// Embedded returns the incidents shipped with the binary.
func Embedded() ([]Incident, error) {
	entries, err := embedded.ReadDir("packs")
	if err != nil {
		return nil, err
	}
	var out []Incident
	for _, e := range entries {
		b, err := embedded.ReadFile("packs/" + e.Name())
		if err != nil {
			return nil, err
		}
		inc, _, err := Parse(b, "embedded:"+e.Name())
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		out = append(out, inc...)
	}
	return out, nil
}

// LoadFile reads an incident pack, a STIX 2.1 bundle or a MISP event.
// skipped counts indicators whose form is not supported.
func LoadFile(path string) ([]Incident, int, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, 0, err
	}
	if fi.Size() > MaxFileBytes {
		return nil, 0, fmt.Errorf("%s: %d bytes exceeds the %d-byte limit for IOC feeds", path, fi.Size(), MaxFileBytes)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}
	return Parse(b, path)
}

// Parse detects the format and returns validated incidents.
func Parse(b []byte, origin string) ([]Incident, int, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(b, &probe); err != nil {
		return nil, 0, fmt.Errorf("not JSON: %w", err)
	}
	var incs []Incident
	skipped := 0
	var err error
	switch {
	case probe["incidents"] != nil:
		var p Pack
		if err = json.Unmarshal(b, &p); err != nil {
			return nil, 0, err
		}
		incs = p.Incidents
	case string(probe["type"]) == `"bundle"`:
		incs, skipped, err = parseSTIX(b, origin)
	case probe["Event"] != nil || probe["response"] != nil:
		incs, skipped, err = parseMISP(b, origin)
	default:
		return nil, 0, fmt.Errorf("unrecognised IOC format (want an agentdfir incident pack, a STIX 2.1 bundle or a MISP event)")
	}
	if err != nil {
		return nil, 0, err
	}
	total := 0
	for i := range incs {
		inc := &incs[i]
		inc.Origin = origin
		inc.Title = sanitize.Terminal(inc.Title)
		inc.Summary = sanitize.Terminal(inc.Summary)
		if inc.ID == "" {
			return nil, 0, fmt.Errorf("incident without id")
		}
		var keep []Indicator
		for _, ind := range inc.Indicators {
			ok, err := ind.validate()
			if err != nil {
				return nil, 0, fmt.Errorf("incident %s: %w", inc.ID, err)
			}
			if !ok {
				skipped++
				continue
			}
			keep = append(keep, ind)
		}
		inc.Indicators = keep
		total += len(keep)
		if total > MaxIndicators {
			return nil, 0, fmt.Errorf("more than %d indicators", MaxIndicators)
		}
	}
	return incs, skipped, nil
}

// validate normalizes the indicator; ok=false drops it (too weak to match
// safely), err rejects the whole feed (malformed).
func (ind *Indicator) validate() (bool, error) {
	ind.Kind = strings.ToLower(strings.TrimSpace(ind.Kind))
	ind.Value = strings.TrimSpace(refang(ind.Value))
	if ind.Confidence == "" {
		ind.Confidence = "high"
	}
	if ind.Value == "" {
		return false, nil
	}
	switch ind.Kind {
	case KindDomain:
		ind.Value = strings.TrimSuffix(strings.ToLower(ind.Value), ".")
		return strings.Contains(ind.Value, ".") || strings.Contains(ind.Value, ":"), nil
	case KindURL:
		v := strings.ToLower(ind.Value)
		v = strings.TrimPrefix(strings.TrimPrefix(v, "https://"), "http://")
		ind.Value = v
		return len(v) >= MinStringLen, nil
	case KindPackage:
		if ind.Ecosystem == "" {
			ind.Ecosystem = "npm"
		}
		ind.Value = strings.ToLower(ind.Value)
		return true, nil
	case KindSHA256:
		ind.Value = strings.ToLower(ind.Value)
		if len(ind.Value) != 64 {
			return false, nil
		}
		return true, nil
	case KindPath, KindRepoName:
		return len(ind.Value) >= 6, nil
	case KindString:
		return len(ind.Value) >= MinStringLen, nil
	case KindCommandRegex:
		if len(ind.Value) > MaxRegexLen {
			return false, fmt.Errorf("command_regex longer than %d bytes", MaxRegexLen)
		}
		// Matched against lowercased text, so case-insensitive.
		re, err := regexp.Compile("(?i)" + ind.Value)
		if err != nil {
			return false, fmt.Errorf("command_regex %q: %w", ind.Value, err)
		}
		ind.re = re
		return true, nil
	}
	return false, nil
}

// refang undoes the defanging threat reports use: hxxp, [.], (.), [:].
func refang(s string) string {
	r := strings.NewReplacer("[.]", ".", "(.)", ".", "{.}", ".", "[dot]", ".", "[:]", ":", "hxxps", "https", "hxxp", "http", "[at]", "@", "[@]", "@")
	return r.Replace(s)
}

// Severity is what a hit on this indicator weighs, by where it was seen.
func (ind Indicator) Severity(where string) string {
	sev := "CRITICAL"
	switch ind.Confidence {
	case "medium":
		sev = "HIGH"
	case "low":
		sev = "MEDIUM"
	}
	if where == WhereOutput {
		sev = downgrade(sev)
	}
	return sev
}

func downgrade(s string) string {
	switch s {
	case "CRITICAL":
		return "HIGH"
	case "HIGH":
		return "MEDIUM"
	}
	return "LOW"
}

// Where an indicator was seen.
const (
	WhereObserved  = "OBSERVED"       // a command the agent ran, a configured package, an installed file
	WhereOutput    = "SEEN_IN_OUTPUT" // in a tool's output
	WhereMentioned = "MENTIONED"      // in user or model prose: context, not a hit
)

// ---- matching primitives ----

// MatchPackage reports whether name@version is covered by a package
// indicator. version may be "" (unknown): then only indicators without a
// version constraint match.
func (ind Indicator) MatchPackage(eco, name, version string) bool {
	if ind.Kind != KindPackage || !strings.EqualFold(ind.Value, name) {
		return false
	}
	if eco != "" && ind.Ecosystem != "" && !strings.EqualFold(eco, ind.Ecosystem) {
		return false
	}
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	if len(ind.Versions) == 0 && ind.FromVersion == "" && ind.BelowVersion == "" {
		return true
	}
	if version == "" {
		return false
	}
	for _, v := range ind.Versions {
		if v == version {
			return true
		}
	}
	if ind.BelowVersion != "" && compareVersions(version, ind.BelowVersion) < 0 {
		return true
	}
	return ind.FromVersion != "" && compareVersions(version, ind.FromVersion) >= 0
}

// compareVersions compares dotted numeric versions; pre-release suffixes
// sort as their base version.
func compareVersions(a, b string) int {
	pa, pb := strings.Split(cut(a), "."), strings.Split(cut(b), ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func cut(v string) string {
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		return v[:i]
	}
	return v
}

// MatchHost reports whether a destination host is the indicator domain or
// under it.
func (ind Indicator) MatchHost(host string) bool {
	if ind.Kind != KindDomain {
		return false
	}
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h, "]") && strings.Count(h, ":") == 1 {
		h = h[:i]
	}
	return h == ind.Value || strings.HasSuffix(h, "."+ind.Value)
}

// MatchText reports whether a literal-kind indicator occurs in lowered
// text (the caller lowercases once for all indicators).
func (ind Indicator) MatchText(lower string) bool {
	switch ind.Kind {
	case KindDomain:
		v := ind.Value
		for off := 0; ; {
			i := strings.Index(lower[off:], v)
			if i < 0 {
				return false
			}
			i += off
			end := i + len(v)
			before := i == 0 || !labelChar(lower[i-1]) // a subdomain's "." is a boundary
			after := end == len(lower) || (!labelChar(lower[end]) && lower[end] != '.') ||
				(lower[end] == '.' && (end+1 == len(lower) || !labelChar(lower[end+1])))
			if before && after {
				return true
			}
			off = i + 1
		}
	case KindURL, KindPath, KindRepoName, KindString:
		return strings.Contains(lower, strings.ToLower(ind.Value))
	case KindCommandRegex:
		return ind.re != nil && ind.re.MatchString(lower)
	}
	return false
}

func labelChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}

// Label renders the indicator for output.
func (ind Indicator) Label() string {
	switch ind.Kind {
	case KindPackage:
		v := ""
		switch {
		case len(ind.Versions) > 0:
			v = "@" + strings.Join(ind.Versions, "|")
		case ind.FromVersion != "":
			v = "@>=" + ind.FromVersion
		case ind.BelowVersion != "":
			v = "@<" + ind.BelowVersion
		}
		return ind.Ecosystem + ":" + ind.Value + v
	}
	return ind.Kind + ":" + ind.Value
}

// Select returns the incidents with the given ids ("all" or empty = every one).
func Select(all []Incident, ids []string) ([]Incident, error) {
	if len(ids) == 0 || (len(ids) == 1 && ids[0] == "all") {
		return all, nil
	}
	by := map[string]Incident{}
	for _, i := range all {
		by[i.ID] = i
	}
	var out []Incident
	for _, id := range ids {
		i, ok := by[id]
		if !ok {
			known := make([]string, 0, len(by))
			for k := range by {
				known = append(known, k)
			}
			sort.Strings(known)
			return nil, fmt.Errorf("unknown incident %q (known: %s)", id, strings.Join(known, ", "))
		}
		out = append(out, i)
	}
	return out, nil
}
