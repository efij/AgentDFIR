// Package redact masks sensitive values in derivative outputs — the RSMF
// export, reports and production sets made from a case. It never touches
// evidence: callers hand it copies of derived data, and the sealed zone is
// read-only to every code path that uses it.
//
// A masked value becomes [REDACTED:<category>:<sha256 prefix>]. The prefix
// (first 8 hex characters of the value's SHA-256) lets a reviewer see that
// two masks hide the same value without seeing it; it also lets someone
// who already holds a candidate value confirm it, which is stated in the
// docs. The redaction log records category, location and count — never
// the value.
//
// Categories: secrets (the credential formats the SECRET detection rules
// recognize, internal/detect), emails, paths (absolute filesystem paths),
// ips (IPv4/IPv6 literals) and custom (a file of regular expressions).
package redact

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/efij/AgentDFIR/v4/internal/detect"
)

// Category names as they appear in markers and the log.
const (
	Secret = "secret"
	Email  = "email"
	Path   = "path"
	IP     = "ip"
	Custom = "custom"
)

// Bounds on a custom pattern file: it is operator input, but still input.
const (
	maxCustomBytes    = 64 << 10
	maxCustomPatterns = 256
	maxWalkDepth      = 64
	// privateKeyWindow bounds how far past a private-key header the END
	// marker is searched for; without one the rest of the value is masked.
	privateKeyWindow = 64 << 10
)

var (
	emailRe = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	// unixPathRe: an absolute (or home-relative) path with at least two
	// components. Matches preceded by a word character, '/', ':' or '.' are
	// rejected in code (relative paths, URLs), since RE2 has no lookbehind.
	unixPathRe = regexp.MustCompile(`(?:~|\$HOME)?/[A-Za-z0-9._@%+=~-]+(?:/[A-Za-z0-9._@%+=~-]*)+`)
	winPathRe  = regexp.MustCompile(`(?:[A-Za-z]:[\\/]|\\\\[A-Za-z0-9._$-]+\\)[^\s"'<>|*?]+`)
	ipv4Re     = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6Re     = regexp.MustCompile(`[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}`)
	markerRe   = regexp.MustCompile(`\[REDACTED:[a-z]+:[0-9a-f]{8}\]`)
	pkEndRe    = regexp.MustCompile(`-----END [A-Z ]*PRIVATE KEY-----`)
)

// Entry is one line of the redaction log: how many values of a category
// (and, for secrets, which credential format) were masked at a location.
type Entry struct {
	Category string `json:"category"`
	Kind     string `json:"kind,omitempty"`
	Location string `json:"location"`
	Count    int    `json:"count"`
}

// Spec describes what a Redactor masks, for the production manifest.
type Spec struct {
	Categories     []string `json:"categories"`
	CustomFile     string   `json:"custom_file,omitempty"`
	CustomSHA256   string   `json:"custom_file_sha256,omitempty"`
	CustomPatterns int      `json:"custom_patterns,omitempty"`
}

type logKey struct{ cat, kind, loc string }

// Redactor masks values and keeps the log. Not safe for concurrent use.
type Redactor struct {
	spec    Spec
	secrets []detect.SecretPattern
	custom  []*regexp.Regexp
	on      map[string]bool
	log     map[logKey]int
}

// Parse builds a Redactor from a --redact value: a comma-separated list of
// secrets, emails, paths, ips and custom:<file> (custom=<file> also
// accepted). "all" selects the four built-in categories. An empty spec
// returns nil: no redaction.
func Parse(spec string) (*Redactor, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	r := &Redactor{on: map[string]bool{}, log: map[logKey]int{}}
	for _, raw := range strings.Split(spec, ",") {
		tok := strings.TrimSpace(raw)
		switch {
		case tok == "":
		case tok == "all":
			for _, c := range []string{Secret, Email, Path, IP} {
				r.on[c] = true
			}
		case tok == "secrets" || tok == "secret":
			r.on[Secret] = true
		case tok == "emails" || tok == "email":
			r.on[Email] = true
		case tok == "paths" || tok == "path":
			r.on[Path] = true
		case tok == "ips" || tok == "ip":
			r.on[IP] = true
		case strings.HasPrefix(tok, "custom:") || strings.HasPrefix(tok, "custom="):
			if r.on[Custom] {
				return nil, fmt.Errorf("redact: only one custom pattern file is supported")
			}
			if err := r.loadCustom(tok[len("custom:"):]); err != nil {
				return nil, err
			}
			r.on[Custom] = true
		default:
			return nil, fmt.Errorf("redact: unknown category %q (want secrets, emails, paths, ips, custom:<file>)", tok)
		}
	}
	if len(r.on) == 0 {
		return nil, fmt.Errorf("redact: no category selected")
	}
	for _, c := range []string{Secret, Email, Path, IP, Custom} {
		if r.on[c] {
			r.spec.Categories = append(r.spec.Categories, c)
		}
	}
	if r.on[Secret] {
		r.secrets = detect.SecretPatterns()
	}
	return r, nil
}

// loadCustom reads one regular expression per line ('#' starts a comment
// line). A pattern that matches the empty string is refused: it would mask
// between every character.
func (r *Redactor) loadCustom(path string) error {
	if path == "" {
		return fmt.Errorf("redact: custom: needs a file path")
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("redact: %w", err)
	}
	defer f.Close()
	var buf bytes.Buffer
	n, err := buf.ReadFrom(&limited{f, maxCustomBytes + 1})
	if err != nil {
		return fmt.Errorf("redact: %w", err)
	}
	if n > maxCustomBytes {
		return fmt.Errorf("redact: custom pattern file is larger than %d bytes", maxCustomBytes)
	}
	sum := sha256.Sum256(buf.Bytes())
	sc := bufio.NewScanner(bytes.NewReader(buf.Bytes()))
	sc.Buffer(make([]byte, 0, 4096), maxCustomBytes)
	line := 0
	for sc.Scan() {
		line++
		p := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(p) == "" || strings.HasPrefix(strings.TrimSpace(p), "#") {
			continue
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return fmt.Errorf("redact: %s line %d: %w", path, line, err)
		}
		if re.MatchString("") {
			return fmt.Errorf("redact: %s line %d: pattern matches the empty string", path, line)
		}
		if len(r.custom) >= maxCustomPatterns {
			return fmt.Errorf("redact: more than %d custom patterns", maxCustomPatterns)
		}
		r.custom = append(r.custom, re)
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("redact: %w", err)
	}
	if len(r.custom) == 0 {
		return fmt.Errorf("redact: %s holds no patterns", path)
	}
	r.spec.CustomFile = path
	r.spec.CustomSHA256 = hex.EncodeToString(sum[:])
	r.spec.CustomPatterns = len(r.custom)
	return nil
}

type limited struct {
	f *os.File
	n int64
}

func (l *limited) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, fmt.Errorf("limit reached")
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.f.Read(p)
	l.n -= int64(n)
	return n, err
}

// Spec reports what this Redactor masks.
func (r *Redactor) Spec() Spec {
	if r == nil {
		return Spec{}
	}
	return r.spec
}

// Marker is the replacement text for a masked value.
func Marker(category, value string) string {
	sum := sha256.Sum256([]byte(value))
	return "[REDACTED:" + category + ":" + hex.EncodeToString(sum[:4]) + "]"
}

// String masks s and records what it masked under location. A nil
// Redactor returns s unchanged.
func (r *Redactor) String(s, location string) string {
	if r == nil || s == "" {
		return s
	}
	if r.on[Secret] {
		for _, p := range r.secrets {
			kind := p.Name
			if kind == "PRIVATE_KEY_BLOCK" {
				s = r.privateKeys(s, p.Re, location)
				continue
			}
			s = r.replace(s, p.Re, Secret, kind, location, nil)
		}
	}
	if r.on[Email] {
		s = r.replace(s, emailRe, Email, "", location, nil)
	}
	if r.on[IP] {
		s = r.replace(s, ipv4Re, IP, "", location, func(s string, a, b int) bool {
			if a > 0 && (s[a-1] == '.') || b < len(s) && s[b] == '.' && b+1 < len(s) && isDigit(s[b+1]) {
				return false // part of a longer dotted number (a version string)
			}
			return net.ParseIP(s[a:b]) != nil
		})
		s = r.replace(s, ipv6Re, IP, "", location, func(s string, a, b int) bool {
			m := s[a:b]
			if !strings.Contains(m, "::") && strings.Count(m, ":") != 7 {
				return false // 14:00:05 and the like are times, not addresses
			}
			if strings.Trim(m, ":") == "" {
				return false
			}
			if a > 0 && (isWord(s[a-1]) || s[a-1] == ':') || b < len(s) && (isWord(s[b]) || s[b] == ':') {
				return false // std::string, a::b::c — identifiers, not addresses
			}
			return net.ParseIP(m) != nil
		})
	}
	if r.on[Path] {
		s = r.replace(s, unixPathRe, Path, "", location, func(s string, a, b int) bool {
			if a == 0 {
				return true
			}
			c := s[a-1]
			return !(isWord(c) || c == '/' || c == ':' || c == '.')
		})
		s = r.replace(s, winPathRe, Path, "", location, func(s string, a, b int) bool {
			return a == 0 || !isWord(s[a-1])
		})
	}
	if r.on[Custom] {
		for _, re := range r.custom {
			s = r.replace(s, re, Custom, "", location, nil)
		}
	}
	return s
}

// replace masks every accepted match of re that does not overlap an
// existing marker.
func (r *Redactor) replace(s string, re *regexp.Regexp, cat, kind, loc string, accept func(string, int, int) bool) string {
	idx := re.FindAllStringIndex(s, -1)
	if len(idx) == 0 {
		return s
	}
	marks := markerRe.FindAllStringIndex(s, -1)
	var b strings.Builder
	last, n := 0, 0
	for _, m := range idx {
		a, e := m[0], m[1]
		if a == e || overlaps(marks, a, e) || (accept != nil && !accept(s, a, e)) {
			continue
		}
		b.WriteString(s[last:a])
		b.WriteString(Marker(cat, s[a:e]))
		last = e
		n++
	}
	if n == 0 {
		return s
	}
	b.WriteString(s[last:])
	r.log[logKey{cat, kind, loc}] += n
	return b.String()
}

// privateKeys masks a private-key header and the key body after it, up to
// the END marker (or the end of the value when none follows in the
// window): detection only needs the header, a redaction needs the body.
func (r *Redactor) privateKeys(s string, header *regexp.Regexp, loc string) string {
	n := 0
	var b strings.Builder
	for {
		m := header.FindStringIndex(s)
		if m == nil || overlaps(markerRe.FindAllStringIndex(s, -1), m[0], m[1]) {
			break
		}
		end := len(s)
		win := s[m[1]:]
		if len(win) > privateKeyWindow {
			win = win[:privateKeyWindow]
		}
		if e := pkEndRe.FindStringIndex(win); e != nil {
			end = m[1] + e[1]
		}
		b.WriteString(s[:m[0]])
		b.WriteString(Marker(Secret, s[m[0]:end]))
		s = s[end:]
		n++
	}
	if n == 0 {
		return s
	}
	b.WriteString(s)
	r.log[logKey{Secret, "PRIVATE_KEY_BLOCK", loc}] += n
	return b.String()
}

func overlaps(marks [][]int, a, e int) bool {
	for _, m := range marks {
		if a < m[1] && m[0] < e {
			return true
		}
	}
	return false
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isWord(c byte) bool {
	return c == '_' || isDigit(c) || (c|0x20) >= 'a' && (c|0x20) <= 'z'
}

// Walk masks every exported string reachable from ptr (struct fields,
// slices, maps — keys included — and interface values), in place. ptr must
// be a non-nil pointer. Locations are root plus the JSON field path, e.g.
// "event evt-000003.summary".
func (r *Redactor) Walk(ptr any, root string) {
	if r == nil {
		return
	}
	v := reflect.ValueOf(ptr)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return
	}
	r.walk(v.Elem(), root, 0)
}

func (r *Redactor) walk(v reflect.Value, loc string, depth int) {
	if depth > maxWalkDepth {
		return
	}
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			r.walk(v.Elem(), loc, depth+1)
		}
	case reflect.String:
		if v.CanSet() {
			if out := r.String(v.String(), loc); out != v.String() {
				v.SetString(out)
			}
		}
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = f.Name
			}
			r.walk(v.Field(i), loc+"."+name, depth+1)
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			r.walk(v.Index(i), loc+"["+strconv.Itoa(i)+"]", depth+1)
		}
	case reflect.Interface:
		if v.IsNil() || !v.CanSet() {
			return
		}
		inner := v.Elem()
		cp := reflect.New(inner.Type()).Elem()
		cp.Set(inner)
		r.walk(cp, loc, depth+1)
		v.Set(cp)
	case reflect.Map:
		if v.IsNil() || !v.CanSet() {
			return
		}
		keys := v.MapKeys()
		sort.Slice(keys, func(i, j int) bool { return fmt.Sprint(keys[i]) < fmt.Sprint(keys[j]) })
		out := reflect.MakeMapWithSize(v.Type(), len(keys))
		for _, k := range keys {
			nk := reflect.New(k.Type()).Elem()
			nk.Set(k)
			if nk.Kind() == reflect.String {
				r.walk(nk, loc+"{key}", depth+1)
			}
			nv := reflect.New(v.Type().Elem()).Elem()
			nv.Set(v.MapIndex(k))
			r.walk(nv, loc+"["+fmt.Sprint(k)+"]", depth+1)
			out.SetMapIndex(nk, nv)
		}
		v.Set(out)
	}
}

// Log returns the redaction log in a fixed order (location, category,
// kind).
func (r *Redactor) Log() []Entry {
	if r == nil {
		return nil
	}
	out := make([]Entry, 0, len(r.log))
	for k, n := range r.log {
		out = append(out, Entry{Category: k.cat, Kind: k.kind, Location: k.loc, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Location != out[j].Location {
			return out[i].Location < out[j].Location
		}
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}

// Totals sums the log per category.
func (r *Redactor) Totals() map[string]int {
	out := map[string]int{}
	if r == nil {
		return out
	}
	for k, n := range r.log {
		out[k.cat] += n
	}
	return out
}
