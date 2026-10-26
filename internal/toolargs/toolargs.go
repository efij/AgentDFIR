// Package toolargs derives the structured tool-call evidence fields of a
// normalized event (schema.Event ArgsDigest, ArgKeys, SafeArgs,
// ResultDigest, ToolDefDigest, MCPServerVersion) from raw tool arguments
// and results, without copying them.
//
// Raw arguments and results stay in the sealed source artifact. What comes
// out of here is a digest of their canonical JSON, the sorted list of
// top-level argument names, and a short allowlist of argument values that
// identify a target rather than carry content: filesystem paths, the
// scheme and host of a URL, an HTTP method, cloud resource identifiers,
// repository and branch names, tool and server names. Every allowlisted
// value is passed through internal/redact (credential formats masked),
// bounded in length, and dropped when it looks like free text. Prompts,
// file contents, command bodies, message text and anything else not on
// the list never appear.
//
// All input is hostile: sizes are bounded, deeply nested or invalid JSON
// falls back to a digest of the raw bytes, invalid UTF-8 is replaced, and
// nothing here panics.
package toolargs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/efij/AgentDFIR/v5/internal/redact"
	"github.com/efij/AgentDFIR/v5/internal/schema"
)

// Bounds.
const (
	// MaxCanonicalBytes is the largest argument or result document that is
	// re-encoded canonically. Larger ones are digested as raw bytes: still
	// stable for the same input, just not key-order independent.
	MaxCanonicalBytes = 4 << 20
	// MaxKeys bounds ArgKeys; MaxSafeArgs bounds SafeArgs.
	MaxKeys     = 64
	MaxSafeArgs = 16
	// MaxKeyLen and MaxValueLen bound one key or allowlisted value.
	MaxKeyLen   = 64
	MaxValueLen = 256
)

// Args is what one tool call's arguments yield.
type Args struct {
	Digest string
	Keys   string
	Safe   map[string]string
}

// Apply sets ArgsDigest, ArgKeys and SafeArgs on ev from raw arguments.
// raw is the argument document as recorded (a JSON object, or for tools
// that take one string, that string's bytes). Empty raw leaves ev alone.
func Apply(ev *schema.Event, raw []byte) {
	a := Analyze(raw)
	ev.ArgsDigest, ev.ArgKeys, ev.SafeArgs = a.Digest, a.Keys, a.Safe
}

// Analyze derives the digest, key list and allowlisted values of raw.
func Analyze(raw []byte) Args {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return Args{}
	}
	out := Args{Digest: Digest(raw)}
	if raw[0] != '{' || len(raw) > MaxCanonicalBytes {
		return out
	}
	var top map[string]json.RawMessage
	if json.Unmarshal(raw, &top) != nil {
		return out
	}
	keys := make([]string, 0, len(top))
	for k := range top {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out.Keys = keyList(keys)
	for _, k := range keys {
		if len(out.Safe) >= MaxSafeArgs {
			break
		}
		kind := allowKind(k)
		if kind == "" {
			continue
		}
		var s string
		if json.Unmarshal(top[k], &s) != nil {
			continue // only string values are ever kept
		}
		v, ok := safeValue(kind, s)
		if !ok {
			continue
		}
		if out.Safe == nil {
			out.Safe = map[string]string{}
		}
		out.Safe[clean(k, MaxKeyLen)] = v
	}
	return out
}

// Digest returns the hex sha256 of raw's canonical JSON (object keys
// sorted, insignificant whitespace removed, numbers as written). raw that
// is not JSON, is too large or too deeply nested to re-encode is digested
// as its bytes. Empty input yields "".
func Digest(raw []byte) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return ""
	}
	if c, ok := canonical(raw); ok {
		raw = c
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// DigestString digests a result recorded as a plain string (not JSON).
func DigestString(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// canonical re-encodes a JSON document with sorted keys. Go's decoder
// rejects nesting beyond 10,000 levels, which bounds the recursion.
func canonical(raw []byte) ([]byte, bool) {
	if len(raw) > MaxCanonicalBytes {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil {
		return nil, false
	}
	if dec.More() {
		return nil, false // trailing data: not one document
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if enc.Encode(v) != nil {
		return nil, false
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), true
}

// keyList renders sorted keys comma-separated, bounded. A list cut at
// MaxKeys ends in "…".
func keyList(keys []string) string {
	var b strings.Builder
	for i, k := range keys {
		if i == MaxKeys {
			b.WriteString(",…")
			break
		}
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strings.ReplaceAll(clean(k, MaxKeyLen), ",", "_"))
	}
	return b.String()
}

// Allowlist kinds.
const (
	kindPath   = "path"
	kindURL    = "url"
	kindMethod = "method"
	kindARN    = "arn"
	kindIdent  = "ident"
)

// allowed maps a normalized argument name (lower case, no '_' or '-') to
// the kind of value it may hold.
var allowed = map[string]string{
	"filepath": kindPath, "path": kindPath, "cwd": kindPath, "notebookpath": kindPath,
	"workdir": kindPath, "directory": kindPath,
	"url": kindURL, "uri": kindURL, "endpoint": kindURL, "baseurl": kindURL,
	"method": kindMethod,
	"arn":    kindARN, "resourcearn": kindARN, "rolearn": kindARN,
	"resourceid": kindIdent, "resourcename": kindIdent, "bucket": kindIdent,
	"instanceid": kindIdent, "projectid": kindIdent, "subscriptionid": kindIdent,
	"region": kindIdent, "cluster": kindIdent, "namespace": kindIdent,
	"repo": kindIdent, "repository": kindIdent, "owner": kindIdent,
	"branch": kindIdent, "ref": kindIdent,
	"tool": kindIdent, "toolname": kindIdent, "server": kindIdent, "servername": kindIdent,
	"subagenttype": kindIdent, "skill": kindIdent,
}

// keyNorm normalizes an argument name for the allowlist; built once, it is
// safe for concurrent use.
var keyNorm = strings.NewReplacer("_", "", "-", "")

func allowKind(key string) string {
	if len(key) > MaxKeyLen {
		return ""
	}
	return allowed[keyNorm.Replace(strings.ToLower(key))]
}

var httpMethods = map[string]bool{"GET": true, "HEAD": true, "POST": true, "PUT": true,
	"PATCH": true, "DELETE": true, "OPTIONS": true, "CONNECT": true, "TRACE": true}

// safeValue validates and reduces one allowlisted value.
func safeValue(kind, s string) (string, bool) {
	s = strings.TrimSpace(strings.ToValidUTF8(s, "\uFFFD"))
	if s == "" || strings.ContainsAny(s, "\n\r\t\x00") {
		return "", false // free text or a control character: not an identifier
	}
	switch kind {
	case kindPath:
		if len(s) > MaxValueLen*4 {
			return "", false
		}
	case kindURL:
		u, err := url.Parse(s)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return "", false
		}
		// Scheme and host only: the path and query of a URL carry tokens,
		// search terms and personal data; userinfo carries credentials.
		s = strings.ToLower(u.Scheme) + "://" + u.Host
	case kindMethod:
		s = strings.ToUpper(s)
		if !httpMethods[s] {
			return "", false
		}
	case kindARN:
		if !strings.HasPrefix(s, "arn:") || !identLike(s) {
			return "", false
		}
	case kindIdent:
		if !identLike(s) {
			return "", false
		}
	}
	s = scrub(s)
	return clean(s, MaxValueLen), true
}

// identLike accepts identifier-shaped values: no spaces, bounded, from
// the characters resource ids, ARNs, repository and branch names use.
func identLike(s string) bool {
	if len(s) > MaxValueLen {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune(":/._@+=,-~*#", r):
		default:
			return false
		}
	}
	return true
}

// clean bounds s to n bytes on a rune boundary, with invalid UTF-8 and
// control characters replaced.
func clean(s string, n int) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '_'
		}
		return r
	}, s)
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

var (
	redMu    sync.Mutex
	redactor *redact.Redactor
)

// Scrub masks credential formats in s (internal/redact secrets category).
// Callers outside this package use it for identity values copied from
// witness records.
func Scrub(s string) string { return scrub(s) }

// scrub masks credential formats in s (internal/redact secrets category).
func scrub(s string) string {
	redMu.Lock()
	defer redMu.Unlock()
	if redactor == nil {
		redactor, _ = redact.Parse("secrets")
	}
	return redactor.String(s, "safe_args")
}

// ToolDefDigest fingerprints an MCP tool definition: the hex sha256 of the
// canonical JSON of its name, description, inputSchema and annotations
// (the keys present). Other keys (title, outputSchema, vendor extensions)
// are not part of it. A definition without a name yields "".
func ToolDefDigest(def map[string]json.RawMessage) string {
	if len(def) == 0 {
		return ""
	}
	var name string
	if json.Unmarshal(def["name"], &name) != nil || name == "" {
		return ""
	}
	sub := map[string]json.RawMessage{}
	for _, k := range []string{"name", "description", "inputSchema", "annotations"} {
		if v, ok := def[k]; ok {
			sub[k] = v
		}
	}
	b, err := json.Marshal(sub)
	if err != nil {
		return ""
	}
	return Digest(b)
}

// ServerVersion renders an MCP initialize result's serverInfo as
// "name/version" (bounded). raw is the serverInfo object.
func ServerVersion(raw []byte) string {
	var si struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if json.Unmarshal(raw, &si) != nil {
		return ""
	}
	name, ver := strings.TrimSpace(si.Name), strings.TrimSpace(si.Version)
	switch {
	case name == "" && ver == "":
		return ""
	case ver == "":
		return clean(scrub(name), 128)
	}
	return clean(scrub(name+"/"+ver), 128)
}

// Unwrap returns the arguments inside a JSON string (OpenAI-style tool
// calls record them JSON-encoded: "{\"path\":…}"), or raw unchanged.
func Unwrap(raw []byte) []byte {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '"' {
		return raw
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return raw
	}
	return []byte(s)
}
