package decode

import (
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Base64 is everywhere in a normal transcript — images, JWTs, lockfile
// integrity hashes, source maps. Decoding all of it would turn every rule
// into a false-positive generator, so commands are decoded only when they
// carry a decode step or hand a string to an interpreter: the shape of a
// payload, not the shape of data.
var (
	decodeCtxRe = regexp.MustCompile(`(?i)(\bbase64\s+(-d|--decode|-D)\b|\bb64decode\b|\batob\(|FromBase64String|Buffer\.from\([^)]*['"](base64|hex)['"]|\s-e(nc(odedcommand)?)?\s|\bxxd\s+-r|\bbase32\s+(-d|--decode)\b|\bfromhex\b|\bdecompress\b|\bgunzip\b|\bzcat\b|\bpython[0-9.]*\s+-c\b|\bnode\s+-e\b|\bperl\s+-e\b|\beval\b|\b(ba|z|da)?sh\s+-c\b|\b(powershell|pwsh)\b|\biex\b|String\.fromCharCode)`)
	base32CtxRe = regexp.MustCompile(`(?i)\bbase32\b|b32decode`)
	// A decode step whose output is executed: `… | base64 -d | sh` (the
	// interpreter reads its program from stdin — `| python3 -c '…'` reads
	// data, not code),
	// `eval "$(echo … | base64 -d)"`, `exec(b64decode(…))`, `powershell -enc`.
	decodeExecRe = regexp.MustCompile(`(?i)((base64\s+(-d|--decode|-D)|xxd\s+-r|base32\s+-d|gunzip|zcat)[^;&]*\|\s*(sudo\s+)?(((ba|z|da)?sh|python[0-9.]*|node|perl|ruby|bash)(\s+-s?)?\s*($|[;&|)'"])|iex\b)|\beval\b[^;&]*\b(base64|b64decode|atob|xxd)\b|\bexec\s*\([^)]*\b(b64decode|decompress|fromhex|a2b_base64)\b|\b(powershell|pwsh)\b[^;&]*\s-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{16,}|\biex\b[^;&]*FromBase64String)`)

	jwtRe      = regexp.MustCompile(`^eyJ[A-Za-z0-9_-]+$`)
	charCodeRe = regexp.MustCompile(`String\.fromCharCode\(\s*((?:\d{1,6}\s*,\s*){7,}\d{1,6})\s*\)`)
)

// HasDecodeContext reports whether a command decodes or evaluates a string.
func HasDecodeContext(cmd string) bool { return decodeCtxRe.MatchString(cmd) }

// ExecutesDecoded reports whether a command pipes a decode step into an
// interpreter (or evals / execs decoded data).
func ExecutesDecoded(cmd string) bool { return decodeExecRe.MatchString(cmd) }

// FindInCommand returns the payloads a command line carries, gated on
// decode context. Returns nil for commands with no decode step.
func FindInCommand(cmd string) []Result {
	if !HasDecodeContext(cmd) {
		return nil
	}
	allow32 := base32CtxRe.MatchString(cmd)
	var out []Result
	for _, r := range findGated(cmd, allow32) {
		out = append(out, r)
	}
	for _, m := range charCodeRe.FindAllStringSubmatchIndex(cmd, 4) {
		if t, ok := fromCharCodes(cmd[m[2]:m[3]]); ok {
			out = append(out, Result{Chain: []string{"charcode"}, Text: t, Offset: m[0]})
		}
	}
	return out
}

func findGated(s string, allow32 bool) []Result {
	var out []Result
	seen := map[string]bool{}
	gate := func(c cand, dec string, src string) bool {
		if dec == "base32" && !allow32 {
			return false
		}
		return !preReject(c, src)
	}
	findWith(normalize(s), nil, 0, 0, &out, seen, gate)
	return out
}

// preReject drops blobs whose surroundings say they are data: a JWT, a
// data: URI, a lockfile/SRI integrity hash, a git SHA or a digest.
func preReject(c cand, s string) bool {
	if jwtRe.MatchString(c.text) && strings.HasPrefix(s[c.start+len(c.text):], ".") {
		return true
	}
	before := s[:c.start]
	if len(before) > 16 {
		before = before[len(before)-16:]
	}
	lb := strings.ToLower(before)
	if strings.HasSuffix(lb, "base64,") && strings.Contains(lb, "data:") || strings.Contains(lb, "data:") && strings.HasSuffix(lb, ",") {
		return true
	}
	for _, p := range []string{"sha1-", "sha256-", "sha384-", "sha512-", "sha256:", "sha512:"} {
		if strings.HasSuffix(lb, p) {
			return true
		}
	}
	if allHex(c.text) && (len(c.text) == 40 || len(c.text) == 64) {
		return true
	}
	return false
}

// utf16le converts PowerShell's -EncodedCommand encoding (UTF-16LE) to UTF-8
// when every other byte is zero — otherwise the printable test rejects the
// one format Windows payloads actually use.
func utf16le(b []byte) ([]byte, bool) {
	if len(b) < 8 || len(b)%2 != 0 {
		return nil, false
	}
	zeros := 0
	for i := 1; i < len(b); i += 2 {
		if b[i] == 0 {
			zeros++
		}
	}
	if zeros*10 < (len(b)/2)*9 {
		return nil, false
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	return []byte(string(utf16.Decode(u))), true
}

func fromCharCodes(list string) (string, bool) {
	var b strings.Builder
	for _, f := range strings.Split(list, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil || n < 0 || n > 0x10ffff {
			return "", false
		}
		b.WriteRune(rune(n))
	}
	out := b.String()
	return out, readable([]byte(out))
}
