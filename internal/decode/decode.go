// Package decode unwraps encoded payloads found in agent commands and
// transcripts — base64, base32, hex, and gzip/zlib/bzip2 inside them —
// entirely offline.
//
// The OpenAI–Hugging Face agent intrusion (July 2026) hid its programs in
// more than 80,000 payloads wrapped in 1,588 combinations of encodings, and
// the responders' commercial models refused to decode them. A rule that
// reads `curl … | sh` does not fire on `echo H4sI… | base64 -d | gunzip |
// sh`; this package gives every rule a second look at what the shell would
// actually have run.
//
// Bounded by construction: a blob is at most MaxBlob bytes, decompression
// stops at MaxOut, at most MaxBlobs candidates per input and MaxDepth
// layers, so a decompression bomb costs a few hundred KB and nothing more.
package decode

import (
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"compress/zlib"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Limits. Exported so callers and tests can reason about the worst case.
const (
	MaxBlob  = 64 << 10  // longest encoded candidate considered
	MaxOut   = 256 << 10 // most bytes one decompression may produce
	MaxBlobs = 32        // candidates per input string
	MaxDepth = 4         // nested layers followed
	minB64   = 24
	minB32   = 32
	minHex   = 32
)

// Result is one decoded payload.
type Result struct {
	Chain  []string // e.g. ["base64", "gzip"]
	Text   string   // the decoded text
	Offset int      // byte offset of the outermost blob in the input; -1 when line-wrapped input was joined first
}

// ChainString renders the layers as "base64→gzip".
func (r Result) ChainString() string { return strings.Join(r.Chain, "→") }

var (
	// Whitespace inside a quoted blob is folded before matching (see
	// normalize), so a payload split across lines still decodes.
	b64Re = regexp.MustCompile(`[A-Za-z0-9+/_-]{24,}={0,2}`)
	b32Re = regexp.MustCompile(`[A-Za-z2-7]{32,}={0,6}`)
	hexRe = regexp.MustCompile(`(?:\\x)?[0-9a-fA-F]{2}(?:(?:\\x)?[0-9a-fA-F]{2}){15,}`)
)

// Find returns every payload in s that decodes to readable text, outermost
// first. Results whose text is identical are reported once.
func Find(s string) []Result {
	var out []Result
	seen := map[string]bool{}
	ns := normalize(s)
	findWith(ns, nil, 0, 0, &out, seen, func(c cand, dec, src string) bool { return !preReject(c, src) })
	if ns != s {
		// Offsets index the joined text, not the input: do not report them.
		for i := range out {
			out[i].Offset = -1
		}
	}
	return out
}

// normalize folds line continuations and whitespace runs inside long
// runs of base64-alphabet text, so "SGVsbG8g\nd29ybGQ=" is one blob.
func normalize(s string) string {
	if !strings.ContainsAny(s, "\n\r\\") {
		return s
	}
	s = strings.ReplaceAll(s, "\\\n", "")
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c == '\n' || c == '\r') && i > 0 && i+1 < len(s) && isB64(s[i-1]) && isB64(s[i+1]) {
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func isB64(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '='
}

type cand struct {
	start int
	text  string
}

func candidates(s string) []cand {
	var cs []cand
	add := func(re *regexp.Regexp) {
		for _, m := range re.FindAllStringIndex(s, MaxBlobs) {
			if m[1]-m[0] > MaxBlob {
				continue
			}
			cs = append(cs, cand{m[0], s[m[0]:m[1]]})
		}
	}
	add(hexRe)
	add(b64Re)
	add(b32Re)
	if len(cs) > MaxBlobs {
		cs = cs[:MaxBlobs]
	}
	return cs
}

// findWith walks candidates; gate may veto a (candidate, decoder) pair.
func findWith(s string, chain []string, base, depth int, out *[]Result, seen map[string]bool, gate func(c cand, dec, src string) bool) {
	if depth >= MaxDepth || len(*out) >= MaxBlobs {
		return
	}
	for _, c := range candidates(s) {
		for _, d := range decoders {
			if !gate(c, d.name, s) {
				continue
			}
			raw, ok := d.fn(c.text)
			if !ok {
				continue
			}
			layers := append(append([]string(nil), chain...), d.name)
			raw, layers = inflate(raw, layers)
			if u, ok := utf16le(raw); ok {
				raw, layers = u, append(layers, "utf16le")
			}
			if !readable(raw) {
				continue
			}
			text := string(raw)
			if seen[text] || strings.TrimSpace(text) == "" {
				break
			}
			seen[text] = true
			off := base
			if depth == 0 {
				off = c.start
			}
			*out = append(*out, Result{Chain: layers, Text: text, Offset: off})
			// The payload may itself carry another encoded layer.
			findWith(text, layers, off, depth+1, out, seen, gate)
			break
		}
		if len(*out) >= MaxBlobs {
			return
		}
	}
}

type decoder struct {
	name string
	fn   func(string) ([]byte, bool)
}

// Hex before base64: a hex string is also valid base64 and would decode to
// noise. Base32 last: its alphabet is a subset of base64's.
var decoders = []decoder{
	{"hex", decHex},
	{"base64", decB64},
	{"base32", decB32},
}

func decHex(s string) ([]byte, bool) {
	s = strings.ReplaceAll(s, `\x`, "")
	if len(s) < minHex || len(s)%2 != 0 || !allHex(s) {
		return nil, false
	}
	b, err := hex.DecodeString(s)
	return b, err == nil
}

func allHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func decB64(s string) ([]byte, bool) {
	if len(s) < minB64 {
		return nil, false
	}
	// A word made of letters only (a long identifier, a CamelCase name) is
	// valid base64 and decodes to binary noise; readable() rejects that, but
	// skipping it early saves the work on large transcripts.
	if !strings.ContainsAny(s, "0123456789+/=_-") && strings.ToLower(s) == s {
		return nil, false
	}
	trim := strings.TrimRight(s, "=")
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(trim); err == nil {
			return b, true
		}
	}
	return nil, false
}

func decB32(s string) ([]byte, bool) {
	if len(s) < minB32 {
		return nil, false
	}
	u := strings.ToUpper(strings.TrimRight(s, "="))
	b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(u)
	return b, err == nil
}

// inflate follows compression layers (gzip, zlib, bzip2), bounded by MaxOut.
func inflate(b []byte, chain []string) ([]byte, []string) {
	for i := 0; i < MaxDepth; i++ {
		var r io.Reader
		var name string
		switch {
		case len(b) > 2 && b[0] == 0x1f && b[1] == 0x8b:
			zr, err := gzip.NewReader(bytes.NewReader(b))
			if err != nil {
				return b, chain
			}
			r, name = zr, "gzip"
		case len(b) > 2 && b[0] == 0x78 && (b[1] == 0x01 || b[1] == 0x5e || b[1] == 0x9c || b[1] == 0xda):
			zr, err := zlib.NewReader(bytes.NewReader(b))
			if err != nil {
				return b, chain
			}
			r, name = zr, "zlib"
		case len(b) > 3 && b[0] == 'B' && b[1] == 'Z' && b[2] == 'h':
			r, name = bzip2.NewReader(bytes.NewReader(b)), "bzip2"
		default:
			return b, chain
		}
		out, err := io.ReadAll(io.LimitReader(r, MaxOut))
		if len(out) == 0 || (err != nil && err != io.ErrUnexpectedEOF) {
			return b, chain
		}
		if len(out) > 100*len(b) && len(out) >= MaxOut {
			// A >100× ratio that fills the cap is a bomb, not a script.
			return b, chain
		}
		b, chain = out, append(chain, name)
	}
	return b, chain
}

// readable: valid UTF-8, at least 85% printable, and at least 8 bytes.
// Binary (images, keys, protobufs) is never reported as a payload.
func readable(b []byte) bool {
	if len(b) < 8 || !utf8.Valid(b) {
		return false
	}
	printable, total := 0, 0
	for _, r := range string(b) {
		total++
		if r == '\n' || r == '\r' || r == '\t' || (r >= 0x20 && r != 0x7f && r != utf8.RuneError) {
			printable++
		}
	}
	return total > 0 && printable*100 >= total*85
}
