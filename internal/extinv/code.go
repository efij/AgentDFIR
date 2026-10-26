package extinv

import (
	"bytes"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/efij/AgentDFIR/v5/internal/detect"
	"github.com/efij/AgentDFIR/v5/internal/shellshape"
)

// ---- invisible code

// Invisible-character classes. GlassWorm-class loaders encode a payload
// one byte per invisible code point (variation selectors are the usual
// carrier) inside what renders as an empty string, then decode and eval
// it. A reviewer, a diff and most editors show nothing.
//
// The signal is a RUN: legitimate code never carries dozens of these in a
// row. A single U+FE0F after an emoji, a bidi mark in Hebrew UI text, an
// icon-font glyph in a string — all isolated — never reach the threshold,
// however much non-ASCII a localized extension contains.
const (
	invisibleRunThreshold = 16 // consecutive strong invisible code points
	puaRunThreshold       = 64 // consecutive private-use code points (icon fonts make shorter runs plausible)
)

// strongInvisible: no visible rendering and no business in source code
// in bulk.
func strongInvisible(r rune) bool {
	switch {
	case r >= 0xFE00 && r <= 0xFE0F: // variation selectors
		return true
	case r >= 0xE0100 && r <= 0xE01EF: // variation selectors supplement
		return true
	case r >= 0xE0000 && r <= 0xE007F: // tag characters
		return true
	case r >= 0x200B && r <= 0x200F, r >= 0x2060 && r <= 0x2064, r == 0xFEFF: // zero-width, invisible operators
		return true
	case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069: // bidi controls
		return true
	case r == 0x115F, r == 0x1160, r == 0x3164, r == 0xFFA0: // Hangul fillers (invisible identifiers)
		return true
	}
	return false
}

func privateUse(r rune) bool {
	return (r >= 0xE000 && r <= 0xF8FF) || (r >= 0xF0000 && r <= 0xFFFFD) || (r >= 0x100000 && r <= 0x10FFFD)
}

// codeSignals is what the heuristics found in an extension's entry code.
type codeSignals struct {
	InvisibleRun    int   // longest run of strong invisible code points
	InvisibleTotal  int   // all strong invisible code points
	PUARun          int   // longest run of private-use code points
	InvisibleOffset int64 // byte offset where the longest run starts (-1 none)
	Decoder         bool  // code-point arithmetic over the variation-selector ranges
	DynamicExec     bool  // eval / new Function / vm.run*
	Loader          []string
	Network         bool
}

func (s *codeSignals) merge(o codeSignals) {
	if o.InvisibleRun > s.InvisibleRun {
		s.InvisibleRun, s.InvisibleOffset = o.InvisibleRun, o.InvisibleOffset
	}
	s.InvisibleTotal += o.InvisibleTotal
	if o.PUARun > s.PUARun {
		s.PUARun = o.PUARun
	}
	s.Decoder = s.Decoder || o.Decoder
	s.DynamicExec = s.DynamicExec || o.DynamicExec
	s.Network = s.Network || o.Network
	for _, l := range o.Loader {
		if !contains(s.Loader, l) {
			s.Loader = append(s.Loader, l)
		}
	}
}

var (
	// Arithmetic on the variation-selector ranges: how a decoder turns
	// invisible code points back into bytes.
	vsDecoderRe = regexp.MustCompile(`(?i)\b(0xfe0[0f]|0xe01[0-9a-f]{2}|0xe0100|65024|65039|917760|917999)\b`)
	dynExecRe   = regexp.MustCompile(`\beval\s*\(|\bnew\s+Function\s*\(|\bvm\.(runInThisContext|runInNewContext|runInContext)\s*\(|\bnew\s+vm\.Script\s*\(`)

	// Loader shapes. Code patterns only: no domains, no hashes.
	evalDecodedRe = regexp.MustCompile(`(\beval|\bnew\s+Function|\bFunction)\s*\(\s*(atob|Buffer\.from|unescape|decodeURIComponent|[A-Za-z_$][\w$]*\.from\([^)]{0,40}base64)\s*\(`)
	shellFetchRe  = regexp.MustCompile("(?i)(curl|wget)\\b[^\"'`\\n]{0,200}\\|\\s*(sudo\\s+)?(ba|z|da)?sh\\b|\\b(powershell|pwsh)(\\.exe)?\\b[^\"'`\\n]{0,80}\\s-(e|ec|enc|encodedcommand)\\s+[A-Za-z0-9+/=]{16,}|\\biex\\s*\\(\\s*(new-object|iwr|irm|invoke-webrequest|invoke-restmethod)\\b|Invoke-Expression\\s*\\(?\\s*\\(?\\s*(iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\\b")
	// Code fetched as text and executed: a dead drop (a paste, a calendar
	// entry, a blockchain memo) read at run time.
	fetchEvalRe = regexp.MustCompile(`\.text\(\)\s*\)?\s*\.then\(\s*(eval|Function)\b|\.then\(\s*\(?\s*[\w$]+\s*\)?\s*=>\s*(eval|new\s+Function)\s*\(\s*[\w$]+\s*\)|\b(eval|new\s+Function)\s*\(\s*await\s+[\w$.]+\.(text|json)\(\)|\b(eval|new\s+Function)\s*\(\s*\(\s*await\s+[\w$.]+\s*\)\.data\b`)
)

// scanCode runs every code heuristic over one entry file.
func scanCode(b []byte) codeSignals {
	s := codeSignals{InvisibleOffset: -1}
	if len(b) == 0 {
		return s
	}
	run, puaRun := 0, 0
	runStart := 0
	for off := 0; off < len(b); {
		c := b[off]
		if c < utf8.RuneSelf {
			run, puaRun = 0, 0
			off++
			continue
		}
		r, size := utf8.DecodeRune(b[off:])
		switch {
		case strongInvisible(r) && !(r == 0xFEFF && off == 0):
			if run == 0 {
				runStart = off
			}
			run++
			s.InvisibleTotal++
			puaRun = 0
			if run > s.InvisibleRun {
				s.InvisibleRun, s.InvisibleOffset = run, int64(runStart)
			}
		case privateUse(r):
			puaRun++
			run = 0
			if puaRun > s.PUARun {
				s.PUARun = puaRun
			}
		default:
			run, puaRun = 0, 0
		}
		off += size
	}
	// The regexes run only in windows around literal anchors: Go's regexp
	// over a whole multi-megabyte bundle costs seconds per pattern, and an
	// editor profile holds dozens of bundles.
	s.Decoder = anyWindow(b, codePointAnchors, 200, 200, vsDecoderRe)
	s.DynamicExec = anyWindow(b, dynExecAnchors, 16, 24, dynExecRe)
	s.Network = containsAny(b, networkLiterals)

	if anyWindow(b, decodeAnchors, 40, 8, evalDecodedRe) {
		s.Loader = append(s.Loader, "evaluates a decoded string (eval/Function over atob or Buffer.from)")
	}
	if blobNearExec(b, isB64, 400) {
		s.Loader = append(s.Loader, "a long base64 blob next to eval/new Function/vm")
	}
	if blobNearExec(b, isHex, 800) {
		s.Loader = append(s.Loader, "a long hex blob next to eval/new Function/vm")
	}
	if containsAny(b, childProcLiterals) {
		low := bytes.ToLower(b)
		if anyWindow(low, shellAnchors, 220, 220, shellFetchRe) {
			s.Loader = append(s.Loader, "spawns a shell that downloads and runs code (curl|sh, powershell -enc, iex)")
		}
	}
	if s.DynamicExec && anyWindow(b, dynExecAnchors, 80, 80, fetchEvalRe) {
		s.Loader = append(s.Loader, "fetches text at run time and executes it")
	}
	if s.DynamicExec && containsAny(b, solanaLiterals) {
		s.Loader = append(s.Loader, "reads blockchain transactions (Solana RPC) and contains dynamic code execution")
	}
	return s
}

var (
	codePointAnchors  = [][]byte{[]byte("codePointAt"), []byte("charCodeAt")}
	dynExecAnchors    = [][]byte{[]byte("eval"), []byte("Function"), []byte("vm.")}
	decodeAnchors     = [][]byte{[]byte("atob"), []byte("Buffer.from"), []byte("unescape"), []byte("decodeURIComponent"), []byte(".from(")}
	shellAnchors      = [][]byte{[]byte("curl"), []byte("wget"), []byte("powershell"), []byte("pwsh"), []byte("iex"), []byte("invoke-expression")}
	childProcLiterals = [][]byte{[]byte("child_process"), []byte("execSync"), []byte("spawnSync")}
	// Solana RPC calls in an editor extension: the GlassWorm family read
	// its next-stage location from transaction memos.
	solanaLiterals  = [][]byte{[]byte("getSignaturesForAddress"), []byte("getParsedTransaction"), []byte("getConfirmedSignaturesForAddress2")}
	networkLiterals = [][]byte{[]byte("XMLHttpRequest"), []byte("WebSocket("), []byte("fetch("), []byte(`"https"`), []byte(`'https'`),
		[]byte(`"http"`), []byte(`'http'`), []byte("node:https"), []byte("node:http"), []byte(`"net"`), []byte(`'net'`),
		[]byte(`"tls"`), []byte(`'tls'`), []byte("axios"), []byte("node-fetch"), []byte("undici")}
)

func containsAny(b []byte, lits [][]byte) bool {
	for _, l := range lits {
		if bytes.Contains(b, l) {
			return true
		}
	}
	return false
}

// maxAnchorHits bounds the windows examined per anchor (hostile input can
// repeat an anchor millions of times).
const maxAnchorHits = 200000

// anyWindow reports whether re matches within [before, after] bytes of
// any occurrence of an anchor.
func anyWindow(b []byte, anchors [][]byte, before, after int, re *regexp.Regexp) bool {
	for _, a := range anchors {
		hits := 0
		for off := 0; off < len(b); {
			i := bytes.Index(b[off:], a)
			if i < 0 {
				break
			}
			i += off
			lo, hi := i-before, i+len(a)+after
			if lo < 0 {
				lo = 0
			}
			if hi > len(b) {
				hi = len(b)
			}
			if re.Match(b[lo:hi]) {
				return true
			}
			if hits++; hits > maxAnchorHits {
				break
			}
			off = i + len(a)
		}
	}
	return false
}

func isB64(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/'
}

func isHex(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }

func isQuote(c byte) bool { return c == '"' || c == '\'' || c == '`' }

// blobNearExec: a quoted literal of at least min encoded characters with
// dynamic execution within a few hundred bytes. Inlined wasm and fonts are
// blobs too, but they are handed to WebAssembly or a data URI, not to eval.
func blobNearExec(b []byte, class func(byte) bool, min int) bool {
	checked := 0
	for i := 0; i < len(b); {
		if !class(b[i]) {
			i++
			continue
		}
		j := i
		for j < len(b) && class(b[j]) {
			j++
		}
		end := j
		for end < len(b) && end-j < 2 && b[end] == '=' {
			end++
		}
		if j-i >= min && i > 0 && isQuote(b[i-1]) && end < len(b) && isQuote(b[end]) {
			lo, hi := i-300, end+300
			if lo < 0 {
				lo = 0
			}
			if hi > len(b) {
				hi = len(b)
			}
			if anyWindow(b[lo:i], dynExecAnchors, 16, 24, dynExecRe) || anyWindow(b[end:hi], dynExecAnchors, 16, 24, dynExecRe) {
				return true
			}
			if checked++; checked > 64 {
				return false
			}
		}
		i = j + 1
	}
	return false
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ---- hidden instructions in skill / agent / command markdown

type hiddenSignals struct {
	Tags, Bidi, ZeroWidth, VS int
	Phrase                    string // outside quotes
	QuotedPhrase              string // only inside quotes or "do not tell the user to …"
}

func (h hiddenSignals) invisible() bool {
	// Same bar as the case-wide INVISIBLE_UNICODE_INSTRUCTION rule: tag
	// characters always; bidi and zero-width only in numbers that ordinary
	// right-to-left text and emoji do not produce.
	return h.Tags > 0 || h.Bidi >= 3 || h.ZeroWidth >= 8 || h.VS >= invisibleRunThreshold
}

func scanHidden(text, p string) hiddenSignals {
	var h hiddenSignals
	for i, r := range text {
		switch {
		case r >= 0xE0000 && r <= 0xE007F:
			h.Tags++
		case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
			h.Bidi++
		case r >= 0x200B && r <= 0x200D, r == 0x2060, r == 0xFEFF && i > 0:
			h.ZeroWidth++
		case r >= 0xFE00 && r <= 0xFE0E, r >= 0xE0100 && r <= 0xE01EF:
			// U+FE0F (emoji presentation) is excluded: every emoji has one.
			h.VS++
		}
	}
	// A security tool's own rule material quotes the phrases it detects.
	if !shellshape.SelfReferentialPath(p) && !docsOrTests(p) {
		if ph, ok := detect.ToolContentPhrase(unquoted(text)); ok {
			h.Phrase = ph
		} else if ph, ok := detect.ToolContentPhrase(text); ok {
			h.QuotedPhrase = ph
		}
	}
	return h
}

var (
	// A phrase inside quotes is being quoted — a defensive skill telling
	// the model what to refuse ("ignore previous instructions," …).
	quotedRe = regexp.MustCompile("\"[^\"\\n]{0,200}\"|“[^”\\n]{0,200}”|`[^`\\n]{0,200}`")
	// "do not tell the user to run X" is advice about the user, not secrecy.
	tellToRe = regexp.MustCompile(`(?i)(do not tell the user|without informing the user) to\b`)
)

func unquoted(text string) string {
	return tellToRe.ReplaceAllString(quotedRe.ReplaceAllString(text, " "), " ")
}

func docsOrTests(p string) bool {
	l := "/" + strings.ToLower(p)
	return strings.Contains(l, "/tests/") || strings.Contains(l, "/test/") || strings.Contains(l, "/__tests__/") ||
		strings.Contains(l, "/docs/reports/") || strings.Contains(l, "/changelog")
}
