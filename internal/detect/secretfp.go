package detect

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// SecretFingerprint identifies one credential without carrying it: the
// credential type, the fixed literal every value of that type starts with
// (never a character of the value beyond it), and a truncated SHA-256 of
// the value. Two cases holding the same key produce the same fingerprint,
// which is what cross-case correlation needs; the fingerprint cannot be
// turned back into the key. 64 bits of hash keep accidental collisions out
// of any realistic case set while giving an offline guesser nothing a
// full digest would not.
type SecretFingerprint struct {
	Type        string `json:"type"`
	Prefix      string `json:"prefix"`
	Fingerprint string `json:"fingerprint"` // "sha256:" + first 16 hex digits
	Count       int    `json:"count"`
	FirstOffset int64  `json:"first_offset"`
}

// maxPEMBody bounds how far past a private-key header the body is read.
const maxPEMBody = 16 << 10

// SecretFingerprints fingerprints every credential-format value in data,
// with the same patterns and placeholder rules POTENTIAL_SECRET_EXPOSURE
// uses, so a documentation key that rule ignores is ignored here too. A
// value matched by two patterns (an Anthropic key also has the generic
// sk- shape) is reported once, under the first, more specific type. A
// private key is fingerprinted by its base64 body; a header with no body
// and no END marker within maxPEMBody is not a key and is skipped.
// Output is ordered by first offset, then fingerprint.
func SecretFingerprints(data []byte) []SecretFingerprint {
	byFP := map[string]*SecretFingerprint{}
	for _, p := range secretPatterns {
		for _, start := range anchoredMatches(data, p) {
			m := p.re.Find(data[start:])
			if len(m) == 0 || isPlaceholderSecret(m) {
				continue
			}
			value := m
			if p.name == "PRIVATE_KEY_BLOCK" {
				value = pemBody(data[start+len(m):])
				if value == nil {
					continue
				}
			}
			sum := sha256.Sum256(value)
			fp := "sha256:" + hex.EncodeToString(sum[:8])
			if ex := byFP[fp]; ex != nil {
				if ex.Type == p.name {
					ex.Count++
				}
				continue
			}
			byFP[fp] = &SecretFingerprint{Type: p.name, Prefix: p.lit, Fingerprint: fp, Count: 1, FirstOffset: int64(start)}
		}
	}
	out := make([]SecretFingerprint, 0, len(byFP))
	for _, v := range byFP {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].FirstOffset != out[j].FirstOffset {
			return out[i].FirstOffset < out[j].FirstOffset
		}
		return out[i].Fingerprint < out[j].Fingerprint
	})
	return out
}

// pemBody returns the base64 body between a private-key header and its END
// marker with whitespace and JSON-escaped newlines removed, or nil when
// there is no END marker within maxPEMBody or no body worth the name.
func pemBody(after []byte) []byte {
	if len(after) > maxPEMBody {
		after = after[:maxPEMBody]
	}
	end := bytes.Index(after, []byte("-----END"))
	if end < 0 {
		return nil
	}
	body := bytes.ReplaceAll(after[:end], []byte(`\n`), nil)
	body = bytes.ReplaceAll(body, []byte(`\r`), nil)
	var out []byte
	for _, c := range body {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/', c == '=':
			out = append(out, c)
		}
	}
	if len(out) < 20 {
		return nil
	}
	return out
}

// MaskSecrets replaces every credential-format value in s with its type's
// fixed literal and its fingerprint, so text derived from evidence (a
// lineage label, an exported graph) can name which key a command carried
// without carrying the key. Placeholder-looking values are masked too:
// masking costs nothing, and a missed real key costs a great deal.
func MaskSecrets(s string) string {
	for _, p := range secretPatterns {
		if !strings.Contains(s, p.lit) {
			continue
		}
		s = p.re.ReplaceAllStringFunc(s, func(m string) string {
			if strings.HasPrefix(m, "-----BEGIN") {
				return m // the header alone carries no key material
			}
			sum := sha256.Sum256([]byte(m))
			return p.lit + "…[" + p.name + " sha256:" + hex.EncodeToString(sum[:8]) + "]"
		})
	}
	return s
}
