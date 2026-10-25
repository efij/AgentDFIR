package detect

import "regexp"

// SecretPattern is one credential format the SECRET rules match, exported
// so derivative redaction (internal/redact) masks exactly what detection
// recognizes instead of keeping a second, drifting list.
type SecretPattern struct {
	Name string
	Re   *regexp.Regexp
}

// SecretPatterns returns the credential formats in rule order. The
// regexps are shared and safe for concurrent use; callers must not
// replace them.
func SecretPatterns() []SecretPattern {
	out := make([]SecretPattern, len(secretPatterns))
	for i, p := range secretPatterns {
		out[i] = SecretPattern{Name: p.name, Re: p.re}
	}
	return out
}
