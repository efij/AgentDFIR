package crosscase

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"sort"
	"strings"

	"github.com/efij/AgentDFIR/v5/internal/detect"
)

// urlIdentity turns a URL from evidence (an MCP server endpoint, a package
// reference) into a matching key and a display form, neither of which can
// carry a credential embedded in it.
//
// Key: the SHA-256 of the normalized URL — lower-cased scheme and host, the
// port, the path, and the query as sorted names with each value replaced by
// its fingerprint. Two cases using the same server with the same token
// match; the token itself is never in the key.
//
// Display: scheme://host[:port]/path, userinfo dropped, every query value
// replaced by "<sha256:…>", then MaskSecrets over the result for anything
// credential-shaped left in the path. A URL that does not parse is shown
// only by its fingerprint.
func urlIdentity(raw string) (key, display string) {
	raw = strings.TrimSpace(raw)
	scheme := ""
	if i := strings.Index(raw, "+"); i > 0 && i < strings.Index(raw, "://") {
		scheme, raw = raw[:i+1], raw[i+1:] // git+https://… keeps its prefix
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		fp := fingerprint(raw)
		return fp, "unparseable URL " + fp
	}
	norm := strings.ToLower(scheme+u.Scheme) + "://" + strings.ToLower(u.Host) + u.EscapedPath()
	q := u.Query()
	names := make([]string, 0, len(q))
	for n := range q {
		names = append(names, n)
	}
	sort.Strings(names)
	var parts []string
	for _, n := range names {
		vals := append([]string(nil), q[n]...)
		sort.Strings(vals)
		for _, v := range vals {
			parts = append(parts, url.QueryEscape(n)+"=<"+fingerprint(v)+">")
		}
	}
	if len(parts) > 0 {
		norm += "?" + strings.Join(parts, "&")
	}
	if u.Fragment != "" {
		norm += "#<" + fingerprint(u.Fragment) + ">"
	}
	return fingerprint(norm), detect.MaskSecrets(norm)
}

func fingerprint(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:8])
}
