package supplychain

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/efij/AgentDFIR/v5/internal/detect"
)

// scpUserinfoRe matches the credential part of an scp-style or schemeless
// remote ("user:token@host:path").
var scpUserinfoRe = regexp.MustCompile(`^[^/@\s]*:[^/@\s]*@`)

// safeURL makes a URL or git remote from evidence safe to store and show:
// userinfo is dropped, every query value is replaced by "<redacted>", an
// scp-style remote loses a "user:secret@" prefix (a bare "git@" stays),
// and credential-shaped strings left anywhere are masked. The scheme
// prefix of "git+https://…" is kept.
func safeURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	prefix := ""
	if i := strings.Index(raw, "+"); i > 0 && strings.Contains(raw, "://") && i < strings.Index(raw, "://") {
		prefix, raw = raw[:i+1], raw[i+1:]
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			// Unparseable: drop anything before the last '@' of the authority.
			if i := strings.Index(raw, "://"); i >= 0 {
				rest := raw[i+3:]
				end := strings.IndexAny(rest, "/?#")
				if end < 0 {
					end = len(rest)
				}
				if at := strings.LastIndex(rest[:end], "@"); at >= 0 {
					raw = raw[:i+3] + rest[at+1:]
				}
			}
			return detect.MaskSecrets(prefix + raw)
		}
		u.User = nil
		if u.RawQuery != "" {
			q := u.Query()
			for k := range q {
				q[k] = []string{"<redacted>"}
			}
			u.RawQuery = q.Encode()
		}
		if u.Fragment != "" {
			u.Fragment = "<redacted>"
		}
		return detect.MaskSecrets(prefix + u.String())
	}
	raw = scpUserinfoRe.ReplaceAllString(raw, "")
	return detect.MaskSecrets(prefix + raw)
}
