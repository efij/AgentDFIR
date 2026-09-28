package ioc

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/efij/AgentDFIR/v3/internal/schema"
)

// Lockfiles are the answer to "did we install a bad version?" — the first
// question in every npm-worm response. Parsed offline, never resolved.

const maxLockBytes = 64 << 20

var (
	pnpmRe   = regexp.MustCompile(`^\s+['"]?/?((?:@[^/@\s'"]+/)?[^/@\s:'"()]+)[@/](\d+\.\d+\.\d+[^:'"\s(]*)`)
	yarnVer  = regexp.MustCompile(`^\s+version:?\s+"?([^"\s]+)"?`)
	reqRe    = regexp.MustCompile(`(?i)^\s*([a-z0-9][a-z0-9._-]*)\s*==\s*([0-9][^\s;#]*)`)
	tomlName = regexp.MustCompile(`^name\s*=\s*"([^"]+)"`)
	tomlVer  = regexp.MustCompile(`^version\s*=\s*"([^"]+)"`)
)

func scanLockfile(cols []*collector, p string) {
	fi, err := os.Stat(p)
	if err != nil || fi.Size() > maxLockBytes {
		return
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return
	}
	ts := fi.ModTime().UTC().Format("2006-01-02T15:04:05Z")
	var refs []PkgRef
	name := strings.ToLower(filepath.Base(p))
	switch {
	case strings.HasSuffix(name, ".json"):
		refs = npmLock(b)
	case name == "yarn.lock":
		refs = yarnLock(b)
	case name == "pnpm-lock.yaml":
		refs = lineRefs(b, pnpmRe, "npm")
	case name == "bun.lock":
		for _, m := range pkgTokRe.FindAllSubmatch(bytes.ToLower(b), -1) {
			refs = append(refs, PkgRef{Ecosystem: "npm", Name: string(m[1]), Version: string(m[2])})
		}
	case strings.HasPrefix(name, "requirements"):
		refs = lineRefs(b, reqRe, "pypi")
	case name == "poetry.lock" || name == "uv.lock":
		refs = tomlLock(b)
	}
	for _, r := range refs {
		for _, c := range cols {
			for _, ind := range c.inc.Indicators {
				if ind.MatchPackage(r.Ecosystem, normPkg(r.Ecosystem, r.Name), r.Version) {
					c.add(ind, WhereObserved, "lockfile", p+" ("+r.Name+"@"+r.Version+")", ts, "file_mtime", schema.StateObserved)
				}
			}
		}
	}
}

func normPkg(eco, n string) string {
	n = strings.ToLower(n)
	if eco == "pypi" {
		n = strings.NewReplacer("_", "-", ".", "-").Replace(n)
	}
	return n
}

func npmLock(b []byte) []PkgRef {
	var doc struct {
		Packages     map[string]struct{ Version string } `json:"packages"`
		Dependencies map[string]json.RawMessage          `json:"dependencies"`
	}
	if json.Unmarshal(b, &doc) != nil {
		return nil
	}
	var out []PkgRef
	for k, v := range doc.Packages {
		i := strings.LastIndex(k, "node_modules/")
		if i < 0 || v.Version == "" {
			continue
		}
		out = append(out, PkgRef{Ecosystem: "npm", Name: k[i+len("node_modules/"):], Version: v.Version})
	}
	var walk func(m map[string]json.RawMessage, depth int)
	walk = func(m map[string]json.RawMessage, depth int) {
		if depth > 32 {
			return
		}
		for n, raw := range m {
			var d struct {
				Version      string                     `json:"version"`
				Dependencies map[string]json.RawMessage `json:"dependencies"`
			}
			if json.Unmarshal(raw, &d) != nil {
				continue
			}
			out = append(out, PkgRef{Ecosystem: "npm", Name: n, Version: d.Version})
			walk(d.Dependencies, depth+1)
		}
	}
	if len(doc.Packages) == 0 {
		walk(doc.Dependencies, 0)
	}
	return out
}

func yarnLock(b []byte) []PkgRef {
	var out []PkgRef
	var names []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		l := sc.Text()
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if !strings.HasPrefix(l, " ") && strings.HasSuffix(l, ":") {
			names = names[:0]
			for _, spec := range strings.Split(strings.TrimSuffix(l, ":"), ",") {
				spec = strings.Trim(strings.TrimSpace(spec), `"`)
				at := strings.LastIndex(spec, "@")
				if at <= 0 {
					continue
				}
				names = append(names, spec[:at])
			}
			continue
		}
		if m := yarnVer.FindStringSubmatch(l); m != nil && len(names) > 0 {
			for _, n := range names {
				out = append(out, PkgRef{Ecosystem: "npm", Name: n, Version: m[1]})
			}
			names = names[:0]
		}
	}
	return out
}

func lineRefs(b []byte, re *regexp.Regexp, eco string) []PkgRef {
	var out []PkgRef
	for _, l := range strings.Split(string(b), "\n") {
		if m := re.FindStringSubmatch(l); m != nil {
			out = append(out, PkgRef{Ecosystem: eco, Name: m[1], Version: m[2]})
		}
	}
	return out
}

func tomlLock(b []byte) []PkgRef {
	var out []PkgRef
	name := ""
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "[[package]]" {
			name = ""
			continue
		}
		if m := tomlName.FindStringSubmatch(l); m != nil {
			name = m[1]
			continue
		}
		if m := tomlVer.FindStringSubmatch(l); m != nil && name != "" {
			out = append(out, PkgRef{Ecosystem: "pypi", Name: name, Version: m[1]})
			name = ""
		}
	}
	return out
}
