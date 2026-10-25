package suite

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Cellebrite extraction descriptors.
//
// A .ufd file is an INI-style text file written next to an extraction:
// [Section] headers and Key=Value lines (acquisition date, extraction
// type, device vendor/model, tool version, the dump files and their
// hashes). A .ufdx file is an XML document that groups extractions. Both
// are read generically: every section/key (or element/attribute) is kept
// with its name, device identifiers are masked in the normalized output,
// and file names with an evidence-container extension are listed as the
// images the descriptor links to. No key is given a meaning beyond its
// name.

// Bounds for descriptors.
const (
	MaxDescriptorBytes = 1 << 20
	maxDescriptorKeys  = 4096
	maxLinked          = 256
	maxUFDXTokens      = 200000
)

// UFD is a parsed descriptor.
type UFD struct {
	Format   string // "ufd-ini" | "ufdx-xml"
	Root     string // UFDX root element
	Sections []UFDSection
	Linked   []string // file names the descriptor references, in order, deduplicated
	Dropped  int      // keys over the bound
	Problems []string
}

// UFDSection is one [Section] (or, for UFDX, one element path).
type UFDSection struct {
	Name string
	Keys []KV
}

var linkedExtRe = regexp.MustCompile(`(?i)\.(bin|img|dd|raw|e01|ex01|zip|tar|tgz|gz|7z|ufdr|ufd|dmg|dar|clbx|ufdx)$`)

// linkedName returns the base name of v when v names an evidence file.
func linkedName(v string) string {
	v = strings.Trim(strings.TrimSpace(v), `"'`)
	if v == "" || len(v) > 1024 {
		return ""
	}
	base := path.Base(strings.ReplaceAll(v, `\`, "/"))
	if strings.ContainsAny(base, "<>|*?\x00") || !linkedExtRe.MatchString(base) {
		return ""
	}
	return base
}

// ParseUFD reads an INI-style .ufd descriptor.
func ParseUFD(r io.Reader) (*UFD, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxDescriptorBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxDescriptorBytes {
		return nil, fmt.Errorf("descriptor exceeds %d bytes", MaxDescriptorBytes)
	}
	data = decodeUTF16(data)
	u := &UFD{Format: "ufd-ini"}
	seen := map[string]bool{}
	link := func(v string) {
		if n := linkedName(v); n != "" && !seen[strings.ToLower(n)] && len(u.Linked) < maxLinked {
			seen[strings.ToLower(n)] = true
			u.Linked = append(u.Linked, n)
		}
	}
	keys := 0
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(strings.TrimPrefix(sc.Text(), "\xef\xbb\xbf"))
		if line == "" || line[0] == ';' || line[0] == '#' {
			continue
		}
		if line[0] == '[' && strings.HasSuffix(line, "]") {
			u.Sections = append(u.Sections, UFDSection{Name: clip(line[1:len(line)-1], 128)})
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			if len(u.Problems) < 8 {
				u.Problems = append(u.Problems, fmt.Sprintf("line %d: not a [section] or key=value line", n))
			}
			continue
		}
		if len(u.Sections) == 0 {
			u.Sections = append(u.Sections, UFDSection{Name: ""})
		}
		if keys >= maxDescriptorKeys {
			u.Dropped++
			continue
		}
		keys++
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		s := &u.Sections[len(u.Sections)-1]
		s.Keys = append(s.Keys, KV{clip(k, 128), clip(v, 1024)})
		link(k)
		link(v)
	}
	if err := sc.Err(); err != nil {
		return u, fmt.Errorf("line %d: %w", n+1, err)
	}
	if len(u.Sections) == 0 {
		return u, fmt.Errorf("no [section] or key=value lines")
	}
	return u, nil
}

// ParseUFDX reads an XML .ufdx descriptor generically: every attribute and
// text value is kept under its element path; evidence file names among
// them are the linked files.
func ParseUFDX(r io.Reader) (u *UFD, err error) {
	u = &UFD{Format: "ufdx-xml"}
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("ufdx reader stopped: %v", p)
		}
	}()
	dec := xml.NewDecoder(io.LimitReader(r, MaxDescriptorBytes))
	dec.Strict = true
	dec.CharsetReader = func(label string, _ io.Reader) (io.Reader, error) {
		return nil, fmt.Errorf("character set %q is not supported", label)
	}
	seen := map[string]bool{}
	link := func(v string) {
		if n := linkedName(v); n != "" && !seen[strings.ToLower(n)] && len(u.Linked) < maxLinked {
			seen[strings.ToLower(n)] = true
			u.Linked = append(u.Linked, n)
		}
	}
	idx := map[string]int{}
	add := func(sect, k, v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		link(v)
		i, ok := idx[sect]
		if !ok {
			if len(u.Sections) >= maxDescriptorKeys {
				u.Dropped++
				return
			}
			i = len(u.Sections)
			idx[sect] = i
			u.Sections = append(u.Sections, UFDSection{Name: sect})
		}
		if len(u.Sections[i].Keys) >= 256 {
			u.Dropped++
			return
		}
		u.Sections[i].Keys = append(u.Sections[i].Keys, KV{clip(k, 128), clip(v, 1024)})
	}
	var stack []string
	for n := 0; ; n++ {
		if n > maxUFDXTokens {
			return u, fmt.Errorf("more than %d XML tokens", maxUFDXTokens)
		}
		tok, terr := dec.Token()
		if terr == io.EOF {
			break
		}
		if terr != nil {
			return u, terr
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if len(stack) >= 64 {
				return u, fmt.Errorf("element nesting exceeds 64 levels")
			}
			stack = append(stack, t.Name.Local)
			if u.Root == "" {
				u.Root = t.Name.Local
			}
			sect := strings.Join(stack, "/")
			for _, a := range t.Attr {
				add(sect, a.Name.Local, a.Value)
			}
		case xml.CharData:
			if len(stack) > 0 {
				add(strings.Join(stack[:len(stack)-1], "/"), stack[len(stack)-1], string(t))
			}
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}
	if u.Root == "" {
		return u, fmt.Errorf("no XML element")
	}
	return u, nil
}

// decodeUTF16 converts a UTF-16 descriptor (BOM-marked) to UTF-8.
func decodeUTF16(b []byte) []byte {
	if len(b) >= 2 && ((b[0] == 0xFF && b[1] == 0xFE) || (b[0] == 0xFE && b[1] == 0xFF)) {
		out, _ := io.ReadAll(newUTF16Reader(bytes.NewReader(b[2:]), b[0] == 0xFE))
		return out
	}
	return b
}

// summaryKeys are the descriptor key names (case-insensitive substrings)
// shown in an event summary; every key is in the entity attributes.
var summaryKeys = []string{"date", "time", "type", "model", "vendor", "manufacturer", "version", "tool", "os", "device"}

// Summary renders the descriptor's notable keys (identifiers masked) and
// linked files for case notes and events.
func (u *UFD) Summary(max int) string {
	var parts []string
	for _, s := range u.Sections {
		for _, kv := range s.Keys {
			l := strings.ToLower(kv.Name)
			show := idCategory(kv.Name) != ""
			for _, k := range summaryKeys {
				if strings.Contains(l, k) {
					show = true
					break
				}
			}
			if show {
				name := kv.Name
				if s.Name != "" {
					name = s.Name + "." + kv.Name
				}
				parts = append(parts, name+"="+maskField(kv.Name, kv.Value))
			}
		}
	}
	if len(u.Linked) > 0 {
		parts = append(parts, "linked files: "+strings.Join(u.Linked, ", "))
	}
	return clip(strings.Join(parts, "; "), max)
}

// Attributes returns every key as an entity attribute, identifiers masked.
func (u *UFD) Attributes(max int) map[string]string {
	out := map[string]string{}
	for _, s := range u.Sections {
		for _, kv := range s.Keys {
			if len(out) >= max {
				return out
			}
			k := "ufd:" + kv.Name
			if s.Name != "" {
				k = "ufd:" + s.Name + "." + kv.Name
			}
			out[k] = clip(maskField(kv.Name, kv.Value), 256)
		}
	}
	return out
}

// UFDLink is a descriptor found next to a disk image that names it.
type UFDLink struct {
	Path    string
	UFD     *UFD
	Summary string
}

// DescriptorsFor looks next to an image file for .ufd/.ufdx descriptors
// that list the image among their linked files. It reads at most 64
// candidate files, each bounded by MaxDescriptorBytes.
func DescriptorsFor(imagePath string) []UFDLink {
	dir, base := filepath.Dir(imagePath), filepath.Base(imagePath)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []UFDLink
	tried := 0
	for _, e := range entries {
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if !e.Type().IsRegular() || (ext != ".ufd" && ext != ".ufdx") {
			continue
		}
		if tried++; tried > 64 {
			break
		}
		p := filepath.Join(dir, e.Name())
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		var u *UFD
		if ext == ".ufd" {
			u, err = ParseUFD(f)
		} else {
			u, err = ParseUFDX(f)
		}
		f.Close()
		if u == nil || (err != nil && len(u.Linked) == 0) {
			continue
		}
		for _, l := range u.Linked {
			if strings.EqualFold(l, base) {
				out = append(out, UFDLink{Path: p, UFD: u, Summary: u.Summary(600)})
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}
