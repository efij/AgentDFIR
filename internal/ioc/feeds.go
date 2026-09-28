package ioc

import (
	"encoding/json"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// STIX 2.1: indicator objects with a pattern made of simple comparisons.
// Each `[object:path = 'value']` (or MATCHES for process:command_line)
// becomes one indicator; AND/OR/FOLLOWEDBY structure is flattened, which
// is the conservative reading for "has this machine seen any of these".
var stixCmpRe = regexp.MustCompile(`\[?\s*([a-z0-9-]+):([A-Za-z0-9_.'\- ]+?)\s*(=|MATCHES|LIKE)\s*'((?:[^'\\]|\\.)*)'`)

func parseSTIX(b []byte, origin string) ([]Incident, int, error) {
	var bundle struct {
		ID      string `json:"id"`
		Objects []struct {
			Type        string `json:"type"`
			ID          string `json:"id"`
			Name        string `json:"name"`
			Description string `json:"description"`
			Pattern     string `json:"pattern"`
			PatternType string `json:"pattern_type"`
			ValidFrom   string `json:"valid_from"`
		} `json:"objects"`
	}
	if err := json.Unmarshal(b, &bundle); err != nil {
		return nil, 0, err
	}
	inc := Incident{ID: "stix:" + strings.TrimPrefix(bundle.ID, "bundle--"), Title: "STIX bundle " + filepath.Base(origin)}
	skipped := 0
	for _, o := range bundle.Objects {
		switch o.Type {
		case "report", "campaign", "intrusion-set":
			if inc.Summary == "" && o.Name != "" {
				inc.Title, inc.Summary = o.Name, o.Description
			}
			continue
		case "indicator":
		default:
			continue
		}
		if o.PatternType != "" && o.PatternType != "stix" {
			skipped++
			continue
		}
		ms := stixCmpRe.FindAllStringSubmatch(o.Pattern, -1)
		if len(ms) == 0 {
			skipped++
			continue
		}
		for _, m := range ms {
			obj, prop, op, val := m[1], strings.TrimSpace(m[2]), m[3], strings.ReplaceAll(m[4], `\'`, `'`)
			ind, ok := stixIndicator(obj, prop, op, val)
			if !ok {
				skipped++
				continue
			}
			ind.Note = o.Name
			inc.Indicators = append(inc.Indicators, ind)
		}
	}
	return []Incident{inc}, skipped, nil
}

func stixIndicator(obj, prop, op, val string) (Indicator, bool) {
	switch {
	case (obj == "domain-name" || obj == "ipv4-addr" || obj == "ipv6-addr") && prop == "value" && op == "=":
		return Indicator{Kind: KindDomain, Value: val}, true
	case obj == "url" && prop == "value" && op == "=":
		return Indicator{Kind: KindURL, Value: val}, true
	case obj == "file" && prop == "name" && op == "=":
		return Indicator{Kind: KindPath, Value: val}, true
	case obj == "file" && strings.HasPrefix(prop, "hashes.") && strings.Contains(strings.ToUpper(prop), "SHA-256") || obj == "file" && strings.EqualFold(prop, "hashes.SHA256"):
		return Indicator{Kind: KindSHA256, Value: val}, true
	case obj == "process" && prop == "command_line" && op == "MATCHES":
		return Indicator{Kind: KindCommandRegex, Value: val}, true
	case obj == "process" && prop == "command_line" && op == "=":
		return Indicator{Kind: KindString, Value: val}, true
	}
	return Indicator{}, false
}

// MISP: an event (or {"response":[{"Event":…}]}) with Attribute[] and
// Object[].Attribute[].
type mispAttr struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	IDS   *bool  `json:"to_ids"`
}

type mispEvent struct {
	ID        string     `json:"id"`
	UUID      string     `json:"uuid"`
	Info      string     `json:"info"`
	Date      string     `json:"date"`
	Attribute []mispAttr `json:"Attribute"`
	Object    []struct {
		Attribute []mispAttr `json:"Attribute"`
	} `json:"Object"`
}

func parseMISP(b []byte, origin string) ([]Incident, int, error) {
	var one struct {
		Event    *mispEvent `json:"Event"`
		Response []struct {
			Event mispEvent `json:"Event"`
		} `json:"response"`
	}
	if err := json.Unmarshal(b, &one); err != nil {
		return nil, 0, err
	}
	var evs []mispEvent
	if one.Event != nil {
		evs = append(evs, *one.Event)
	}
	for _, r := range one.Response {
		evs = append(evs, r.Event)
	}
	var out []Incident
	skipped := 0
	for _, e := range evs {
		id := e.UUID
		if id == "" {
			id = e.ID
		}
		inc := Incident{ID: "misp:" + id, Title: e.Info, FirstSeen: e.Date}
		attrs := append([]mispAttr(nil), e.Attribute...)
		for _, o := range e.Object {
			attrs = append(attrs, o.Attribute...)
		}
		for _, a := range attrs {
			for _, ind := range mispIndicators(a) {
				inc.Indicators = append(inc.Indicators, ind)
			}
			if len(mispIndicators(a)) == 0 {
				skipped++
			}
		}
		out = append(out, inc)
	}
	return out, skipped, nil
}

func mispIndicators(a mispAttr) []Indicator {
	v := a.Value
	switch a.Type {
	case "domain", "hostname", "ip-dst", "ip-src":
		return []Indicator{{Kind: KindDomain, Value: v}}
	case "domain|ip", "ip-dst|port":
		return []Indicator{{Kind: KindDomain, Value: strings.SplitN(v, "|", 2)[0]}}
	case "url", "uri", "link":
		if a.Type == "link" {
			return nil // references, not observables
		}
		return []Indicator{{Kind: KindURL, Value: v}}
	case "sha256":
		return []Indicator{{Kind: KindSHA256, Value: v}}
	case "filename":
		return []Indicator{{Kind: KindPath, Value: v}}
	case "filename|sha256":
		p := strings.SplitN(v, "|", 2)
		if len(p) == 2 {
			return []Indicator{{Kind: KindPath, Value: p[0]}, {Kind: KindSHA256, Value: p[1], FileName: path.Base(p[0])}}
		}
	case "email-dst", "email-src":
		return []Indicator{{Kind: KindString, Value: v}}
	case "github-repository":
		return []Indicator{{Kind: KindRepoName, Value: v}}
	}
	return nil
}
