package diskimage

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"strconv"
	"strings"
)

// A minimal XML property-list decoder for the two Apple plists the
// container readers need (the UDIF resource fork and a sparsebundle's
// Info.plist). Values decode to map[string]any, []any, string, int64,
// []byte and bool. Depth and element count are bounded.

const (
	maxPlistDepth = 32
	maxPlistElems = 1 << 20
)

type plistDecoder struct {
	d     *xml.Decoder
	elems int
}

func parsePlist(b []byte) (any, error) {
	p := &plistDecoder{d: xml.NewDecoder(bytes.NewReader(b))}
	p.d.Strict = false
	for {
		tok, err := p.d.Token()
		if err != nil {
			return nil, errors.New("plist: no root value")
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local != "plist" {
			return p.value(se, 0)
		}
	}
}

func (p *plistDecoder) text() (string, error) {
	var sb strings.Builder
	for {
		tok, err := p.d.Token()
		if err != nil {
			return "", err
		}
		switch t := tok.(type) {
		case xml.CharData:
			if sb.Len()+len(t) > 64<<20 {
				return "", errors.New("plist: value too large")
			}
			sb.Write(t)
		case xml.EndElement:
			return sb.String(), nil
		case xml.StartElement:
			return "", errors.New("plist: unexpected element inside a scalar")
		}
	}
}

func (p *plistDecoder) value(se xml.StartElement, depth int) (any, error) {
	p.elems++
	if depth > maxPlistDepth || p.elems > maxPlistElems {
		return nil, errors.New("plist: too deep or too large")
	}
	switch se.Name.Local {
	case "dict":
		m := map[string]any{}
		key := ""
		for {
			tok, err := p.d.Token()
			if err != nil {
				return nil, err
			}
			switch t := tok.(type) {
			case xml.EndElement:
				return m, nil
			case xml.StartElement:
				if t.Name.Local == "key" {
					if key, err = p.text(); err != nil {
						return nil, err
					}
					continue
				}
				v, err := p.value(t, depth+1)
				if err != nil {
					return nil, err
				}
				m[key] = v
			}
		}
	case "array":
		var a []any
		for {
			tok, err := p.d.Token()
			if err != nil {
				return nil, err
			}
			switch t := tok.(type) {
			case xml.EndElement:
				return a, nil
			case xml.StartElement:
				v, err := p.value(t, depth+1)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
		}
	case "true", "false":
		if err := p.d.Skip(); err != nil {
			return nil, err
		}
		return se.Name.Local == "true", nil
	}
	s, err := p.text()
	if err != nil {
		return nil, err
	}
	switch se.Name.Local {
	case "integer":
		return strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	case "data":
		clean := strings.Map(func(r rune) rune {
			if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
				return -1
			}
			return r
		}, s)
		return base64.StdEncoding.DecodeString(clean)
	}
	return s, nil
}
