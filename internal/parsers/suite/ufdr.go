package suite

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Cellebrite UFDR report.xml, read as a stream.
//
// The structure read is the one publicly described for UFDR reports:
//
//	<project …>                                   root, attributes kept
//	  <sourceExtractions><extractionInfo …/>      one per extraction (attributes kept)
//	  <caseInformation><field name=…><value>…     case number, examiner …
//	  <metadata section=…><item name=…>…</item>   device / extraction / tool metadata
//	  <taggedFiles><file …>                       counted only
//	  <decodedData>
//	    <modelType type=…>
//	      <model type=… id=…>
//	        <field name=… type=…><value …>…</value></field>
//	        <multiField name=…><value>…</value>…</multiField>
//	        <modelField name=…><model …>…</model></modelField>
//	        <multiModelField name=…><model …>…</model>…</multiModelField>
//
// Nothing is decoded beyond that generic shape: a model is a type, an id
// and named string values. The document is never loaded whole: tokens are
// pulled one at a time from encoding/xml, and every token is bounded
// (maxTokenBytes) by the reader underneath the decoder, so one giant text
// node cannot exhaust memory. encoding/xml never fetches external entities
// and never expands entities declared in a DTD: a reference to one is a
// syntax error, so XXE and billion-laughs documents stop at that point and
// are reported as malformed.

// Bounds on what one report may ask of the reader.
const (
	maxTokenBytes     = 16 << 20 // one XML token (a text node, a start tag)
	maxXMLDepth       = 256
	maxModelDepth     = 64
	maxValueBytes     = 64 << 10 // one collected value
	maxFieldsPerModel = 512
	maxMetaItems      = 4096
	maxCaseFields     = 256
	maxExtractions    = 256
	maxAttrs          = 64
	maxPending        = 50000  // candidate descendants held while their top-level model is open
	maxAIRecords      = 200000 // AI records reported from one report
)

// errNotUFDR is returned when the root element is not <project>.
var errNotUFDR = errors.New("root element is not <project>")

// errTokenTooLarge is returned when one token exceeds maxTokenBytes.
var errTokenTooLarge = fmt.Errorf("an XML token exceeds the %d-byte bound", maxTokenBytes)

// KV is one named value, in document order.
type KV struct {
	Name  string
	Value string
}

// MetaItem is one <metadata section=…><item name=…> value.
type MetaItem struct {
	Section          string
	Name             string
	Value            string
	SourceExtraction string
}

// UFDRRecord is one decoded model the reader reports to its caller: a
// model of an AI application, or a generic Chat / InstantMessage /
// WebBookmark / VisitedPage / SearchedItem model that references an
// AI-service URL.
type UFDRRecord struct {
	ModelType string
	ModelID   string
	Deleted   string // deleted_state attribute
	Path      string // XPath-like location of the model in report.xml
	Offset    int64  // byte offset just past the model's start tag
	Line      int
	Fields    []KV
	App       *AIApp    // the AI application (own Source field or inherited from the top-level model)
	URL       *URLMatch // the first AI-service URL among its values
	TimeField string
	TimeRaw   string
	Time      time.Time
	Parent    string // "<type> <id>" of the enclosing model, when nested
	Top       string // "<type>:<id>" of the top-level model it belongs to (itself when top level)
}

// UFDRResult is everything else the reader learned, for the inventory.
type UFDRResult struct {
	Root           string
	ProjectAttrs   []KV
	Extractions    [][]KV
	CaseInfo       []KV
	Metadata       []MetaItem
	ModelCounts    map[string]int // every model, nested ones included, by type
	TopModelCounts map[string]int // models directly under a modelType
	TaggedFiles    int
	Sections       map[string]int // top-level sections other than the known ones
	Unrecognized   map[string]int // elements inside decodedData/models that are not part of the generic shape
	UntypedModels  int
	FieldsDropped  int // field values over maxFieldsPerModel
	MetaDropped    int
	AIRecords      int
	AIDropped      int // AI records over maxAIRecords, or candidates over maxPending
}

// genericTypes are the model types matched by URL regardless of their
// source application.
var genericTypes = map[string]bool{
	"Chat": true, "InstantMessage": true, "WebBookmark": true, "VisitedPage": true, "SearchedItem": true,
}

// appFields are the model fields that name the application a record came from.
var appFields = map[string]bool{"Source": true, "Application": true, "SourceApplication": true}

var knownSections = map[string]bool{
	"sourceExtractions": true, "caseInformation": true, "metadata": true, "taggedFiles": true, "decodedData": true,
}

var modelElements = map[string]bool{
	"model": true, "field": true, "multiField": true, "modelField": true, "multiModelField": true,
	"value": true, "empty": true, "jumptargets": true, "targetid": true,
}

// budgetReader fails a read once more than max bytes were consumed since
// the last reset; the decoder is reset after every token. Once tripped it
// stays failed: a decoder hands back the partial token first and must not
// carry on reading after the next reset.
type budgetReader struct {
	r       io.Reader
	n       int64
	max     int64
	tripped bool
}

func (b *budgetReader) Read(p []byte) (int, error) {
	if b.tripped || b.n >= b.max {
		b.tripped = true
		return 0, errTokenTooLarge
	}
	if rem := b.max - b.n; int64(len(p)) > rem {
		p = p[:rem]
	}
	k, err := b.r.Read(p)
	b.n += int64(k)
	return k, err
}

type xmlFrame struct {
	local string
	step  string
	name  string // name attribute (field-like elements)
}

type modelState struct {
	rec       UFDRRecord
	curField  string
	timeField bool
	pending   []UFDRRecord
	top       bool
}

// ReadUFDRReport streams a report.xml and calls fn for every AI record.
// The result is returned even with an error, holding what was read up to
// the failure.
func ReadUFDRReport(r io.Reader, fn func(UFDRRecord)) (res *UFDRResult, err error) {
	res = &UFDRResult{ModelCounts: map[string]int{}, TopModelCounts: map[string]int{},
		Sections: map[string]int{}, Unrecognized: map[string]int{}}
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("report.xml reader stopped: %v", p)
		}
	}()
	br := &budgetReader{r: r, max: maxTokenBytes}
	dec := xml.NewDecoder(br)
	dec.Strict = true
	dec.CharsetReader = func(label string, _ io.Reader) (io.Reader, error) {
		return nil, fmt.Errorf("character set %q is not supported", label)
	}
	var (
		stack      []xmlFrame
		models     []*modelState
		section    string
		metaSect   string
		caseField  string
		collecting int // 0 none, 1 case value, 2 meta item, 3 model value
		itemName   string
		itemSrc    string
		buf        bytes.Buffer
		bufCut     bool
	)
	const (
		colNone = iota
		colCase
		colMeta
		colModel
	)
	startCollect := func(kind int) {
		collecting, bufCut = kind, false
		buf.Reset()
	}
	for {
		br.n = 0
		tok, terr := dec.Token()
		if terr == io.EOF {
			if len(stack) > 0 {
				return res, fmt.Errorf("document ends inside <%s>", stack[len(stack)-1].local)
			}
			if res.Root == "" {
				return res, errNotUFDR
			}
			return res, nil
		}
		if terr != nil {
			return res, terr
		}
		switch t := tok.(type) {
		case xml.StartElement:
			local := t.Name.Local
			depth := len(stack)
			if depth >= maxXMLDepth {
				return res, fmt.Errorf("element nesting exceeds %d levels", maxXMLDepth)
			}
			attr := func(n string) string {
				for _, a := range t.Attr {
					if a.Name.Local == n {
						return a.Value
					}
				}
				return ""
			}
			fr := xmlFrame{local: local, step: local}
			if depth == 0 {
				if local != "project" {
					res.Root = local
					return res, errNotUFDR
				}
				res.Root = local
				for _, a := range t.Attr {
					if len(res.ProjectAttrs) < maxAttrs && a.Name.Space != "xmlns" && a.Name.Local != "xmlns" {
						res.ProjectAttrs = append(res.ProjectAttrs, KV{a.Name.Local, clip(a.Value, 512)})
					}
				}
				stack = append(stack, fr)
				continue
			}
			if depth == 1 {
				section = local
				if !knownSections[local] {
					res.Sections[local]++
				}
				if local == "metadata" {
					metaSect = attr("section")
					fr.step = fmt.Sprintf("metadata[@section='%s']", xq(metaSect))
				}
			}
			switch section {
			case "sourceExtractions":
				if local == "extractionInfo" && len(res.Extractions) < maxExtractions {
					var kv []KV
					for _, a := range t.Attr {
						if len(kv) < maxAttrs {
							kv = append(kv, KV{a.Name.Local, clip(a.Value, 512)})
						}
					}
					res.Extractions = append(res.Extractions, kv)
				}
			case "caseInformation":
				switch {
				case local == "field" && depth == 2:
					caseField = attr("name")
				case local == "value" && caseField != "":
					startCollect(colCase)
				}
			case "metadata":
				if local == "item" && depth == 2 {
					itemName, itemSrc = attr("name"), attr("sourceExtraction")
					startCollect(colMeta)
				}
			case "taggedFiles":
				if local == "file" && depth == 2 {
					res.TaggedFiles++
				}
			case "decodedData":
				switch {
				case depth == 2:
					if local == "modelType" {
						fr.step = fmt.Sprintf("modelType[@type='%s']", xq(attr("type")))
					} else {
						res.Unrecognized["decodedData/"+local]++
					}
				case local == "model":
					if len(models) >= maxModelDepth {
						return res, fmt.Errorf("models nested more than %d deep", maxModelDepth)
					}
					typ, id := attr("type"), attr("id")
					if typ == "" {
						res.UntypedModels++
						typ = "(untyped)"
					}
					fr.step = fmt.Sprintf("model[@type='%s'][@id='%s']", xq(typ), xq(id))
					ms := &modelState{top: len(models) == 0}
					line, _ := dec.InputPos()
					ms.rec = UFDRRecord{ModelType: clip(typ, 128), ModelID: clip(id, 128), Deleted: attr("deleted_state"),
						Offset: dec.InputOffset(), Line: line}
					if len(models) > 0 {
						p := models[len(models)-1].rec
						ms.rec.Parent = p.ModelType + " " + p.ModelID
					}
					stack = append(stack, fr)
					ms.rec.Path = xpath(stack)
					models = append(models, ms)
					continue
				case local == "field" || local == "multiField" || local == "modelField" || local == "multiModelField":
					fr.name = attr("name")
					fr.step = fmt.Sprintf("%s[@name='%s']", local, xq(fr.name))
					if len(models) > 0 && (local == "field" || local == "multiField") {
						m := models[len(models)-1]
						m.curField = fr.name
						m.timeField = strings.EqualFold(attr("type"), "TimeStamp")
					}
				case local == "value":
					if len(models) > 0 && models[len(models)-1].curField != "" {
						if strings.EqualFold(attr("type"), "TimeStamp") {
							models[len(models)-1].timeField = true
						}
						startCollect(colModel)
					}
				case !modelElements[local]:
					res.Unrecognized["decodedData/…/"+local]++
				}
			}
			stack = append(stack, fr)
		case xml.CharData:
			if collecting != colNone && !bufCut {
				if buf.Len()+len(t) > maxValueBytes {
					buf.Write(t[:maxValueBytes-buf.Len()])
					bufCut = true
				} else {
					buf.Write(t)
				}
			}
		case xml.EndElement:
			if len(stack) == 0 {
				return res, errors.New("unbalanced end element")
			}
			fr := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			local := fr.local
			switch {
			case collecting == colCase && local == "value":
				if len(res.CaseInfo) < maxCaseFields {
					res.CaseInfo = append(res.CaseInfo, KV{caseField, valueText(&buf, bufCut)})
				}
				collecting = colNone
			case section == "caseInformation" && local == "field" && len(stack) == 2:
				caseField = ""
			case collecting == colMeta && local == "item":
				if len(res.Metadata) < maxMetaItems {
					res.Metadata = append(res.Metadata, MetaItem{Section: metaSect, Name: itemName, Value: valueText(&buf, bufCut), SourceExtraction: itemSrc})
				} else {
					res.MetaDropped++
				}
				collecting = colNone
			case collecting == colModel && local == "value":
				m := models[len(models)-1]
				v := valueText(&buf, bufCut)
				if len(m.rec.Fields) < maxFieldsPerModel {
					m.rec.Fields = append(m.rec.Fields, KV{m.curField, v})
				} else {
					res.FieldsDropped++
				}
				if m.timeField && m.rec.TimeRaw == "" && v != "" {
					m.rec.TimeField, m.rec.TimeRaw = m.curField, clip(v, 64)
					if ts, ok := parseXMLTime(v); ok {
						m.rec.Time = ts
					}
				}
				collecting = colNone
			case section == "decodedData" && (local == "field" || local == "multiField"):
				if len(models) > 0 {
					models[len(models)-1].curField = ""
					models[len(models)-1].timeField = false
				}
			case section == "decodedData" && local == "model" && len(models) > 0:
				ms := models[len(models)-1]
				models = models[:len(models)-1]
				res.finishModel(ms, models, fn)
			}
			if len(stack) == 1 {
				section = ""
			}
		}
	}
}

// finishModel classifies a closed model and either reports it (top
// level) or hands it to its parent, which decides once it closes: the
// parent's Source field may come after its messages.
func (res *UFDRResult) finishModel(ms *modelState, open []*modelState, fn func(UFDRRecord)) {
	rec := ms.rec
	res.ModelCounts[rec.ModelType]++
	for _, f := range rec.Fields {
		if appFields[f.Name] {
			if a := MatchApp(f.Value); a != nil {
				rec.App = a
				break
			}
		}
	}
	if genericTypes[rec.ModelType] {
		for _, f := range rec.Fields {
			if m := FindAIURL(f.Value); m != nil {
				m.Field = f.Name
				rec.URL = m
				break
			}
		}
	}
	if !ms.top {
		parent := open[len(open)-1]
		add := func(r UFDRRecord) {
			if len(parent.pending) >= maxPending {
				res.AIDropped++
				return
			}
			parent.pending = append(parent.pending, r)
		}
		if genericTypes[rec.ModelType] || rec.App != nil || rec.URL != nil {
			add(rec)
		}
		for _, r := range ms.pending {
			add(r)
		}
		return
	}
	res.TopModelCounts[rec.ModelType]++
	report := func(r UFDRRecord) {
		if res.AIRecords >= maxAIRecords {
			res.AIDropped++
			return
		}
		res.AIRecords++
		fn(r)
	}
	rec.Top = rec.ModelType + ":" + rec.ModelID
	if rec.App != nil || (genericTypes[rec.ModelType] && rec.URL != nil) {
		report(rec)
	}
	for _, r := range ms.pending {
		r.Top = rec.Top
		if r.App == nil {
			r.App = rec.App
		}
		if r.App != nil || r.URL != nil {
			report(r)
		}
	}
}

func valueText(buf *bytes.Buffer, cut bool) string {
	s := strings.TrimSpace(buf.String())
	if cut {
		s += "…"
	}
	return s
}

func xpath(stack []xmlFrame) string {
	var b strings.Builder
	for _, f := range stack {
		b.WriteByte('/')
		b.WriteString(f.step)
	}
	return b.String()
}

// xq keeps an attribute value usable inside an XPath-like '…' literal.
func xq(s string) string {
	return strings.ReplaceAll(clip(s, 128), "'", "&apos;")
}

func parseXMLTime(v string) (time.Time, bool) {
	v = strings.TrimSpace(v)
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999-0700"} {
		if t, err := time.Parse(layout, v); err == nil && t.Year() > 1970 {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut] + "…"
}
