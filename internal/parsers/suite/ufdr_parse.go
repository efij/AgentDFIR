package suite

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/efij/AgentDFIR/v5/internal/schema"
)

// normalizedMeta maps report metadata item names (case-insensitive
// substrings, first match wins) to the normalized attribute they fill.
// The item is always also reported under its own name; this only chooses
// which values are lifted into the summary.
var normalizedMeta = []struct {
	attr  string
	match []string
}{
	{"device_model", []string{"detectedphonemodel", "selecteddevicename", "devicemodel", "device model", "model"}},
	{"device_vendor", []string{"selectedmanufacturer", "detectedmanufacturer", "manufacturer", "vendor"}},
	{"os", []string{"osversion", "os version", "ostype", "os type", "operating system"}},
	{"extraction_type", []string{"extractiontype", "extraction type", "extraction method", "extractionmethod"}},
	{"extraction_start", []string{"extractionstart", "extraction start", "start time", "starttime", "start date"}},
	{"extraction_end", []string{"extractionend", "extraction end", "end time", "endtime", "end date"}},
	{"tool_version", []string{"ufed_pa_version", "ufed version", "physical analyzer version", "reader version", "ufedversion", "pa version", "tool version", "version"}},
}

func normalizeMetaName(name string) string {
	l := strings.ToLower(name)
	for _, n := range normalizedMeta {
		for _, m := range n.match {
			if strings.Contains(l, m) {
				return n.attr
			}
		}
	}
	return ""
}

// summaryFields are the model fields lifted into a record summary, in
// this order, when present.
var summaryFields = []string{"Name", "Title", "Subject", "Body", "Text", "Url", "URL", "Value", "Status"}

func (p *parser) parseUFDR(r io.Reader) error {
	n := 0
	res, err := ReadUFDRReport(r, func(rec UFDRRecord) {
		n++
		p.ufdrRecord(rec)
	})
	switch {
	case errors.Is(err, errNotUFDR):
		why := "report.xml root element is not <project>"
		if res.Root != "" {
			why = fmt.Sprintf("report.xml root element is <%s>, not <project>", clip(res.Root, 64))
		}
		p.unsupported(why + "; the file is sealed, nothing was read from it")
		return nil
	case err != nil:
		var se *xml.SyntaxError
		line := 0
		if errors.As(err, &se) {
			line = se.Line
		}
		p.gap(0, line, fmt.Sprintf("UFDR report.xml is malformed or truncated (%v); %d AI record(s) and %d model(s) were read before it, the rest of the file is preserved unparsed", err, n, sum(res.ModelCounts)))
	}
	p.ufdrMetadata(res)
	inv := fmt.Sprintf("UFDR report.xml inventory: %d decoded model(s) (%d top-level) — %s; %d tagged file(s); %d extraction(s); %d AI record(s) normalized",
		sum(res.ModelCounts), sum(res.TopModelCounts), counts(res.TopModelCounts, 24), res.TaggedFiles, len(res.Extractions), res.AIRecords)
	if res.AIDropped > 0 {
		inv += fmt.Sprintf(", %d over the per-report bound left in the file", res.AIDropped)
	}
	if res.FieldsDropped+res.MetaDropped > 0 {
		inv += fmt.Sprintf("; %d field value(s) and %d metadata item(s) over the bounds left in the file", res.FieldsDropped, res.MetaDropped)
	}
	if len(res.Sections) > 0 {
		inv += "; other sections preserved: " + counts(res.Sections, 12)
	}
	inv += ". Every other model is preserved, unparsed, in the sealed report.xml."
	p.meta(actionInventory, "ufdr:inventory", inv)
	attrs := map[string]string{"models_total": fmt.Sprint(sum(res.ModelCounts)), "ai_records": fmt.Sprint(res.AIRecords),
		"tagged_files": fmt.Sprint(res.TaggedFiles)}
	for k, v := range res.TopModelCounts {
		if len(attrs) < 80 {
			attrs["models:"+k] = fmt.Sprint(v)
		}
	}
	p.describe(p.session, "", attrs)
	if res.UntypedModels > 0 || len(res.Unrecognized) > 0 {
		why := "UFDR structure not in the generic project/decodedData/modelType/model/field shape:"
		if res.UntypedModels > 0 {
			why += fmt.Sprintf(" %d <model> element(s) without a type attribute;", res.UntypedModels)
		}
		if len(res.Unrecognized) > 0 {
			why += " unrecognized elements " + counts(res.Unrecognized, 12) + ";"
		}
		p.unsupported(why + " those parts are preserved unparsed in the sealed report.xml")
	}
	return nil
}

func (p *parser) ufdrMetadata(res *UFDRResult) {
	attrs := map[string]string{}
	var proj []string
	for _, kv := range res.ProjectAttrs {
		v := maskField(kv.Name, kv.Value)
		proj = append(proj, kv.Name+"="+v)
		attrs["project:"+kv.Name] = v
	}
	if len(proj) > 0 {
		p.meta(actionMeta, "ufdr:project", "UFDR project: "+strings.Join(proj, "; "))
	}
	if len(res.CaseInfo) > 0 {
		var parts []string
		for _, kv := range res.CaseInfo {
			v := maskField(kv.Name, kv.Value)
			if v == "" {
				continue
			}
			parts = append(parts, kv.Name+"="+v)
			if len(attrs) < maxEntityAttrs {
				attrs["case:"+kv.Name] = v
			}
		}
		if len(parts) > 0 {
			p.meta(actionMeta, "ufdr:case", "UFDR case information: "+strings.Join(parts, "; "))
		}
	}
	for i, ex := range res.Extractions {
		var parts []string
		for _, kv := range ex {
			v := maskField(kv.Name, kv.Value)
			parts = append(parts, kv.Name+"="+v)
			if len(attrs) < maxEntityAttrs {
				attrs[fmt.Sprintf("extraction%d:%s", i, kv.Name)] = v
			}
		}
		p.meta(actionMeta, "ufdr:extraction", "UFDR source extraction: "+strings.Join(parts, "; "))
	}
	// Metadata, one event per section, normalized values first.
	var order []string
	bySect := map[string][]MetaItem{}
	for _, it := range res.Metadata {
		if _, ok := bySect[it.Section]; !ok {
			order = append(order, it.Section)
		}
		bySect[it.Section] = append(bySect[it.Section], it)
	}
	norm := map[string]string{}
	for si, sect := range order {
		if si >= 64 {
			p.meta(actionMeta, "ufdr:metadata", fmt.Sprintf("%d more metadata section(s) preserved in the sealed report.xml", len(order)-64))
			break
		}
		var lifted, rest []string
		ids := 0
		for _, it := range bySect[sect] {
			v := maskField(it.Name, it.Value)
			if v == "" {
				continue
			}
			if idCategory(it.Name) != "" {
				ids++
				lifted = append(lifted, it.Name+"="+v)
			} else if a := normalizeMetaName(it.Name); a != "" {
				if _, set := norm[a]; !set {
					norm[a] = v
				}
				lifted = append(lifted, a+"("+it.Name+")="+v)
			} else {
				rest = append(rest, it.Name+"="+v)
			}
			if len(attrs) < maxEntityAttrs {
				attrs["meta:"+sect+":"+it.Name] = v
			}
		}
		name := sect
		if name == "" {
			name = "(unnamed)"
		}
		s := fmt.Sprintf("UFDR metadata [%s]: %s", name, strings.Join(append(lifted, rest...), "; "))
		if ids > 0 {
			s += fmt.Sprintf(" (%d device identifier(s) masked; verbatim in the sealed report.xml)", ids)
		}
		p.meta(actionMeta, "ufdr:metadata", s)
	}
	keys := make([]string, 0, len(norm))
	for k := range norm {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		attrs[k] = norm[k]
	}
	p.describe(p.session, "", attrs)
}

func (p *parser) ufdrRecord(rec UFDRRecord) {
	ev := schema.Event{SourceOffset: rec.Offset, SourceLine: rec.Line, SourceJSONPath: rec.Path}
	var who string
	switch {
	case rec.App != nil:
		ev.Vendor, who = rec.App.Key, rec.App.Name
		ev.Result = "ai-app:" + rec.ModelType
	default:
		ev.Vendor, who = rec.URL.Key, rec.URL.Name+" URL"
		ev.Result = "ai-url:" + rec.URL.Kind
	}
	key := ev.Vendor
	ev.SessionID = "ufdr:" + key + ":" + clip(rec.Top, 160)
	p.setTime(&ev, rec.TimeField, rec.TimeRaw, rec.Time)
	parts := []string{"UFDR " + rec.ModelType + " (" + who + ")"}
	shown := map[string]bool{}
	for _, want := range summaryFields {
		for _, f := range rec.Fields {
			if f.Name == want && !shown[f.Name] && f.Value != "" {
				shown[f.Name] = true
				parts = append(parts, f.Name+"="+clip(maskField(f.Name, f.Value), 200))
			}
		}
	}
	if rec.URL != nil && !shown[rec.URL.Field] {
		parts = append(parts, rec.URL.Field+"="+clip(rec.URL.URL, 200))
	}
	if rec.URL != nil && rec.URL.ID != "" {
		parts = append(parts, rec.URL.Kind+" id="+rec.URL.ID)
	}
	if rec.Deleted != "" && !strings.EqualFold(rec.Deleted, "Intact") {
		parts = append(parts, "deleted_state="+rec.Deleted)
	}
	parts = append(parts, "model id="+rec.ModelID)
	if rec.Parent != "" {
		parts = append(parts, "in "+rec.Parent)
	}
	ev.Summary = strings.Join(parts, " · ")
	p.record(ev)
	p.describe(ev.SessionID, who+" — "+rec.Top, map[string]string{"service": key, "report": p.art.LogicalPath, "top_model": rec.Top})
}

// parseDescriptor reads a .ufd or .ufdx descriptor.
func (p *parser) parseDescriptor(r io.Reader) error {
	head, rr := readHead(r, 4096)
	var u *UFD
	var err error
	if t := bytes.TrimLeft(head, "\xef\xbb\xbf \t\r\n"); len(t) > 0 && t[0] == '<' {
		u, err = ParseUFDX(rr)
	} else {
		u, err = ParseUFD(rr)
	}
	if u == nil || (err != nil && len(u.Sections) == 0) {
		p.unsupported(fmt.Sprintf("descriptor not readable as INI-style .ufd or XML .ufdx: %v", err))
		return nil
	}
	if err != nil {
		p.gap(0, 0, fmt.Sprintf("descriptor %s is malformed or truncated (%v); keys before it were read", path.Base(p.art.LogicalPath), err))
	}
	s := fmt.Sprintf("Cellebrite %s descriptor %s: %s", u.Format, path.Base(p.art.LogicalPath), u.Summary(900))
	if u.Dropped > 0 {
		s += fmt.Sprintf(" (%d key(s) over the bound left in the file)", u.Dropped)
	}
	p.meta(actionMeta, "ufd:descriptor", s)
	attrs := u.Attributes(120)
	if len(u.Linked) > 0 {
		attrs["linked_files"] = strings.Join(u.Linked, ", ")
	}
	p.describe(p.session, "", attrs)
	return nil
}
