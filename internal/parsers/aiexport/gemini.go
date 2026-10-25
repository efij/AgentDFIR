package aiexport

import (
	"encoding/json"
	"html"
	"io"
	"regexp"
	"strings"
)

// Google Takeout exports Gemini Apps activity as My Activity records:
//
//	[{"header": "Gemini Apps", "title": "Prompted <prompt text>",
//	  "time": "2025-01-02T10:00:00.123Z", "products": ["Gemini Apps"],
//	  "safeHtmlItem": [{"html": "<p>response</p>"}], "attachedFiles": [...]}]
//
// Activity records carry no conversation id, so each artifact is one
// session. A "Prompted …" record yields the prompt and, when the record
// holds it, the response (HTML reduced to text). Any other activity
// (feedback, Gems, extensions) is kept as session metadata with its title.
// Takeout's default HTML format is reported UNSUPPORTED by parseArtifact.

var tagRE = regexp.MustCompile(`(?s)<[^>]*>`)

type activityRecord struct {
	Title        string `json:"title"`
	Time         string `json:"time"`
	SafeHTMLItem []struct {
		HTML string `json:"html"`
	} `json:"safeHtmlItem"`
	AttachedFiles []json.RawMessage `json:"attachedFiles"`
	ImageFile     string            `json:"imageFile"`
}

func (p *parser) parseGeminiActivity(r io.Reader) error {
	sid := "gemini-activity-" + shortID(p.art.ArtifactID)
	p.describeSession(sid, map[string]string{"title": "Gemini Apps activity (" + p.art.LogicalPath + ")"})
	err := walkArray(r, MaxElementBytes, func(el element) error {
		var a activityRecord
		if json.Unmarshal(el.Raw, &a) != nil {
			p.gap(sid, el.Offset, el.Line, pointer(el.Index), "activity record is not an object")
			return nil
		}
		ev := p.base(sid)
		ev.Result = resultActive
		at(&ev, el.Offset, el.Line, pointer(el.Index))
		isoTime(&ev, "time", a.Time)
		if strings.HasPrefix(a.Title, "Prompted ") {
			p.prompt(ev, strings.TrimPrefix(a.Title, "Prompted "))
			for i, item := range a.SafeHTMLItem {
				if i >= maxBlocks {
					break
				}
				re := ev
				re.SourceJSONPath = pointer(el.Index, "safeHtmlItem", i, "html")
				if t := htmlText(item.HTML); t != "" {
					p.reply(re, t)
				}
			}
		} else {
			p.meta(ev, resultActive, "activity: "+a.Title)
		}
		for i, f := range a.AttachedFiles {
			if i >= maxAttachments {
				break
			}
			name := str(f)
			if name == "" {
				name = compactJSON(f)
			}
			p.attachment(ev, name, "", "attached file")
		}
		if a.ImageFile != "" {
			p.attachment(ev, a.ImageFile, "", "image")
		}
		return nil
	})
	if we, ok := err.(*walkError); ok {
		p.gap(sid, we.Offset, we.Line, pointer(we.Index), "activity array: "+we.Error())
		return nil
	}
	return err
}

// htmlText reduces Takeout's sanitized HTML to readable text.
func htmlText(s string) string {
	s = strings.NewReplacer("<br>", "\n", "<br/>", "\n", "</p>", "\n", "</li>", "\n").Replace(s)
	s = tagRE.ReplaceAllString(s, "")
	return strings.TrimSpace(html.UnescapeString(s))
}
