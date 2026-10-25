package aiexport

import (
	"bytes"
	"encoding/json"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Services and the products their events carry.
const (
	ServiceChatGPT  = "chatgpt"
	ServiceClaudeAI = "claude-ai"
	ServiceDeepSeek = "deepseek"
	ServiceGemini   = "gemini-apps"
)

// Kinds of export file.
const (
	KindConversations = "conversations" // ChatGPT / Claude.ai / DeepSeek conversations
	KindAccount       = "account"       // user.json / users.json
	KindFeedback      = "feedback"      // ChatGPT message_feedback.json
	KindShared        = "shared"        // ChatGPT shared_conversations.json
	KindProjects      = "projects"      // Claude.ai projects.json
	KindActivity      = "activity"      // Takeout My Activity (Gemini Apps), JSON
	KindActivityHTML  = "activity-html" // the same, exported as HTML only
	KindUnsupported   = "unsupported"   // a known export file whose structure is not one we read
)

// SniffBytes is the head of a file read to classify it.
const SniffBytes = 1 << 20

const (
	maxSniffedValues  = 16       // captured string values per key
	maxShapeDepth     = 7        // structural summary depth
	htmlSniffLimit    = 64 << 10 // bytes of an HTML head searched for the product label
	maxMissingKeys    = 8
	geminiActivityTag = "Gemini Apps" // Takeout product label
	bardActivityTag   = "Bard"        // the label before the 2024 rename
	unknownService    = "unknown"
	genericProduct    = "ai-export"
)

// Detection is what Sniff concluded about one file.
type Detection struct {
	Service string   `json:"service"`
	Kind    string   `json:"kind"`
	Variant string   `json:"variant,omitempty"` // schema variant, e.g. "mapping-tree" or "content-blocks"
	Missing []string `json:"missing_keys,omitempty"`
	Reason  string   `json:"reason,omitempty"` // set for KindUnsupported
}

// Product is the event/artifact product id for the detection.
func (d Detection) Product() string {
	switch d.Service {
	case ServiceChatGPT, ServiceClaudeAI, ServiceDeepSeek, ServiceGemini:
		return d.Service
	}
	return genericProduct
}

// Vendor is the provider behind the service.
func (d Detection) Vendor() string {
	switch d.Service {
	case ServiceChatGPT:
		return "openai"
	case ServiceClaudeAI:
		return "anthropic"
	case ServiceDeepSeek:
		return "deepseek"
	case ServiceGemini:
		return "google"
	}
	return unknownService
}

// String renders the detection for case notes.
func (d Detection) String() string {
	s := d.Service + "/" + d.Kind
	if d.Variant != "" {
		s += "/" + d.Variant
	}
	return s
}

// shape is a structural summary of a JSON head: the keys seen at each
// path (array indices collapse to "[]", ids under "mapping" to "*") and
// the string values of a few keys whose value decides the service.
type shape struct {
	root byte
	keys map[string]map[string]bool
	vals map[string][]string
}

var capturedKeys = map[string]bool{"header": true, "products": true, "type": true}

func (s *shape) has(p string, keys ...string) bool {
	for _, k := range keys {
		if !s.keys[p][k] {
			return false
		}
	}
	return true
}

func (s *shape) any(p string, keys ...string) bool {
	for _, k := range keys {
		if s.keys[p][k] {
			return true
		}
	}
	return false
}

func (s *shape) missing(p string, keys ...string) []string {
	var out []string
	for _, k := range keys {
		if !s.keys[p][k] {
			out = append(out, k)
		}
	}
	return out
}

func (s *shape) valueContains(key, want string) bool {
	for _, v := range s.vals[key] {
		if strings.Contains(v, want) {
			return true
		}
	}
	return false
}

// summarize walks the tokens of a (possibly cut) JSON head. A head that
// ends mid-value is normal: whatever was seen before the cut is kept.
func summarize(head []byte) *shape {
	s := &shape{keys: map[string]map[string]bool{}, vals: map[string][]string{}}
	dec := json.NewDecoder(bytes.NewReader(head))
	type frame struct {
		array     bool
		path      string
		expectKey bool
		key       string
	}
	var stack []*frame
	for {
		tok, err := dec.Token()
		if err != nil {
			return s
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if top != nil && !top.array && top.expectKey {
			if k, ok := tok.(string); ok {
				if s.keys[top.path] == nil {
					s.keys[top.path] = map[string]bool{}
				}
				s.keys[top.path][k] = true
				top.key, top.expectKey = k, false
				continue
			}
		}
		childPath := ""
		switch {
		case top == nil:
		case top.array:
			childPath = top.path + "[]"
		case path.Base("/"+top.path) == "mapping":
			childPath = top.path + ".*"
		default:
			childPath = top.path + "." + top.key
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '[', '{':
				if top == nil {
					s.root = byte(d)
				}
				stack = append(stack, &frame{array: d == '[', path: childPath, expectKey: d == '{'})
				if len(stack) > maxShapeDepth+2 {
					return s
				}
			default:
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
				if len(stack) > 0 && !stack[len(stack)-1].array {
					stack[len(stack)-1].expectKey = true
				}
			}
			continue
		}
		if top == nil {
			return s // a scalar document
		}
		capKey := top.key
		if top.array {
			// products: ["Gemini Apps"] — the values sit in an array whose
			// path ends with the key that holds it.
			capKey = top.path[strings.LastIndex(top.path, ".")+1:]
		}
		if str, ok := tok.(string); ok && capturedKeys[capKey] && len(s.vals[capKey]) < maxSniffedValues {
			s.vals[capKey] = append(s.vals[capKey], str)
		}
		if !top.array {
			top.expectKey = true
		}
	}
}

var splitConversations = regexp.MustCompile(`^conversations(-\d+)?\.json$`)

// knownExportName reports whether a file name is one the services use for
// an export file. It is a hint for reporting only: a file with such a name
// whose structure is not recognized is reported UNSUPPORTED instead of
// being silently ignored. Parsing never depends on the name.
func knownExportName(logicalPath string) bool {
	base := strings.ToLower(path.Base(strings.ReplaceAll(logicalPath, `\`, "/")))
	switch {
	case splitConversations.MatchString(base):
		return true
	case base == "users.json", base == "user.json", base == "projects.json",
		base == "message_feedback.json", base == "shared_conversations.json":
		return true
	case base == "myactivity.json" || base == "myactivity.html":
		return geminiPath(logicalPath)
	}
	return false
}

func geminiPath(logicalPath string) bool {
	l := strings.ToLower(logicalPath)
	return strings.Contains(l, "gemini") || strings.Contains(l, "bard")
}

// Sniff classifies a file from its head (at most SniffBytes) by structure.
// The logical path is consulted only to decide whether an unrecognized
// file should be reported as an unsupported export file; ok is false for
// files that are neither recognized nor named like an export file.
func Sniff(head []byte, logicalPath string) (Detection, bool) {
	trimmed := bytes.TrimLeft(head, " \t\r\n\xef\xbb\xbf")
	if len(trimmed) == 0 {
		if knownExportName(logicalPath) {
			return Detection{Service: unknownService, Kind: KindUnsupported, Reason: "empty file"}, true
		}
		return Detection{}, false
	}
	if trimmed[0] == '<' {
		h := trimmed
		if len(h) > htmlSniffLimit {
			h = h[:htmlSniffLimit]
		}
		low := bytes.ToLower(h)
		if bytes.Contains(low, []byte("<html")) &&
			(bytes.Contains(h, []byte(geminiActivityTag)) || bytes.Contains(h, []byte(bardActivityTag))) {
			return Detection{Service: ServiceGemini, Kind: KindActivityHTML, Variant: "takeout-html"}, true
		}
		if knownExportName(logicalPath) {
			return Detection{Service: unknownService, Kind: KindUnsupported, Reason: "markup document where JSON was expected"}, true
		}
		return Detection{}, false
	}
	if trimmed[0] != '[' && trimmed[0] != '{' {
		if knownExportName(logicalPath) {
			return Detection{Service: unknownService, Kind: KindUnsupported, Reason: "not a JSON document"}, true
		}
		return Detection{}, false
	}
	s := summarize(trimmed)
	if d, ok := classify(s); ok {
		return d, true
	}
	if !knownExportName(logicalPath) {
		return Detection{}, false
	}
	return unsupported(s, logicalPath), true
}

func classify(s *shape) (Detection, bool) {
	const el = "[]"
	if s.root == '{' {
		// ChatGPT user.json: one account object.
		if s.has("", "id", "email") && s.any("", "chatgpt_plus_user", "phone_number", "birth_year") {
			return Detection{Service: ServiceChatGPT, Kind: KindAccount, Variant: "user-object"}, true
		}
		return Detection{}, false
	}
	if s.root != '[' {
		return Detection{}, false
	}
	switch {
	case s.has(el, "mapping"):
		node := el + ".mapping.*.message"
		deep := s.any(node, "fragments") || s.any(el, "inserted_at")
		gpt := s.any(node, "author") || s.any(el, "create_time", "current_node")
		switch {
		case deep && !s.any(node, "author"):
			return Detection{Service: ServiceDeepSeek, Kind: KindConversations, Variant: "mapping-fragments"}, true
		case gpt:
			// Whether current_node is present cannot be told from a head:
			// it follows the (often huge) mapping. The parser reports it.
			return Detection{Service: ServiceChatGPT, Kind: KindConversations, Variant: "mapping-tree"}, true
		}
	case s.has(el, "uuid", "chat_messages"):
		v := "text-only"
		if s.any(el+".chat_messages[]", "content") {
			v = "content-blocks"
		}
		return Detection{Service: ServiceClaudeAI, Kind: KindConversations, Variant: v}, true
	case s.has(el, "uuid") && s.any(el, "email_address", "full_name"):
		return Detection{Service: ServiceClaudeAI, Kind: KindAccount, Variant: "users-array"}, true
	case s.has(el, "uuid") && s.any(el, "docs", "prompt_template") && s.any(el, "name"):
		return Detection{Service: ServiceClaudeAI, Kind: KindProjects, Variant: "projects-array"}, true
	case s.has(el, "conversation_id", "rating"):
		return Detection{Service: ServiceChatGPT, Kind: KindFeedback, Variant: "feedback-array"}, true
	case s.has(el, "conversation_id") && s.any(el, "is_anonymous"):
		return Detection{Service: ServiceChatGPT, Kind: KindShared, Variant: "shared-array"}, true
	case s.has(el, "header", "title", "time") &&
		(s.valueContains("header", geminiActivityTag) || s.valueContains("products", geminiActivityTag) ||
			s.valueContains("header", bardActivityTag) || s.valueContains("products", bardActivityTag)):
		return Detection{Service: ServiceGemini, Kind: KindActivity, Variant: "takeout-json"}, true
	}
	return Detection{}, false
}

// unsupported names what an export file of this name was expected to hold
// and which of those keys are absent.
func unsupported(s *shape, logicalPath string) Detection {
	const el = "[]"
	base := strings.ToLower(path.Base(strings.ReplaceAll(logicalPath, `\`, "/")))
	d := Detection{Service: unknownService, Kind: KindUnsupported}
	switch {
	case strings.HasPrefix(base, "conversations"):
		if s.root != '[' {
			d.Reason = "top-level value is not an array of conversations"
			d.Missing = []string{"[]"}
			break
		}
		if s.keys[el] == nil {
			d.Reason = "array holds no conversation objects"
			d.Missing = []string{"[].mapping", "[].chat_messages"}
			break
		}
		d.Reason = "conversation objects match no known export schema (keys present: " + strings.Join(sortedKeys(s.keys[el]), ", ") + ")"
		d.Missing = []string{"mapping (ChatGPT/DeepSeek)", "uuid+chat_messages (Claude.ai)"}
	case strings.HasPrefix(base, "myactivity"):
		d.Reason = "activity records match no known Takeout schema"
		d.Missing = s.missing(el, "header", "title", "time")
		if len(d.Missing) == 0 {
			d.Missing = []string{"products/header naming Gemini Apps"}
		}
	case base == "users.json":
		d.Reason = "account records match no known schema"
		d.Missing = s.missing(el, "uuid", "email_address", "full_name")
	case base == "user.json":
		d.Reason = "account object matches no known schema"
		d.Missing = s.missing("", "id", "email")
	case base == "projects.json":
		d.Reason = "project records match no known schema"
		d.Missing = s.missing(el, "uuid", "name", "docs")
	case base == "message_feedback.json":
		d.Reason = "feedback records match no known schema"
		d.Missing = s.missing(el, "conversation_id", "rating")
	case base == "shared_conversations.json":
		d.Reason = "shared-conversation records match no known schema"
		d.Missing = s.missing(el, "conversation_id", "is_anonymous")
	default:
		d.Reason = "structure not recognized"
	}
	if len(d.Missing) > maxMissingKeys {
		d.Missing = d.Missing[:maxMissingKeys]
	}
	return d
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) > 12 {
		out = append(out[:12], "…")
	}
	return out
}
