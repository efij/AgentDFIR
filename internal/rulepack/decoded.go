package rulepack

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/efij/AgentDFIR/v3/internal/decode"
	"github.com/efij/AgentDFIR/v3/internal/schema"
	"github.com/efij/AgentDFIR/v3/internal/shellshape"
)

// decoded holds, per event index, the payloads its command decodes to, and
// what the command rules made of the command before and after decoding.
type decoded struct {
	byEvent map[int][]decode.Result
	raw     map[int]bool          // a HIGH/CRITICAL rule matched the command as written
	inner   map[int]*decodedMatch // strongest rule matched only after decoding
}

type decodedMatch struct {
	rule   *Rule
	result decode.Result
}

// maxDecodedPerEvent bounds decoded bytes kept for one event.
const maxDecodedPerEvent = 2 << 20

func decodeEvents(events []schema.Event) *decoded {
	d := &decoded{byEvent: map[int][]decode.Result{}, raw: map[int]bool{}, inner: map[int]*decodedMatch{}}
	for i := range events {
		// A heredoc body is a file being written, not a command being run;
		// and a payload that is decoded but never executed is data.
		cmd := shellshape.StripHeredocs(events[i].FullCommand())
		if cmd == "" || !decode.ExecutesDecoded(cmd) {
			continue
		}
		rs := decode.FindInCommand(cmd)
		total := 0
		var keep []decode.Result
		for _, r := range rs {
			total += len(r.Text)
			if total > maxDecodedPerEvent {
				break
			}
			keep = append(keep, r)
		}
		d.byEvent[i] = keep
	}
	return d
}

func highSev(s string) bool { return s == "HIGH" || s == "CRITICAL" }

func (d *decoded) rawHit(i int, r *Rule) {
	if highSev(r.Severity) {
		d.raw[i] = true
	}
}

func (d *decoded) decodedHit(i int, r *Rule, res decode.Result) {
	if !highSev(r.Severity) {
		return
	}
	if cur := d.inner[i]; cur == nil || (cur.rule.Severity != "CRITICAL" && r.Severity == "CRITICAL") {
		d.inner[i] = &decodedMatch{rule: r, result: res}
	}
}

// findings emits the decoder's own two findings:
//
//	ENCODED_PAYLOAD_EXECUTED  the command runs decoded data, and the decoded
//	                          text is itself something a HIGH+ rule flags
//	ENCODED_EXEC_UNRESOLVED   the command runs decoded data, nothing decoded,
//	                          and no HIGH+ rule already covers the command
func (d *decoded) findings(events []schema.Event) []schema.Finding {
	var out []schema.Finding
	for i := range events {
		rs, ok := d.byEvent[i]
		if !ok {
			continue
		}
		ev := &events[i]
		evidence := fmt.Sprintf("%s:%d (artifact %.12s)", ev.SourcePath, ev.SourceLine, ev.SourceArtifact)
		if m := d.inner[i]; m != nil {
			out = append(out, schema.Finding{
				RuleID: "ENCODED_PAYLOAD_EXECUTED", Severity: "HIGH",
				Title: "Encoded Payload Decoded and Run",
				Description: fmt.Sprintf("The command decodes a payload (%s) and the decoded text matches %s (%s). Decoded sha256 %s.",
					m.result.ChainString(), m.rule.ID, m.rule.Title, shortSum(m.result.Text)),
				SessionID: ev.SessionID, AgentID: ev.AgentID, EvidenceRefs: []string{evidence},
				Related: []string{"decoded: " + m.result.ChainString(), "inner_rule: " + m.rule.ID},
				Status:  ev.Corroboration, Endpoint: schema.StateUnknown,
				MitreATTACK: "T1027", MitreATLAS: "AML.T0050",
				FalsePositive: "Installers occasionally ship base64 bootstrap scripts; read the decoded text.",
			})
			continue
		}
		if len(rs) == 0 && !d.raw[i] {
			out = append(out, schema.Finding{
				RuleID: "ENCODED_EXEC_UNRESOLVED", Severity: "MEDIUM",
				Title:       "Encoded Data Run Through an Interpreter, Payload Not Recoverable",
				Description: "The command pipes decoded data into an interpreter (or evals it), but the payload is not in the command line — it came from a file, a variable or a download, or was cut. Recover it from the file system or endpoint telemetry.",
				SessionID:   ev.SessionID, AgentID: ev.AgentID, EvidenceRefs: []string{evidence},
				Status: ev.Corroboration, Endpoint: schema.StateUnknown,
				MitreATTACK: "T1027", MitreATLAS: "AML.T0050",
				FalsePositive: "Build scripts decode bundled assets; check what the interpreter received.",
			})
		}
	}
	return out
}

func shortSum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:16]
}
