package journal

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/efij/AgentDFIR/v3/internal/casepkg"
	"github.com/efij/AgentDFIR/v3/internal/hashchain"
	"github.com/efij/AgentDFIR/v3/internal/schema"
)

type rec struct {
	Kind       string `json:"kind"`
	Path       string `json:"path"`
	Size       int64  `json:"size"`
	Offset     int64  `json:"offset"`
	Len        int64  `json:"len"`
	SHA256     string `json:"sha256"`
	Prefix     string `json:"prefix_sha256"`
	FileID     string `json:"file_id"`
	OldID      string `json:"old_file_id"`
	NewID      string `json:"new_file_id"`
	OldSize    int64  `json:"old_size"`
	Was        int64  `json:"was"`
	Now        int64  `json:"now"`
	At         string `json:"monitor_utc"`
	PrevBroken string `json:"previous_chain_broken"`
}

// maxJournal bounds the journal read at analysis.
const maxJournal = 256 << 20

// Check verifies the collected transcripts of a package against the
// monitor journal collected with them. No journal: no findings.
func Check(man *casepkg.Manifest, store *casepkg.Store) []schema.Finding {
	var ja *casepkg.ArtifactRecord
	cur := man.Current()
	bySource := map[string]casepkg.ArtifactRecord{}
	for i := range cur {
		a := cur[i]
		lp := strings.ReplaceAll(a.LogicalPath, `\`, "/")
		if strings.HasSuffix(lp, ".agentdfir/monitor/journal.jsonl") && a.Status == casepkg.StatusOK {
			ja = &cur[i]
		}
		if a.Status == casepkg.StatusOK {
			bySource[a.SourcePath] = a
		}
	}
	if ja == nil {
		return nil
	}
	data, err := store.ReadAll(ja.ArtifactID, maxJournal)
	if err != nil {
		return nil
	}
	jref := fmt.Sprintf("%s (artifact %.12s)", ja.LogicalPath, ja.ArtifactID)
	var out []schema.Finding
	if n, err := hashchain.Verify(bytes.NewReader(data)); err != nil {
		out = append(out, schema.Finding{RuleID: "JOURNAL_TAMPERED", Severity: "CRITICAL", Title: "Monitor Journal Was Edited",
			Description:  fmt.Sprintf("The monitor's hash-chained transcript journal is broken after record %d (%v). Records before the break still hold; everything after it is unproven.", n, err),
			EvidenceRefs: []string{jref}, Status: schema.StateObserved, Endpoint: schema.StateUnknown, MitreATTACK: "T1070"})
	}
	var recs []rec
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20)
	lastKind := ""
	for sc.Scan() {
		var r rec
		if json.Unmarshal(sc.Bytes(), &r) != nil {
			continue
		}
		if r.Kind == "start" {
			if r.PrevBroken != "" {
				out = append(out, schema.Finding{RuleID: "JOURNAL_TAMPERED", Severity: "CRITICAL", Title: "Monitor Found Its Previous Journal Broken",
					Description:  "When the monitor started at " + r.At + " the existing journal's chain did not verify (" + r.PrevBroken + "); it was set aside and a new one begun. Something edited the journal while the monitor was not running.",
					EvidenceRefs: []string{jref}, Status: schema.StateObserved, Endpoint: schema.StateUnknown, MitreATTACK: "T1070"})
			}
			if lastKind != "" && lastKind != "stop" {
				out = append(out, schema.Finding{RuleID: "MONITOR_GAP", Severity: "INFO", Title: "Monitor Stopped Without Closing Its Journal",
					Description:  "The monitor was restarted at " + r.At + " without a stop record before it: it was killed or the host went down. Transcript changes in that gap are not journaled.",
					EvidenceRefs: []string{jref}, Status: schema.StateObserved, Endpoint: schema.StateUnknown})
			}
		}
		lastKind = r.Kind
		recs = append(recs, r)
	}
	// Group by path; verify from the last baseline or replacement onward.
	byPath := map[string][]rec{}
	var paths []string
	for _, r := range recs {
		if r.Path == "" {
			continue
		}
		if _, ok := byPath[r.Path]; !ok {
			paths = append(paths, r.Path)
		}
		byPath[r.Path] = append(byPath[r.Path], r)
	}
	sort.Strings(paths)
	for _, p := range paths {
		out = append(out, checkPath(p, byPath[p], bySource, store, jref)...)
	}
	return out
}

func checkPath(p string, rs []rec, bySource map[string]casepkg.ArtifactRecord, store *casepkg.Store, jref string) []schema.Finding {
	var out []schema.Finding
	start := 0
	for i, r := range rs {
		switch r.Kind {
		case "replaced":
			out = append(out, schema.Finding{RuleID: "TRANSCRIPT_REPLACED", Severity: "HIGH", Title: "Transcript File Was Replaced While Monitored",
				Description:  fmt.Sprintf("%s was swapped for a different file (%s → %s) at %s, after %d bytes had been journaled. Atomic replacement is how a transcript is rewritten without truncating it in place.", path.Base(p), r.OldID, r.NewID, r.At, r.OldSize),
				EvidenceRefs: []string{jref}, Related: []string{"path: " + p}, Status: schema.StateObserved, Endpoint: schema.StateUnknown, MitreATTACK: "T1070"})
			start = i + 1
		case "truncate":
			out = append(out, schema.Finding{RuleID: "TRANSCRIPT_TRUNCATED", Severity: "HIGH", Title: "Transcript Shrank While Monitored",
				Description:  fmt.Sprintf("The monitor saw %s shrink from %d to %d bytes at %s. Agent transcripts are append-only; a shrinking one was edited or cut.", path.Base(p), r.Was, r.Now, r.At),
				EvidenceRefs: []string{jref}, Related: []string{"path: " + p}, Status: schema.StateObserved, Endpoint: schema.StateUnknown, MitreATTACK: "T1070"})
			start = i + 1
		}
		// A baseline does NOT reset: a monitor restarted after an edit
		// baselines the edited file, and the appends journaled before the
		// restart still say what the bytes were. Every range is checked.
	}
	rs = rs[start:]
	if len(rs) == 0 {
		return out
	}
	a, ok := bySource[p]
	if !ok {
		last := rs[len(rs)-1]
		if last.Kind == "deleted" || last.Kind == "append" || last.Kind == "baseline" {
			out = append(out, schema.Finding{RuleID: "TRANSCRIPT_DELETED", Severity: "INFO", Title: "Journaled Transcript Not in the Case",
				Description:  fmt.Sprintf("%s was journaled by the monitor but is not among the collected files. Agents clean up old sessions on their own (Claude Code: cleanupPeriodDays); check whether this one was due.", p),
				EvidenceRefs: []string{jref}, Related: []string{"path: " + p}, Status: schema.StateObserved, Endpoint: schema.StateUnknown, MitreATTACK: "T1070.004"})
		}
		return out
	}
	aref := fmt.Sprintf("%s (artifact %.12s)", a.LogicalPath, a.ArtifactID)
	for _, r := range rs {
		var off, n int64
		var want string
		switch r.Kind {
		case "baseline":
			off, n, want = 0, r.Size, r.SHA256
		case "append":
			off, n, want = r.Offset, r.Len, r.SHA256
		default:
			continue
		}
		if off+n > a.Size {
			return append(out, truncated(p, aref, jref, a.Size, off+n, r.At))
		}
		f, err := store.OpenAt(a.ArtifactID, off)
		if err != nil {
			return out
		}
		h := sha256.New()
		got, _ := io.CopyN(h, f, n)
		f.Close()
		if got < n {
			return append(out, truncated(p, aref, jref, a.Size, off+n, r.At))
		}
		if hex.EncodeToString(h.Sum(nil)) != want {
			return append(out, schema.Finding{RuleID: "TRANSCRIPT_REWRITTEN", Severity: "CRITICAL", Title: "Transcript Differs From What the Monitor Recorded",
				Description:  fmt.Sprintf("Bytes %d–%d of %s no longer match the SHA-256 the monitor journaled at %s. The transcript was edited after it was written: what it says now is not what the agent logged.", off, off+n, path.Base(p), r.At),
				EvidenceRefs: []string{aref, jref}, Related: []string{"path: " + p}, Status: schema.StateContradicted, Endpoint: schema.StateUnknown, MitreATTACK: "T1070", MitreATLAS: "AML.T0101"})
		}
	}
	return out
}

func truncated(p, aref, jref string, have, want int64, at string) schema.Finding {
	return schema.Finding{RuleID: "TRANSCRIPT_TRUNCATED", Severity: "HIGH", Title: "Transcript Is Shorter Than the Monitor Recorded",
		Description:  fmt.Sprintf("%s is %d bytes; the monitor journaled %d bytes of it by %s. Journaled content is missing.", path.Base(p), have, want, at),
		EvidenceRefs: []string{aref, jref}, Related: []string{"path: " + p}, Status: schema.StateContradicted, Endpoint: schema.StateUnknown, MitreATTACK: "T1070"}
}

// VerifyAnchor reports whether a chain head recorded elsewhere is still a
// line of the journal (a rebuilt chain would not contain it).
func VerifyAnchor(journalPath, head string) (bool, int, error) {
	f, err := os.Open(journalPath)
	if err != nil {
		return false, 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20)
	n := 0
	for sc.Scan() {
		n++
		s := sha256.Sum256(sc.Bytes())
		if hex.EncodeToString(s[:]) == strings.ToLower(strings.TrimSpace(head)) {
			return true, n, nil
		}
	}
	return false, n, sc.Err()
}
