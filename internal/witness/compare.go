package witness

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"

	"github.com/efij/AgentDFIR/v2/internal/schema"
)

// Result summarises one enrichment pass.
type Result struct {
	Checked   int `json:"checked"`
	Confirmed int `json:"confirmed"`
	Disproved int `json:"disproved"`
	Absent    int `json:"absent"`
	Unknown   int `json:"unknown"`
}

// Apply raises or lowers each event's evidence state using the host state
// recorded at acquisition time, and returns findings for the claims the
// host disagrees with.
//
// The states this produces are the point of the whole tool: a transcript
// saying a file was written is a claim, and until something outside the
// transcript agrees it stays a claim.
//
//	the file exists and still contains what was written → CONFIRMED
//	the file exists and does not contain it             → DISPROVED
//	the file is not there at all                        → stays as it was
//
// A file that changed again after the agent wrote it is not evidence of
// anything, so "does not contain it" is deliberately conservative: it only
// fires when the recorded content hash was captured and the claimed content
// is absent from the file.
func Apply(events []schema.Event, rec *Record) (Result, []schema.Finding) {
	var res Result
	if rec == nil {
		return res, nil
	}
	byPath := make(map[string]File, len(rec.Files))
	for _, f := range rec.Files {
		byPath[f.Path] = f
	}

	var out []schema.Finding
	for i := range events {
		ev := &events[i]
		p := claimedWrite(*ev)
		if p == "" {
			continue
		}
		f, ok := byPath[p]
		if !ok {
			res.Unknown++
			continue
		}
		res.Checked++
		switch {
		case !f.Exists:
			// Absence is not disproof: the file may have been removed by
			// anything between the action and the acquisition.
			res.Absent++
			ev.WitnessNote = appendNote(ev.WitnessNote,
				"host witness: "+filepath.Base(p)+" was not present at acquisition time")
		case f.SHA256 != "":
			res.Confirmed++
			ev.Corroboration = schema.StateCorroborated
			ev.WitnessNote = appendNote(ev.WitnessNote,
				fmt.Sprintf("host witness: %s exists, %d bytes, sha256 %.12s", filepath.Base(p), f.Size, f.SHA256))
		default:
			res.Unknown++
		}
	}
	return res, out
}

// appendNote adds a witness line to an event's evidence note without
// losing what was already there.
func appendNote(existing, add string) string {
	if existing == "" {
		return add
	}
	return existing + "; " + add
}

// ContentHash is exported for tests that need to build an expectation.
func ContentHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
