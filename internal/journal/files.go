package journal

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"time"
)

// File states reported by VerifyFiles.
const (
	FileOK            = "OK"             // every journaled range still hashes to what was recorded
	FilePruned        = "PRUNED"         // deleted by retention, and the deletion is journaled
	FileDeleted       = "DELETED"        // journaled, now missing, and no prune record accounts for it
	FileRewritten     = "REWRITTEN"      // a journaled range no longer matches its SHA-256
	FileTruncated     = "TRUNCATED"      // shorter than what was journaled
	FileReplaced      = "REPLACED"       // swapped for a different file, or shrank, while monitored
	FilePruneMismatch = "PRUNE_MISMATCH" // pruned, but its content at pruning differed from the journal
)

// FileCheck is the verdict for one journaled file.
type FileCheck struct {
	Path      string `json:"path"`             // as recorded in the journal
	Local     string `json:"local,omitempty"`  // where it was looked for
	State     string `json:"state"`            // one of the File* constants
	Detail    string `json:"detail,omitempty"` // human-readable reason
	Journaled int64  `json:"journaled_bytes"`
	Problem   bool   `json:"problem"`
}

// FilesReport sums up VerifyFiles.
type FilesReport struct {
	Files    []FileCheck `json:"files"`
	OK       int         `json:"ok"`
	Pruned   int         `json:"pruned"`
	Problems int         `json:"problems"`
}

type fileRec struct {
	rec
}

// VerifyFiles checks every file the journal recorded whose path resolve
// accepts: still-present files are re-hashed range by range against the
// journal; missing files must be covered by a prune record, or they are
// reported DELETED. resolve maps a recorded path to where the file is now
// (the same path on the live host, or the copy next to a collected
// journal) and returns false for paths outside the check (agent
// transcripts are checked at analysis, where agent clean-up is expected).
func VerifyFiles(journalPath string, resolve func(recorded string) (string, bool)) (*FilesReport, error) {
	f, err := os.Open(journalPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	byPath := map[string][]fileRec{}
	var order []string
	sc := bufio.NewScanner(io.LimitReader(f, maxJournal))
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20)
	for sc.Scan() {
		var r fileRec
		if json.Unmarshal(sc.Bytes(), &r) != nil || r.Path == "" {
			continue
		}
		if _, ok := byPath[r.Path]; !ok {
			if _, in := resolve(r.Path); !in {
				byPath[r.Path] = nil
				continue
			}
			order = append(order, r.Path)
		} else if byPath[r.Path] == nil {
			continue
		}
		byPath[r.Path] = append(byPath[r.Path], r)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	sort.Strings(order)
	rep := &FilesReport{}
	for _, p := range order {
		local, _ := resolve(p)
		fc := verifyOne(p, local, byPath[p])
		rep.Files = append(rep.Files, fc)
		switch {
		case fc.Problem:
			rep.Problems++
		case fc.State == FilePruned:
			rep.Pruned++
		default:
			rep.OK++
		}
	}
	return rep, nil
}

func verifyOne(p, local string, rs []fileRec) FileCheck {
	fc := FileCheck{Path: p, Local: local}
	// Ranges since the last replacement or truncation; the earlier ones
	// describe a file that no longer exists by design of the event.
	var ranges []fileRec
	var lastPrefix string
	var journaled int64
	var prune *fileRec
	pruneFailed := false
	for i := range rs {
		r := rs[i]
		switch r.Kind {
		case "baseline":
			ranges = append(ranges, r)
			journaled, lastPrefix = r.Size, r.SHA256
		case "append":
			ranges = append(ranges, r)
			journaled, lastPrefix = r.Offset+r.Len, r.Prefix
		case "replaced", "truncate":
			fc.State, fc.Problem = FileReplaced, true
			fc.Detail = fmt.Sprintf("%s recorded at %s", r.Kind, r.At)
			ranges, journaled, lastPrefix = nil, 0, ""
		case "prune":
			prune, pruneFailed = &rs[i], false
		case "prune_failed":
			pruneFailed = true
		}
	}
	fc.Journaled = journaled
	if fc.Problem {
		return fc
	}
	_, statErr := os.Stat(local)
	if statErr != nil {
		if prune == nil || pruneFailed {
			fc.State, fc.Problem = FileDeleted, true
			fc.Detail = fmt.Sprintf("%d journaled bytes; the file is gone and no prune record accounts for it", journaled)
			return fc
		}
		fc.State = FilePruned
		fc.Detail = fmt.Sprintf("pruned at %s (%s), %d bytes", prune.At, prune.Reason, prune.Size)
		if why := pruneVerdict(journaled, lastPrefix, &prune.rec); why != "" {
			fc.State, fc.Problem = FilePruneMismatch, true
			fc.Detail = fmt.Sprintf("pruned at %s, but %s", prune.At, why)
		} else if journaled > 0 && lastPrefix != "" {
			fc.Detail += "; content at deletion matches the journal"
			if prune.Size > journaled {
				fc.Detail += fmt.Sprintf(" (%d bytes past the last journaled range were never journaled)", prune.Size-journaled)
			}
		}
		return fc
	}
	if prune != nil && !pruneFailed {
		fc.Detail = "a prune was journaled but the file is present again; checked as a new file"
	}
	fh, err := os.Open(local)
	if err != nil {
		fc.State, fc.Problem = FileDeleted, true
		fc.Detail = "cannot open: " + err.Error()
		return fc
	}
	defer fh.Close()
	fi, _ := fh.Stat()
	for _, r := range ranges {
		off, n, want := r.Offset, r.Len, r.SHA256
		if r.Kind == "baseline" {
			off, n = 0, r.Size
		}
		if fi != nil && off+n > fi.Size() {
			fc.State, fc.Problem = FileTruncated, true
			fc.Detail = fmt.Sprintf("%d bytes on disk; %d were journaled by %s", fi.Size(), off+n, r.At)
			return fc
		}
		h := sha256.New()
		got, _ := io.Copy(h, io.NewSectionReader(fh, off, n))
		if got < n {
			fc.State, fc.Problem = FileTruncated, true
			fc.Detail = fmt.Sprintf("bytes %d–%d unreadable", off, off+n)
			return fc
		}
		if hex.EncodeToString(h.Sum(nil)) != want {
			fc.State, fc.Problem = FileRewritten, true
			fc.Detail = fmt.Sprintf("bytes %d–%d no longer match the SHA-256 journaled at %s", off, off+n, r.At)
			return fc
		}
	}
	fc.State = FileOK
	if fc.Detail == "" {
		fc.Detail = fmt.Sprintf("%d range(s), %d bytes verified", len(ranges), journaled)
	}
	return fc
}

// JournaledFile is what the journal holds for one path.
type JournaledFile struct {
	First time.Time // first baseline/append record
	Size  int64     // end of the last journaled range
}

// JournaledPaths returns every path the journal recorded content for
// (baseline or append): when it was first journaled and how many bytes
// were journaled. Retention uses it to touch only files this monitor
// journaled, and to hash the journaled range of what it deletes.
func JournaledPaths(journalPath string) (map[string]JournaledFile, error) {
	f, err := os.Open(journalPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]JournaledFile{}
	sc := bufio.NewScanner(io.LimitReader(f, maxJournal))
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20)
	for sc.Scan() {
		var r rec
		if json.Unmarshal(sc.Bytes(), &r) != nil || r.Path == "" {
			continue
		}
		jf, seen := out[r.Path]
		switch r.Kind {
		case "baseline":
			jf.Size = r.Size
		case "append":
			jf.Size = r.Offset + r.Len
		case "replaced", "truncate":
			jf.Size = 0
		default:
			continue
		}
		if !seen {
			jf.First, _ = time.Parse(time.RFC3339Nano, r.At)
		}
		out[r.Path] = jf
	}
	return out, sc.Err()
}
