package casepkg

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Rounds are transactional.
//
// A round appends to the manifest and both hash chains as it goes and
// writes blobs into raw/, and only Seal makes any of it part of the sealed
// package. A round that never reaches Seal — an error, a refused disk
// floor, Ctrl+C, a crash — used to leave that unsealed tail behind: the
// next round then extended chains whose last records no seal covered, and
// the case no longer verified. Every later round inherited the failure.
//
// So before a round writes anything, the sealed state it starts from is
// recorded in .round-pending.json: the lengths of the three append-only
// files and a copy of case.json. A round that is abandoned is rolled back
// to exactly that state — by Close, or by the next round when the process
// died — and the next round's custody chain records what was discarded:
// nothing is lost silently, and nothing unsealed is ever presented as part
// of a seal. The file is removed once the round is sealed.
//
// A round counts as sealed as soon as a new SHA256SUMS is in place (Seal
// writes it last, atomically). A crash after that point is a completed
// round and is not rolled back.

const (
	pendingFile = ".round-pending.json"
	abortedFile = ".round-aborted.json"
)

// appendOnlyFiles are the files a round appends to before it is sealed.
var appendOnlyFiles = []string{manifestJSONL, "collection.jsonl", "chain-of-custody.jsonl"}

type pendingRound struct {
	Round      int              `json:"round"`
	StartedUTC string           `json:"started_utc"`
	Lengths    map[string]int64 `json:"lengths"` // -1: the file did not exist
	CaseJSON   []byte           `json:"case_json"`
	SumsSHA256 string           `json:"sums_sha256"`
}

// AbortedRound describes a round that was rolled back.
type AbortedRound struct {
	Round          int    `json:"round"`
	StartedUTC     string `json:"started_utc"`
	DiscardedBlobs int    `json:"discarded_blobs"`
	DiscardedBytes int64  `json:"discarded_bytes"`
	How            string `json:"how"` // "abandoned" (rolled back on exit) or "crashed" (found by the next round)
}

func sumsDigest(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, sumsFile))
	if err != nil {
		return ""
	}
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:])
}

// beginPending records the sealed state a round of an existing package
// starts from. It must run before the round writes anything.
func beginPending(dir string, round int) error {
	p := pendingRound{Round: round, StartedUTC: time.Now().UTC().Format(time.RFC3339), Lengths: map[string]int64{}, SumsSHA256: sumsDigest(dir)}
	for _, f := range appendOnlyFiles {
		fi, err := os.Stat(filepath.Join(dir, f))
		switch {
		case errors.Is(err, os.ErrNotExist):
			p.Lengths[f] = -1
		case err != nil:
			return err
		default:
			p.Lengths[f] = fi.Size()
		}
	}
	cj, err := os.ReadFile(filepath.Join(dir, "case.json"))
	if err != nil {
		return err
	}
	p.CaseJSON = cj
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, pendingFile), data, 0o600)
}

// endPending marks the round sealed.
func endPending(dir string) {
	_ = os.Remove(filepath.Join(dir, pendingFile))
}

// rollbackPending restores the sealed state recorded by beginPending, if
// a round was left unsealed. It returns nil when there was nothing to roll
// back.
func rollbackPending(dir, how string) (*AbortedRound, error) {
	data, err := os.ReadFile(filepath.Join(dir, pendingFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p pendingRound
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("%s: %w", pendingFile, err)
	}
	if sumsDigest(dir) != p.SumsSHA256 {
		// The new seal was written: the round completed.
		endPending(dir)
		return nil, nil
	}
	sealed, err := readSums(filepath.Join(dir, sumsFile))
	if err != nil {
		return nil, fmt.Errorf("roll back round %d: the seal it started from is unreadable: %w", p.Round, err)
	}
	// Every blob the seal lists must still be there before anything is
	// removed: a seal that does not describe raw/ is not one to restore to.
	for rel := range sealed {
		if strings.HasPrefix(rel, "raw/") {
			if _, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(rel))); err != nil {
				return nil, fmt.Errorf("roll back round %d: sealed %s is missing; leaving the package for verify to examine", p.Round, rel)
			}
		}
	}
	ab := &AbortedRound{Round: p.Round, StartedUTC: p.StartedUTC, How: how}
	for _, f := range appendOnlyFiles {
		path := filepath.Join(dir, f)
		want, ok := p.Lengths[f]
		if !ok {
			continue
		}
		if want < 0 {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
			continue
		}
		fi, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("roll back round %d: %s: %w", p.Round, f, err)
		}
		if fi.Size() < want {
			return nil, fmt.Errorf("roll back round %d: %s is shorter than when the round began; leaving the package for verify to examine", p.Round, f)
		}
		if err := os.Truncate(path, want); err != nil {
			return nil, err
		}
	}
	if err := writeAtomic(filepath.Join(dir, "case.json"), p.CaseJSON, 0o600); err != nil {
		return nil, err
	}
	// Blobs and archived seals the round wrote are not in the seal it
	// started from.
	for _, sub := range []string{"raw", sealsDir} {
		entries, err := os.ReadDir(filepath.Join(dir, sub))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if _, ok := sealed[sub+"/"+e.Name()]; ok {
				continue
			}
			path := filepath.Join(dir, sub, e.Name())
			if fi, err := os.Lstat(path); err == nil && sub == "raw" {
				ab.DiscardedBlobs++
				ab.DiscardedBytes += fi.Size()
			}
			_ = os.Chmod(path, 0o600)
			if err := os.Remove(path); err != nil {
				return nil, err
			}
		}
	}
	endPending(dir)
	return ab, nil
}

// noteAborted leaves the record of a rolled-back round for the next round
// to put in its custody chain.
func noteAborted(dir string, ab *AbortedRound) {
	if ab == nil {
		return
	}
	var list []AbortedRound
	if data, err := os.ReadFile(filepath.Join(dir, abortedFile)); err == nil {
		_ = json.Unmarshal(data, &list)
	}
	list = append(list, *ab)
	if data, err := json.Marshal(list); err == nil {
		_ = writeAtomic(filepath.Join(dir, abortedFile), data, 0o600)
	}
}

// takeAborted returns and clears the rounds rolled back since the last
// round began.
func takeAborted(dir string) []AbortedRound {
	path := filepath.Join(dir, abortedFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var list []AbortedRound
	_ = json.Unmarshal(data, &list)
	_ = os.Remove(path)
	return list
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Chmod(tmp.Name(), mode); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}
