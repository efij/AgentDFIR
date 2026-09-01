// Package hashchain implements tamper-evident, hash-chained JSONL logs.
//
// Each line is a JSON object carrying a "prev" field: the lowercase hex
// SHA-256 of the previous line's exact bytes (without the trailing
// newline). The first record's prev is 64 zero characters. Any
// modification, insertion, deletion or reordering of a line breaks the
// chain for every subsequent record.
package hashchain

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// Genesis is the prev value of the first record in a chain.
const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// Writer appends hash-chained records to a JSONL file.
type Writer struct {
	f    *os.File
	prev string
	seq  int
}

// NewWriter creates (or truncates) the chain file at path.
func NewWriter(path string) (*Writer, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	return &Writer{f: f, prev: Genesis}, nil
}

// Append writes one record. The map is copied and extended with seq,
// ts_utc and prev fields; callers must not use those keys.
func (w *Writer) Append(record map[string]any) error {
	rec := make(map[string]any, len(record)+3)
	for k, v := range record {
		rec[k] = v
	}
	rec["seq"] = w.seq
	rec["ts_utc"] = time.Now().UTC().Format(time.RFC3339Nano)
	rec["prev"] = w.prev

	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if _, err := w.f.Write(append(line, '\n')); err != nil {
		return err
	}
	sum := sha256.Sum256(line)
	w.prev = hex.EncodeToString(sum[:])
	w.seq++
	return nil
}

// Close syncs and closes the underlying file.
func (w *Writer) Close() error {
	if err := w.f.Sync(); err != nil {
		w.f.Close()
		return err
	}
	return w.f.Close()
}

// VerifyFile checks the hash chain in the JSONL file at path.
// It returns the number of records and an error describing the first
// break found, if any.
func VerifyFile(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return Verify(f)
}

// Verify checks the hash chain read from r.
func Verify(r io.Reader) (int, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	expect := Genesis
	n := 0
	for sc.Scan() {
		line := sc.Bytes()
		var rec struct {
			Prev string `json:"prev"`
			Seq  int    `json:"seq"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			return n, fmt.Errorf("record %d: invalid JSON: %w", n, err)
		}
		if rec.Prev != expect {
			return n, fmt.Errorf("record %d (seq %d): chain broken: prev=%s want=%s", n, rec.Seq, rec.Prev, expect)
		}
		if rec.Seq != n {
			return n, fmt.Errorf("record %d: unexpected seq %d", n, rec.Seq)
		}
		sum := sha256.Sum256(line)
		expect = hex.EncodeToString(sum[:])
		n++
	}
	if err := sc.Err(); err != nil {
		return n, err
	}
	return n, nil
}
