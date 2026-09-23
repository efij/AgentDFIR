package detect

import (
	"bufio"
	"bytes"
	"io"

	"github.com/efij/AgentDFIR/v2/internal/casepkg"
)

// Streaming content scanning. Artifacts of ANY size are scanned with
// bounded memory: 1 MiB chunks with a 4 KiB overlap so patterns spanning
// a chunk boundary are still found. Replaces the earlier whole-blob read
// that silently skipped artifacts over 16 MiB — a blind spot adversary
// transcripts (often large) would fall into.

const (
	scanChunk   = 1 << 20 // 1 MiB
	scanOverlap = 4 << 10 // 4 KiB; longer than any pattern we match
)

// scanHit is one match: category name and absolute byte offset.
type scanHit struct {
	name   string
	offset int64
}

// blobReader opens one artifact's plaintext. Scanning goes through the
// package store, so it sees evidence content regardless of how the bytes
// are stored on disk (compressed, or split across appended chunks).
type blobReader struct {
	store *casepkg.Store
	id    string
}

// streamChunks calls fn for each chunk with its absolute base offset.
// Chunks overlap by scanOverlap bytes; callers dedupe hits whose offset
// falls inside the overlap of the previous chunk (offset < base +
// scanOverlap when base > 0).
func streamChunks(b blobReader, fn func(chunk []byte, base int64) bool) error {
	f, err := b.store.Open(b.id)
	if err != nil {
		return err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, scanChunk)
	buf := make([]byte, scanChunk+scanOverlap)
	var base int64
	carry := 0
	for {
		n, err := io.ReadFull(r, buf[carry:])
		total := carry + n
		if total == 0 {
			return nil
		}
		if !fn(buf[:total], base) {
			return nil
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil
		}
		if err != nil {
			return err
		}
		// Keep the tail as overlap for the next chunk.
		copy(buf, buf[total-scanOverlap:total])
		base += int64(total - scanOverlap)
		carry = scanOverlap
	}
}

// anchorWindow bounds the text a pattern is matched against once its
// literal anchor has been found. It equals the chunk overlap, which the
// scan already relies on being longer than any credential we match.
const anchorWindow = scanOverlap

// anchoredMatches returns the start offsets of p's non-overlapping matches
// in chunk — the same offsets FindAllIndex would return — by searching for
// the literal anchor and matching the regex only around each occurrence.
// A match must start at an anchor occurrence, so the leftmost match at or
// after the previous match's end is the first anchor occurrence there
// that the regex accepts. One byte before the anchor is included so the
// leading word boundary is judged against real context. Anchors do not
// overlap themselves at shift one (a test pins this), so a match found in
// the window either starts at the anchor or does not exist.
func anchoredMatches(chunk []byte, p secretPattern) []int {
	var out []int
	next := 0
	for i := 0; i < len(chunk); {
		j := bytes.Index(chunk[i:], []byte(p.lit))
		if j < 0 {
			break
		}
		at := i + j
		if at < next {
			i = at + 1
			continue
		}
		lo, hi := at-1, at+anchorWindow
		if lo < 0 {
			lo = 0
		}
		if hi > len(chunk) {
			hi = len(chunk)
		}
		loc := p.re.FindIndex(chunk[lo:hi])
		if loc == nil || lo+loc[0] != at || lo+loc[1] <= at {
			i = at + 1
			continue
		}
		out = append(out, at)
		next = lo + loc[1]
		i = next
	}
	return out
}

// scanRegex returns the first hit per pattern (and a count) across the
// whole artifact, streaming.
func scanRegex(b blobReader, patterns []secretPattern) (hits []scanHit, counts map[string]int) {
	acc := newSecretAcc(patterns)
	_ = streamChunks(b, func(chunk []byte, base int64) bool {
		acc.feed(chunk, base)
		return true
	})
	return acc.hits(), acc.counts
}

// scanContains reports the first occurrence of any exact marker.
func scanContains(b blobReader, markers []string) (marker string, offset int64, found bool) {
	acc := newContainsAcc(markers)
	_ = streamChunks(b, func(chunk []byte, base int64) bool {
		return !acc.feed(chunk, base)
	})
	return acc.marker, acc.offset, acc.found
}
