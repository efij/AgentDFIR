package detect

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
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

// blobPath resolves an artifact's sealed blob path.
func blobPath(pkgDir, artifactID string) string {
	return filepath.Join(pkgDir, "raw", artifactID)
}

// streamChunks calls fn for each chunk with its absolute base offset.
// Chunks overlap by scanOverlap bytes; callers dedupe hits whose offset
// falls inside the overlap of the previous chunk (offset < base +
// scanOverlap when base > 0).
func streamChunks(path string, fn func(chunk []byte, base int64) bool) error {
	f, err := os.Open(path)
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

// scanRegex returns the first hit per pattern (and a count) across the
// whole artifact, streaming.
func scanRegex(path string, patterns []struct {
	name string
	re   *regexp.Regexp
}) (hits []scanHit, counts map[string]int) {
	counts = map[string]int{}
	first := map[string]int64{}
	_ = streamChunks(path, func(chunk []byte, base int64) bool {
		for _, p := range patterns {
			for _, loc := range p.re.FindAllIndex(chunk, -1) {
				off := base + int64(loc[0])
				if base > 0 && loc[0] < scanOverlap {
					continue // already counted in previous chunk
				}
				counts[p.name]++
				if _, seen := first[p.name]; !seen {
					first[p.name] = off
				}
			}
		}
		return true
	})
	for name, off := range first {
		hits = append(hits, scanHit{name: name, offset: off})
	}
	return hits, counts
}

// scanPhrases finds the first occurrence (case-insensitive) of any phrase.
func scanPhrases(path string, phrases []string) (phrase string, offset int64, found bool) {
	lower := make([]string, len(phrases))
	for i, p := range phrases {
		lower[i] = strings.ToLower(p)
	}
	_ = streamChunks(path, func(chunk []byte, base int64) bool {
		low := strings.ToLower(string(chunk))
		for i, p := range lower {
			if idx := strings.Index(low, p); idx >= 0 {
				if base > 0 && idx < scanOverlap {
					continue
				}
				phrase, offset, found = phrases[i], base+int64(idx), true
				return false
			}
		}
		return true
	})
	return
}

// scanContains reports the first occurrence of any exact marker.
func scanContains(path string, markers []string) (marker string, offset int64, found bool) {
	_ = streamChunks(path, func(chunk []byte, base int64) bool {
		s := string(chunk)
		for _, m := range markers {
			if m == "" {
				continue
			}
			if idx := strings.Index(s, m); idx >= 0 {
				if base > 0 && idx < scanOverlap {
					continue
				}
				marker, offset, found = m, base+int64(idx), true
				return false
			}
		}
		return true
	})
	return
}

// invisibleStats counts invisible/reordering runes across an artifact.
func invisibleStats(path string) (tags, bidi, zw int, firstOff int64) {
	firstOff = -1
	_ = streamChunks(path, func(chunk []byte, base int64) bool {
		start := 0
		if base > 0 {
			start = scanOverlap
		}
		off := start
		for _, r := range string(chunk[start:]) {
			hit := false
			switch {
			case r >= 0xE0000 && r <= 0xE007F:
				tags++
				hit = true
			case (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069):
				bidi++
				hit = true
			case r >= 0x200B && r <= 0x200F, r == 0xFEFF:
				zw++
				hit = true
			case unicode.Is(unicode.Cf, r) && r != '­':
				zw++
				hit = true
			}
			if hit && firstOff == -1 {
				firstOff = base + int64(off)
			}
			off += len(string(r))
		}
		return true
	})
	if firstOff == -1 {
		firstOff = 0
	}
	return
}
