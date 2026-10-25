package diskimage

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// openRaw opens a dd/raw image, or a split raw set when the name carries
// a split suffix (.001/.002 … or .aa/.ab …) and the first segment's
// siblings exist next to it.
func openRaw(path string) (*Image, error) {
	segs := splitSegments(path)
	if len(segs) <= 1 {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		fi, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, err
		}
		return &Image{r: f, size: fi.Size(), Format: FormatRaw, Segments: []string{path}, closers: []io.Closer{f}, Meta: map[string]string{}}, nil
	}
	im := &Image{Format: FormatSplitRaw, Segments: segs, Meta: map[string]string{"segments": strconv.Itoa(len(segs))}}
	mr := &multiReader{}
	for _, s := range segs {
		f, err := openSegment(s, path)
		if err != nil {
			im.Close()
			return nil, err
		}
		im.closers = append(im.closers, f)
		fi, err := f.Stat()
		if err != nil {
			im.Close()
			return nil, err
		}
		mr.parts = append(mr.parts, part{r: f, start: mr.size, size: fi.Size()})
		mr.size += fi.Size()
	}
	im.r, im.size = mr, mr.size
	return im, nil
}

// splitSegments returns the ordered segment list when path is the first
// segment of a split set; otherwise just path. A later segment given on
// the command line is resolved back to the first one when it exists.
func splitSegments(path string) []string {
	ext := filepath.Ext(path)
	if len(ext) < 3 {
		return []string{path}
	}
	suf := ext[1:]
	base := strings.TrimSuffix(path, ext)
	var first string
	switch {
	case isDigits(suf):
		w := len(suf)
		for _, start := range []int{0, 1} {
			cand := base + "." + pad(start, w)
			if fileExists(cand) {
				first = cand
				break
			}
		}
	case isLower(suf) && len(suf) <= 3:
		cand := base + "." + strings.Repeat("a", len(suf))
		if fileExists(cand) {
			first = cand
		}
	}
	if first == "" {
		return []string{path}
	}
	segs := []string{first}
	cur := filepath.Ext(first)[1:]
	for len(segs) < maxSegments {
		next, ok := nextSuffix(cur)
		if !ok {
			break
		}
		cand := base + "." + next
		if !fileExists(cand) {
			break
		}
		segs = append(segs, cand)
		cur = next
	}
	return segs
}

func nextSuffix(s string) (string, bool) {
	if isDigits(s) {
		n, err := strconv.Atoi(s)
		if err != nil {
			return "", false
		}
		out := pad(n+1, len(s))
		return out, len(out) == len(s)
	}
	b := []byte(s)
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] < 'z' {
			b[i]++
			return string(b), true
		}
		b[i] = 'a'
	}
	return "", false
}

func pad(n, w int) string {
	s := strconv.Itoa(n)
	for len(s) < w {
		s = "0" + s
	}
	return s
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

func isLower(s string) bool {
	for _, c := range s {
		if c < 'a' || c > 'z' {
			return false
		}
	}
	return s != ""
}

// fileExists reports whether a sibling name is present at all (any file
// type). Opening goes through openRegular, which refuses symlinks and
// non-regular files loudly instead of silently ending the series there.
func fileExists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// openSegment opens the path the operator gave as is, and every sibling
// the image implies through openRegular.
func openSegment(p, given string) (*os.File, error) {
	if p == given {
		return os.Open(p)
	}
	return openRegular(p)
}
