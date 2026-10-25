package suite

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Delimited text exports (AXIOM CSV, Autopsy "Files - Text").
//
// Suites write these in several encodings and with several separators,
// so the reader detects both from the head: a UTF-8 BOM is dropped, a
// UTF-16 BOM (or a NUL-interleaved head without one) is decoded to UTF-8,
// and the separator is the one of , TAB ; | that occurs most often
// outside quotes in the header line. Quoted fields may span lines. Each
// record is bounded (maxRecordBytes, maxColumns); an over-long record
// stops the read with an error naming the line, since a CSV stream cannot
// be resynchronized safely after it.

const (
	maxRecordBytes = 4 << 20
	maxColumns     = 1024
	maxCell        = 16 << 10
	tableSniff     = 64 << 10
)

var errRecordTooLarge = fmt.Errorf("a record exceeds the %d-byte bound", maxRecordBytes)

// utf16Reader decodes UTF-16 (no BOM) to UTF-8.
type utf16Reader struct {
	r   *bufio.Reader
	be  bool
	out []byte
	hi  rune
	err error
}

func newUTF16Reader(r io.Reader, bigEndian bool) io.Reader {
	return &utf16Reader{r: bufio.NewReaderSize(r, 32<<10), be: bigEndian}
}

func (u *utf16Reader) Read(p []byte) (int, error) {
	for len(u.out) == 0 {
		if u.err != nil {
			return 0, u.err
		}
		var pair [2]byte
		for i := 0; i < 2048; i++ {
			if _, err := io.ReadFull(u.r, pair[:]); err != nil {
				if err == io.ErrUnexpectedEOF {
					u.out = utf8.AppendRune(u.out, utf8.RuneError)
					err = io.EOF
				}
				u.err = err
				break
			}
			c := rune(pair[0]) | rune(pair[1])<<8
			if u.be {
				c = rune(pair[1]) | rune(pair[0])<<8
			}
			switch {
			case utf16.IsSurrogate(c) && c < 0xDC00:
				if u.hi != 0 {
					u.out = utf8.AppendRune(u.out, utf8.RuneError)
				}
				u.hi = c
				continue
			case utf16.IsSurrogate(c):
				if u.hi != 0 {
					c = utf16.DecodeRune(u.hi, c)
				} else {
					c = utf8.RuneError
				}
				u.hi = 0
			case u.hi != 0:
				u.out = utf8.AppendRune(u.out, utf8.RuneError)
				u.hi = 0
			}
			u.out = utf8.AppendRune(u.out, c)
		}
	}
	n := copy(p, u.out)
	u.out = u.out[n:]
	return n, nil
}

// textReader detects the encoding of r and returns a UTF-8 reader plus the
// encoding's name.
func textReader(r io.Reader) (*bufio.Reader, string) {
	br := bufio.NewReaderSize(r, 64<<10)
	head, _ := br.Peek(4096)
	switch {
	case bytes.HasPrefix(head, []byte{0xEF, 0xBB, 0xBF}):
		_, _ = br.Discard(3)
		return br, "utf-8-bom"
	case bytes.HasPrefix(head, []byte{0xFF, 0xFE}):
		_, _ = br.Discard(2)
		return bufio.NewReaderSize(newUTF16Reader(br, false), 64<<10), "utf-16le"
	case bytes.HasPrefix(head, []byte{0xFE, 0xFF}):
		_, _ = br.Discard(2)
		return bufio.NewReaderSize(newUTF16Reader(br, true), 64<<10), "utf-16be"
	}
	if len(head) >= 16 {
		even, odd := 0, 0
		for i, c := range head {
			if c == 0 {
				if i%2 == 0 {
					even++
				} else {
					odd++
				}
			}
		}
		half := len(head) / 2
		switch {
		case odd > half*3/4 && even == 0:
			return bufio.NewReaderSize(newUTF16Reader(br, false), 64<<10), "utf-16le"
		case even > half*3/4 && odd == 0:
			return bufio.NewReaderSize(newUTF16Reader(br, true), 64<<10), "utf-16be"
		}
	}
	return br, "utf-8"
}

// headLines returns up to n complete lines from a decoded head.
func headLines(head []byte, n int) []string {
	parts := strings.Split(string(head), "\n")
	if len(parts) > 1 {
		parts = parts[:len(parts)-1] // the last may be cut
	}
	var out []string
	for _, p := range parts {
		p = strings.TrimRight(p, "\r")
		if strings.TrimSpace(p) == "" {
			continue
		}
		out = append(out, p)
		if len(out) == n {
			break
		}
	}
	return out
}

// delimiter picks the separator of a header line.
func delimiter(line string) (rune, int) {
	best, bestN := ',', 0
	for _, d := range []rune{',', '\t', ';', '|'} {
		n, inQ := 0, false
		for _, c := range line {
			switch {
			case c == '"':
				inQ = !inQ
			case c == d && !inQ:
				n++
			}
		}
		if n > bestN {
			best, bestN = d, n
		}
	}
	return best, bestN
}

func splitHeader(line string, d rune) []string {
	r := csv.NewReader(strings.NewReader(line))
	r.Comma = d
	r.LazyQuotes = true
	r.FieldsPerRecord = -1
	rec, err := r.Read()
	if err != nil {
		return nil
	}
	for i := range rec {
		rec[i] = strings.TrimSpace(strings.TrimPrefix(rec[i], "\ufeff"))
	}
	return rec
}

// tableShape is what a head says about a delimited export.
type tableShape struct {
	Encoding string
	Delim    rune
	Title    string // a one-cell line before the header (AXIOM writes the artifact name there in some versions)
	Header   []string
}

// sniffTable decodes a head and finds its header line (the first or,
// after a one-cell title line, the second).
func sniffTable(head []byte) (tableShape, bool) {
	br, enc := textReader(bytes.NewReader(head))
	dec, _ := io.ReadAll(io.LimitReader(br, tableSniff))
	lines := headLines(dec, 3)
	if len(lines) == 0 {
		return tableShape{}, false
	}
	sh := tableShape{Encoding: enc}
	d, n := delimiter(lines[0])
	if n == 0 && len(lines) > 1 {
		if d2, n2 := delimiter(lines[1]); n2 > 0 {
			sh.Title = strings.Trim(strings.TrimSpace(lines[0]), `"`)
			lines, d, n = lines[1:], d2, n2
		}
	}
	if n == 0 {
		return tableShape{}, false
	}
	sh.Delim = d
	sh.Header = splitHeader(lines[0], d)
	return sh, len(sh.Header) > 1
}

// readTable streams the records after the header and calls fn for each
// with its starting line. It returns the number of records read.
func readTable(r io.Reader, onHeader func(tableShape), fn func(row []string, line int) error) (tableShape, int, error) {
	br, enc := textReader(r)
	head, _ := br.Peek(tableSniff)
	sh, ok := sniffTable(append([]byte(nil), head...))
	if !ok {
		return sh, 0, errors.New("no delimited header line")
	}
	sh.Encoding = enc
	if onHeader != nil {
		onHeader(sh)
	}
	budget := &budgetReader{r: br, max: maxRecordBytes}
	cr := csv.NewReader(budget)
	cr.Comma = sh.Delim
	cr.LazyQuotes = true
	cr.FieldsPerRecord = -1
	cr.ReuseRecord = true
	skip := 1
	if sh.Title != "" {
		skip = 2
	}
	rows := 0
	for i := 0; ; i++ {
		budget.n = 0
		rec, err := cr.Read()
		if err == io.EOF {
			return sh, rows, nil
		}
		if err != nil {
			if errors.Is(err, errTokenTooLarge) {
				return sh, rows, fmt.Errorf("record %d (byte %d): %w", rows+1, cr.InputOffset(), errRecordTooLarge)
			}
			var pe *csv.ParseError
			if errors.As(err, &pe) {
				return sh, rows, fmt.Errorf("line %d: %v", pe.StartLine, pe.Err)
			}
			return sh, rows, err
		}
		if i < skip {
			continue
		}
		line := 0
		if len(rec) > 0 {
			line, _ = cr.FieldPos(0)
		}
		if len(rec) > maxColumns {
			rec = rec[:maxColumns]
		}
		for j := range rec {
			rec[j] = clip(rec[j], maxCell)
		}
		rows++
		if err := fn(rec, line); err != nil {
			return sh, rows, err
		}
	}
}

// column finds a header column by exact (case-insensitive) name, or -1.
func column(header []string, names ...string) int {
	for _, n := range names {
		for i, h := range header {
			if strings.EqualFold(h, n) {
				return i
			}
		}
	}
	return -1
}

// columnPrefix finds the first header column starting with one of the
// prefixes (case-insensitive), or -1.
func columnPrefix(header []string, prefixes ...string) int {
	for _, p := range prefixes {
		p = strings.ToLower(p)
		for i, h := range header {
			if strings.HasPrefix(strings.ToLower(h), p) {
				return i
			}
		}
	}
	return -1
}
