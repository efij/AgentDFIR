// Package linereader reads JSONL transcripts one line at a time with a
// per-line size bound, recovering past over-long lines instead of
// aborting. A single giant line (accidental or adversarial) must never
// blind a forensic parser to the evidence that follows it.
package linereader

import (
	"bufio"
	"io"
)

// Line is one logical transcript line.
type Line struct {
	Bytes     []byte // line content without the trailing newline; nil when Overflow
	Offset    int64  // byte offset of the line start
	Number    int    // 1-based line number
	Overflow  bool   // true when the line exceeded maxLine and was skipped
	OverBytes int64  // number of bytes skipped when Overflow is true
}

// Reader yields bounded lines from r.
type Reader struct {
	br      *bufio.Reader
	maxLine int
	offset  int64
	lineNo  int
}

// New creates a Reader bounding each line to maxLine bytes.
func New(r io.Reader, maxLine int) *Reader {
	return &Reader{br: bufio.NewReaderSize(r, 64*1024), maxLine: maxLine}
}

// Next returns the next line, or io.EOF when done. On an over-long line
// it returns a Line with Overflow set and consumes through the next
// newline so subsequent lines parse normally.
func (r *Reader) Next() (Line, error) {
	start := r.offset
	var buf []byte
	overflow := false
	var over int64
	for {
		chunk, err := r.br.ReadSlice('\n')
		if len(chunk) > 0 {
			r.offset += int64(len(chunk))
		}
		if !overflow {
			// Would appending exceed the bound?
			if len(buf)+len(chunk) > r.maxLine {
				overflow = true
				over = int64(len(buf) + len(chunk))
				buf = nil
			} else {
				buf = append(buf, chunk...)
			}
		} else {
			over += int64(len(chunk))
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err == io.EOF {
			if len(buf) == 0 && !overflow && over == 0 {
				return Line{}, io.EOF
			}
			r.lineNo++
			return finish(buf, start, r.lineNo, overflow, over), nil
		}
		if err != nil {
			return Line{}, err
		}
		// Got a full line (ended with '\n').
		r.lineNo++
		return finish(buf, start, r.lineNo, overflow, over), nil
	}
}

func finish(buf []byte, start int64, n int, overflow bool, over int64) Line {
	if overflow {
		return Line{Offset: start, Number: n, Overflow: true, OverBytes: over}
	}
	// Trim a single trailing newline.
	if len(buf) > 0 && buf[len(buf)-1] == '\n' {
		buf = buf[:len(buf)-1]
	}
	// Return a copy so callers may retain it across Next calls.
	out := make([]byte, len(buf))
	copy(out, buf)
	return Line{Bytes: out, Offset: start, Number: n}
}
