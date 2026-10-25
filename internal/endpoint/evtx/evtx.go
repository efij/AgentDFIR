// Package evtx reads Windows XML Event Log (.evtx) files: the file
// header, 64 KiB chunks and the Binary XML event records inside them,
// with no Windows API and no third-party code.
//
// Inputs are hostile evidence. Checksums are verified and mismatches
// reported, every read is bounds-checked, nesting and node counts are
// capped, and a malformed record or chunk becomes a recorded problem
// while parsing continues with the next one.
package evtx

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"strconv"
	"time"
)

const (
	// FileMagic starts every .evtx file.
	FileMagic       = "ElfFile\x00"
	chunkMagic      = "ElfChnk\x00"
	recordMagic     = 0x00002a2a
	fileHeaderBlock = 4096
	ChunkSize       = 65536
	chunkHeaderSize = 512 // header + string table + template table
	recordHeader    = 24
	flagDirty       = 0x1
	flagFull        = 0x2
	maxProblems     = 20
)

// System holds the <System> fields of one event.
type System struct {
	Provider          string
	ProviderGUID      string
	EventSourceName   string
	EventID           string
	Qualifiers        string
	Version           string
	Level             string
	Task              string
	Opcode            string
	Keywords          string
	TimeCreated       string // as rendered: 2006-01-02T15:04:05.0000000Z
	EventRecordID     string
	ActivityID        string
	RelatedActivityID string
	ProcessID         string
	ThreadID          string
	Channel           string
	Computer          string
	UserID            string
}

// Event is one parsed event record.
type Event struct {
	RecordID uint64    // record header identifier
	Written  time.Time // record header FILETIME
	Chunk    int       // chunk index in the file
	Offset   int64     // file offset of the record
	System   System
	// Data maps EventData <Data Name="…"> (unnamed items as Data[i]) or
	// the leaf elements of UserData to their rendered values.
	Data map[string]string
	// Unverified is set when the record's chunk failed a checksum; the
	// record itself was structurally valid.
	Unverified bool
}

// Stats summarizes one file.
type Stats struct {
	MajorVersion, MinorVersion uint16
	HeaderChecksumOK           bool
	Dirty, Full                bool // header flags
	Chunks                     int  // chunks with a valid signature
	EmptyChunks                int  // preallocated, all-zero chunks
	BadChunks                  int  // bad signature or checksum mismatch
	Records                    int  // records delivered
	BadRecords                 int  // records that failed to parse
	SlackRecords               int  // record signatures found past a chunk's free-space offset (not parsed)
	Problems                   []string
	ProblemCount               int
}

func (s *Stats) problem(format string, a ...any) {
	s.ProblemCount++
	if len(s.Problems) < maxProblems {
		s.Problems = append(s.Problems, fmt.Sprintf(format, a...))
	}
}

// ErrNotEVTX is returned when the file does not start with FileMagic.
var ErrNotEVTX = errors.New("evtx: missing ElfFile signature")

// Parse walks every chunk of an .evtx image and calls fn for each event
// record that parses. It returns an error only for I/O failures or a
// missing file signature; everything else is recorded in Stats.
func Parse(r io.ReaderAt, size int64, fn func(*Event)) (*Stats, error) {
	st := &Stats{}
	hdr := make([]byte, 128)
	n, err := r.ReadAt(hdr, 0)
	if n < 8 || !bytes.Equal(hdr[:8], []byte(FileMagic)) {
		if err != nil && err != io.EOF && n < 8 {
			return nil, err
		}
		return nil, ErrNotEVTX
	}
	if n < 128 {
		st.problem("file header truncated (%d of 128 bytes)", n)
	} else {
		le := binary.LittleEndian
		st.MinorVersion, st.MajorVersion = le.Uint16(hdr[36:]), le.Uint16(hdr[38:])
		flags := le.Uint32(hdr[120:])
		st.Dirty, st.Full = flags&flagDirty != 0, flags&flagFull != 0
		st.HeaderChecksumOK = crc32.ChecksumIEEE(hdr[:120]) == le.Uint32(hdr[124:])
		if !st.HeaderChecksumOK {
			st.problem("file header checksum mismatch (stored %08x, computed %08x); parsing chunks anyway", le.Uint32(hdr[124:]), crc32.ChecksumIEEE(hdr[:120]))
		}
		if st.MajorVersion != 3 {
			st.problem("UNSUPPORTED evtx format version %d.%d (expected 3.x); parsing attempted", st.MajorVersion, st.MinorVersion)
		}
	}
	if size < fileHeaderBlock+chunkHeaderSize {
		if size != fileHeaderBlock { // exactly one header block is an empty log
			st.problem("file truncated: %d bytes, no complete chunk", size)
		}
		return st, nil
	}
	buf := make([]byte, ChunkSize)
	for i := 0; ; i++ {
		off := int64(fileHeaderBlock) + int64(i)*ChunkSize
		if off >= size {
			break
		}
		n, err := r.ReadAt(buf, off)
		if err != nil && err != io.EOF {
			return st, err
		}
		if n < ChunkSize {
			st.problem("chunk %d truncated (%d of %d bytes)", i, n, ChunkSize)
			for j := n; j < ChunkSize; j++ {
				buf[j] = 0
			}
			if n < chunkHeaderSize {
				st.BadChunks++
				break
			}
		}
		parseChunk(buf, i, off, st, fn)
	}
	return st, nil
}

// parseChunk validates one chunk and delivers its records.
func parseChunk(b []byte, idx int, fileOff int64, st *Stats, fn func(*Event)) {
	le := binary.LittleEndian
	if !bytes.Equal(b[:8], []byte(chunkMagic)) {
		if allZero(b) {
			st.EmptyChunks++
			return
		}
		st.BadChunks++
		st.problem("chunk %d: bad signature %q; skipped", idx, b[:8])
		return
	}
	st.Chunks++
	unverified := false
	hc := crc32.NewIEEE()
	hc.Write(b[:120])
	hc.Write(b[128:512])
	if hc.Sum32() != le.Uint32(b[124:]) {
		unverified = true
		st.problem("chunk %d: header checksum mismatch", idx)
	}
	free := int(le.Uint32(b[48:]))
	if free < chunkHeaderSize || free > ChunkSize {
		unverified = true
		st.problem("chunk %d: free-space offset %d out of range", idx, free)
		free = ChunkSize
	} else if crc32.ChecksumIEEE(b[chunkHeaderSize:free]) != le.Uint32(b[52:]) {
		unverified = true
		st.problem("chunk %d: event records checksum mismatch", idx)
	}
	if unverified {
		st.BadChunks++
	}
	p := newChunkParser(b)
	off := chunkHeaderSize
	for off+recordHeader <= free {
		if le.Uint32(b[off:]) != recordMagic {
			if allZero(b[off:free]) {
				break
			}
			st.BadRecords++
			st.problem("chunk %d offset %d: bad record signature; rest of chunk skipped", idx, off)
			break
		}
		size := int(le.Uint32(b[off+4:]))
		if size < recordHeader+4 || off+size > ChunkSize || le.Uint32(b[off+size-4:]) != uint32(size) {
			st.BadRecords++
			st.problem("chunk %d offset %d: bad record size %d; rest of chunk skipped", idx, off, size)
			break
		}
		ev, err := parseRecord(p, b, off, size)
		if err != nil {
			st.BadRecords++
			st.problem("chunk %d record %d: %v", idx, le.Uint64(b[off+8:]), err)
		} else {
			ev.Chunk, ev.Offset, ev.Unverified = idx, fileOff+int64(off), unverified
			st.Records++
			fn(ev)
		}
		off += size
	}
	// Slack: record signatures left past the free-space offset by
	// earlier writes. Counted, not parsed.
	for i := free; i+recordHeader <= ChunkSize; i++ {
		if b[i] != 0x2a || le.Uint32(b[i:]) != recordMagic {
			continue
		}
		size := int(le.Uint32(b[i+4:]))
		if size >= recordHeader+4 && i+size <= ChunkSize && le.Uint32(b[i+size-4:]) == uint32(size) {
			st.SlackRecords++
			i += size - 1
		}
	}
}

// parseRecord renders one record into an Event. A panic here would be a
// parser bug; it is converted to an error so one hostile record cannot
// abort the file.
func parseRecord(p *chunkParser, b []byte, off, size int) (ev *Event, err error) {
	defer func() {
		if r := recover(); r != nil {
			ev, err = nil, fmt.Errorf("parser fault: %v", r)
		}
	}()
	le := binary.LittleEndian
	ev = &Event{RecordID: le.Uint64(b[off+8:]), Written: FileTime(le.Uint64(b[off+16:]))}
	c := &cursor{b: b, pos: off + recordHeader, end: off + size - 4}
	nodes, err := p.parseFragment(c, 0)
	if err != nil {
		return nil, err
	}
	r := &renderer{p: p}
	elems, _, err := r.render(nodes, nil, 0)
	if err != nil {
		return nil, err
	}
	var root *Elem
	for _, e := range elems {
		if e.Name == "Event" {
			root = e
			break
		}
	}
	if root == nil {
		return nil, errors.New("no <Event> element")
	}
	fillEvent(ev, root)
	return ev, nil
}

// fillEvent copies System fields and EventData/UserData values.
func fillEvent(ev *Event, root *Elem) {
	sys := root.Child("System")
	s := &ev.System
	if pr := sys.Child("Provider"); pr != nil {
		s.Provider, s.ProviderGUID, s.EventSourceName = pr.Attr("Name"), pr.Attr("Guid"), pr.Attr("EventSourceName")
	}
	if id := sys.Child("EventID"); id != nil {
		s.EventID, s.Qualifiers = id.Text, id.Attr("Qualifiers")
	}
	text := func(name string) string {
		if e := sys.Child(name); e != nil {
			return e.Text
		}
		return ""
	}
	s.Version, s.Level, s.Task, s.Opcode, s.Keywords = text("Version"), text("Level"), text("Task"), text("Opcode"), text("Keywords")
	s.TimeCreated = sys.Child("TimeCreated").Attr("SystemTime")
	s.EventRecordID = text("EventRecordID")
	s.ActivityID, s.RelatedActivityID = sys.Child("Correlation").Attr("ActivityID"), sys.Child("Correlation").Attr("RelatedActivityID")
	s.ProcessID, s.ThreadID = sys.Child("Execution").Attr("ProcessID"), sys.Child("Execution").Attr("ThreadID")
	s.Channel, s.Computer = text("Channel"), text("Computer")
	s.UserID = sys.Child("Security").Attr("UserID")

	ev.Data = map[string]string{}
	if ed := root.Child("EventData"); ed != nil {
		for i, d := range ed.Children {
			name := d.Attr("Name")
			if name == "" {
				name = d.Name + "[" + strconv.Itoa(i) + "]"
			}
			ev.Data[name] = d.Text
		}
	}
	if ud := root.Child("UserData"); ud != nil {
		// UserData holds one provider-defined element; its leaves are the fields.
		for _, top := range ud.Children {
			for _, leaf := range top.Children {
				ev.Data[leaf.Name] = leaf.Text
			}
		}
	}
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
