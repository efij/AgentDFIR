package ntfs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// USN change journal ($Extend\$UsnJrnl, named stream $J).
//
// $J is a sparse stream: Windows deallocates the oldest part as the
// journal wraps, so only the allocated runs are read and the zeroed
// leading region is skipped by run, never scanned. Records are
// USN_RECORD_V2 / V3 (decoded) and V4 range-tracking records (counted and
// marked UNSUPPORTED). Records are 8-byte aligned and never cross a 4 KiB
// page; zero padding between them is skipped, and anything that is not a
// plausible record is skipped 8 bytes at a time until the scanner
// resynchronizes. Skipped garbage is counted, never silently dropped.

const (
	usnJournalName   = "$UsnJrnl"
	usnStreamName    = "$J"
	minUSNRecordV2   = 60
	minUSNRecordV3   = 76
	minUSNRecordV4   = 80
	maxUSNRecordLen  = 4096 // a record never crosses a 4 KiB page
	usnChunk         = 1 << 20
	maxUSNCollect    = 1 << 20 // USN() convenience cap; WalkUSN streams without one
	maxUSNProblems   = 50
	maxPathCacheSize = 1 << 18
)

// Status values used by the USN and deleted-record readers.
const (
	StatusUnsupported = "UNSUPPORTED"
	// PathReusedEntry marks a path whose parent MFT record now carries a
	// different sequence number: the directory the journal named has been
	// deleted and its record reused, so the current name would be wrong.
	PathReusedEntry = "(reused-mft-entry)"
)

// USNRecord is one normalized journal record.
type USNRecord struct {
	Offset         int64     `json:"offset"` // byte offset of the record inside $J
	MajorVersion   uint16    `json:"major_version"`
	MinorVersion   uint16    `json:"minor_version"`
	FileRef        string    `json:"file_ref,omitempty"` // hex: 16 digits (V2) or 32 (V3/V4)
	FileRecord     uint64    `json:"file_record"`        // MFT record number (low 48 bits)
	FileSeq        uint16    `json:"file_seq"`
	ParentRef      string    `json:"parent_ref,omitempty"`
	ParentRecord   uint64    `json:"parent_record"`
	ParentSeq      uint16    `json:"parent_seq"`
	USN            int64     `json:"usn"`
	Timestamp      time.Time `json:"timestamp,omitzero"`
	ReasonFlags    uint32    `json:"reason_flags"`
	Reasons        []string  `json:"reasons,omitempty"`
	SourceInfo     uint32    `json:"source_info"`
	SourceInfoText []string  `json:"source_info_names,omitempty"`
	SecurityID     uint32    `json:"security_id"`
	FileAttributes uint32    `json:"file_attributes"`
	Attributes     []string  `json:"attributes,omitempty"`
	FileName       string    `json:"file_name,omitempty"`
	Path           string    `json:"path,omitempty"`        // best effort, from the parent reference
	PathStatus     string    `json:"path_status,omitempty"` // resolved | reused-mft-entry | unresolved
	Status         string    `json:"status,omitempty"`      // UNSUPPORTED for V4 range records
	Problem        string    `json:"problem,omitempty"`
}

// USNStats summarizes one journal scan.
type USNStats struct {
	Present        bool     `json:"present"`
	Status         string   `json:"status"` // read | absent | UNSUPPORTED | CORRUPT
	Reason         string   `json:"reason,omitempty"`
	StreamSize     int64    `json:"stream_size"`
	SparseSkipped  int64    `json:"sparse_bytes_skipped"`
	BytesScanned   int64    `json:"bytes_scanned"`
	Records        int      `json:"records"`
	V2             int      `json:"v2_records"`
	V3             int      `json:"v3_records"`
	V4Unsupported  int      `json:"v4_records_unsupported"`
	GarbageSkipped int64    `json:"garbage_bytes_skipped"`
	Resyncs        int      `json:"resyncs"`
	Truncated      bool     `json:"truncated,omitempty"` // USN() collection cap hit
	Problems       []string `json:"problems,omitempty"`
}

func (s *USNStats) problem(format string, args ...any) {
	if len(s.Problems) < maxUSNProblems {
		s.Problems = append(s.Problems, fmt.Sprintf(format, args...))
	}
}

// errStopWalk ends a walk early from inside a callback without an error.
var errStopWalk = errors.New("stop")

// USN returns the decoded journal (at most maxUSNCollect records; the
// stats say when the cap was hit). Use WalkUSN to stream a large journal.
func (f *Volume) USN() ([]USNRecord, USNStats, error) {
	var out []USNRecord
	st, err := f.WalkUSN(func(r USNRecord) error {
		if len(out) >= maxUSNCollect {
			return errStopWalk
		}
		out = append(out, r)
		return nil
	})
	if errors.Is(err, errStopWalk) {
		st.Truncated = true
		st.problem("collection stopped at %d records; use WalkUSN for the rest", maxUSNCollect)
		err = nil
	}
	return out, st, err
}

// WalkUSN decodes $Extend\$UsnJrnl:$J and calls fn for every record in
// stream order. A volume without a journal returns Status "absent" and no
// error. fn may return an error to stop the walk; it is returned as is.
func (f *Volume) WalkUSN(fn func(USNRecord) error) (st USNStats, err error) {
	defer func() {
		if r := recover(); r != nil {
			st.Status = "CORRUPT"
			err = fmt.Errorf("ntfs: usn journal: %v", r)
		}
	}()
	s, err := f.usnStream()
	if err != nil {
		st.Status, st.Reason = "CORRUPT", err.Error()
		if errors.Is(err, ErrUnsupported) {
			st.Status = StatusUnsupported
		}
		st.Present = true
		return st, nil
	}
	if s == nil {
		st.Status, st.Reason = "absent", "no $Extend\\$UsnJrnl:$J stream on this volume"
		return st, nil
	}
	st.Present, st.Status, st.StreamSize = true, "read", s.size
	if s.encrypted || s.compressed {
		st.Status, st.Reason = StatusUnsupported, "$J stream is compressed or encrypted"
		return st, nil
	}
	sc := &usnScanner{fsys: f, st: &st, fn: fn, paths: map[uint64]pathResult{}}
	for _, ex := range s.extents() {
		if err := sc.scanExtent(s, ex[0], ex[1]); err != nil {
			return st, err
		}
	}
	st.SparseSkipped = st.StreamSize - st.BytesScanned
	if st.SparseSkipped < 0 {
		st.SparseSkipped = 0
	}
	return st, nil
}

// usnStream finds the $J stream of $Extend\$UsnJrnl (nil, nil if absent).
func (f *Volume) usnStream() (*stream, error) {
	var jr *node
	for _, nd := range f.nodes {
		for _, fn := range nd.names {
			if fn.parent == extendRecord && strings.EqualFold(fn.name, usnJournalName) {
				if jr == nil || nd.rec < jr.rec {
					jr = nd
				}
			}
		}
	}
	if jr == nil {
		return nil, nil
	}
	return f.namedStream(jr, usnStreamName)
}

// namedStream re-reads a record and assembles one named $DATA stream.
// It returns nil, nil when the record has no such stream.
func (f *Volume) namedStream(nd *node, name string) (*stream, error) {
	rec, err := f.v.readRecord(nd.rec)
	if err != nil {
		return nil, err
	}
	as := rec.attrs
	if nd.attrList || hasAttr(as, atAttributeList) {
		if as, err = f.v.withExtensions(rec); err != nil {
			return nil, err
		}
	}
	frags := dataFragments(as, name)
	if len(frags) == 0 {
		return nil, nil
	}
	return f.v.newStream(frags)
}

// extents returns the byte ranges [start, end) of the stream that are
// backed by allocated clusters, clipped to the initialized size. Sparse
// runs are left out: they read as zeros and hold no records.
func (s *stream) extents() [][2]int64 {
	limit := s.initSize
	if s.resident != nil || s.runs == nil {
		if limit > 0 {
			return [][2]int64{{0, limit}}
		}
		return nil
	}
	cs := s.v.clusterSize
	var out [][2]int64
	for _, r := range s.runs {
		if r.lcn < 0 {
			continue
		}
		a, b := r.vcn*cs, (r.vcn+r.length)*cs
		if b > limit {
			b = limit
		}
		if a >= b {
			continue
		}
		if n := len(out); n > 0 && out[n-1][1] == a {
			out[n-1][1] = b
			continue
		}
		out = append(out, [2]int64{a, b})
	}
	return out
}

type pathResult struct {
	path, status string
}

type usnScanner struct {
	fsys    *Volume
	st      *USNStats
	fn      func(USNRecord) error
	paths   map[uint64]pathResult
	garbage bool // inside a garbage run (one resync per run)
}

// scanExtent reads [start, end) of $J in chunks; a record cut by a chunk
// boundary is carried into the next read.
func (sc *usnScanner) scanExtent(s *stream, start, end int64) error {
	buf := make([]byte, usnChunk+maxUSNRecordLen)
	carry := 0
	pos := start // stream offset of buf[carry]
	for pos < end || carry > 0 {
		n := 0
		if pos < end {
			want := int64(usnChunk)
			if rem := end - pos; rem < want {
				want = rem
			}
			got, err := s.ReadAt(buf[carry:carry+int(want)], pos)
			if err != nil && !errors.Is(err, io.EOF) {
				sc.st.problem("$J read at %d: %v", pos, err)
				return nil
			}
			n = got
			if n == 0 {
				break
			}
		}
		base := pos - int64(carry)
		data := buf[:carry+n]
		pos += int64(n)
		sc.st.BytesScanned += int64(n)
		final := pos >= end
		used, err := sc.scanBuffer(data, base, final)
		if err != nil {
			return err
		}
		carry = copy(buf, data[used:])
		if final {
			if carry > 0 {
				sc.st.GarbageSkipped += int64(carry)
				sc.st.problem("$J: %d trailing bytes at %d form no complete record", carry, base+int64(used))
			}
			break
		}
	}
	return nil
}

// scanBuffer decodes records from data (stream offset base) and returns
// how many bytes were consumed; the rest is a record cut by the chunk.
func (sc *usnScanner) scanBuffer(data []byte, base int64, final bool) (int, error) {
	i := 0
	for i+8 <= len(data) {
		ln := int(binary.LittleEndian.Uint32(data[i:]))
		if ln == 0 {
			sc.garbage = false // zero padding up to the next page is normal
			i += 8
			continue
		}
		major := binary.LittleEndian.Uint16(data[i+4:])
		if ln%8 != 0 || ln < minUSNRecordV2 || ln > maxUSNRecordLen || major < 2 || major > 4 {
			sc.skip(base + int64(i))
			i += 8
			continue
		}
		if i+ln > len(data) {
			if !final {
				return i, nil
			}
			sc.skip(base + int64(i))
			i += 8
			continue
		}
		rec, err := ParseUSNRecord(data[i : i+ln])
		if err != nil {
			sc.skip(base + int64(i))
			i += 8
			continue
		}
		sc.garbage = false
		rec.Offset = base + int64(i)
		switch rec.MajorVersion {
		case 2:
			sc.st.V2++
		case 3:
			sc.st.V3++
		case 4:
			sc.st.V4Unsupported++
		}
		sc.st.Records++
		if rec.Status == "" {
			rec.Path, rec.PathStatus = sc.path(rec.ParentRecord, rec.ParentSeq, rec.FileName)
		}
		if err := sc.fn(rec); err != nil {
			return i, err
		}
		i += ln
	}
	return i, nil
}

func (sc *usnScanner) skip(off int64) {
	sc.st.GarbageSkipped += 8
	if !sc.garbage {
		sc.garbage = true
		sc.st.Resyncs++
		sc.st.problem("$J: no valid record at offset %d; resynchronizing", off)
	}
}

func (sc *usnScanner) path(parent uint64, seq uint16, name string) (string, string) {
	key := parent<<16 | uint64(seq)
	pr, ok := sc.paths[key]
	if !ok {
		p, status := sc.fsys.refPath(parent, seq)
		pr = pathResult{p, status}
		if len(sc.paths) < maxPathCacheSize {
			sc.paths[key] = pr
		}
	}
	if name == "" || pr.status == "unresolved" {
		return pr.path, pr.status
	}
	if pr.path == "/" {
		return "/" + name, pr.status
	}
	return pr.path + "/" + name, pr.status
}

// refPath resolves an MFT reference to a full path on the current volume.
// A sequence-number mismatch means the record was reused since the
// reference was written: the path is then PathReusedEntry, never the
// current occupant's name.
func (f *Volume) refPath(rec uint64, seq uint16) (string, string) {
	nd := f.nodes[rec]
	if nd == nil {
		return fmt.Sprintf("(mft-record-%d-not-in-use)", rec), "unresolved"
	}
	if seq != 0 && nd.seq != 0 && nd.seq != seq {
		return PathReusedEntry, "reused-mft-entry"
	}
	return f.nodePath(nd), "resolved"
}

// nodePath builds a node's path from its first link name upward. The walk
// is depth-capped and cycle-guarded; a gap is marked, never guessed.
func (f *Volume) nodePath(nd *node) string {
	var parts []string
	seen := map[uint64]bool{}
	cur := nd
	for depth := 0; ; depth++ {
		if cur.rec == rootRecord {
			break
		}
		if depth >= maxResolveDepth || seen[cur.rec] {
			parts = append(parts, "(parent-loop)")
			break
		}
		seen[cur.rec] = true
		names := cur.linkNames()
		if len(names) == 0 {
			parts = append(parts, fmt.Sprintf("(mft-record-%d-unnamed)", cur.rec))
			break
		}
		fn := names[0]
		parts = append(parts, safeName(fn.name))
		p := f.nodes[fn.parent]
		if p == nil || (fn.parentSeq != 0 && p.seq != 0 && fn.parentSeq != p.seq) {
			parts = append(parts, fmt.Sprintf("(mft-record-%d-gone)", fn.parent))
			break
		}
		cur = p
	}
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return "/" + strings.Join(parts, "/")
}

// ParseUSNRecord decodes one record (b holds exactly RecordLength bytes,
// or more). It never panics; V4 range records come back with Status
// UNSUPPORTED and only their header fields set.
func ParseUSNRecord(b []byte) (USNRecord, error) {
	var r USNRecord
	if len(b) < 8 {
		return r, fmt.Errorf("usn record: %d bytes", len(b))
	}
	ln := int(binary.LittleEndian.Uint32(b[0:4]))
	r.MajorVersion = binary.LittleEndian.Uint16(b[4:6])
	r.MinorVersion = binary.LittleEndian.Uint16(b[6:8])
	if ln > len(b) || ln%8 != 0 || ln > maxUSNRecordLen {
		return r, fmt.Errorf("usn record length %d invalid", ln)
	}
	b = b[:ln]
	le := binary.LittleEndian
	var nameLen, nameOff int
	switch r.MajorVersion {
	case 2:
		if ln < minUSNRecordV2 {
			return r, fmt.Errorf("usn v2 record length %d", ln)
		}
		fr, pr := le.Uint64(b[8:]), le.Uint64(b[16:])
		r.FileRef, r.FileRecord, r.FileSeq = fmt.Sprintf("%016x", fr), fr&0xFFFFFFFFFFFF, uint16(fr>>48)
		r.ParentRef, r.ParentRecord, r.ParentSeq = fmt.Sprintf("%016x", pr), pr&0xFFFFFFFFFFFF, uint16(pr>>48)
		r.USN = int64(le.Uint64(b[24:]))
		r.Timestamp = filetime(b[32:])
		r.ReasonFlags, r.SourceInfo = le.Uint32(b[40:]), le.Uint32(b[44:])
		r.SecurityID, r.FileAttributes = le.Uint32(b[48:]), le.Uint32(b[52:])
		nameLen, nameOff = int(le.Uint16(b[56:])), int(le.Uint16(b[58:]))
		if nameOff < minUSNRecordV2 {
			return r, fmt.Errorf("usn v2 file name offset %d", nameOff)
		}
	case 3:
		if ln < minUSNRecordV3 {
			return r, fmt.Errorf("usn v3 record length %d", ln)
		}
		r.FileRef, r.FileRecord, r.FileSeq = ref128(b[8:24])
		r.ParentRef, r.ParentRecord, r.ParentSeq = ref128(b[24:40])
		r.USN = int64(le.Uint64(b[40:]))
		r.Timestamp = filetime(b[48:])
		r.ReasonFlags, r.SourceInfo = le.Uint32(b[56:]), le.Uint32(b[60:])
		r.SecurityID, r.FileAttributes = le.Uint32(b[64:]), le.Uint32(b[68:])
		nameLen, nameOff = int(le.Uint16(b[72:])), int(le.Uint16(b[74:]))
		if nameOff < minUSNRecordV3 {
			return r, fmt.Errorf("usn v3 file name offset %d", nameOff)
		}
	case 4:
		if ln < minUSNRecordV4 {
			return r, fmt.Errorf("usn v4 record length %d", ln)
		}
		r.FileRef, r.FileRecord, r.FileSeq = ref128(b[8:24])
		r.ParentRef, r.ParentRecord, r.ParentSeq = ref128(b[24:40])
		r.USN = int64(le.Uint64(b[40:]))
		r.ReasonFlags, r.SourceInfo = le.Uint32(b[48:]), le.Uint32(b[52:])
		r.Reasons, r.SourceInfoText = reasonNames(r.ReasonFlags), sourceInfoNames(r.SourceInfo)
		r.Status = StatusUnsupported
		r.Problem = "USN_RECORD_V4 (range tracking extents) is not decoded"
		return r, nil
	default:
		return r, fmt.Errorf("usn record version %d.%d", r.MajorVersion, r.MinorVersion)
	}
	if nameLen%2 != 0 || nameOff+nameLen > ln {
		return r, fmt.Errorf("usn file name (offset %d, length %d) outside the %d-byte record", nameOff, nameLen, ln)
	}
	if r.USN < 0 {
		return r, fmt.Errorf("usn %d negative", r.USN)
	}
	r.FileName = utf16LE(b[nameOff : nameOff+nameLen])
	r.Reasons = reasonNames(r.ReasonFlags)
	r.SourceInfoText = sourceInfoNames(r.SourceInfo)
	r.Attributes = AttributeNames(r.FileAttributes)
	return r, nil
}

// ref128 decodes a FILE_ID_128. On NTFS the low 64 bits are the classic
// reference (48-bit record, 16-bit sequence) and the high half is zero.
func ref128(b []byte) (string, uint64, uint16) {
	lo, hi := binary.LittleEndian.Uint64(b[0:8]), binary.LittleEndian.Uint64(b[8:16])
	return fmt.Sprintf("%016x%016x", hi, lo), lo & 0xFFFFFFFFFFFF, uint16(lo >> 48)
}

type flagName struct {
	bit  uint32
	name string
}

var usnReasons = []flagName{
	{0x00000001, "DATA_OVERWRITE"}, {0x00000002, "DATA_EXTEND"}, {0x00000004, "DATA_TRUNCATION"},
	{0x00000010, "NAMED_DATA_OVERWRITE"}, {0x00000020, "NAMED_DATA_EXTEND"}, {0x00000040, "NAMED_DATA_TRUNCATION"},
	{0x00000100, "FILE_CREATE"}, {0x00000200, "FILE_DELETE"}, {0x00000400, "EA_CHANGE"},
	{0x00000800, "SECURITY_CHANGE"}, {0x00001000, "RENAME_OLD_NAME"}, {0x00002000, "RENAME_NEW_NAME"},
	{0x00004000, "INDEXABLE_CHANGE"}, {0x00008000, "BASIC_INFO_CHANGE"}, {0x00010000, "HARD_LINK_CHANGE"},
	{0x00020000, "COMPRESSION_CHANGE"}, {0x00040000, "ENCRYPTION_CHANGE"}, {0x00080000, "OBJECT_ID_CHANGE"},
	{0x00100000, "REPARSE_POINT_CHANGE"}, {0x00200000, "STREAM_CHANGE"}, {0x00400000, "TRANSACTED_CHANGE"},
	{0x00800000, "INTEGRITY_CHANGE"}, {0x01000000, "DESIRED_STORAGE_CLASS_CHANGE"}, {0x80000000, "CLOSE"},
}

var usnSources = []flagName{
	{0x1, "DATA_MANAGEMENT"}, {0x2, "AUXILIARY_DATA"}, {0x4, "REPLICATION_MANAGEMENT"}, {0x8, "CLIENT_REPLICATION_MANAGEMENT"},
}

var fileAttrs = []flagName{
	{0x1, "READONLY"}, {0x2, "HIDDEN"}, {0x4, "SYSTEM"}, {0x10, "DIRECTORY"}, {0x20, "ARCHIVE"},
	{0x40, "DEVICE"}, {0x80, "NORMAL"}, {0x100, "TEMPORARY"}, {0x200, "SPARSE_FILE"}, {0x400, "REPARSE_POINT"},
	{0x800, "COMPRESSED"}, {0x1000, "OFFLINE"}, {0x2000, "NOT_CONTENT_INDEXED"}, {0x4000, "ENCRYPTED"},
	{0x8000, "INTEGRITY_STREAM"}, {0x10000, "VIRTUAL"}, {0x20000, "NO_SCRUB_DATA"}, {0x40000, "RECALL_ON_OPEN"},
	{0x80000, "PINNED"}, {0x100000, "UNPINNED"}, {0x400000, "RECALL_ON_DATA_ACCESS"},
}

// decodeFlags names every set bit in table order; bits without a documented name are
// reported as hex, so nothing is dropped.
func decodeFlags(v uint32, table []flagName) []string {
	var out []string
	known := uint32(0)
	for _, f := range table {
		known |= f.bit
		if v&f.bit != 0 {
			out = append(out, f.name)
		}
	}
	if rest := v &^ known; rest != 0 {
		out = append(out, fmt.Sprintf("0x%08x", rest))
	}
	return out
}

func reasonNames(v uint32) []string     { return decodeFlags(v, usnReasons) }
func sourceInfoNames(v uint32) []string { return decodeFlags(v, usnSources) }

// AttributeNames decodes Windows FILE_ATTRIBUTE_* bits.
func AttributeNames(v uint32) []string { return decodeFlags(v, fileAttrs) }
