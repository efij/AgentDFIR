package diskimage

import (
	"bytes"
	"compress/zlib"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/adler32"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"unicode/utf16"
)

// EWF-E01 (EnCase 1-7 / libewf "encase" and "smart" formats).
//
// A segment file is a 13-byte header followed by a linked list of
// sections, each introduced by a 76-byte descriptor. The media is split
// into chunks (sectors_per_chunk × bytes_per_sector, usually 32 KiB);
// "table" sections list where each chunk starts, the high bit marking a
// zlib-compressed chunk. Uncompressed chunks carry a trailing Adler-32.
// "hash" and "digest" sections store the acquisition MD5 / SHA-1, which
// VerifyStored checks against a full re-read.

const (
	ewfHeaderSize     = 13
	ewfDescriptorSize = 76
	maxEWFChunks      = 1 << 28
	maxEWFChunkSize   = 64 << 20
	maxEWFSections    = 1 << 20
	maxEWFHeaderText  = 1 << 20
)

type ewfChunk struct {
	seg        int
	off        int64 // absolute offset in the segment file
	size       int64 // stored size (compressed, or chunk+adler32)
	compressed bool
}

type ewfImage struct {
	files       []*os.File
	chunks      []ewfChunk
	chunkSize   int64
	mediaSize   int64
	storedMD5   []byte
	storedSHA1  []byte
	mu          sync.Mutex
	cacheIdx    int
	cacheData   []byte
	cacheFilled bool
}

// openEWF opens path (any .E01-style first segment) and its siblings.
func openEWF(path string) (*Image, error) {
	segs, err := ewfSegments(path)
	if err != nil {
		return nil, err
	}
	im := &Image{Format: FormatEWF, Meta: map[string]string{}}
	e := &ewfImage{cacheIdx: -1}
	fail := func(err error) (*Image, error) {
		for _, f := range e.files {
			f.Close()
		}
		return nil, err
	}
	var sectorsPerChunk, bytesPerSector uint32
	var sectorCount uint64
	var declaredChunks uint32
	for i, s := range segs {
		f, err := openSegment(s, path)
		if err != nil {
			return fail(err)
		}
		e.files = append(e.files, f)
		fi, err := f.Stat()
		if err != nil {
			return fail(err)
		}
		hdr := make([]byte, ewfHeaderSize)
		if _, err := f.ReadAt(hdr, 0); err != nil {
			return fail(corrupt("ewf", "%s: short segment header", filepath.Base(s)))
		}
		if string(hdr[:8]) != "EVF\x09\x0d\x0a\xff\x00" {
			return fail(corrupt("ewf", "%s: not an EWF segment", filepath.Base(s)))
		}
		if n := binary.LittleEndian.Uint16(hdr[9:11]); int(n) != i+1 {
			return fail(corrupt("ewf", "%s: segment number %d, expected %d (missing or misordered segment)", filepath.Base(s), n, i+1))
		}
		ctx := &ewfSegCtx{e: e, seg: i, f: f, size: fi.Size(), im: im}
		if err := ctx.walk(); err != nil {
			return fail(err)
		}
		if ctx.volSeen {
			sectorsPerChunk, bytesPerSector, sectorCount, declaredChunks = ctx.spc, ctx.bps, ctx.sectors, ctx.chunkCount
		}
		if ctx.done && i != len(segs)-1 {
			segs = segs[:i+1]
			break
		}
		if !ctx.done && !ctx.next {
			return fail(corrupt("ewf", "%s: section chain ends without next/done (truncated segment)", filepath.Base(s)))
		}
		if ctx.next && i == len(segs)-1 {
			return fail(corrupt("ewf", "%s: segment says another follows but none was found next to it", filepath.Base(s)))
		}
	}
	if sectorsPerChunk == 0 || bytesPerSector == 0 {
		return fail(corrupt("ewf", "no volume/disk section"))
	}
	e.chunkSize = int64(sectorsPerChunk) * int64(bytesPerSector)
	if e.chunkSize <= 0 || e.chunkSize > maxEWFChunkSize {
		return fail(corrupt("ewf", "implausible chunk size %d", e.chunkSize))
	}
	if sectorCount > uint64(maxEWFChunks)*uint64(sectorsPerChunk) {
		return fail(corrupt("ewf", "implausible sector count %d", sectorCount))
	}
	e.mediaSize = int64(sectorCount) * int64(bytesPerSector)
	need := (e.mediaSize + e.chunkSize - 1) / e.chunkSize
	if int64(len(e.chunks)) < need {
		return fail(corrupt("ewf", "chunk tables list %d chunks, media needs %d (declared %d)", len(e.chunks), need, declaredChunks))
	}
	e.chunks = e.chunks[:need]
	im.r, im.size, im.ewf = e, e.mediaSize, e
	im.Segments = segs
	for _, f := range e.files {
		im.closers = append(im.closers, f)
	}
	im.Meta["segments"] = strconv.Itoa(len(segs))
	im.Meta["chunk_size"] = strconv.FormatInt(e.chunkSize, 10)
	im.Meta["bytes_per_sector"] = strconv.Itoa(int(bytesPerSector))
	if e.storedMD5 != nil {
		im.Meta["stored_md5"] = hex.EncodeToString(e.storedMD5)
	}
	if e.storedSHA1 != nil {
		im.Meta["stored_sha1"] = hex.EncodeToString(e.storedSHA1)
	}
	return im, nil
}

// ewfSegments lists path and its siblings: .E01 … .E99, .EAA … .EZZ,
// .FAA … (the case of the extension letter is kept).
func ewfSegments(path string) ([]string, error) {
	ext := filepath.Ext(path)
	if len(ext) != 4 {
		return []string{path}, nil
	}
	base := strings.TrimSuffix(path, ext)
	first := ext[1]
	segs := []string{path}
	for n := 2; n <= maxSegments; n++ {
		suf, ok := ewfSuffix(first, n)
		if !ok {
			break
		}
		cand := base + "." + suf
		if !fileExists(cand) {
			break
		}
		segs = append(segs, cand)
	}
	return segs, nil
}

// ewfSuffix names segment n (1-based) given the first segment's letter:
// E01 … E99, then EAA … EZZ, FAA … ZZZ.
func ewfSuffix(first byte, n int) (string, bool) {
	if n <= 99 {
		return fmt.Sprintf("%c%02d", first, n), true
	}
	a := byte('A')
	if first >= 'a' && first <= 'z' {
		a = 'a'
	}
	k := n - 100
	lead := int(first-a) + k/(26*26)
	if lead >= 26 || first < a {
		return "", false
	}
	rest := k % (26 * 26)
	return string([]byte{a + byte(lead), a + byte(rest/26), a + byte(rest%26)}), true
}

type ewfSegCtx struct {
	e          *ewfImage
	im         *Image
	seg        int
	f          *os.File
	size       int64
	done, next bool
	volSeen    bool
	spc, bps   uint32
	sectors    uint64
	chunkCount uint32
	// sectorsEnd: end offset of the most recent "sectors" section, which
	// bounds the last chunk a following table lists.
	sectorsEnd int64
	tableSeen  bool
}

func (c *ewfSegCtx) walk() error {
	off := int64(ewfHeaderSize)
	seen := map[int64]bool{}
	for n := 0; n < maxEWFSections; n++ {
		if off < 0 || off > c.size-ewfDescriptorSize {
			return corrupt("ewf", "segment %d: section descriptor at %d past end of file (truncated)", c.seg+1, off)
		}
		if seen[off] {
			return corrupt("ewf", "segment %d: section loop at %d", c.seg+1, off)
		}
		seen[off] = true
		d := make([]byte, ewfDescriptorSize)
		if _, err := c.f.ReadAt(d, off); err != nil {
			return corrupt("ewf", "segment %d: read descriptor: %v", c.seg+1, err)
		}
		if adler32.Checksum(d[:72]) != binary.LittleEndian.Uint32(d[72:76]) {
			return corrupt("ewf", "segment %d: section descriptor checksum mismatch at %d", c.seg+1, off)
		}
		typ := strings.TrimRight(string(d[:16]), "\x00")
		next := int64(binary.LittleEndian.Uint64(d[16:24]))
		size := int64(binary.LittleEndian.Uint64(d[24:32]))
		dataOff := off + ewfDescriptorSize
		dataLen := size - ewfDescriptorSize
		if size != 0 && (size < ewfDescriptorSize || size > c.size-off) && typ != "done" && typ != "next" {
			return corrupt("ewf", "segment %d: section %q size %d out of bounds", c.seg+1, typ, size)
		}
		switch typ {
		case "header", "header2":
			c.header(typ, dataOff, dataLen)
		case "volume", "disk", "data":
			if err := c.volume(dataOff, dataLen); err != nil {
				return err
			}
		case "sectors":
			c.sectorsEnd = off + size
		case "table":
			if err := c.table(dataOff, dataLen, off); err != nil {
				return err
			}
			c.tableSeen = true
		case "table2":
			// Mirror of the preceding table. Used only if that table was unreadable.
			if !c.tableSeen {
				if err := c.table(dataOff, dataLen, off); err != nil {
					return err
				}
			}
			c.tableSeen = false
		case "hash":
			if dataLen >= 16 {
				b := make([]byte, 16)
				if _, err := c.f.ReadAt(b, dataOff); err == nil && !allZero(b) {
					c.e.storedMD5 = b
				}
			}
		case "digest":
			if dataLen >= 36 {
				b := make([]byte, 36)
				if _, err := c.f.ReadAt(b, dataOff); err == nil {
					if !allZero(b[:16]) {
						c.e.storedMD5 = b[:16]
					}
					if !allZero(b[16:36]) {
						c.e.storedSHA1 = b[16:36]
					}
				}
			}
		case "done":
			c.done = true
			return nil
		case "next":
			c.next = true
			return nil
		}
		if next == off || next <= 0 {
			return corrupt("ewf", "segment %d: section chain stops at %q without next/done", c.seg+1, typ)
		}
		if next < off {
			return corrupt("ewf", "segment %d: section chain points backwards", c.seg+1)
		}
		off = next
	}
	return corrupt("ewf", "segment %d: too many sections", c.seg+1)
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

func (c *ewfSegCtx) volume(off, n int64) error {
	if n < 20 {
		return corrupt("ewf", "volume section too short")
	}
	if n > 4096 {
		n = 4096
	}
	b := make([]byte, n)
	if _, err := c.f.ReadAt(b, off); err != nil {
		return corrupt("ewf", "read volume section: %v", err)
	}
	c.chunkCount = binary.LittleEndian.Uint32(b[4:8])
	c.spc = binary.LittleEndian.Uint32(b[8:12])
	c.bps = binary.LittleEndian.Uint32(b[12:16])
	if n >= 24 && n != 94 {
		c.sectors = binary.LittleEndian.Uint64(b[16:24])
	} else {
		c.sectors = uint64(binary.LittleEndian.Uint32(b[16:20]))
	}
	if c.bps == 0 || c.bps > 1<<16 || c.spc == 0 || c.spc > 1<<20 {
		return corrupt("ewf", "implausible geometry: %d sectors/chunk, %d bytes/sector", c.spc, c.bps)
	}
	if c.chunkCount > maxEWFChunks {
		return corrupt("ewf", "implausible chunk count %d", c.chunkCount)
	}
	if n >= 1052 && b[36]&0x02 != 0 {
		c.im.Meta["physical"] = "true"
	}
	c.volSeen = true
	return nil
}

// table parses one table section: header (entry count, base offset,
// adler32), entries, and appends chunk locations.
func (c *ewfSegCtx) table(off, n, descOff int64) error {
	if n < 24 {
		return corrupt("ewf", "segment %d: table section too short", c.seg+1)
	}
	h := make([]byte, 24)
	if _, err := c.f.ReadAt(h, off); err != nil {
		return corrupt("ewf", "segment %d: read table: %v", c.seg+1, err)
	}
	count := int64(binary.LittleEndian.Uint32(h[0:4]))
	base := int64(binary.LittleEndian.Uint64(h[8:16]))
	if adler32.Checksum(h[:20]) != binary.LittleEndian.Uint32(h[20:24]) {
		return corrupt("ewf", "segment %d: table header checksum mismatch", c.seg+1)
	}
	if count == 0 {
		return nil
	}
	if count > maxEWFChunks || count*4 > n-24 || off+24 > c.size || count > (c.size-(off+24))/4 || int64(len(c.e.chunks))+count > maxEWFChunks {
		return corrupt("ewf", "segment %d: table lists %d entries, section holds %d bytes", c.seg+1, count, n-24)
	}
	if base < 0 || base > c.size {
		return corrupt("ewf", "segment %d: table base offset %d out of bounds", c.seg+1, base)
	}
	raw := make([]byte, count*4)
	if _, err := c.f.ReadAt(raw, off+24); err != nil {
		return corrupt("ewf", "segment %d: read table entries: %v", c.seg+1, err)
	}
	return c.addEntries(ParseEWFTable(raw, base), descOff)
}

// EWFEntry is one decoded table entry.
type EWFEntry struct {
	Offset     int64
	Compressed bool
}

// ParseEWFTable decodes raw little-endian table entries relative to base.
// Exposed for fuzzing; it never panics on any input.
func ParseEWFTable(raw []byte, base int64) []EWFEntry {
	out := make([]EWFEntry, 0, len(raw)/4)
	for i := 0; i+4 <= len(raw); i += 4 {
		v := binary.LittleEndian.Uint32(raw[i:])
		out = append(out, EWFEntry{Offset: base + int64(v&0x7fffffff), Compressed: v&0x80000000 != 0})
	}
	return out
}

func (c *ewfSegCtx) addEntries(ents []EWFEntry, descOff int64) error {
	end := c.sectorsEnd
	if end <= 0 || end > descOff {
		end = descOff
	}
	for i, en := range ents {
		var stop int64
		if i+1 < len(ents) {
			stop = ents[i+1].Offset
		} else {
			stop = end
		}
		size := stop - en.Offset
		if en.Offset < ewfHeaderSize || en.Offset >= c.size || size <= 0 || size > maxEWFChunkSize+4 {
			return corrupt("ewf", "segment %d: chunk %d at %d (size %d) out of bounds", c.seg+1, len(c.e.chunks), en.Offset, size)
		}
		c.e.chunks = append(c.e.chunks, ewfChunk{seg: c.seg, off: en.Offset, size: size, compressed: en.Compressed})
	}
	return nil
}

// header decodes the zlib-compressed case metadata (ASCII "header" or
// UTF-16LE "header2") into Image.Meta. Failures are recorded, not fatal.
func (c *ewfSegCtx) header(typ string, off, n int64) {
	if _, done := c.im.Meta["case_number"]; done || n <= 0 || n > maxEWFHeaderText {
		return
	}
	b := make([]byte, n)
	if _, err := c.f.ReadAt(b, off); err != nil {
		return
	}
	zr, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		c.im.Meta["header_problem"] = typ + ": " + err.Error()
		return
	}
	text, err := io.ReadAll(io.LimitReader(zr, maxEWFHeaderText))
	if err != nil {
		c.im.Meta["header_problem"] = typ + ": " + err.Error()
		return
	}
	s := string(text)
	if typ == "header2" {
		s = utf16le(text)
	}
	lines := strings.Split(strings.ReplaceAll(s, "\r", ""), "\n")
	// Layout: count, "main", tab-separated keys, tab-separated values.
	for i := 0; i+1 < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != "main" || i+2 >= len(lines) {
			continue
		}
		keys := strings.Split(lines[i+1], "\t")
		vals := strings.Split(lines[i+2], "\t")
		names := map[string]string{"c": "case_number", "n": "evidence_number", "a": "description", "e": "examiner", "t": "notes", "av": "acquisition_software_version", "ov": "acquisition_os", "m": "acquired_date", "u": "system_date", "md": "media_model", "sn": "media_serial"}
		for k, key := range keys {
			if name, ok := names[strings.TrimSpace(key)]; ok && k < len(vals) && strings.TrimSpace(vals[k]) != "" {
				c.im.Meta[name] = strings.TrimSpace(vals[k])
			}
		}
		return
	}
}

func utf16le(b []byte) string {
	if len(b) >= 2 && b[0] == 0xff && b[1] == 0xfe {
		b = b[2:]
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}

// ReadAt serves the logical media from chunks (one-chunk cache).
func (e *ewfImage) ReadAt(p []byte, off int64) (int, error) {
	total := 0
	for len(p) > 0 {
		if off >= e.mediaSize {
			return total, io.EOF
		}
		idx := int(off / e.chunkSize)
		in := off % e.chunkSize
		e.mu.Lock()
		data, err := e.chunk(idx)
		if err != nil {
			e.mu.Unlock()
			return total, err
		}
		n := copy(p, data[in:])
		e.mu.Unlock()
		if n == 0 {
			return total, io.ErrUnexpectedEOF
		}
		total += n
		p = p[n:]
		off += int64(n)
	}
	return total, nil
}

// chunk returns chunk idx decompressed, from the cache when possible.
// Caller holds e.mu.
func (e *ewfImage) chunk(idx int) ([]byte, error) {
	if e.cacheFilled && e.cacheIdx == idx {
		return e.cacheData, nil
	}
	if idx < 0 || idx >= len(e.chunks) {
		return nil, corrupt("ewf", "chunk %d not in any table", idx)
	}
	want := e.chunkSize
	if rem := e.mediaSize - int64(idx)*e.chunkSize; rem < want {
		want = rem
	}
	c := e.chunks[idx]
	raw := make([]byte, c.size)
	if _, err := e.files[c.seg].ReadAt(raw, c.off); err != nil && !(errors.Is(err, io.EOF) && c.compressed) {
		return nil, corrupt("ewf", "chunk %d: read: %v", idx, err)
	}
	var out []byte
	if c.compressed {
		zr, err := zlib.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, corrupt("ewf", "chunk %d: zlib: %v", idx, err)
		}
		out = make([]byte, e.chunkSize)
		n, err := io.ReadFull(zr, out)
		if err != nil && !(errors.Is(err, io.ErrUnexpectedEOF) && int64(n) >= want) {
			return nil, corrupt("ewf", "chunk %d: zlib: %v", idx, err)
		}
		out = out[:n]
	} else {
		if int64(len(raw)) < want {
			return nil, corrupt("ewf", "chunk %d: %d stored bytes, want %d", idx, len(raw), want)
		}
		out = raw[:want]
		if int64(len(raw)) >= want+4 {
			if adler32.Checksum(out) != binary.LittleEndian.Uint32(raw[want:want+4]) {
				return nil, corrupt("ewf", "chunk %d: Adler-32 mismatch", idx)
			}
		}
	}
	if int64(len(out)) < want {
		return nil, corrupt("ewf", "chunk %d: decompressed to %d bytes, want %d", idx, len(out), want)
	}
	e.cacheIdx, e.cacheData, e.cacheFilled = idx, out[:want], true
	return e.cacheData, nil
}

// Stored-hash verification results.
const (
	HashMatch    = "match"
	HashMismatch = "mismatch"
	HashAbsent   = "absent"
)

// StoredHashResult is the outcome of checking an E01's acquisition hashes.
type StoredHashResult struct {
	MD5          string `json:"md5"`  // match | mismatch | absent
	SHA1         string `json:"sha1"` // match | mismatch | absent
	StoredMD5    string `json:"stored_md5,omitempty"`
	StoredSHA1   string `json:"stored_sha1,omitempty"`
	ComputedMD5  string `json:"computed_md5,omitempty"`
	ComputedSHA1 string `json:"computed_sha1,omitempty"`
	Error        string `json:"error,omitempty"` // media unreadable: neither match nor mismatch
}

// HasStoredHashes reports whether the container carries acquisition
// hashes (E01 hash/digest sections).
func (im *Image) HasStoredHashes() bool {
	return im.ewf != nil && (im.ewf.storedMD5 != nil || im.ewf.storedSHA1 != nil)
}

// VerifyStored re-reads the whole logical media and compares it with the
// acquisition hashes stored in the container. Non-EWF images report
// absent for both. progress, when set, receives bytes read so far.
func (im *Image) VerifyStored(progress func(done, total int64)) StoredHashResult {
	res := StoredHashResult{MD5: HashAbsent, SHA1: HashAbsent}
	if im.ewf == nil || (im.ewf.storedMD5 == nil && im.ewf.storedSHA1 == nil) {
		return res
	}
	m, s := md5.New(), sha1.New()
	buf := make([]byte, 1<<20)
	var off int64
	for off < im.size {
		n := len(buf)
		if rem := im.size - off; rem < int64(n) {
			n = int(rem)
		}
		got, err := im.ReadAt(buf[:n], off)
		if got > 0 {
			m.Write(buf[:got])
			s.Write(buf[:got])
			off += int64(got)
		}
		if err != nil && off < im.size {
			res.Error = err.Error()
			return res
		}
		if progress != nil {
			progress(off, im.size)
		}
	}
	cm, cs := m.Sum(nil), s.Sum(nil)
	if im.ewf.storedMD5 != nil {
		res.StoredMD5, res.ComputedMD5 = hex.EncodeToString(im.ewf.storedMD5), hex.EncodeToString(cm)
		res.MD5 = HashMismatch
		if bytes.Equal(cm, im.ewf.storedMD5) {
			res.MD5 = HashMatch
		}
	}
	if im.ewf.storedSHA1 != nil {
		res.StoredSHA1, res.ComputedSHA1 = hex.EncodeToString(im.ewf.storedSHA1), hex.EncodeToString(cs)
		res.SHA1 = HashMismatch
		if bytes.Equal(cs, im.ewf.storedSHA1) {
			res.SHA1 = HashMatch
		}
	}
	return res
}
