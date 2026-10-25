package ntfs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"
	"unicode/utf16"
)

// Attribute type codes.
const (
	atStandardInformation = 0x10
	atAttributeList       = 0x20
	atFileName            = 0x30
	atVolumeName          = 0x60
	atData                = 0x80
	atReparsePoint        = 0xC0
	atEnd                 = 0xFFFFFFFF
)

// Attribute flags.
const (
	afCompressed = 0x0001
	afEncrypted  = 0x4000
	afSparse     = 0x8000
)

// Record flags.
const (
	rfInUse     = 0x0001
	rfDirectory = 0x0002
)

const maxAttrsPerRecord = 512

var (
	errNotFile  = errors.New("not a FILE record")
	errBadFixup = errors.New("update sequence mismatch (torn or corrupt record)")
)

// attr is one parsed attribute header plus its value or run list.
type attr struct {
	typ         uint32
	name        string
	flags       uint16
	id          uint16
	resident    bool
	value       []byte // resident value
	startVCN    int64
	lastVCN     int64
	runs        []run
	compUnit    uint16
	allocSize   int64
	dataSize    int64
	initSize    int64
	fromRecord  uint64
	runListErr  error
	nonResident bool
}

// record is one parsed MFT record (after fixups).
type record struct {
	num       uint64
	seq       uint16
	flags     uint16
	baseRef   uint64 // 0 for a base record
	attrs     []attr
	linkCount uint16
}

func (r *record) inUse() bool { return r.flags&rfInUse != 0 }
func (r *record) isDir() bool { return r.flags&rfDirectory != 0 }

// applyFixups validates and undoes the update sequence array in place.
// stride is 512 bytes per the on-disk format.
func applyFixups(b []byte) error {
	if len(b) < 48 {
		return errNotFile
	}
	usaOff := int(binary.LittleEndian.Uint16(b[4:6]))
	usaCount := int(binary.LittleEndian.Uint16(b[6:8]))
	if usaCount == 0 || usaOff+2*usaCount > len(b) || usaOff < 8 || (usaCount-1)*512 > len(b) {
		return fmt.Errorf("update sequence array (offset %d, count %d) out of bounds", usaOff, usaCount)
	}
	usn := b[usaOff : usaOff+2]
	for i := 1; i < usaCount; i++ {
		end := i*512 - 2
		if end+2 > len(b) {
			break
		}
		if b[end] != usn[0] || b[end+1] != usn[1] {
			return errBadFixup
		}
		b[end] = b[usaOff+2*i]
		b[end+1] = b[usaOff+2*i+1]
	}
	return nil
}

// ParseRecord parses one raw MFT record (fixups are applied to a copy).
// Exposed for fuzzing; never panics.
func ParseRecord(raw []byte, num uint64) (*record, error) {
	b := make([]byte, len(raw))
	copy(b, raw)
	return parseRecord(b, num)
}

func parseRecord(b []byte, num uint64) (*record, error) {
	if len(b) < 48 {
		return nil, errNotFile
	}
	switch string(b[:4]) {
	case "FILE":
	case "BAAD":
		return nil, fmt.Errorf("record %d marked BAAD (multi-sector transfer failed)", num)
	default:
		return nil, errNotFile
	}
	if err := applyFixups(b); err != nil {
		return nil, fmt.Errorf("record %d: %w", num, err)
	}
	r := &record{
		num:       num,
		seq:       binary.LittleEndian.Uint16(b[16:18]),
		linkCount: binary.LittleEndian.Uint16(b[18:20]),
		flags:     binary.LittleEndian.Uint16(b[22:24]),
		baseRef:   binary.LittleEndian.Uint64(b[32:40]) & 0xFFFFFFFFFFFF,
	}
	used := int(binary.LittleEndian.Uint32(b[24:28]))
	if used > len(b) || used < 48 {
		used = len(b)
	}
	off := int(binary.LittleEndian.Uint16(b[20:22]))
	for n := 0; n < maxAttrsPerRecord; n++ {
		if off+8 > used {
			break
		}
		typ := binary.LittleEndian.Uint32(b[off:])
		if typ == atEnd {
			break
		}
		ln := int(binary.LittleEndian.Uint32(b[off+4:]))
		if ln < 16 || off+ln > used {
			return r, fmt.Errorf("record %d: attribute 0x%x length %d out of bounds", num, typ, ln)
		}
		a, err := parseAttr(b[off:off+ln], num)
		if err != nil {
			return r, fmt.Errorf("record %d: %w", num, err)
		}
		r.attrs = append(r.attrs, a)
		off += ln
	}
	return r, nil
}

func parseAttr(b []byte, recNum uint64) (attr, error) {
	a := attr{
		typ:        binary.LittleEndian.Uint32(b[0:4]),
		flags:      binary.LittleEndian.Uint16(b[12:14]),
		id:         binary.LittleEndian.Uint16(b[14:16]),
		fromRecord: recNum,
	}
	nonRes := b[8] != 0
	nameLen := int(b[9])
	nameOff := int(binary.LittleEndian.Uint16(b[10:12]))
	if nameLen > 0 {
		if nameOff+2*nameLen > len(b) {
			return a, fmt.Errorf("attribute name out of bounds")
		}
		a.name = utf16LE(b[nameOff : nameOff+2*nameLen])
	}
	if !nonRes {
		if len(b) < 24 {
			return a, fmt.Errorf("resident attribute header truncated")
		}
		vlen := int(binary.LittleEndian.Uint32(b[16:20]))
		voff := int(binary.LittleEndian.Uint16(b[20:22]))
		if voff+vlen > len(b) || vlen < 0 {
			return a, fmt.Errorf("resident value out of bounds")
		}
		a.resident = true
		a.value = b[voff : voff+vlen]
		a.dataSize = int64(vlen)
		a.initSize = int64(vlen)
		return a, nil
	}
	if len(b) < 64 {
		return a, fmt.Errorf("non-resident attribute header truncated")
	}
	a.nonResident = true
	a.startVCN = int64(binary.LittleEndian.Uint64(b[16:24]))
	a.lastVCN = int64(binary.LittleEndian.Uint64(b[24:32]))
	rlOff := int(binary.LittleEndian.Uint16(b[32:34]))
	a.compUnit = binary.LittleEndian.Uint16(b[34:36])
	a.allocSize = int64(binary.LittleEndian.Uint64(b[40:48]))
	a.dataSize = int64(binary.LittleEndian.Uint64(b[48:56]))
	a.initSize = int64(binary.LittleEndian.Uint64(b[56:64]))
	if a.startVCN < 0 || a.lastVCN < -1 || a.dataSize < 0 || a.initSize < 0 || a.allocSize < 0 {
		return a, fmt.Errorf("non-resident attribute with negative sizes")
	}
	if rlOff >= len(b) || rlOff < 64 {
		return a, fmt.Errorf("run list offset out of bounds")
	}
	a.runs, a.runListErr = decodeRuns(b[rlOff:], a.startVCN)
	return a, nil
}

// run maps a range of virtual clusters to logical clusters. lcn < 0 is a
// sparse (unallocated) run.
type run struct {
	vcn, lcn, length int64
}

const maxRuns = 1 << 20

// decodeRuns decodes a mapping-pairs run list starting at startVCN.
func decodeRuns(b []byte, startVCN int64) ([]run, error) {
	var out []run
	vcn, lcn := startVCN, int64(0)
	i := 0
	for i < len(b) && len(out) < maxRuns {
		h := b[i]
		if h == 0 {
			return out, nil
		}
		ls, os := int(h&0x0F), int(h>>4)
		if ls == 0 || ls > 8 || os > 8 || i+1+ls+os > len(b) {
			return out, fmt.Errorf("run list header 0x%02x malformed", h)
		}
		length := int64(0)
		for k := ls - 1; k >= 0; k-- {
			length = length<<8 | int64(b[i+1+k])
		}
		if length <= 0 {
			return out, fmt.Errorf("run of %d clusters", length)
		}
		r := run{vcn: vcn, length: length, lcn: -1}
		if os > 0 {
			delta := int64(int8(b[i+1+ls+os-1])) // sign-extend the top byte
			for k := os - 2; k >= 0; k-- {
				delta = delta<<8 | int64(b[i+1+ls+k])
			}
			lcn += delta
			if lcn < 0 {
				return out, fmt.Errorf("run points before the volume start")
			}
			r.lcn = lcn
		}
		out = append(out, r)
		vcn += length
		if vcn < 0 {
			return out, fmt.Errorf("VCN overflow")
		}
		i += 1 + ls + os
	}
	if len(out) >= maxRuns {
		return out, fmt.Errorf("more than %d runs", maxRuns)
	}
	return out, nil
}

// fileName is a parsed $FILE_NAME value.
type fileName struct {
	parent    uint64 // MFT record number of the parent directory
	parentSeq uint16
	namespace uint8 // 0 POSIX, 1 Win32, 2 DOS, 3 Win32+DOS
	name      string
	times     [4]time.Time // btime, mtime, ctime(MFT), atime
	flags     uint32
	size      int64
}

func parseFileName(v []byte) (fileName, bool) {
	if len(v) < 66 {
		return fileName{}, false
	}
	n := int(v[64])
	if 66+2*n > len(v) || n == 0 {
		return fileName{}, false
	}
	ref := binary.LittleEndian.Uint64(v[0:8])
	return fileName{
		parent:    ref & 0xFFFFFFFFFFFF,
		parentSeq: uint16(ref >> 48),
		namespace: v[65],
		name:      utf16LE(v[66 : 66+2*n]),
		times:     [4]time.Time{filetime(v[8:]), filetime(v[16:]), filetime(v[24:]), filetime(v[32:])},
		size:      int64(binary.LittleEndian.Uint64(v[48:56])),
		flags:     binary.LittleEndian.Uint32(v[56:60]),
	}, true
}

// stdInfo holds $STANDARD_INFORMATION times and attributes.
type stdInfo struct {
	btime, mtime, ctime, atime time.Time
	attrs                      uint32
	ok                         bool
}

func parseStdInfo(v []byte) stdInfo {
	if len(v) < 36 {
		return stdInfo{}
	}
	return stdInfo{
		btime: filetime(v[0:]), mtime: filetime(v[8:]), ctime: filetime(v[16:]), atime: filetime(v[24:]),
		attrs: binary.LittleEndian.Uint32(v[32:36]), ok: true,
	}
}

// filetime converts a Windows FILETIME (100 ns since 1601-01-01 UTC).
func filetime(b []byte) time.Time {
	v := binary.LittleEndian.Uint64(b[:8])
	if v == 0 {
		return time.Time{}
	}
	if v > math.MaxInt64 {
		return time.Time{}
	}
	const epochDiff = 116444736000000000 // 1601 → 1970 in 100 ns
	d := int64(v) - epochDiff
	return time.Unix(d/10000000, (d%10000000)*100).UTC()
}

func utf16LE(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}
