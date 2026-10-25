package diskimage

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"strconv"
	"strings"
)

// VHDX (MS-VHDX v1): two 4 KiB headers at 64 KiB and 128 KiB (the valid
// one with the higher sequence number wins), two region tables at 192 KiB
// and 256 KiB locating the BAT and the metadata region, and payload
// blocks addressed by the BAT in 1 MiB units. Every BAT "chunk ratio"
// payload entries are followed by one sector-bitmap entry.
//
// A header whose log GUID is set means the log holds updates that were
// never applied; replaying it is a write-path operation, so such images
// are reported UNSUPPORTED ("dirty log") rather than read inconsistently.

var crc32c = crc32.MakeTable(crc32.Castagnoli)

// GUIDs in their on-disk (mixed-endian) byte order.
var (
	vhdxBATRegion      = guidBytes("2DC27766-F623-4200-9D64-115E9BFD4A08")
	vhdxMetaRegion     = guidBytes("8B7CA206-4790-4B9A-B8FE-575F050F886E")
	vhdxFileParameters = guidBytes("CAA16737-FA36-4D43-B3B6-33F0AA44E76B")
	vhdxVirtualSize    = guidBytes("2FA54224-CD1B-4876-B211-5DBED83BF4B8")
	vhdxLogicalSector  = guidBytes("8141BF1D-A96F-4709-BA47-F233A8FAAB5F")
	vhdxPhysSector     = guidBytes("CDA348C7-445D-4471-9CC9-E9885251C556")
	vhdxPage83         = guidBytes("BECA12AB-B2E6-4523-93EF-C309E000C746")
	vhdxParentLocator  = guidBytes("A8D35F2D-B30B-454D-ABF7-D3D84834AB0C")
)

const (
	maxVHDXBATEntries = 1 << 26
	maxVHDXMetaItems  = 2047
)

func openVHDX(f *os.File, fileSize int64, path string) (*Image, error) {
	fail := func(err error) (*Image, error) {
		f.Close()
		return nil, err
	}
	if fileSize < 1<<20 {
		return fail(corrupt("vhdx", "file is %d bytes, smaller than the fixed 1 MiB header area", fileSize))
	}
	var best []byte
	var bestSeq uint64
	for _, off := range []int64{64 << 10, 128 << 10} {
		h := make([]byte, 4096)
		if _, err := f.ReadAt(h, off); err != nil || string(h[:4]) != "head" {
			continue
		}
		if !crc32cOK(h, 4) {
			continue
		}
		if seq := binary.LittleEndian.Uint64(h[8:16]); best == nil || seq > bestSeq {
			best, bestSeq = h, seq
		}
	}
	if best == nil {
		return fail(corrupt("vhdx", "no valid header (both copies fail their CRC-32C)"))
	}
	if !allZero(best[48:64]) {
		return fail(unsupported("vhdx", "dirty log: the log holds unapplied updates; open the disk once in Hyper-V (or qemu-img check -r all on a copy) to replay it, then re-image"))
	}
	if v := binary.LittleEndian.Uint16(best[66:68]); v != 1 {
		return fail(unsupported("vhdx", "format version %d", v))
	}
	var batOff, metaOff int64
	var batLen, metaLen int64
	var region []byte
	for _, off := range []int64{192 << 10, 256 << 10} {
		r := make([]byte, 64<<10)
		if _, err := f.ReadAt(r, off); err != nil || string(r[:4]) != "regi" || !crc32cOK(r, 4) {
			continue
		}
		region = r
		break
	}
	if region == nil {
		return fail(corrupt("vhdx", "no valid region table"))
	}
	count := int(binary.LittleEndian.Uint32(region[8:12]))
	if count > 2047 {
		return fail(corrupt("vhdx", "region table lists %d entries", count))
	}
	for i := 0; i < count; i++ {
		e := region[16+32*i : 16+32*(i+1)]
		off := int64(binary.LittleEndian.Uint64(e[16:24]))
		ln := int64(binary.LittleEndian.Uint32(e[24:28]))
		required := binary.LittleEndian.Uint32(e[28:32])&1 != 0
		switch {
		case string(e[:16]) == string(vhdxBATRegion):
			batOff, batLen = off, ln
		case string(e[:16]) == string(vhdxMetaRegion):
			metaOff, metaLen = off, ln
		case required:
			return fail(unsupported("vhdx", "unknown required region %s", guidString(e[:16])))
		}
	}
	if batOff <= 0 || metaOff <= 0 || batOff+batLen > fileSize || metaOff+metaLen > fileSize || metaLen < 32 || metaLen > 64<<20 {
		return fail(corrupt("vhdx", "BAT or metadata region out of bounds"))
	}
	meta := make([]byte, metaLen)
	if _, err := f.ReadAt(meta, metaOff); err != nil || string(meta[:8]) != "metadata" {
		return fail(corrupt("vhdx", "metadata table missing"))
	}
	items := int(binary.LittleEndian.Uint16(meta[10:12]))
	if items > maxVHDXMetaItems || 32+items*32 > len(meta) {
		return fail(corrupt("vhdx", "metadata table lists %d items", items))
	}
	var blockSize, logical uint32
	var virtSize uint64
	var hasParent bool
	var locator []byte
	item := func(off, ln uint32) ([]byte, bool) {
		if int64(off)+int64(ln) > int64(len(meta)) || int64(off) < 32+int64(items)*32 {
			return nil, false
		}
		return meta[off : off+ln], true
	}
	for i := 0; i < items; i++ {
		e := meta[32+32*i : 32+32*(i+1)]
		off := binary.LittleEndian.Uint32(e[16:20])
		ln := binary.LittleEndian.Uint32(e[20:24])
		required := binary.LittleEndian.Uint32(e[24:28])&4 != 0
		v, ok := item(off, ln)
		id := string(e[:16])
		switch {
		case id == string(vhdxFileParameters) && ok && ln >= 8:
			blockSize = binary.LittleEndian.Uint32(v[0:4])
			hasParent = binary.LittleEndian.Uint32(v[4:8])&2 != 0
		case id == string(vhdxVirtualSize) && ok && ln >= 8:
			virtSize = binary.LittleEndian.Uint64(v[0:8])
		case id == string(vhdxLogicalSector) && ok && ln >= 4:
			logical = binary.LittleEndian.Uint32(v[0:4])
		case id == string(vhdxParentLocator) && ok:
			locator = v
		case id == string(vhdxPhysSector), id == string(vhdxPage83):
		case required:
			return fail(unsupported("vhdx", "unknown required metadata item %s", guidString(e[:16])))
		}
	}
	if hasParent {
		return fail(unsupported("vhdx", "differencing disk; needs its parent %q — merge it first", vhdxParentName(locator)))
	}
	if blockSize < 1<<20 || blockSize > 256<<20 || blockSize&(blockSize-1) != 0 {
		return fail(corrupt("vhdx", "implausible block size %d", blockSize))
	}
	if logical != 512 && logical != 4096 {
		return fail(corrupt("vhdx", "implausible logical sector size %d", logical))
	}
	if virtSize == 0 || virtSize > 64<<40 {
		return fail(corrupt("vhdx", "implausible virtual size %d", virtSize))
	}
	chunkRatio := (int64(1) << 23) * int64(logical) / int64(blockSize)
	dataBlocks := (int64(virtSize) + int64(blockSize) - 1) / int64(blockSize)
	totalEntries := dataBlocks + (dataBlocks-1)/chunkRatio
	if totalEntries > maxVHDXBATEntries || totalEntries*8 > batLen {
		return fail(corrupt("vhdx", "BAT needs %d entries, region holds %d bytes", totalEntries, batLen))
	}
	raw := make([]byte, totalEntries*8)
	if _, err := f.ReadAt(raw, batOff); err != nil {
		return fail(corrupt("vhdx", "read BAT: %v", err))
	}
	v := &vhdxReader{f: f, fileSize: fileSize, blockSize: int64(blockSize), chunkRatio: chunkRatio, bat: make([]uint64, totalEntries)}
	for i := range v.bat {
		v.bat[i] = binary.LittleEndian.Uint64(raw[8*i:])
	}
	m := map[string]string{
		"block_size":          strconv.Itoa(int(blockSize)),
		"logical_sector_size": strconv.Itoa(int(logical)),
		"creator":             strings.TrimRight(utf16le(readAtN(f, 8, 512)), "\x00"),
	}
	return &Image{r: v, size: int64(virtSize), Format: FormatVHDX, Segments: []string{path}, Meta: m, closers: []io.Closer{f}}, nil
}

func readAtN(f *os.File, off, n int64) []byte {
	b := make([]byte, n)
	k, _ := f.ReadAt(b, off)
	return b[:k]
}

type vhdxReader struct {
	f          *os.File
	fileSize   int64
	blockSize  int64
	chunkRatio int64
	bat        []uint64
}

func (v *vhdxReader) ReadAt(p []byte, off int64) (int, error) {
	total := 0
	for len(p) > 0 {
		blk := off / v.blockSize
		in := off % v.blockSize
		n := len(p)
		if rem := v.blockSize - in; int64(n) > rem {
			n = int(rem)
		}
		idx := blk + blk/v.chunkRatio
		if idx >= int64(len(v.bat)) {
			return total, io.EOF
		}
		e := v.bat[idx]
		switch e & 7 {
		case 0, 1, 2, 3: // not present, undefined, zero, unmapped
			clear(p[:n])
		case 6: // fully present
			at := int64(e>>20)<<20 + in
			if at+int64(n) > v.fileSize {
				return total, corrupt("vhdx", "payload block %d past end of file", blk)
			}
			if _, err := v.f.ReadAt(p[:n], at); err != nil {
				return total, err
			}
		case 7:
			return total, unsupported("vhdx", "partially present block %d (differencing data)", blk)
		default:
			return total, corrupt("vhdx", "payload block %d has invalid state %d", blk, e&7)
		}
		total += n
		p = p[n:]
		off += int64(n)
	}
	return total, nil
}

// crc32cOK checks a CRC-32C stored at csOff, computed with that field zeroed.
func crc32cOK(b []byte, csOff int) bool {
	want := binary.LittleEndian.Uint32(b[csOff : csOff+4])
	c := make([]byte, len(b))
	copy(c, b)
	clear(c[csOff : csOff+4])
	return crc32.Checksum(c, crc32c) == want
}

// vhdxParentName pulls a path out of a parent locator's key/value table.
func vhdxParentName(loc []byte) string {
	if len(loc) < 20 {
		return "unknown"
	}
	n := int(binary.LittleEndian.Uint16(loc[18:20]))
	vals := map[string]string{}
	for i := 0; i < n && 20+12*(i+1) <= len(loc); i++ {
		e := loc[20+12*i:]
		ko, vo := int(binary.LittleEndian.Uint32(e[0:4])), int(binary.LittleEndian.Uint32(e[4:8]))
		kl, vl := int(binary.LittleEndian.Uint16(e[8:10])), int(binary.LittleEndian.Uint16(e[10:12]))
		if ko+kl > len(loc) || vo+vl > len(loc) || ko < 0 || vo < 0 {
			continue
		}
		vals[utf16le(loc[ko:ko+kl])] = utf16le(loc[vo : vo+vl])
	}
	for _, k := range []string{"relative_path", "absolute_win32_path", "volume_path"} {
		if v := vals[k]; v != "" {
			return v
		}
	}
	return "unknown"
}

// guidBytes renders a textual GUID in on-disk mixed-endian order.
func guidBytes(s string) []byte {
	h := strings.ReplaceAll(s, "-", "")
	b := make([]byte, 16)
	for i := 0; i < 16; i++ {
		fmt.Sscanf(h[2*i:2*i+2], "%02x", &b[i])
	}
	// First three groups are little-endian on disk.
	b[0], b[1], b[2], b[3] = b[3], b[2], b[1], b[0]
	b[4], b[5] = b[5], b[4]
	b[6], b[7] = b[7], b[6]
	return b
}

// guidString renders on-disk GUID bytes as text.
func guidString(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	return fmt.Sprintf("%08X-%04X-%04X-%X-%X",
		binary.LittleEndian.Uint32(b[0:4]), binary.LittleEndian.Uint16(b[4:6]), binary.LittleEndian.Uint16(b[6:8]), b[8:10], b[10:16])
}
