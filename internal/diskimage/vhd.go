package diskimage

import (
	"encoding/binary"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode/utf16"
)

// VHD (Microsoft Virtual Hard Disk, the "conectix" format): a 512-byte
// big-endian footer at the end of the file. Fixed disks are the raw bytes
// followed by the footer. Dynamic disks have a dynamic header and a block
// allocation table (BAT); each allocated block is a sector bitmap followed
// by the block's data. Differencing disks need their parent and are
// reported UNSUPPORTED with the parent's name.

const (
	vhdTypeFixed        = 2
	vhdTypeDynamic      = 3
	vhdTypeDifferencing = 4
	maxVHDBlockSize     = 256 << 20
	maxVHDBATEntries    = 1 << 26
)

func openVHD(f *os.File, fileSize int64, path string) (*Image, error) {
	footer := make([]byte, 512)
	if _, err := f.ReadAt(footer, fileSize-512); err != nil || string(footer[:8]) != "conectix" {
		// Footer damaged: dynamic disks keep a copy at offset 0.
		if _, err := f.ReadAt(footer, 0); err != nil || string(footer[:8]) != "conectix" {
			f.Close()
			return nil, corrupt("vhd", "no valid footer")
		}
	}
	if !vhdChecksumOK(footer, 64) {
		f.Close()
		return nil, corrupt("vhd", "footer checksum mismatch")
	}
	diskType := binary.BigEndian.Uint32(footer[60:64])
	current := int64(binary.BigEndian.Uint64(footer[48:56]))
	if current < 0 {
		f.Close()
		return nil, corrupt("vhd", "negative disk size")
	}
	meta := map[string]string{
		"creator_app": strings.TrimRight(string(footer[28:32]), "\x00 "),
		"disk_type":   strconv.Itoa(int(diskType)),
	}
	switch diskType {
	case vhdTypeFixed:
		if current > fileSize-512 {
			f.Close()
			return nil, corrupt("vhd", "fixed disk declares %d bytes, file holds %d", current, fileSize-512)
		}
		return &Image{r: f, size: current, Format: FormatVHDFixed, Segments: []string{path}, Meta: meta, closers: []io.Closer{f}}, nil
	case vhdTypeDynamic, vhdTypeDifferencing:
	default:
		f.Close()
		return nil, unsupported("vhd", "disk type %d", diskType)
	}
	dynOff := int64(binary.BigEndian.Uint64(footer[16:24]))
	if dynOff <= 0 || dynOff > fileSize-1024 {
		f.Close()
		return nil, corrupt("vhd", "dynamic header offset %d out of bounds", dynOff)
	}
	dh := make([]byte, 1024)
	if _, err := f.ReadAt(dh, dynOff); err != nil || string(dh[:8]) != "cxsparse" {
		f.Close()
		return nil, corrupt("vhd", "missing dynamic disk header")
	}
	if !vhdChecksumOK(dh, 36) {
		f.Close()
		return nil, corrupt("vhd", "dynamic header checksum mismatch")
	}
	if diskType == vhdTypeDifferencing {
		parent := utf16be(dh[64:576])
		f.Close()
		return nil, unsupported("vhd", "differencing disk; needs its parent %q — merge it first (qemu-img convert the child to raw with the parent next to it)", parent)
	}
	batOff := int64(binary.BigEndian.Uint64(dh[16:24]))
	entries := int64(binary.BigEndian.Uint32(dh[28:32]))
	blockSize := int64(binary.BigEndian.Uint32(dh[32:36]))
	if blockSize < 512 || blockSize > maxVHDBlockSize || blockSize%512 != 0 {
		f.Close()
		return nil, corrupt("vhd", "implausible block size %d", blockSize)
	}
	if entries > maxVHDBATEntries || batOff <= 0 || batOff > fileSize-entries*4 {
		f.Close()
		return nil, corrupt("vhd", "BAT (%d entries at %d) out of bounds", entries, batOff)
	}
	if entries*blockSize < current {
		f.Close()
		return nil, corrupt("vhd", "BAT covers %d bytes, disk is %d", entries*blockSize, current)
	}
	raw := make([]byte, entries*4)
	if _, err := f.ReadAt(raw, batOff); err != nil {
		f.Close()
		return nil, corrupt("vhd", "read BAT: %v", err)
	}
	bat := make([]uint32, entries)
	for i := range bat {
		bat[i] = binary.BigEndian.Uint32(raw[4*i:])
	}
	bitmap := (blockSize/512 + 7) / 8
	bitmap = (bitmap + 511) / 512 * 512
	meta["block_size"] = strconv.FormatInt(blockSize, 10)
	v := &vhdDynamic{f: f, fileSize: fileSize, bat: bat, blockSize: blockSize, bitmap: bitmap}
	return &Image{r: v, size: current, Format: FormatVHDDynamic, Segments: []string{path}, Meta: meta, closers: []io.Closer{f}}, nil
}

type vhdDynamic struct {
	f         *os.File
	fileSize  int64
	bat       []uint32
	blockSize int64
	bitmap    int64
}

func (v *vhdDynamic) ReadAt(p []byte, off int64) (int, error) {
	total := 0
	for len(p) > 0 {
		blk := off / v.blockSize
		in := off % v.blockSize
		n := len(p)
		if rem := v.blockSize - in; int64(n) > rem {
			n = int(rem)
		}
		if blk >= int64(len(v.bat)) || v.bat[blk] == 0xFFFFFFFF {
			clear(p[:n])
		} else {
			at := int64(v.bat[blk])*512 + v.bitmap + in
			if at > v.fileSize-int64(n) {
				return total, corrupt("vhd", "block %d data past end of file", blk)
			}
			if _, err := v.f.ReadAt(p[:n], at); err != nil {
				return total, err
			}
		}
		total += n
		p = p[n:]
		off += int64(n)
	}
	return total, nil
}

// vhdChecksumOK checks the one's-complement byte-sum checksum at csOff.
func vhdChecksumOK(b []byte, csOff int) bool {
	var sum uint32
	for i, x := range b {
		if i >= csOff && i < csOff+4 {
			continue
		}
		sum += uint32(x)
	}
	return ^sum == binary.BigEndian.Uint32(b[csOff:csOff+4])
}

func utf16be(b []byte) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.BigEndian.Uint16(b[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}
