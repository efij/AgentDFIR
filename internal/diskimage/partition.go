package diskimage

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"strings"
	"unicode/utf16"
)

// Volume is one partition (or the whole disk when there is no table).
type Volume struct {
	Index  int    `json:"index"`  // 1-based partition number; 0 = whole disk
	Scheme string `json:"scheme"` // gpt | mbr | none
	Offset int64  `json:"offset"` // bytes from the start of the disk
	Size   int64  `json:"size"`
	Type   string `json:"type"`           // MBR type byte (0x07) or GPT type GUID
	Name   string `json:"name,omitempty"` // GPT partition name, or a friendly type name
}

// Section returns the volume's bytes as an io.ReaderAt.
func (v Volume) Section(r io.ReaderAt) *io.SectionReader {
	return io.NewSectionReader(r, v.Offset, v.Size)
}

// PartitionTable is what Partitions found.
type PartitionTable struct {
	Scheme   string   `json:"scheme"` // gpt | mbr | none
	Volumes  []Volume `json:"volumes"`
	Problems []string `json:"problems,omitempty"` // backup GPT mismatch, overlapping entries …
}

const (
	maxMBRLogical = 128
	maxGPTEntries = 1024
)

// Partitions reads the partition table of a disk of the given size.
// A disk with no recognizable table (a bare volume image) yields one
// whole-disk volume.
func Partitions(r io.ReaderAt, size int64) (*PartitionTable, error) {
	if size < 512 {
		return nil, corrupt("partition", "disk is %d bytes", size)
	}
	s0 := make([]byte, 512)
	if _, err := r.ReadAt(s0, 0); err != nil {
		return nil, corrupt("partition", "read sector 0: %v", err)
	}
	whole := &PartitionTable{Scheme: "none", Volumes: []Volume{{Index: 0, Scheme: "none", Offset: 0, Size: size}}}
	// A bare filesystem's boot sector also ends in 55 AA; recognize it first.
	if looksLikeVolumeBootSector(s0) {
		return whole, nil
	}
	for _, ss := range []int64{512, 4096} {
		if t, err := readGPT(r, size, ss); t != nil || err != nil {
			return t, err
		}
	}
	if s0[510] != 0x55 || s0[511] != 0xAA {
		return whole, nil
	}
	t, ok := readMBR(r, size, s0)
	if !ok {
		return whole, nil
	}
	return t, nil
}

// looksLikeVolumeBootSector spots NTFS/FAT/exFAT/ReFS/BitLocker boot
// sectors so a bare volume image is not misread as an MBR.
func looksLikeVolumeBootSector(s []byte) bool {
	oem := string(s[3:11])
	switch {
	case oem == "NTFS    ", oem == "EXFAT   ", oem == "-FVE-FS-", string(s[3:7]) == "ReFS":
		return true
	case string(s[54:59]) == "FAT12", string(s[54:59]) == "FAT16", string(s[82:87]) == "FAT32":
		return true
	}
	return false
}

func readMBR(r io.ReaderAt, size int64, s0 []byte) (*PartitionTable, bool) {
	t := &PartitionTable{Scheme: "mbr"}
	valid := 0
	for i := 0; i < 4; i++ {
		e := s0[446+16*i : 446+16*(i+1)]
		status, typ := e[0], e[4]
		start := int64(binary.LittleEndian.Uint32(e[8:12])) * 512
		n := int64(binary.LittleEndian.Uint32(e[12:16])) * 512
		if status != 0 && status != 0x80 {
			return nil, false // not a partition table (boot code / garbage)
		}
		if typ == 0 || n == 0 {
			continue
		}
		valid++
		if start+n > size {
			t.Problems = append(t.Problems, fmt.Sprintf("partition %d extends past the end of the disk (%d > %d); truncated", i+1, start+n, size))
			n = size - start
			if n <= 0 {
				continue
			}
		}
		if typ == 0x05 || typ == 0x0F || typ == 0x85 {
			t.logical(r, size, start, n)
			continue
		}
		t.Volumes = append(t.Volumes, Volume{Index: i + 1, Scheme: "mbr", Offset: start, Size: n, Type: fmt.Sprintf("0x%02x", typ), Name: mbrTypeName(typ)})
	}
	if valid == 0 {
		return nil, false
	}
	return t, true
}

// logical walks the extended partition's EBR chain. Each EBR's first
// entry is a logical partition relative to that EBR; its second entry
// links the next EBR relative to the extended partition's start.
func (t *PartitionTable) logical(r io.ReaderAt, size, extStart, extSize int64) {
	ebr := extStart
	seen := map[int64]bool{}
	idx := 5
	for n := 0; n < maxMBRLogical; n++ {
		if seen[ebr] {
			t.Problems = append(t.Problems, "extended partition chain loops; stopped")
			return
		}
		seen[ebr] = true
		s := make([]byte, 512)
		if ebr+512 > size {
			t.Problems = append(t.Problems, "extended partition chain points past the end of the disk")
			return
		}
		if _, err := r.ReadAt(s, ebr); err != nil || s[510] != 0x55 || s[511] != 0xAA {
			t.Problems = append(t.Problems, fmt.Sprintf("EBR at %d unreadable or unsigned", ebr))
			return
		}
		e1, e2 := s[446:462], s[462:478]
		if typ := e1[4]; typ != 0 {
			start := ebr + int64(binary.LittleEndian.Uint32(e1[8:12]))*512
			ln := int64(binary.LittleEndian.Uint32(e1[12:16])) * 512
			if ln > 0 && start+ln <= size && start >= extStart && start+ln <= extStart+extSize {
				t.Volumes = append(t.Volumes, Volume{Index: idx, Scheme: "mbr", Offset: start, Size: ln, Type: fmt.Sprintf("0x%02x", typ), Name: mbrTypeName(typ)})
			} else if ln > 0 {
				t.Problems = append(t.Problems, fmt.Sprintf("logical partition %d lies outside the extended partition; skipped", idx))
			}
			idx++
		}
		next := int64(binary.LittleEndian.Uint32(e2[8:12])) * 512
		if e2[4] == 0 || next == 0 {
			return
		}
		ebr = extStart + next
	}
	t.Problems = append(t.Problems, "more than 128 logical partitions; stopped")
}

func mbrTypeName(t byte) string {
	switch t {
	case 0x07:
		return "NTFS/exFAT/HPFS"
	case 0x0b, 0x0c:
		return "FAT32"
	case 0x01, 0x04, 0x06, 0x0e:
		return "FAT"
	case 0x83:
		return "Linux"
	case 0x82:
		return "Linux swap"
	case 0x8e:
		return "Linux LVM"
	case 0xaf:
		return "Apple HFS/HFS+"
	case 0xee:
		return "GPT protective"
	case 0x27:
		return "Windows recovery"
	}
	return ""
}

// readGPT reads the primary GPT (falling back to the backup) for a given
// logical sector size. It returns (nil, nil) when there is no GPT.
func readGPT(r io.ReaderAt, size, ss int64) (*PartitionTable, error) {
	if size < ss*3 {
		return nil, nil
	}
	lastLBA := size/ss - 1
	primary, perr := gptHeader(r, size, ss, 1)
	if perr == errNoGPT {
		return nil, nil
	}
	t := &PartitionTable{Scheme: "gpt"}
	backupLBA := lastLBA
	if primary != nil {
		backupLBA = int64(primary.backupLBA)
	}
	backup, berr := gptHeader(r, size, ss, backupLBA)
	if backup == nil && backupLBA != lastLBA {
		backup, berr = gptHeader(r, size, ss, lastLBA)
	}
	use := primary
	switch {
	case primary == nil && backup == nil:
		return nil, corrupt("gpt", "primary header invalid (%v) and backup unusable (%v)", perr, berr)
	case primary == nil:
		t.Problems = append(t.Problems, fmt.Sprintf("primary GPT header invalid (%v); using the backup", perr))
		use = backup
	case backup == nil:
		t.Problems = append(t.Problems, fmt.Sprintf("backup GPT header missing or invalid (%v)", berr))
	default:
		if primary.entriesCRC != backup.entriesCRC || primary.diskGUID != backup.diskGUID || primary.numEntries != backup.numEntries {
			t.Problems = append(t.Problems, "backup GPT differs from the primary (entries CRC or disk GUID)")
		}
	}
	for i, e := range use.entries {
		if allZero(e[:16]) {
			continue
		}
		first := int64(binary.LittleEndian.Uint64(e[32:40]))
		last := int64(binary.LittleEndian.Uint64(e[40:48]))
		if first < 0 || last < first || last > lastLBA {
			t.Problems = append(t.Problems, fmt.Sprintf("GPT entry %d range %d-%d out of bounds; skipped", i+1, first, last))
			continue
		}
		t.Volumes = append(t.Volumes, Volume{
			Index: i + 1, Scheme: "gpt", Offset: first * ss, Size: (last - first + 1) * ss,
			Type: guidString(e[:16]), Name: gptName(e[56:128]),
		})
	}
	return t, nil
}

var errNoGPT = fmt.Errorf("no GPT signature")

type gptHdr struct {
	backupLBA  uint64
	diskGUID   [16]byte
	numEntries uint32
	entriesCRC uint32
	entries    [][]byte
}

func gptHeader(r io.ReaderAt, size, ss, lba int64) (*gptHdr, error) {
	if lba <= 0 || lba > size/ss-1 {
		return nil, fmt.Errorf("header LBA %d out of bounds", lba)
	}
	h := make([]byte, ss)
	if _, err := r.ReadAt(h, lba*ss); err != nil {
		return nil, err
	}
	if string(h[:8]) != "EFI PART" {
		return nil, errNoGPT
	}
	hsize := int64(binary.LittleEndian.Uint32(h[12:16]))
	if hsize < 92 || hsize > ss {
		return nil, fmt.Errorf("header size %d", hsize)
	}
	want := binary.LittleEndian.Uint32(h[16:20])
	c := make([]byte, hsize)
	copy(c, h[:hsize])
	clear(c[16:20])
	if crc32.ChecksumIEEE(c) != want {
		return nil, fmt.Errorf("header CRC mismatch")
	}
	g := &gptHdr{backupLBA: binary.LittleEndian.Uint64(h[32:40])}
	copy(g.diskGUID[:], h[56:72])
	entLBA := int64(binary.LittleEndian.Uint64(h[72:80]))
	g.numEntries = binary.LittleEndian.Uint32(h[80:84])
	esize := int64(binary.LittleEndian.Uint32(h[84:88]))
	g.entriesCRC = binary.LittleEndian.Uint32(h[88:92])
	if g.numEntries > maxGPTEntries || esize < 128 || esize > 4096 || esize%8 != 0 {
		return nil, fmt.Errorf("entry table %d × %d implausible", g.numEntries, esize)
	}
	tbl := int64(g.numEntries) * esize
	if entLBA <= 0 || tbl > size || entLBA > (size-tbl)/ss {
		return nil, fmt.Errorf("entry table out of bounds")
	}
	raw := make([]byte, tbl)
	if _, err := r.ReadAt(raw, entLBA*ss); err != nil {
		return nil, err
	}
	if crc32.ChecksumIEEE(raw) != g.entriesCRC {
		return nil, fmt.Errorf("partition entry array CRC mismatch")
	}
	for i := int64(0); i < int64(g.numEntries); i++ {
		g.entries = append(g.entries, raw[i*esize:i*esize+128])
	}
	return g, nil
}

func gptName(b []byte) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return strings.TrimSpace(string(utf16.Decode(u)))
}

// GPTTypeName names well-known GPT partition type GUIDs.
func GPTTypeName(guid string) string {
	switch strings.ToUpper(guid) {
	case "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7":
		return "Microsoft basic data"
	case "C12A7328-F81F-11D2-BA4B-00A0C93EC93B":
		return "EFI system"
	case "E3C9E316-0B5C-4DB8-817D-F92DF00215AE":
		return "Microsoft reserved"
	case "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC":
		return "Windows recovery"
	case "0FC63DAF-8483-4772-8E79-3D69D8477DE4":
		return "Linux filesystem"
	case "E6D6D379-F507-44C2-A23C-238F2A3DF928":
		return "Linux LVM"
	case "CA7D7CCB-63ED-4C53-861C-1742536059CC":
		return "LUKS"
	case "7C3457EF-0000-11AA-AA11-00306543ECAC":
		return "Apple APFS"
	case "48465300-0000-11AA-AA11-00306543ECAC":
		return "Apple HFS+"
	case "53746F72-6167-11AA-AA11-00306543ECAC":
		return "Apple Core Storage"
	case "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F":
		return "Linux swap"
	}
	return ""
}
