// Package fat reads FAT12, FAT16, FAT32 and exFAT filesystems from a raw
// filesystem image, read-only, in pure Go.
//
// Supported:
//   - FAT12/16/32 boot sector (BPB) with the FAT type chosen by cluster
//     count, the fixed FAT12/16 root directory and the FAT32 root chain
//   - VFAT long file names (UTF-16, checksum-verified against the short
//     entry; orphaned or mismatched LFN runs fall back to the 8.3 name),
//     the NT lower-case flags on 8.3 names, CP437 for 8.3 bytes >= 0x80
//   - exFAT boot sector, active FAT selection, cluster heap, file + stream
//     extension + file name entry sets, the NoFatChain (contiguous) flag,
//     ValidDataLength (bytes past it read as zeros), entry-set checksums
//     (a mismatch is reported in Sys()["checksum_mismatch"], not hidden)
//   - timestamps: FAT stores local time without a zone, so FAT times are
//     returned as wall-clock values in time.UTC with Sys()["tz"] set to
//     "local-unknown"; exFAT times carry their UTC offset when the volume
//     recorded one (Sys()["tz"] = "+hh:mm"), else "local-unknown"
//   - deleted entries (0xE5 / exFAT in-use bit clear) are skipped and
//     counted in Stats()["deleted_entries"]
//
// Not used or not supported: the exFAT up-case table (lookups fold case
// with Unicode simple folding instead), the exFAT allocation bitmap,
// TexFAT transactions, FAT mirroring repair, and recovery of deleted file
// content. Name lookups are case-insensitive, as on the original volume,
// with an exact match preferred.
//
// Every allocation is bounded by the filesystem size; cluster chains are
// length- and range-checked so loops terminate; malformed structures
// produce errors, never panics. A subdirectory whose first cluster equals
// that of a directory on the current path (or the root) is not listed and
// not resolved, and is counted in Stats()["corrupt_entries"]; the total
// number of entries listed over the life of the FS is capped
// proportionally to the volume size. Walkers can deduplicate directories
// by Sys()["dir_id"] (the first cluster; 0 for the fixed FAT12/16 root).
package fat

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

const (
	maxPathDeep = 256
	maxDirBytes = 64 << 20 // largest directory read into memory
	fatWindow   = 64 << 10
	cacheLimit  = 1 << 20
)

var errCorrupt = errors.New("fat: corrupt filesystem")

func corrupt(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errCorrupt, fmt.Sprintf(format, a...))
}

var le = binary.LittleEndian

func readFull(r io.ReaderAt, p []byte, off int64) error {
	n, err := r.ReadAt(p, off)
	if n == len(p) {
		return nil
	}
	if err == nil || err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return err
}

// geometry is the parsed boot sector.
type geometry struct {
	kind         string // fat12, fat16, fat32, exfat
	bps          int64
	clusterSize  int64
	clusterCount uint32
	fatOff       int64
	fatBytes     int64
	dataOff      int64 // byte offset of cluster 2
	rootOff      int64 // FAT12/16 fixed root directory
	rootBytes    int64
	rootCluster  uint32
	volBytes     int64
	label        string
	serial       uint32
	volFlags     uint16 // exFAT VolumeFlags
}

func parseBoot(b []byte) (*geometry, error) {
	if len(b) < 512 {
		return nil, corrupt("boot sector too short")
	}
	if string(b[3:11]) == "EXFAT   " {
		return parseExFAT(b)
	}
	if b[510] != 0x55 || b[511] != 0xAA {
		return nil, corrupt("missing boot signature")
	}
	if b[0] != 0xEB && b[0] != 0xE9 {
		return nil, corrupt("bad jump instruction")
	}
	g := &geometry{}
	g.bps = int64(le.Uint16(b[0x0B:]))
	spc := int64(b[0x0D])
	rsvd := int64(le.Uint16(b[0x0E:]))
	nfats := int64(b[0x10])
	rootEnt := int64(le.Uint16(b[0x11:]))
	tot := int64(le.Uint16(b[0x13:]))
	if tot == 0 {
		tot = int64(le.Uint32(b[0x20:]))
	}
	fatsz := int64(le.Uint16(b[0x16:]))
	if fatsz == 0 {
		fatsz = int64(le.Uint32(b[0x24:]))
	}
	switch {
	case g.bps != 512 && g.bps != 1024 && g.bps != 2048 && g.bps != 4096:
		return nil, corrupt("bytes per sector %d", g.bps)
	case spc == 0 || spc&(spc-1) != 0:
		return nil, corrupt("sectors per cluster %d", spc)
	case spc*g.bps > 256<<10:
		return nil, corrupt("cluster size %d", spc*g.bps)
	case rsvd == 0 || nfats == 0 || nfats > 4 || fatsz == 0 || tot == 0:
		return nil, corrupt("reserved=%d fats=%d fatsize=%d total=%d", rsvd, nfats, fatsz, tot)
	}
	g.clusterSize = spc * g.bps
	rootSecs := (rootEnt*32 + g.bps - 1) / g.bps
	meta := rsvd + nfats*fatsz + rootSecs
	if meta >= tot {
		return nil, corrupt("metadata (%d sectors) exceeds volume (%d)", meta, tot)
	}
	clusters := (tot - meta) / spc
	switch {
	case clusters < 4085:
		g.kind = "fat12"
	case clusters < 65525:
		g.kind = "fat16"
	default:
		g.kind = "fat32"
	}
	if clusters > 0x0FFFFFF5 {
		return nil, corrupt("cluster count %d", clusters)
	}
	g.clusterCount = uint32(clusters)
	g.fatOff = rsvd * g.bps
	g.fatBytes = fatsz * g.bps
	g.rootOff = (rsvd + nfats*fatsz) * g.bps
	g.rootBytes = rootSecs * g.bps
	g.dataOff = meta * g.bps
	g.volBytes = tot * g.bps
	labelOff, serialOff, sigOff := 0x2B, 0x27, 0x26
	if g.kind == "fat32" {
		if rootEnt != 0 {
			return nil, corrupt("FAT32 with fixed root entries")
		}
		g.rootCluster = le.Uint32(b[0x2C:]) & 0x0FFFFFFF
		g.rootBytes = 0
		labelOff, serialOff, sigOff = 0x47, 0x43, 0x42
	} else if rootEnt == 0 {
		return nil, corrupt("%s without root directory entries", g.kind)
	}
	if b[sigOff] == 0x29 {
		g.serial = le.Uint32(b[serialOff:])
		g.label = strings.TrimRight(string(b[labelOff:labelOff+11]), " \x00")
	}
	width := map[string]int64{"fat12": 3, "fat16": 4, "fat32": 8}[g.kind] // nibbles
	if (int64(g.clusterCount)+2)*width/2 > g.fatBytes {
		return nil, corrupt("FAT too small for %d clusters", g.clusterCount)
	}
	return g, nil
}

func parseExFAT(b []byte) (*geometry, error) {
	for _, c := range b[11:64] {
		if c != 0 {
			return nil, corrupt("exFAT MustBeZero region not zero")
		}
	}
	if b[510] != 0x55 || b[511] != 0xAA {
		return nil, corrupt("missing boot signature")
	}
	bpsShift := int(b[0x6C])
	spcShift := int(b[0x6D])
	if bpsShift < 9 || bpsShift > 12 || spcShift > 25-bpsShift {
		return nil, corrupt("exFAT sector/cluster shift %d/%d", bpsShift, spcShift)
	}
	g := &geometry{kind: "exfat"}
	g.bps = 1 << bpsShift
	g.clusterSize = g.bps << spcShift
	volLen := le.Uint64(b[0x48:])
	fatOff := int64(le.Uint32(b[0x50:]))
	fatLen := int64(le.Uint32(b[0x54:]))
	heapOff := int64(le.Uint32(b[0x58:]))
	g.clusterCount = le.Uint32(b[0x5C:])
	g.rootCluster = le.Uint32(b[0x60:])
	g.serial = le.Uint32(b[0x64:])
	g.volFlags = le.Uint16(b[0x6A:])
	nfats := int64(b[0x6E])
	if volLen == 0 || volLen > (1<<62)/uint64(g.bps) {
		return nil, corrupt("exFAT volume length %d", volLen)
	}
	g.volBytes = int64(volLen) * g.bps
	switch {
	case nfats != 1 && nfats != 2:
		return nil, corrupt("exFAT number of FATs %d", nfats)
	case fatOff < 24 || fatLen == 0 || heapOff < fatOff+fatLen*nfats:
		return nil, corrupt("exFAT layout fat=%d+%d heap=%d", fatOff, fatLen, heapOff)
	case g.clusterCount == 0 || g.clusterCount > 0xFFFFFFF5:
		return nil, corrupt("exFAT cluster count %d", g.clusterCount)
	case (int64(g.clusterCount)+2)*4 > fatLen*g.bps:
		return nil, corrupt("exFAT FAT too small for %d clusters", g.clusterCount)
	case heapOff*g.bps+int64(g.clusterCount)*g.clusterSize > g.volBytes:
		return nil, corrupt("exFAT cluster heap exceeds volume")
	}
	active := int64(0)
	if nfats == 2 && g.volFlags&1 != 0 {
		active = 1
	}
	g.fatOff = (fatOff + active*fatLen) * g.bps
	g.fatBytes = fatLen * g.bps
	g.dataOff = heapOff * g.bps
	return g, nil
}

// Probe reports whether r starts with a FAT12/16/32 or exFAT boot sector.
func Probe(r io.ReaderAt, size int64) bool {
	if r == nil || size < 512 {
		return false
	}
	b := make([]byte, 512)
	if readFull(r, b, 0) != nil {
		return false
	}
	_, err := parseBoot(b)
	return err == nil
}

// entry is one decoded directory entry (or the synthetic root).
type entry struct {
	name      string
	shortName string
	dir       bool
	attr      uint16
	cluster   uint32
	size      uint64 // FileSize / DataLength
	valid     uint64 // exFAT ValidDataLength; == size on FAT
	noChain   bool
	pos       uint64 // image byte offset of the (short / file) entry
	mtime     time.Time
	atime     time.Time
	btime     time.Time
	tz        string
	badSum    bool
	root      bool
}

// FS is a read-only FAT12/16/32 or exFAT filesystem. It implements fs.FS,
// fs.ReadDirFS and fs.StatFS and is safe for concurrent use.
type FS struct {
	r    io.ReaderAt
	size int64
	g    *geometry

	fatMu  sync.Mutex
	fatWin []byte
	fatPos int64

	mu        sync.Mutex
	dirCache  map[uint64][]*entry
	cached    int
	counted   map[uint64]bool
	stats     map[string]int64
	volLabel  string
	cycles    map[[2]uint64]bool
	work      int64
	workLimit int64
}

// Open parses the boot sector of the FAT or exFAT filesystem in r (size
// bytes long) and returns it as an fs.FS.
func Open(r io.ReaderAt, size int64) (fs.FS, error) {
	if r == nil || size < 512 {
		return nil, corrupt("image too small (%d bytes)", size)
	}
	b := make([]byte, 512)
	if err := readFull(r, b, 0); err != nil {
		return nil, fmt.Errorf("fat: read boot sector: %w", err)
	}
	g, err := parseBoot(b)
	if err != nil {
		return nil, err
	}
	if g.volBytes > size {
		return nil, corrupt("truncated image: filesystem declares %d bytes, image has %d", g.volBytes, size)
	}
	if g.kind != "fat12" && g.kind != "fat16" {
		if g.rootCluster < 2 || g.rootCluster > g.clusterCount+1 {
			return nil, corrupt("root cluster %d out of range", g.rootCluster)
		}
	}
	f := &FS{
		r: r, size: size, g: g,
		dirCache:  map[uint64][]*entry{},
		counted:   map[uint64]bool{},
		stats:     map[string]int64{"deleted_entries": 0, "corrupt_entries": 0, "dirs_read": 0},
		cycles:    map[[2]uint64]bool{},
		workLimit: max(size/16, 1<<20),
	}
	if _, err := f.entries(f.rootEntry()); err != nil {
		return nil, fmt.Errorf("fat: root directory: %w", err)
	}
	return f, nil
}

func (f *FS) rootEntry() *entry {
	e := &entry{name: ".", dir: true, root: true, attr: 0x10, cluster: f.g.rootCluster}
	if f.g.rootBytes > 0 {
		e.pos = uint64(f.g.rootOff)
	} else {
		e.pos = uint64(f.clusterPos(f.g.rootCluster))
	}
	return e
}

func (f *FS) clusterPos(c uint32) int64 {
	return f.g.dataOff + int64(c-2)*f.g.clusterSize
}

// fatEntry returns the FAT value of cluster c.
func (f *FS) fatEntry(c uint32) (uint32, error) {
	off, width := int64(c)*4, int64(4)
	switch f.g.kind {
	case "fat12":
		off, width = int64(c)+int64(c)/2, 2
	case "fat16":
		off, width = int64(c)*2, 2
	}
	if off+width > f.g.fatBytes {
		return 0, corrupt("cluster %d beyond FAT", c)
	}
	pos := f.g.fatOff + off
	f.fatMu.Lock()
	defer f.fatMu.Unlock()
	if f.fatWin == nil || pos < f.fatPos || pos+width > f.fatPos+int64(len(f.fatWin)) {
		start := pos &^ (fatWindow - 1)
		end := min(max(start+fatWindow, pos+width), f.g.fatOff+f.g.fatBytes, f.size)
		if end < pos+width {
			return 0, corrupt("FAT entry %d out of image", c)
		}
		w := make([]byte, end-start)
		if err := readFull(f.r, w, start); err != nil {
			return 0, fmt.Errorf("fat: read FAT: %w", err)
		}
		f.fatWin, f.fatPos = w, start
	}
	b := f.fatWin[pos-f.fatPos:]
	switch f.g.kind {
	case "fat12":
		v := uint32(le.Uint16(b))
		if c&1 == 1 {
			return v >> 4, nil
		}
		return v & 0xFFF, nil
	case "fat16":
		return uint32(le.Uint16(b)), nil
	case "fat32":
		return le.Uint32(b) & 0x0FFFFFFF, nil
	}
	return le.Uint32(b), nil
}

func (f *FS) isEOC(v uint32) bool {
	switch f.g.kind {
	case "fat12":
		return v >= 0xFF8
	case "fat16":
		return v >= 0xFFF8
	case "fat32":
		return v >= 0x0FFFFFF8
	}
	return v == 0xFFFFFFFF
}

// extent maps a byte range of a file onto the image.
type extent struct {
	off, pos, n int64
}

// layout returns the image extents holding the first want bytes of the
// cluster stream starting at start. want < 0 means "until end of chain"
// (directories), capped at maxDirBytes.
func (f *FS) layout(start uint32, noChain bool, want int64) ([]extent, int64, error) {
	cs := f.g.clusterSize
	limit := want
	if want < 0 {
		limit = maxDirBytes
	}
	if limit == 0 {
		return nil, 0, nil
	}
	maxClusters := int64(f.g.clusterCount)
	need := (limit + cs - 1) / cs
	if want >= 0 && need > maxClusters {
		return nil, 0, corrupt("size %d exceeds the volume", want)
	}
	need = min(need, maxClusters)
	valid := func(c uint32) bool { return c >= 2 && uint64(c) <= uint64(f.g.clusterCount)+1 }
	if !valid(start) {
		return nil, 0, corrupt("first cluster %d out of range", start)
	}
	var out []extent
	add := func(c uint32, i int64) {
		pos := f.clusterPos(c)
		if n := len(out); n > 0 && out[n-1].pos+out[n-1].n == pos {
			out[n-1].n += cs
			return
		}
		out = append(out, extent{off: i * cs, pos: pos, n: cs})
	}
	if noChain {
		if uint64(start)+uint64(need)-1 > uint64(f.g.clusterCount)+1 {
			return nil, 0, corrupt("contiguous run %d+%d out of range", start, need)
		}
		out = append(out, extent{off: 0, pos: f.clusterPos(start), n: need * cs})
		return out, need * cs, nil
	}
	c := start
	for i := int64(0); ; i++ {
		add(c, i)
		if i+1 == need {
			break
		}
		next, err := f.fatEntry(c)
		if err != nil {
			return nil, 0, err
		}
		if f.isEOC(next) {
			if want >= 0 {
				return nil, 0, corrupt("cluster chain ends after %d of %d clusters", i+1, need)
			}
			break
		}
		if !valid(next) {
			return nil, 0, corrupt("cluster chain hits %#x", next)
		}
		c = next
	}
	var total int64
	for _, e := range out {
		total += e.n
	}
	return out, total, nil
}

// content is a random-access view of a file or directory stream.
type content struct {
	f     *FS
	size  int64
	valid int64
	ext   []extent
}

func (f *FS) contentOf(e *entry) (*content, error) {
	c := &content{f: f, size: int64(e.size), valid: int64(e.valid)}
	if e.root && f.g.rootBytes > 0 {
		c.size, c.valid = f.g.rootBytes, f.g.rootBytes
		c.ext = []extent{{0, f.g.rootOff, f.g.rootBytes}}
		return c, nil
	}
	if e.size > uint64(f.size) || e.valid > e.size {
		return nil, corrupt("size %d (valid %d) exceeds the image", e.size, e.valid)
	}
	want := int64(e.size)
	if e.dir && (f.g.kind != "exfat" || e.root) {
		want = -1 // FAT directories and the exFAT root have no size; follow the chain
	}
	if want == 0 {
		return c, nil
	}
	if e.cluster == 0 {
		return nil, corrupt("non-empty entry without a first cluster")
	}
	ext, total, err := f.layout(e.cluster, e.noChain, want)
	if err != nil {
		return nil, err
	}
	c.ext = ext
	if want < 0 {
		c.size, c.valid = total, total
	}
	return c, nil
}

func (c *content) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("fat: negative offset")
	}
	if off >= c.size {
		return 0, io.EOF
	}
	total := 0
	for len(p) > 0 && off < c.size {
		n := min(int64(len(p)), c.size-off)
		if off >= c.valid {
			clear(p[:n])
		} else {
			n = min(n, c.valid-off)
			i := sort.Search(len(c.ext), func(i int) bool { return c.ext[i].off+c.ext[i].n > off })
			if i == len(c.ext) || c.ext[i].off > off {
				return total, corrupt("offset %d not mapped", off)
			}
			e := c.ext[i]
			n = min(n, e.off+e.n-off)
			if err := readFull(c.f.r, p[:n], e.pos+off-e.off); err != nil {
				return total, fmt.Errorf("fat: read data: %w", err)
			}
		}
		p = p[n:]
		off += n
		total += int(n)
	}
	if len(p) > 0 {
		return total, io.EOF
	}
	return total, nil
}

// ---- directory parsing ----

// cp437 maps 8.3 name bytes 0x80..0xFF.
var cp437 = []rune("ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ ")

func decodeShort(raw []byte, ntres byte) string {
	conv := func(b []byte, lower bool) string {
		var sb strings.Builder
		for _, c := range b {
			switch {
			case c >= 0x80:
				sb.WriteRune(cp437[c-0x80])
			case lower && c >= 'A' && c <= 'Z':
				sb.WriteByte(c + 32)
			default:
				sb.WriteByte(c)
			}
		}
		return sb.String()
	}
	n := make([]byte, 11)
	copy(n, raw)
	if n[0] == 0x05 {
		n[0] = 0xE5
	}
	base := conv([]byte(strings.TrimRight(string(n[:8]), " ")), ntres&0x08 != 0)
	ext := conv([]byte(strings.TrimRight(string(n[8:11]), " ")), ntres&0x10 != 0)
	if ext == "" {
		return base
	}
	return base + "." + ext
}

func lfnChecksum(n []byte) byte {
	var s byte
	for _, c := range n[:11] {
		s = (s&1)<<7 + s>>1 + c
	}
	return s
}

func utf16Name(u []uint16) string {
	for i, c := range u {
		if c == 0 {
			u = u[:i]
			break
		}
	}
	return string(utf16.Decode(u))
}

func validName(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, "/\x00")
}

// fatTime decodes a FAT date/time (local time, no zone).
func fatTime(date, tim uint16, tenths byte) time.Time {
	if date == 0 {
		return time.Time{}
	}
	day, mon := int(date&0x1F), int(date>>5&0x0F)
	if day == 0 || mon == 0 || mon > 12 {
		return time.Time{}
	}
	sec := int(tim&0x1F) * 2
	ns := 0
	if tenths < 200 {
		sec += int(tenths) / 100
		ns = int(tenths) % 100 * 10_000_000
	}
	return time.Date(1980+int(date>>9), time.Month(mon), day, int(tim>>11), int(tim>>5&0x3F), sec, ns, time.UTC)
}

func (f *FS) parseFAT(buf []byte, base func(int) uint64, st map[string]int64) []*entry {
	var out []*entry
	var lfn []uint16
	var lfnNext int
	var lfnSum byte
	for i := 0; i+32 <= len(buf); i += 32 {
		e := buf[i : i+32]
		if e[0] == 0 {
			break
		}
		attr := e[11]
		if e[0] == 0xE5 {
			if attr&0x3F != 0x0F {
				st["deleted_entries"]++
			}
			lfn = nil
			continue
		}
		if attr&0x3F == 0x0F {
			seq := int(e[0] & 0x1F)
			if e[0]&0x40 != 0 {
				if seq == 0 || seq > 20 {
					lfn = nil
					continue
				}
				lfn, lfnNext, lfnSum = make([]uint16, seq*13), seq, e[13]
			}
			if lfn == nil || seq != lfnNext || e[13] != lfnSum {
				lfn = nil
				continue
			}
			p := lfn[(seq-1)*13:]
			for j := 0; j < 5; j++ {
				p[j] = le.Uint16(e[1+2*j:])
			}
			for j := 0; j < 6; j++ {
				p[5+j] = le.Uint16(e[14+2*j:])
			}
			for j := 0; j < 2; j++ {
				p[11+j] = le.Uint16(e[28+2*j:])
			}
			lfnNext--
			continue
		}
		if attr&0x08 != 0 { // volume label
			if base(i) < uint64(f.g.dataOff) || f.g.kind == "fat32" {
				f.mu.Lock()
				if f.volLabel == "" {
					f.volLabel = strings.TrimRight(string(e[:11]), " ")
				}
				f.mu.Unlock()
			}
			lfn = nil
			continue
		}
		short := decodeShort(e[:11], e[12])
		if short == "." || short == ".." {
			lfn = nil
			continue
		}
		name := short
		if lfn != nil && lfnNext == 0 && lfnChecksum(e[:11]) == lfnSum {
			name = utf16Name(lfn)
		}
		lfn = nil
		if !validName(name) {
			st["corrupt_entries"]++
			continue
		}
		cl := uint32(le.Uint16(e[0x1A:]))
		if f.g.kind == "fat32" {
			cl |= uint32(le.Uint16(e[0x14:])) << 16
		}
		size := uint64(le.Uint32(e[0x1C:]))
		ent := &entry{
			name: name, shortName: short, attr: uint16(attr), dir: attr&0x10 != 0,
			cluster: cl, size: size, valid: size, pos: base(i),
			mtime: fatTime(le.Uint16(e[0x18:]), le.Uint16(e[0x16:]), 0),
			atime: fatTime(le.Uint16(e[0x12:]), 0, 0),
			btime: fatTime(le.Uint16(e[0x10:]), le.Uint16(e[0x0E:]), e[0x0D]),
			tz:    "local-unknown",
		}
		if ent.dir {
			ent.size, ent.valid = 0, 0
		}
		out = append(out, ent)
	}
	return out
}

// exTime decodes an exFAT timestamp with its 10 ms increment and UTC
// offset byte.
func exTime(ts uint32, ms10, off byte) (time.Time, string) {
	if ts == 0 {
		return time.Time{}, ""
	}
	day, mon := int(ts>>16&0x1F), int(ts>>21&0x0F)
	if day == 0 || mon == 0 || mon > 12 {
		return time.Time{}, ""
	}
	sec := int(ts&0x1F) * 2
	ns := 0
	if ms10 < 200 {
		sec += int(ms10) / 100
		ns = int(ms10) % 100 * 10_000_000
	}
	loc, tz := time.UTC, "local-unknown"
	if off&0x80 != 0 {
		mins := int(int8(off<<1)>>1) * 15
		sign := '+'
		a := mins
		if a < 0 {
			sign, a = '-', -a
		}
		tz = fmt.Sprintf("%c%02d:%02d", sign, a/60, a%60)
		loc = time.FixedZone(tz, mins*60)
	}
	return time.Date(1980+int(ts>>25), time.Month(mon), day, int(ts>>11&0x1F), int(ts>>5&0x3F), sec, ns, loc), tz
}

func (f *FS) parseExFAT(buf []byte, base func(int) uint64, st map[string]int64) []*entry {
	var out []*entry
	for i := 0; i+32 <= len(buf); {
		t := buf[i]
		switch {
		case t == 0:
			return out
		case t == 0x83:
			n := min(int(buf[i+1]), 11)
			u := make([]uint16, n)
			for j := range u {
				u[j] = le.Uint16(buf[i+2+2*j:])
			}
			f.mu.Lock()
			if f.volLabel == "" {
				f.volLabel = utf16Name(u)
			}
			f.mu.Unlock()
		case t == 0x05:
			st["deleted_entries"]++
		case t == 0x85:
			sc := int(buf[i+1])
			if sc < 2 || sc > 18 || i+32*(1+sc) > len(buf) {
				st["corrupt_entries"]++
				break
			}
			set := buf[i : i+32*(1+sc)]
			ent, ok := f.exEntry(set, base(i))
			if !ok {
				st["corrupt_entries"]++
				break
			}
			out = append(out, ent)
			i += len(set)
			continue
		}
		i += 32
	}
	return out
}

func (f *FS) exEntry(set []byte, pos uint64) (*entry, bool) {
	s := set[32:64]
	if s[0] != 0xC0 {
		return nil, false
	}
	nameLen := int(s[3])
	if nameLen == 0 || (nameLen+14)/15 > len(set)/32-2 {
		return nil, false
	}
	var u []uint16
	for k := 2; k*32 < len(set) && len(u) < nameLen; k++ {
		n := set[k*32 : k*32+32]
		if n[0] != 0xC1 {
			return nil, false
		}
		for j := 0; j < 15 && len(u) < nameLen; j++ {
			u = append(u, le.Uint16(n[2+2*j:]))
		}
	}
	name := string(utf16.Decode(u))
	if !validName(name) {
		return nil, false
	}
	var sum uint16
	for k, c := range set {
		if k == 2 || k == 3 {
			continue
		}
		sum = (sum&1)<<15 | sum>>1
		sum += uint16(c)
	}
	attr := le.Uint16(set[4:])
	e := &entry{
		name: name, attr: attr, dir: attr&0x10 != 0,
		noChain: s[1]&0x02 != 0,
		valid:   le.Uint64(s[8:]),
		cluster: le.Uint32(s[20:]),
		size:    le.Uint64(s[24:]),
		pos:     pos,
		badSum:  sum != le.Uint16(set[2:]),
	}
	e.btime, _ = exTime(le.Uint32(set[8:]), set[20], set[22])
	e.mtime, e.tz = exTime(le.Uint32(set[12:]), set[21], set[23])
	e.atime, _ = exTime(le.Uint32(set[16:]), 0, set[24])
	if e.tz == "" {
		e.tz = "local-unknown"
	}
	if e.valid > e.size {
		e.valid = e.size // reported via ReadAt as zeros beyond, never past DataLength
	}
	return e, true
}

// entries returns the live entries of directory d (unsorted).
func (f *FS) entries(d *entry) ([]*entry, error) {
	if !d.dir {
		return nil, errors.New("not a directory")
	}
	f.mu.Lock()
	if e, ok := f.dirCache[dirKey(d)]; ok {
		f.mu.Unlock()
		return e, nil
	}
	f.mu.Unlock()
	c, err := f.contentOf(d)
	if err != nil {
		return nil, err
	}
	if c.size > maxDirBytes {
		return nil, corrupt("directory of %d bytes", c.size)
	}
	buf := make([]byte, c.size)
	if _, err := c.ReadAt(buf, 0); err != nil && err != io.EOF {
		return nil, err
	}
	base := func(i int) uint64 {
		j := sort.Search(len(c.ext), func(j int) bool { return c.ext[j].off+c.ext[j].n > int64(i) })
		if j == len(c.ext) {
			return 0
		}
		return uint64(c.ext[j].pos + int64(i) - c.ext[j].off)
	}
	st := map[string]int64{}
	var out []*entry
	if f.g.kind == "exfat" {
		out = f.parseExFAT(buf, base, st)
	} else {
		out = f.parseFAT(buf, base, st)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.counted[dirKey(d)] {
		f.counted[dirKey(d)] = true
		f.stats["dirs_read"]++
		for k, v := range st {
			f.stats[k] += v
		}
	}
	if f.cached+len(out) > cacheLimit {
		f.dirCache, f.cached = map[uint64][]*entry{}, 0
	}
	f.dirCache[dirKey(d)] = out
	f.cached += len(out)
	return out, nil
}

// Stats returns counters accumulated while directories were read:
// deleted_entries, corrupt_entries and dirs_read. Each directory is
// counted once.
func (f *FS) Stats() map[string]int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]int64, len(f.stats))
	for k, v := range f.stats {
		out[k] = v
	}
	return out
}

// Metadata returns volume-level facts: fs, label (boot sector),
// volume_label (root directory entry), serial, sector and cluster size,
// cluster count and, for exFAT, the dirty flag.
func (f *FS) Metadata() map[string]any {
	g := f.g
	f.mu.Lock()
	vl := f.volLabel
	f.mu.Unlock()
	m := map[string]any{
		"fs":               g.kind,
		"label":            g.label,
		"volume_label":     vl,
		"serial":           fmt.Sprintf("%04X-%04X", g.serial>>16, g.serial&0xFFFF),
		"bytes_per_sector": g.bps,
		"cluster_size":     g.clusterSize,
		"clusters":         g.clusterCount,
		"volume_bytes":     g.volBytes,
	}
	if g.kind == "exfat" {
		m["dirty"] = g.volFlags&2 != 0
	}
	return m
}

// ---- fs.FS ----

// lookup resolves name. The returned set holds the keys (see dirKey) of
// every directory on the path, the target included when it is one.
func (f *FS) lookup(op, name string) (*entry, map[uint64]bool, error) {
	if !fs.ValidPath(name) {
		return nil, nil, &fs.PathError{Op: op, Path: name, Err: fs.ErrInvalid}
	}
	cur := f.rootEntry()
	anc := map[uint64]bool{0: true, dirKey(cur): true}
	if name == "." {
		return cur, anc, nil
	}
	parts := strings.Split(name, "/")
	if len(parts) > maxPathDeep {
		return nil, nil, &fs.PathError{Op: op, Path: name, Err: errors.New("path too deep")}
	}
	for _, p := range parts {
		if !cur.dir {
			return nil, nil, &fs.PathError{Op: op, Path: name, Err: fmt.Errorf("%w: not a directory", fs.ErrNotExist)}
		}
		ents, err := f.entries(cur)
		if err != nil {
			return nil, nil, &fs.PathError{Op: op, Path: name, Err: err}
		}
		var next *entry
		for _, e := range ents {
			if e.name == p {
				next = e
				break
			}
		}
		if next == nil {
			for _, e := range ents {
				if strings.EqualFold(e.name, p) {
					next = e
					break
				}
			}
		}
		if next == nil {
			return nil, nil, &fs.PathError{Op: op, Path: name, Err: fs.ErrNotExist}
		}
		if next.dir {
			if anc[dirKey(next)] {
				f.noteCycle(dirKey(cur), dirKey(next))
				return nil, nil, &fs.PathError{Op: op, Path: name, Err: corrupt("directory cycle: %q points back to an ancestor", p)}
			}
			anc[dirKey(next)] = true
		}
		cur = next
	}
	return cur, anc, nil
}

// noteCycle counts a directory entry pointing back to an ancestor once per
// (parent, child) pair.
func (f *FS) noteCycle(parent, child uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := [2]uint64{parent, child}
	if !f.cycles[k] {
		f.cycles[k] = true
		f.stats["corrupt_entries"]++
	}
}

// spend charges n listed entries against the total-work budget, which is
// proportional to the volume size, so that hostile hard-linked directory
// graphs cannot make a walk explode.
func (f *FS) spend(n int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.work += int64(n)
	if f.work > f.workLimit {
		return corrupt("work budget exhausted after listing %d entries", f.work)
	}
	return nil
}

type fileInfo struct {
	name string
	e    *entry
	sys  map[string]any
}

func (i *fileInfo) Name() string       { return i.name }
func (i *fileInfo) Size() int64        { return int64(i.e.size) }
func (i *fileInfo) ModTime() time.Time { return i.e.mtime }
func (i *fileInfo) IsDir() bool        { return i.e.dir }
func (i *fileInfo) Sys() any           { return i.sys }
func (i *fileInfo) Mode() fs.FileMode {
	m := fs.FileMode(0o644)
	if i.e.attr&0x01 != 0 {
		m = 0o444
	}
	if i.e.dir {
		m |= fs.ModeDir | 0o111
	}
	return m
}

func (f *FS) info(name string, e *entry) *fileInfo {
	sys := map[string]any{
		"inode":         e.pos,
		"mtime":         e.mtime,
		"atime":         e.atime,
		"ctime":         time.Time{},
		"btime":         e.btime,
		"tz":            e.tz,
		"fs":            f.g.kind,
		"attr":          e.attr,
		"first_cluster": e.cluster,
	}
	if e.dir {
		sys["dir_id"] = dirKey(e)
	}
	if e.shortName != "" && e.shortName != e.name {
		sys["short_name"] = e.shortName
	}
	if f.g.kind == "exfat" && !e.root {
		sys["valid_data_length"] = e.valid
		sys["no_fat_chain"] = e.noChain
		if e.badSum {
			sys["checksum_mismatch"] = true
		}
	}
	if e.root {
		delete(sys, "tz")
		for k, v := range f.Metadata() {
			if k != "fs" {
				sys[k] = v
			}
		}
		for k, v := range f.Stats() {
			sys[k] = v
		}
	}
	return &fileInfo{name: name, e: e, sys: sys}
}

func baseName(name string) string {
	if name == "." {
		return "."
	}
	return path.Base(name)
}

// Open opens the named file or directory.
func (f *FS) Open(name string) (fs.File, error) {
	e, anc, err := f.lookup("open", name)
	if err != nil {
		return nil, err
	}
	info := f.info(baseName(name), e)
	if e.dir {
		return &dirFile{f: f, e: e, info: info, path: name, anc: anc}, nil
	}
	c, err := f.contentOf(e)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	return &file{info: info, path: name, c: c}, nil
}

// Stat returns the FileInfo of name.
func (f *FS) Stat(name string) (fs.FileInfo, error) {
	e, _, err := f.lookup("stat", name)
	if err != nil {
		return nil, err
	}
	return f.info(baseName(name), e), nil
}

// ReadDir returns the entries of the named directory sorted by name.
func (f *FS) ReadDir(name string) ([]fs.DirEntry, error) {
	e, anc, err := f.lookup("readdir", name)
	if err != nil {
		return nil, err
	}
	return f.readDir(name, e, anc)
}

func (f *FS) readDir(name string, d *entry, anc map[uint64]bool) ([]fs.DirEntry, error) {
	ents, err := f.entries(d)
	if err != nil {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: err}
	}
	if err := f.spend(len(ents)); err != nil {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: err}
	}
	out := make([]fs.DirEntry, 0, len(ents))
	for _, e := range ents {
		if e.dir && anc[dirKey(e)] {
			f.noteCycle(dirKey(d), dirKey(e)) // points back to an ancestor or root
			continue
		}
		out = append(out, fs.FileInfoToDirEntry(f.info(e.name, e)))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, nil
}

type file struct {
	info   *fileInfo
	path   string
	c      *content
	off    int64
	closed bool
}

func (fl *file) Stat() (fs.FileInfo, error) { return fl.info, nil }
func (fl *file) Close() error {
	fl.closed = true
	return nil
}

func (fl *file) Read(p []byte) (int, error) {
	if fl.closed {
		return 0, &fs.PathError{Op: "read", Path: fl.path, Err: fs.ErrClosed}
	}
	n, err := fl.c.ReadAt(p, fl.off)
	fl.off += int64(n)
	return n, err
}

func (fl *file) ReadAt(p []byte, off int64) (int, error) {
	if fl.closed {
		return 0, &fs.PathError{Op: "read", Path: fl.path, Err: fs.ErrClosed}
	}
	return fl.c.ReadAt(p, off)
}

func (fl *file) Seek(offset int64, whence int) (int64, error) {
	if fl.closed {
		return 0, &fs.PathError{Op: "seek", Path: fl.path, Err: fs.ErrClosed}
	}
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		offset += fl.off
	case io.SeekEnd:
		offset += fl.c.size
	default:
		return 0, &fs.PathError{Op: "seek", Path: fl.path, Err: fs.ErrInvalid}
	}
	if offset < 0 {
		return 0, &fs.PathError{Op: "seek", Path: fl.path, Err: fs.ErrInvalid}
	}
	fl.off = offset
	return offset, nil
}

type dirFile struct {
	f     *FS
	e     *entry
	anc   map[uint64]bool
	info  *fileInfo
	path  string
	ents  []fs.DirEntry
	read  bool
	pos   int
	close bool
}

func (d *dirFile) Stat() (fs.FileInfo, error) { return d.info, nil }
func (d *dirFile) Close() error {
	d.close = true
	return nil
}
func (d *dirFile) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.path, Err: errors.New("is a directory")}
}

func (d *dirFile) ReadDir(n int) ([]fs.DirEntry, error) {
	if d.close {
		return nil, &fs.PathError{Op: "readdir", Path: d.path, Err: fs.ErrClosed}
	}
	if !d.read {
		ents, err := d.f.readDir(d.path, d.e, d.anc)
		if err != nil {
			return nil, err
		}
		d.ents, d.read = ents, true
	}
	rest := d.ents[d.pos:]
	if n <= 0 {
		d.pos = len(d.ents)
		return rest, nil
	}
	if len(rest) == 0 {
		return nil, io.EOF
	}
	n = min(n, len(rest))
	d.pos += n
	return rest[:n], nil
}

// dirKey identifies a directory by its first cluster (0 for the fixed
// FAT12/16 root). Unlike entry positions it never collides with the
// position of the directory's own first entry, and it is what walkers
// should deduplicate directories by (Sys()["dir_id"]).
func dirKey(d *entry) uint64 {
	if d.root && d.cluster == 0 {
		return 0
	}
	return uint64(d.cluster)
}
