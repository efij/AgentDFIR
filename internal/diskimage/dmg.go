package diskimage

import (
	"bytes"
	"compress/bzip2"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"sync"
)

// UDIF (Apple .dmg): the disk is described by "mish" block tables kept,
// base64-encoded, in an XML plist (resource-fork → blkx) that the
// 512-byte big-endian "koly" trailer points to. Each table maps a sector
// range onto chunks: raw, zero-fill / ignore, zlib or bzip2 (both in the
// standard library). ADC, LZFSE and LZMA chunks are reported UNSUPPORTED
// with the chunk type named; the image is not opened, so no sector is
// silently read as zeros. Encrypted images (encrcdsa / cdsaencr) are
// UNSUPPORTED.

const (
	FormatDMG          = "dmg"
	FormatSparseBundle = "sparsebundle"

	udifSector       = 512
	maxUDIFChunks    = 1 << 22
	maxUDIFChunkSize = 64 << 20 // decompressed bytes per chunk
	maxUDIFXML       = 64 << 20
)

// UDIF chunk types.
const (
	udifZero       = 0x00000000
	udifRaw        = 0x00000001
	udifIgnore     = 0x00000002
	udifADC        = 0x80000004
	udifZlib       = 0x80000005
	udifBzip2      = 0x80000006
	udifLZFSE      = 0x80000007
	udifLZMA       = 0x80000008
	udifComment    = 0x7ffffffe
	udifTerminator = 0xffffffff
)

func udifChunkName(t uint32) string {
	switch t {
	case udifADC:
		return "ADC"
	case udifLZFSE:
		return "LZFSE"
	case udifLZMA:
		return "LZMA"
	}
	return fmt.Sprintf("0x%08x", t)
}

type udifChunk struct {
	typ    uint32
	sector int64 // absolute first sector
	count  int64
	off    int64 // file offset of the compressed data
	length int64
}

type udifImage struct {
	r      io.ReaderAt
	chunks []udifChunk // sorted by sector, non-overlapping
	size   int64

	mu    sync.Mutex
	cache map[int][]byte // chunk index → decoded bytes
	order []int
}

func openDMG(f *os.File, fileSize int64, path string) (*Image, error) {
	im, meta, err := parseUDIF(f, fileSize)
	if err != nil {
		f.Close()
		return nil, err
	}
	return &Image{r: im, size: im.size, Format: FormatDMG, Segments: []string{path}, Meta: meta, closers: []io.Closer{f}}, nil
}

// parseUDIF reads the koly trailer and every blkx table.
func parseUDIF(r io.ReaderAt, fileSize int64) (*udifImage, map[string]string, error) {
	be := binary.BigEndian
	if fileSize < 512 {
		return nil, nil, corrupt("dmg", "file is %d bytes", fileSize)
	}
	k := make([]byte, 512)
	if _, err := r.ReadAt(k, fileSize-512); err != nil {
		return nil, nil, corrupt("dmg", "read trailer: %v", err)
	}
	if string(k[:4]) != "koly" {
		return nil, nil, corrupt("dmg", "no koly trailer")
	}
	if v := be.Uint32(k[4:]); v != 4 {
		return nil, nil, unsupported("dmg", "UDIF version %d", v)
	}
	dataFork := int64(be.Uint64(k[24:]))
	xmlOff, xmlLen := int64(be.Uint64(k[216:])), int64(be.Uint64(k[224:]))
	sectors := int64(be.Uint64(k[492:]))
	if segs := be.Uint32(k[60:]); segs > 1 {
		return nil, nil, unsupported("dmg", "segmented UDIF image (%d segments); join it first (hdiutil convert -format UDZO)", segs)
	}
	if xmlLen <= 0 || xmlLen > maxUDIFXML || xmlOff < 0 || xmlOff > fileSize-xmlLen {
		return nil, nil, corrupt("dmg", "XML plist (%d bytes at %d) out of bounds", xmlLen, xmlOff)
	}
	if sectors <= 0 || sectors > 1<<53/udifSector {
		return nil, nil, corrupt("dmg", "sector count %d", sectors)
	}
	if dataFork < 0 || dataFork > fileSize {
		return nil, nil, corrupt("dmg", "data fork offset %d", dataFork)
	}
	x := make([]byte, xmlLen)
	if _, err := r.ReadAt(x, xmlOff); err != nil {
		return nil, nil, corrupt("dmg", "read XML plist: %v", err)
	}
	root, err := parsePlist(x)
	if err != nil {
		return nil, nil, corrupt("dmg", "%v", err)
	}
	rf, _ := root.(map[string]any)["resource-fork"].(map[string]any)
	blkx, _ := rf["blkx"].([]any)
	if len(blkx) == 0 {
		return nil, nil, corrupt("dmg", "no blkx tables in the resource fork")
	}
	im := &udifImage{r: r, size: sectors * udifSector, cache: map[int][]byte{}}
	counts := map[string]int{}
	for i, e := range blkx {
		d, _ := e.(map[string]any)["Data"].([]byte)
		if len(d) < 204 || string(d[:4]) != "mish" {
			return nil, nil, corrupt("dmg", "blkx %d is not a mish table", i)
		}
		first := int64(be.Uint64(d[8:]))
		dataOff := int64(be.Uint64(d[24:]))
		n := int64(be.Uint32(d[200:]))
		if n < 0 || n > maxUDIFChunks || 204+40*n > int64(len(d)) {
			return nil, nil, corrupt("dmg", "blkx %d: %d chunks in %d bytes", i, n, len(d))
		}
		for j := int64(0); j < n; j++ {
			c := d[204+40*j:]
			ch := udifChunk{
				typ:    be.Uint32(c),
				sector: first + int64(be.Uint64(c[8:])),
				count:  int64(be.Uint64(c[16:])),
				off:    dataFork + dataOff + int64(be.Uint64(c[24:])),
				length: int64(be.Uint64(c[32:])),
			}
			switch ch.typ {
			case udifComment, udifTerminator:
				continue
			case udifADC, udifLZFSE, udifLZMA:
				return nil, nil, unsupported("dmg", "%s-compressed chunks are not supported; convert the image first (hdiutil convert -format UDZO or UDRO)", udifChunkName(ch.typ))
			case udifZero, udifIgnore, udifRaw, udifZlib, udifBzip2:
			default:
				return nil, nil, unsupported("dmg", "unknown chunk type %s", udifChunkName(ch.typ))
			}
			if ch.count == 0 {
				continue
			}
			if ch.sector < 0 || ch.count < 0 || ch.sector+ch.count > sectors || ch.typ != udifZero && ch.typ != udifIgnore && ch.count > maxUDIFChunkSize/udifSector {
				return nil, nil, corrupt("dmg", "chunk at sector %d (+%d) outside the disk (%d sectors)", ch.sector, ch.count, sectors)
			}
			if ch.typ != udifZero && ch.typ != udifIgnore {
				if ch.length < 0 || ch.off < 0 || ch.off > fileSize-ch.length || ch.length > maxUDIFChunkSize*2 {
					return nil, nil, corrupt("dmg", "chunk data (%d bytes at %d) outside the file", ch.length, ch.off)
				}
				if ch.typ == udifRaw && ch.length != ch.count*udifSector {
					return nil, nil, corrupt("dmg", "raw chunk length %d for %d sectors", ch.length, ch.count)
				}
			}
			counts[chunkKind(ch.typ)]++
			im.chunks = append(im.chunks, ch)
			if len(im.chunks) > maxUDIFChunks {
				return nil, nil, corrupt("dmg", "more than %d chunks", maxUDIFChunks)
			}
		}
	}
	sort.Slice(im.chunks, func(i, j int) bool { return im.chunks[i].sector < im.chunks[j].sector })
	for i := 1; i < len(im.chunks); i++ {
		p := im.chunks[i-1]
		if im.chunks[i].sector < p.sector+p.count {
			return nil, nil, corrupt("dmg", "overlapping chunks at sector %d", im.chunks[i].sector)
		}
	}
	meta := map[string]string{"udif_sectors": strconv.FormatInt(sectors, 10), "udif_tables": strconv.Itoa(len(blkx))}
	for k, v := range counts {
		meta["udif_chunks_"+k] = strconv.Itoa(v)
	}
	return im, meta, nil
}

func chunkKind(t uint32) string {
	switch t {
	case udifZero, udifIgnore:
		return "zero"
	case udifRaw:
		return "raw"
	case udifZlib:
		return "zlib"
	case udifBzip2:
		return "bzip2"
	}
	return "other"
}

// chunk returns the decoded bytes of chunk i (a small cache keeps the
// most recent ones).
func (u *udifImage) chunk(i int) ([]byte, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if b, ok := u.cache[i]; ok {
		return b, nil
	}
	c := u.chunks[i]
	want := c.count * udifSector
	src := make([]byte, c.length)
	if _, err := u.r.ReadAt(src, c.off); err != nil {
		return nil, corrupt("dmg", "read chunk at %d: %v", c.off, err)
	}
	var rd io.Reader
	switch c.typ {
	case udifRaw:
		rd = bytes.NewReader(src)
	case udifZlib:
		zr, err := zlib.NewReader(bytes.NewReader(src))
		if err != nil {
			return nil, corrupt("dmg", "zlib chunk at sector %d: %v", c.sector, err)
		}
		defer zr.Close()
		rd = zr
	case udifBzip2:
		rd = bzip2.NewReader(bytes.NewReader(src))
	}
	if c.typ == udifZlib && want > c.length*1032 {
		return nil, corrupt("dmg", "zlib chunk of %d bytes cannot expand to %d", c.length, want)
	}
	// Grow with the decoded data rather than trusting the sector count.
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, io.LimitReader(rd, want+1)); err != nil {
		return nil, corrupt("dmg", "%s chunk at sector %d: %v", chunkKind(c.typ), c.sector, err)
	}
	if int64(buf.Len()) != want {
		return nil, corrupt("dmg", "%s chunk at sector %d decodes to %d bytes, want %d", chunkKind(c.typ), c.sector, buf.Len(), want)
	}
	out := buf.Bytes()
	if len(u.order) >= 8 {
		delete(u.cache, u.order[0])
		u.order = u.order[1:]
	}
	u.cache[i] = out
	u.order = append(u.order, i)
	return out, nil
}

func (u *udifImage) ReadAt(p []byte, off int64) (int, error) {
	total := 0
	for len(p) > 0 {
		if off >= u.size {
			return total, io.EOF
		}
		sec := off / udifSector
		i := sort.Search(len(u.chunks), func(i int) bool { return u.chunks[i].sector+u.chunks[i].count > sec })
		n := len(p)
		if rem := u.size - off; int64(n) > rem {
			n = int(rem)
		}
		if i == len(u.chunks) || u.chunks[i].sector > sec {
			// No chunk describes these sectors: they read as zeros.
			if i < len(u.chunks) {
				if gap := u.chunks[i].sector*udifSector - off; int64(n) > gap {
					n = int(gap)
				}
			}
			clear(p[:n])
		} else {
			c := u.chunks[i]
			in := off - c.sector*udifSector
			if rem := c.count*udifSector - in; int64(n) > rem {
				n = int(rem)
			}
			if c.typ == udifZero || c.typ == udifIgnore {
				clear(p[:n])
			} else {
				b, err := u.chunk(i)
				if err != nil {
					return total, err
				}
				copy(p[:n], b[in:])
			}
		}
		total += n
		p = p[n:]
		off += int64(n)
	}
	return total, nil
}
