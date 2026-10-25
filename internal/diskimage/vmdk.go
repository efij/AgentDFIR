package diskimage

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// VMDK (VMware Virtual Disk, hosted formats): a text descriptor lists
// extents — FLAT/VMFS (raw bytes at an offset in another file), SPARSE
// (hosted sparse extent: "KDMV" header, grain directory → grain tables →
// grains), ZERO. monolithicSparse and streamOptimized embed the
// descriptor in the sparse extent itself; streamOptimized grains are
// zlib-compressed and the grain directory sits in a footer at the end.
// A descriptor with a parent CID is a delta (snapshot) disk and is
// reported UNSUPPORTED with its parent's name.

const (
	vmdkGDAtEnd        = 0xFFFFFFFFFFFFFFFF
	vmdkFlagCompressed = 1 << 16
	maxVMDKCapacity    = 64 << 40 // bytes
	maxVMDKDescriptor  = 1 << 20
	maxVMDKExtents     = 1024
	maxVMDKGrainBytes  = 16 << 20
)

type vmdkExtent struct {
	access   string
	sectors  int64
	kind     string
	file     string
	offset   int64 // sectors, FLAT only
	rawLine  string
	resolved string
}

type vmdkDescriptor struct {
	createType string
	parentCID  string
	parentHint string
	extents    []vmdkExtent
}

func parseVMDKDescriptor(text string) (*vmdkDescriptor, error) {
	d := &vmdkDescriptor{}
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	for sc.Scan() {
		line := strings.TrimSpace(strings.TrimRight(sc.Text(), "\x00"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok && !strings.ContainsAny(k, " \t\"") {
			v = strings.Trim(strings.TrimSpace(v), "\"")
			switch strings.TrimSpace(k) {
			case "createType":
				d.createType = v
			case "parentCID":
				d.parentCID = v
			case "parentFileNameHint":
				d.parentHint = v
			}
			continue
		}
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		switch f[0] {
		case "RW", "RDONLY", "NOACCESS":
		default:
			continue
		}
		if len(d.extents) >= maxVMDKExtents {
			return nil, corrupt("vmdk", "more than %d extents", maxVMDKExtents)
		}
		n, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil || n < 0 || n > maxVMDKCapacity/512 {
			return nil, corrupt("vmdk", "extent size %q", f[1])
		}
		e := vmdkExtent{access: f[0], sectors: n, kind: f[2], rawLine: line}
		if e.kind != "ZERO" {
			// Filename is quoted and may contain spaces.
			q1 := strings.IndexByte(line, '"')
			q2 := strings.LastIndexByte(line, '"')
			if q1 < 0 || q2 <= q1 {
				return nil, corrupt("vmdk", "extent line without a quoted file name: %q", line)
			}
			e.file = line[q1+1 : q2]
			if rest := strings.Fields(line[q2+1:]); len(rest) > 0 {
				if o, err := strconv.ParseInt(rest[0], 10, 64); err == nil && o >= 0 {
					e.offset = o
				}
			}
		}
		d.extents = append(d.extents, e)
	}
	return d, nil
}

func (d *vmdkDescriptor) differencing() bool {
	return d.parentCID != "" && !strings.EqualFold(d.parentCID, "ffffffff")
}

// openVMDKDescriptor opens a text descriptor and every extent it lists.
func openVMDKDescriptor(path string) (*Image, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	text, err := io.ReadAll(io.LimitReader(f, maxVMDKDescriptor+1))
	f.Close()
	if err != nil {
		return nil, err
	}
	if len(text) > maxVMDKDescriptor {
		return nil, corrupt("vmdk", "descriptor larger than %d bytes", maxVMDKDescriptor)
	}
	d, err := parseVMDKDescriptor(string(text))
	if err != nil {
		return nil, err
	}
	if d.differencing() {
		return nil, unsupported("vmdk", "delta (snapshot) disk; needs its parent %q — consolidate snapshots first", d.parentHint)
	}
	if len(d.extents) == 0 {
		return nil, corrupt("vmdk", "descriptor lists no extents")
	}
	im := &Image{Format: FormatVMDK, Segments: []string{path}, Meta: map[string]string{"create_type": d.createType, "extents": strconv.Itoa(len(d.extents))}}
	mr := &multiReader{}
	dir := filepath.Dir(path)
	for _, e := range d.extents {
		size := e.sectors * 512
		var r io.ReaderAt
		switch e.kind {
		case "ZERO":
			r = zeroReader{}
		case "FLAT", "VMFS", "VMFSRAW", "VMFSRDM":
			p, err := sameDirFile(dir, e.file)
			if err != nil {
				im.Close()
				return nil, err
			}
			ef, err := os.Open(p)
			if err != nil {
				im.Close()
				return nil, corrupt("vmdk", "extent %q: %v", e.file, err)
			}
			im.closers = append(im.closers, ef)
			im.Segments = append(im.Segments, p)
			fi, _ := ef.Stat()
			if fi == nil || e.offset*512+size > fi.Size() {
				im.Close()
				return nil, corrupt("vmdk", "flat extent %q shorter than the %d sectors the descriptor declares", e.file, e.sectors)
			}
			r = io.NewSectionReader(ef, e.offset*512, size)
		case "SPARSE":
			p, err := sameDirFile(dir, e.file)
			if err != nil {
				im.Close()
				return nil, err
			}
			ef, err := os.Open(p)
			if err != nil {
				im.Close()
				return nil, corrupt("vmdk", "extent %q: %v", e.file, err)
			}
			im.closers = append(im.closers, ef)
			im.Segments = append(im.Segments, p)
			fi, _ := ef.Stat()
			if fi == nil {
				im.Close()
				return nil, corrupt("vmdk", "extent %q: stat failed", e.file)
			}
			sp, _, err := newSparseExtent(ef, fi.Size())
			if err != nil {
				im.Close()
				return nil, err
			}
			if sp.capacity < size {
				im.Close()
				return nil, corrupt("vmdk", "sparse extent %q holds %d bytes, descriptor declares %d", e.file, sp.capacity, size)
			}
			r = sp
		default:
			im.Close()
			return nil, unsupported("vmdk", "extent type %s", e.kind)
		}
		mr.parts = append(mr.parts, part{r: r, start: mr.size, size: size})
		mr.size += size
	}
	im.r, im.size = mr, mr.size
	return im, nil
}

// openVMDKSparseFile opens a monolithic sparse or streamOptimized VMDK.
func openVMDKSparseFile(f *os.File, fileSize int64, path string) (*Image, error) {
	sp, desc, err := newSparseExtent(f, fileSize)
	if err != nil {
		f.Close()
		return nil, err
	}
	meta := map[string]string{}
	if desc != nil {
		meta["create_type"] = desc.createType
		if desc.differencing() {
			f.Close()
			return nil, unsupported("vmdk", "delta (snapshot) disk; needs its parent %q — consolidate snapshots first", desc.parentHint)
		}
		if len(desc.extents) > 1 {
			f.Close()
			return nil, unsupported("vmdk", "embedded descriptor lists %d extents; open the descriptor file instead", len(desc.extents))
		}
	}
	if sp.compressed {
		meta["compressed"] = "deflate"
	}
	return &Image{r: sp, size: sp.capacity, Format: FormatVMDK, Segments: []string{path}, Meta: meta, closers: []io.Closer{f}}, nil
}

type sparseExtent struct {
	f          *os.File
	fileSize   int64
	capacity   int64 // bytes
	grain      int64 // bytes
	gtes       int64 // entries per grain table
	gd         []uint32
	compressed bool

	mu      sync.Mutex
	gtCache map[int64][]uint32
	gIdx    int64
	gData   []byte
}

// newSparseExtent parses a hosted sparse extent header (using the footer
// copy when the grain directory is at the end) and loads its grain
// directory. The embedded descriptor, if any, is returned parsed.
func newSparseExtent(f *os.File, fileSize int64) (*sparseExtent, *vmdkDescriptor, error) {
	h := make([]byte, 512)
	if _, err := f.ReadAt(h, 0); err != nil || string(h[:4]) != "KDMV" {
		return nil, nil, corrupt("vmdk", "not a hosted sparse extent")
	}
	if v := binary.LittleEndian.Uint32(h[4:8]); v < 1 || v > 3 {
		return nil, nil, unsupported("vmdk", "sparse extent version %d", v)
	}
	var desc *vmdkDescriptor
	if dOff, dSize := int64(binary.LittleEndian.Uint64(h[28:36])), int64(binary.LittleEndian.Uint64(h[36:44])); dOff > 0 && dSize > 0 && dSize*512 <= maxVMDKDescriptor && (dOff+dSize)*512 <= fileSize {
		b := make([]byte, dSize*512)
		if _, err := f.ReadAt(b, dOff*512); err == nil {
			if i := bytes.IndexByte(b, 0); i >= 0 {
				b = b[:i]
			}
			desc, _ = parseVMDKDescriptor(string(b))
		}
	}
	if binary.LittleEndian.Uint64(h[56:64]) == vmdkGDAtEnd {
		// streamOptimized: footer (a header copy) sits 1024 bytes from the end.
		if fileSize < 1536 {
			return nil, nil, corrupt("vmdk", "stream-optimized extent too short for a footer")
		}
		ft := make([]byte, 512)
		if _, err := f.ReadAt(ft, fileSize-1024); err != nil || string(ft[:4]) != "KDMV" {
			return nil, nil, corrupt("vmdk", "stream-optimized extent has no footer (truncated?)")
		}
		h = ft
	}
	flags := binary.LittleEndian.Uint32(h[8:12])
	capSectors := int64(binary.LittleEndian.Uint64(h[12:20]))
	grainSectors := int64(binary.LittleEndian.Uint64(h[20:28]))
	gtes := int64(binary.LittleEndian.Uint32(h[44:48]))
	gdOff := int64(binary.LittleEndian.Uint64(h[56:64]))
	compAlg := binary.LittleEndian.Uint16(h[77:79])
	if capSectors <= 0 || capSectors > maxVMDKCapacity/512 {
		return nil, nil, corrupt("vmdk", "implausible capacity %d sectors", capSectors)
	}
	if grainSectors < 1 || grainSectors*512 > maxVMDKGrainBytes || grainSectors&(grainSectors-1) != 0 {
		return nil, nil, corrupt("vmdk", "implausible grain size %d sectors", grainSectors)
	}
	if gtes < 1 || gtes > 1<<16 {
		return nil, nil, corrupt("vmdk", "implausible grain table size %d", gtes)
	}
	compressed := flags&vmdkFlagCompressed != 0
	if compressed && compAlg != 1 {
		return nil, nil, unsupported("vmdk", "grain compression algorithm %d", compAlg)
	}
	gdEntries := (capSectors + grainSectors*gtes - 1) / (grainSectors * gtes)
	if gdOff <= 0 || (gdOff*512)+gdEntries*4 > fileSize {
		return nil, nil, corrupt("vmdk", "grain directory (%d entries at sector %d) out of bounds", gdEntries, gdOff)
	}
	raw := make([]byte, gdEntries*4)
	if _, err := f.ReadAt(raw, gdOff*512); err != nil {
		return nil, nil, corrupt("vmdk", "read grain directory: %v", err)
	}
	sp := &sparseExtent{
		f: f, fileSize: fileSize, capacity: capSectors * 512, grain: grainSectors * 512, gtes: gtes,
		gd: make([]uint32, gdEntries), compressed: compressed, gtCache: map[int64][]uint32{}, gIdx: -1,
	}
	for i := range sp.gd {
		sp.gd[i] = binary.LittleEndian.Uint32(raw[4*i:])
	}
	return sp, desc, nil
}

func (s *sparseExtent) ReadAt(p []byte, off int64) (int, error) {
	total := 0
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(p) > 0 {
		if off >= s.capacity {
			return total, io.EOF
		}
		g := off / s.grain
		in := off % s.grain
		n := len(p)
		if rem := s.grain - in; int64(n) > rem {
			n = int(rem)
		}
		gte, err := s.entry(g)
		if err != nil {
			return total, err
		}
		switch {
		case gte == 0 || gte == 1: // unallocated / zeroed grain
			clear(p[:n])
		case s.compressed:
			data, err := s.compressedGrain(g, int64(gte))
			if err != nil {
				return total, err
			}
			copy(p[:n], data[in:])
		default:
			at := int64(gte)*512 + in
			if at+int64(n) > s.fileSize {
				return total, corrupt("vmdk", "grain %d past end of extent", g)
			}
			if _, err := s.f.ReadAt(p[:n], at); err != nil {
				return total, err
			}
		}
		total += n
		p = p[n:]
		off += int64(n)
	}
	return total, nil
}

// entry returns the grain table entry for grain g.
func (s *sparseExtent) entry(g int64) (uint32, error) {
	gdi := g / s.gtes
	if gdi >= int64(len(s.gd)) {
		return 0, nil
	}
	gt, ok := s.gtCache[gdi]
	if !ok {
		if s.gd[gdi] == 0 {
			return 0, nil
		}
		at := int64(s.gd[gdi]) * 512
		if at+s.gtes*4 > s.fileSize {
			return 0, corrupt("vmdk", "grain table %d past end of extent", gdi)
		}
		raw := make([]byte, s.gtes*4)
		if _, err := s.f.ReadAt(raw, at); err != nil {
			return 0, corrupt("vmdk", "read grain table %d: %v", gdi, err)
		}
		gt = make([]uint32, s.gtes)
		for i := range gt {
			gt[i] = binary.LittleEndian.Uint32(raw[4*i:])
		}
		if len(s.gtCache) > 4096 {
			clear(s.gtCache)
		}
		s.gtCache[gdi] = gt
	}
	return gt[g%s.gtes], nil
}

// compressedGrain reads a stream-optimized grain: marker {lba u64,
// size u32} followed by a zlib stream inflating to one grain.
func (s *sparseExtent) compressedGrain(g, sector int64) ([]byte, error) {
	if s.gIdx == g {
		return s.gData, nil
	}
	at := sector * 512
	hdr := make([]byte, 12)
	if _, err := s.f.ReadAt(hdr, at); err != nil {
		return nil, corrupt("vmdk", "grain %d marker: %v", g, err)
	}
	size := int64(binary.LittleEndian.Uint32(hdr[8:12]))
	if size <= 0 || size > maxVMDKGrainBytes*2 || at+12+size > s.fileSize {
		return nil, corrupt("vmdk", "grain %d: compressed size %d out of bounds", g, size)
	}
	comp := make([]byte, size)
	if _, err := s.f.ReadAt(comp, at+12); err != nil {
		return nil, corrupt("vmdk", "grain %d: %v", g, err)
	}
	zr, err := zlib.NewReader(bytes.NewReader(comp))
	if err != nil {
		return nil, corrupt("vmdk", "grain %d: zlib: %v", g, err)
	}
	out := make([]byte, s.grain)
	n, err := io.ReadFull(zr, out)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, corrupt("vmdk", "grain %d: zlib: %v", g, err)
	}
	clear(out[n:]) // a short final grain reads as zeros past its data
	s.gIdx, s.gData = g, out
	return out, nil
}
