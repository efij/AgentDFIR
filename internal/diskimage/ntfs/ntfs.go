// Package ntfs is a read-only NTFS reader exposing an io/fs.FS.
//
// It locates $MFT from the boot sector, reads it through its own data
// runs, and walks every record once: update-sequence fixups are applied,
// $STANDARD_INFORMATION supplies the four timestamps, $FILE_NAME supplies
// names (Win32/POSIX preferred over DOS 8.3), and the directory tree is
// built from each name's parent reference — the $I30 index B-trees are not
// needed. File content comes from resident or non-resident $DATA (data
// runs, sparse runs, $ATTRIBUTE_LIST extension records, LZNT1
// compression). Named $DATA streams (ADS) are listed in metadata, never
// presented as files. Deleted records are skipped and counted.
//
// Every value read from the volume is bounded before it drives an
// allocation or a loop; parent chains are cycle-guarded by construction
// (a directory has exactly one parent link).
package ntfs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strings"
)

// ErrUnsupported marks a file (or volume feature) this reader does not
// decode, e.g. EFS-encrypted content.
var ErrUnsupported = errors.New("ntfs: unsupported")

const (
	maxRecords         = 1 << 26
	maxExtensionRecs   = 1024
	maxProblems        = 50
	maxAttrListBytes   = 1 << 20
	maxResolveDepth    = 256
	orphanDirName      = "$OrphanFiles"
	firstUserRecord    = 16
	rootRecord         = 5
	extendRecord       = 11
	vssStoreSuffix     = "{3808876b-c176-4e48-b7ae-04046e6cc752}"
	maxCompressionUnit = 1 << 20
)

// Probe reports whether the volume starts with an NTFS boot sector.
func Probe(r io.ReaderAt, size int64) bool {
	b := make([]byte, 512)
	if size < 512 {
		return false
	}
	if _, err := r.ReadAt(b, 0); err != nil {
		return false
	}
	if string(b[3:11]) != "NTFS    " {
		return false
	}
	bps := binary.LittleEndian.Uint16(b[11:13])
	return bps >= 256 && bps <= 4096 && bps&(bps-1) == 0
}

// Open parses the volume and returns its filesystem tree.
func Open(r io.ReaderAt, size int64) (fs.FS, error) {
	v, err := OpenVolume(r, size)
	if err != nil {
		return nil, err
	}
	return v, nil
}

// OpenVolume is Open with the concrete type, for callers that want Stats.
func OpenVolume(r io.ReaderAt, size int64) (*Volume, error) {
	v, err := newVolume(r, size)
	if err != nil {
		return nil, err
	}
	return v.build()
}

type volume struct {
	r           io.ReaderAt
	size        int64
	bps         int64
	clusterSize int64
	recordSize  int64
	clusters    int64
	mft         *stream
	serial      uint64
}

func newVolume(r io.ReaderAt, size int64) (*volume, error) {
	b := make([]byte, 512)
	if size < 512 {
		return nil, fmt.Errorf("ntfs: volume is %d bytes", size)
	}
	if _, err := r.ReadAt(b, 0); err != nil {
		return nil, fmt.Errorf("ntfs: read boot sector: %w", err)
	}
	if string(b[3:11]) != "NTFS    " {
		return nil, fmt.Errorf("ntfs: no NTFS boot sector")
	}
	v := &volume{r: r, size: size}
	v.bps = int64(binary.LittleEndian.Uint16(b[11:13]))
	if v.bps < 256 || v.bps > 4096 || v.bps&(v.bps-1) != 0 {
		return nil, fmt.Errorf("ntfs: bytes per sector %d", v.bps)
	}
	spc := int64(b[13])
	if spc > 0x80 { // encoded as 2^(256-n)
		shift := 256 - spc
		if shift > 12 {
			return nil, fmt.Errorf("ntfs: sectors per cluster 2^%d", shift)
		}
		spc = 1 << shift
	}
	if spc == 0 || spc&(spc-1) != 0 {
		return nil, fmt.Errorf("ntfs: sectors per cluster %d", spc)
	}
	v.clusterSize = v.bps * spc
	if v.clusterSize > 2<<20 {
		return nil, fmt.Errorf("ntfs: cluster size %d", v.clusterSize)
	}
	totalSectors := int64(binary.LittleEndian.Uint64(b[40:48]))
	if totalSectors <= 0 || totalSectors > size/v.bps+1 {
		// A volume image cut short still reads what it holds.
		totalSectors = size / v.bps
	}
	v.clusters = totalSectors * v.bps / v.clusterSize
	mftLCN := int64(binary.LittleEndian.Uint64(b[48:56]))
	cpr := int8(b[64])
	if cpr > 0 {
		v.recordSize = int64(cpr) * v.clusterSize
	} else if cpr < 0 && cpr >= -16 {
		v.recordSize = 1 << uint(-cpr)
	}
	if v.recordSize < 256 || v.recordSize > 64<<10 || v.recordSize&(v.recordSize-1) != 0 {
		return nil, fmt.Errorf("ntfs: MFT record size %d", v.recordSize)
	}
	v.serial = binary.LittleEndian.Uint64(b[72:80])
	if mftLCN <= 0 || mftLCN >= v.clusters {
		return nil, fmt.Errorf("ntfs: $MFT cluster %d outside the volume", mftLCN)
	}
	// Bootstrap: record 0 describes the MFT's own data runs.
	raw := make([]byte, v.recordSize)
	if _, err := r.ReadAt(raw, mftLCN*v.clusterSize); err != nil {
		return nil, fmt.Errorf("ntfs: read $MFT record 0: %w", err)
	}
	rec0, err := parseRecord(raw, 0)
	if err != nil {
		return nil, fmt.Errorf("ntfs: $MFT record 0: %w", err)
	}
	frags := dataFragments(rec0.attrs, "")
	if len(frags) == 0 || frags[0].resident {
		return nil, fmt.Errorf("ntfs: $MFT has no non-resident $DATA")
	}
	v.mft, err = v.newStream(frags)
	if err != nil {
		return nil, fmt.Errorf("ntfs: $MFT data runs: %w", err)
	}
	if hasAttr(rec0.attrs, atAttributeList) {
		// A heavily fragmented MFT keeps further runs in extension
		// records, which the first fragment's runs can already reach.
		all, err := v.withExtensions(rec0)
		if err == nil {
			if s, err := v.newStream(dataFragments(all, "")); err == nil {
				v.mft = s
			}
		}
	}
	if v.mft.size/v.recordSize > maxRecords {
		return nil, fmt.Errorf("ntfs: $MFT declares %d records", v.mft.size/v.recordSize)
	}
	return v, nil
}

func hasAttr(as []attr, typ uint32) bool {
	for _, a := range as {
		if a.typ == typ {
			return true
		}
	}
	return false
}

// readRecord reads and parses MFT record num.
func (v *volume) readRecord(num uint64) (*record, error) {
	off := int64(num) * v.recordSize
	if num > maxRecords || off+v.recordSize > v.mft.size {
		return nil, fmt.Errorf("record %d outside $MFT", num)
	}
	b := make([]byte, v.recordSize)
	if _, err := v.mft.ReadAt(b, off); err != nil {
		return nil, fmt.Errorf("record %d: %w", num, err)
	}
	return parseRecord(b, num)
}

// withExtensions returns the record's attributes plus those held in the
// extension records its $ATTRIBUTE_LIST names.
func (v *volume) withExtensions(rec *record) ([]attr, error) {
	var list *attr
	for i := range rec.attrs {
		if rec.attrs[i].typ == atAttributeList {
			list = &rec.attrs[i]
			break
		}
	}
	if list == nil {
		return rec.attrs, nil
	}
	var data []byte
	if list.resident {
		data = list.value
	} else {
		if list.dataSize > maxAttrListBytes {
			return rec.attrs, fmt.Errorf("record %d: $ATTRIBUTE_LIST of %d bytes", rec.num, list.dataSize)
		}
		s, err := v.newStream([]attr{*list})
		if err != nil {
			return rec.attrs, err
		}
		data = make([]byte, list.dataSize)
		if _, err := s.ReadAt(data, 0); err != nil && !errors.Is(err, io.EOF) {
			return rec.attrs, err
		}
	}
	seen := map[uint64]bool{rec.num: true}
	out := append([]attr(nil), rec.attrs...)
	for i := 0; i+26 <= len(data); {
		ln := int(binary.LittleEndian.Uint16(data[i+4:]))
		if ln < 26 || i+ln > len(data) {
			break
		}
		ref := binary.LittleEndian.Uint64(data[i+16:]) & 0xFFFFFFFFFFFF
		i += ln
		if seen[ref] {
			continue
		}
		seen[ref] = true
		if len(seen) > maxExtensionRecs {
			return out, fmt.Errorf("record %d: more than %d extension records", rec.num, maxExtensionRecs)
		}
		ext, err := v.readRecord(ref)
		if err != nil {
			return out, err
		}
		if ext.baseRef != rec.num {
			return out, fmt.Errorf("record %d: extension record %d belongs to %d", rec.num, ref, ext.baseRef)
		}
		out = append(out, ext.attrs...)
	}
	return out, nil
}

// dataFragments returns the $DATA attribute fragments with the given
// stream name ("" = the unnamed main stream), ordered by starting VCN.
func dataFragments(as []attr, name string) []attr {
	var out []attr
	for _, a := range as {
		if a.typ == atData && a.name == name {
			out = append(out, a)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].startVCN < out[j].startVCN })
	return out
}

// Stats summarizes the MFT walk.
type Stats struct {
	Records     int      `json:"records"`
	InUse       int      `json:"in_use"`
	Deleted     int      `json:"deleted_skipped"`
	Extension   int      `json:"extension_records"`
	Orphans     int      `json:"orphans"`
	SelfParent  int      `json:"self_parent_records"`
	ParentLoops int      `json:"parent_loop_records"`
	Corrupt     int      `json:"corrupt_records"`
	ShadowStore int      `json:"vss_store_files"`
	Label       string   `json:"label,omitempty"`
	Serial      string   `json:"serial,omitempty"`
	Problems    []string `json:"problems,omitempty"`
}

func (s *Stats) problem(format string, args ...any) {
	if len(s.Problems) < maxProblems {
		s.Problems = append(s.Problems, fmt.Sprintf(format, args...))
	}
}

// build walks every MFT record and links the directory tree.
func (v *volume) build() (*Volume, error) {
	fsys := &Volume{v: v, nodes: map[uint64]*node{}}
	st := &fsys.stats
	st.Serial = fmt.Sprintf("%016X", v.serial)
	n := v.mft.size / v.recordSize
	const batch = 1024
	buf := make([]byte, batch*v.recordSize)
	for base := int64(0); base < n; base += batch {
		cnt := int64(batch)
		if base+cnt > n {
			cnt = n - base
		}
		b := buf[:cnt*v.recordSize]
		if got, err := v.mft.ReadAt(b, base*v.recordSize); err != nil && !errors.Is(err, io.EOF) {
			st.problem("$MFT read at record %d: %v", base, err)
			clear(b[got:])
		}
		for i := int64(0); i < cnt; i++ {
			fsys.scan(b[i*v.recordSize:(i+1)*v.recordSize], uint64(base+i))
		}
	}
	root := fsys.nodes[rootRecord]
	if root == nil || !root.dir {
		return nil, fmt.Errorf("ntfs: root directory record 5 missing or not a directory")
	}
	fsys.root = root
	fsys.link()
	if l := fsys.nodes[3]; l != nil {
		st.Label = l.label
	}
	if svi := root.child("System Volume Information"); svi != nil && svi.n.dir {
		for _, k := range svi.n.kids {
			if strings.HasSuffix(strings.ToLower(k.name), vssStoreSuffix) {
				st.ShadowStore++
			}
		}
	}
	return fsys, nil
}

// scan parses one raw record into a node (in-use base records only).
func (f *Volume) scan(raw []byte, num uint64) {
	st := &f.stats
	if string(raw[:4]) != "FILE" && string(raw[:4]) != "BAAD" {
		return // never used
	}
	st.Records++
	rec, err := parseRecord(raw, num)
	if err != nil && rec == nil {
		st.Corrupt++
		st.problem("%v", err)
		return
	}
	if err != nil {
		st.Corrupt++
		st.problem("%v (partial record used)", err)
	}
	if rec.baseRef != 0 {
		st.Extension++
		return
	}
	if !rec.inUse() {
		if hasAttr(rec.attrs, atFileName) {
			st.Deleted++
		}
		return
	}
	st.InUse++
	attrs := rec.attrs
	nd := &node{rec: num, seq: rec.seq, dir: rec.isDir()}
	if hasAttr(attrs, atAttributeList) {
		nd.attrList = true
		all, err := f.v.withExtensions(rec)
		if err != nil {
			st.problem("%v", err)
		}
		attrs = all
	}
	nd.fill(attrs)
	f.nodes[num] = nd
}

// link attaches every node to its parent directory by name.
func (f *Volume) link() {
	ids := make([]uint64, 0, len(f.nodes))
	for id := range f.nodes {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	var orphans []dirent
	for _, id := range ids {
		nd := f.nodes[id]
		if id == rootRecord || (id < firstUserRecord) {
			continue // metadata files ($MFT, $LogFile, $Bitmap …) are not user content
		}
		names := nd.linkNames()
		if len(names) == 0 {
			continue
		}
		attached := false
		for _, fn := range names {
			if !validName(fn.name) {
				f.stats.problem("record %d: name %q not representable as a path; skipped", id, fn.name)
				continue
			}
			if fn.parent == id {
				f.stats.SelfParent++
				f.stats.problem("record %d names itself as its parent directory; not linked", id)
				continue
			}
			if fn.parent < firstUserRecord && fn.parent != rootRecord {
				attached = true // child of $Extend etc.: metadata, hidden
				continue
			}
			p := f.nodes[fn.parent]
			if p == nil || !p.dir || (fn.parentSeq != 0 && p.seq != 0 && fn.parentSeq != p.seq) {
				continue
			}
			p.add(fn.name, nd)
			if nd.dir {
				nd.parent = p
			}
			attached = true
		}
		if !attached {
			orphans = append(orphans, dirent{name: fmt.Sprintf("%d-%s", id, safeName(names[0].name)), n: nd})
		}
	}
	if len(orphans) > 0 {
		od := &node{rec: 0, dir: true, virtual: true}
		for _, o := range orphans {
			od.add(o.name, o.n)
		}
		f.root.add(orphanDirName, od)
		f.stats.Orphans = len(orphans)
	}
	f.findLoops()
	for _, nd := range f.nodes {
		nd.sortKids()
	}
}

// findLoops follows every directory's single parent link toward the root.
// A chain that revisits a directory (A→B→A) is a parent-reference loop:
// such directories can never be reached from the root, so they are not
// walkable, but they are counted and reported rather than passed over.
func (f *Volume) findLoops() {
	inLoop := map[*node]bool{}
	for _, nd := range f.nodes {
		if !nd.dir || nd == f.root || inLoop[nd] {
			continue
		}
		seen := map[*node]bool{}
		cur := nd
		for cur != nil && cur != f.root && !inLoop[cur] {
			if seen[cur] {
				// cur is on the cycle; mark every member once.
				for c := cur; c != nil && !inLoop[c]; c = c.parent {
					inLoop[c] = true
					f.stats.ParentLoops++
					f.stats.problem("record %d is in a parent-reference loop; unreachable from the root", c.rec)
				}
				break
			}
			seen[cur] = true
			cur = cur.parent
		}
	}
}

func validName(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, "/\x00")
}

func safeName(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '/' || r == 0 {
			return '_'
		}
		return r
	}, s)
}
