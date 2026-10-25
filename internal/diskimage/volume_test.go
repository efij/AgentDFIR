package diskimage

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/efij/AgentDFIR/v3/internal/products"
)

func TestGPT(t *testing.T) {
	raw := rawFixture(t)
	pt, err := Partitions(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if pt.Scheme != "gpt" || len(pt.Volumes) != 1 || len(pt.Problems) != 0 {
		t.Fatalf("table: %+v", pt)
	}
	v := pt.Volumes[0]
	if v.Offset != 2048*512 || v.Size != 6<<20 || v.Name != "data" || GPTTypeName(v.Type) != "Microsoft basic data" {
		t.Fatalf("volume: %+v", v)
	}
	// Damage the backup header: reported, primary still used.
	bad := append([]byte(nil), raw...)
	bad[len(bad)-512+20] ^= 0xff
	pt, err = Partitions(bytes.NewReader(bad), int64(len(bad)))
	if err != nil || len(pt.Volumes) != 1 || len(pt.Problems) == 0 {
		t.Fatalf("backup damage: %+v %v", pt, err)
	}
	// Damage the primary: backup used, problem recorded.
	bad = append([]byte(nil), raw...)
	bad[512+20] ^= 0xff
	pt, err = Partitions(bytes.NewReader(bad), int64(len(bad)))
	if err != nil || len(pt.Volumes) != 1 || !strings.Contains(strings.Join(pt.Problems, " "), "using the backup") {
		t.Fatalf("primary damage: %+v %v", pt, err)
	}
	// Both damaged: typed corrupt error.
	bad[len(bad)-512+20] ^= 0xff
	if _, err := Partitions(bytes.NewReader(bad), int64(len(bad))); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("both damaged: %v", err)
	}
}

func TestMBRExtended(t *testing.T) {
	dir := t.TempDir()
	raw, _ := os.ReadFile(fixture(t, dir, "disk-mbr.raw"))
	pt, err := Partitions(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if pt.Scheme != "mbr" || len(pt.Volumes) != 2 {
		t.Fatalf("table: %+v", pt)
	}
	if pt.Volumes[0].Index != 1 || pt.Volumes[0].Type != "0x83" {
		t.Fatalf("primary: %+v", pt.Volumes[0])
	}
	lg := pt.Volumes[1]
	if lg.Index != 5 || lg.Offset != 6144*512 || lg.Size != 8192*512 || lg.Type != "0x07" {
		t.Fatalf("logical: %+v", lg)
	}
	r := OpenFS(lg.Section(bytes.NewReader(raw)), lg.Size)
	if r.FS == nil {
		t.Fatalf("logical NTFS: %+v", r)
	}
	if _, err := fs.Stat(r.FS, "home/bob/.claude/projects/-Users-bob-proj/session.jsonl"); err != nil {
		t.Fatal(err)
	}
	// Primary partition holds zeros: reported, not skipped.
	r = OpenFS(pt.Volumes[0].Section(bytes.NewReader(raw)), pt.Volumes[0].Size)
	if r.FS != nil || !errors.Is(r.Err, ErrUnknown) {
		t.Fatalf("empty partition: %+v", r)
	}
	// EBR loop: the first EBR links a second EBR one sector later, which
	// links itself.
	loop := append([]byte(nil), raw...)
	ebr := 4096 * 512
	link := []byte{0, 0, 0, 0, 5, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0} // next EBR at extended+1
	copy(loop[ebr+462:ebr+478], link)
	ebr2 := ebr + 512
	copy(loop[ebr2+462:ebr2+478], link)
	loop[ebr2+510], loop[ebr2+511] = 0x55, 0xAA
	pt, err = Partitions(bytes.NewReader(loop), int64(len(loop)))
	if err != nil || !strings.Contains(strings.Join(pt.Problems, " "), "loops") {
		t.Fatalf("EBR loop: %+v %v", pt, err)
	}
}

func TestBareVolumeIsWholeDisk(t *testing.T) {
	raw := rawFixture(t)
	vol := raw[2048*512 : 2048*512+6<<20]
	pt, err := Partitions(bytes.NewReader(vol), int64(len(vol)))
	if err != nil || pt.Scheme != "none" || len(pt.Volumes) != 1 || pt.Volumes[0].Size != int64(len(vol)) {
		t.Fatalf("bare volume: %+v %v", pt, err)
	}
}

func TestUnsupportedSignatures(t *testing.T) {
	mk := func(off int, sig string) []byte {
		b := make([]byte, 1<<20)
		copy(b[off:], sig)
		return b
	}
	cases := []struct {
		b    []byte
		name string
		kind error
	}{
		{mk(3, "-FVE-FS-"), "bitlocker", ErrEncrypted},
		{mk(0, "LUKS\xba\xbe"), "luks", ErrEncrypted},
		{mk(32, "NXSB"), "apfs", ErrUnsupported},
		{mk(1024, "H+"), "hfs+", ErrUnsupported},
		{mk(3, "ReFS\x00\x00\x00\x00"), "refs", ErrUnsupported},
		{mk(0, "XFSB"), "xfs", ErrUnsupported},
		{mk(0x10040, "_BHRfS_M"), "btrfs", ErrUnsupported},
		{make([]byte, 4096), "unknown", ErrUnknown},
	}
	for _, c := range cases {
		r := OpenFS(bytes.NewReader(c.b), int64(len(c.b)))
		if r.Type != c.name || !errors.Is(r.Err, c.kind) || r.FS != nil {
			t.Errorf("%s: got %+v", c.name, r)
		}
		if c.name != "unknown" && !strings.Contains(r.Reason, "collect --import") && c.name != "swap" {
			t.Errorf("%s: reason lacks the workaround: %s", c.name, r.Reason)
		}
	}
}

func TestFindAndExtract(t *testing.T) {
	raw := rawFixture(t)
	pt, _ := Partitions(bytes.NewReader(raw), int64(len(raw)))
	v := pt.Volumes[0]
	r := OpenFS(v.Section(bytes.NewReader(raw)), v.Size)
	if r.FS == nil {
		t.Fatal(r.Err)
	}
	prods, err := products.All()
	if err != nil {
		t.Fatal(err)
	}
	c := FindCandidates(r.FS, prods, Limits{})
	if len(c.Profiles) != 1 || c.Profiles[0].Path != "Users/alice" || c.Profiles[0].Products[0] != "claude-code" {
		t.Fatalf("profiles: %+v", c.Profiles)
	}
	sess := "Users/alice/.claude/projects/-Users-alice-proj/session.jsonl"
	if !contains(c.Files, sess) || !contains(c.Files, "Users/alice/.claude/settings.json") {
		t.Fatalf("files: %v", c.Files)
	}
	if contains(c.Files, "Users/alice/notes.txt") {
		t.Fatal("non-candidate file selected")
	}
	dest := t.TempDir()
	res := ExtractFiles(r.FS, c.Files, dest, Limits{})
	if len(res.Problems) != 0 {
		t.Fatal(res.Problems)
	}
	var got *Extracted
	for i := range res.Files {
		if res.Files[i].FSPath == sess {
			got = &res.Files[i]
		}
	}
	if got == nil || got.Staged == "" || got.SHA256 == "" {
		t.Fatalf("session not extracted: %+v", got)
	}
	fi, err := os.Stat(got.Staged)
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2026, 8, 30, 10, 5, 0, 0, time.UTC); !fi.ModTime().Equal(want) {
		t.Fatalf("staged mtime %v, want %v", fi.ModTime(), want)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("staged mode %v", fi.Mode())
	}
	// Byte cap: stops with a recorded problem.
	res = ExtractFiles(r.FS, c.Files, t.TempDir(), Limits{MaxTotalBytes: 10})
	if !res.Capped || len(res.Problems) == 0 {
		t.Fatalf("byte cap not enforced: %+v", res)
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// loopFS is a hostile filesystem: every directory named "loop" contains a
// directory named "loop" with the same inode, forever.
type loopFS struct{}

type loopInfo struct {
	name string
	dir  bool
	ino  uint64
}

func (i loopInfo) Name() string { return i.name }
func (i loopInfo) Size() int64  { return 1 }
func (i loopInfo) Mode() fs.FileMode {
	if i.dir {
		return fs.ModeDir | 0o555
	}
	return 0o444
}
func (i loopInfo) ModTime() time.Time { return time.Time{} }
func (i loopInfo) IsDir() bool        { return i.dir }
func (i loopInfo) Sys() any           { return map[string]any{"inode": i.ino} }

type loopFile struct {
	info loopInfo
	r    io.Reader
}

func (f *loopFile) Stat() (fs.FileInfo, error) { return f.info, nil }
func (f *loopFile) Read(p []byte) (int, error) { return f.r.Read(p) }
func (f *loopFile) Close() error               { return nil }

func (loopFS) info(name string) (loopInfo, error) {
	if !fs.ValidPath(name) {
		return loopInfo{}, fs.ErrInvalid
	}
	base := path.Base(name)
	switch {
	case name == ".":
		return loopInfo{".", true, 1}, nil
	case name == "home" || name == "home/u":
		return loopInfo{base, true, uint64(len(name))}, nil
	case name == "home/u/.claude", name == "home/u/.claude/projects":
		return loopInfo{base, true, uint64(len(name))}, nil
	case strings.HasPrefix(name, "home/u/.claude/projects/loop") && base == "loop":
		return loopInfo{base, true, 99}, nil // same inode at every depth
	case strings.HasPrefix(name, "home/u/.claude") && base == "f.jsonl":
		return loopInfo{base, false, 100}, nil
	}
	return loopInfo{}, fs.ErrNotExist
}

func (l loopFS) Open(name string) (fs.File, error) {
	i, err := l.info(name)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	return &loopFile{info: i, r: strings.NewReader("x")}, nil
}

func (l loopFS) ReadDir(name string) ([]fs.DirEntry, error) {
	i, err := l.info(name)
	if err != nil || !i.dir {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrNotExist}
	}
	var kids []string
	switch {
	case name == ".":
		kids = []string{"home"}
	case name == "home":
		kids = []string{"u"}
	case name == "home/u":
		kids = []string{".claude"}
	case name == "home/u/.claude":
		kids = []string{"projects"}
	default:
		kids = []string{"loop", "f.jsonl"}
	}
	var out []fs.DirEntry
	for _, k := range kids {
		ci, err := l.info(path.Join(name, k))
		if err == nil {
			out = append(out, fs.FileInfoToDirEntry(ci))
		}
	}
	return out, nil
}

func TestWalkStopsOnDirectoryLoop(t *testing.T) {
	prods, _ := products.All()
	c := FindCandidates(loopFS{}, prods, Limits{})
	if len(c.Profiles) != 1 {
		t.Fatalf("profiles: %+v", c.Profiles)
	}
	if !strings.Contains(strings.Join(c.Problems, " "), "already visited") {
		t.Fatalf("loop not reported: %v", c.Problems)
	}
	if len(c.Files) > 3 {
		t.Fatalf("loop followed: %d files", len(c.Files))
	}
}

// deepFS has no loop but unbounded fan-out: the entry cap must stop it.
type deepFS struct{ loopFS }

func (deepFS) ReadDir(name string) ([]fs.DirEntry, error) {
	var out []fs.DirEntry
	for i := 0; i < 50; i++ {
		out = append(out, fs.FileInfoToDirEntry(loopInfo{name: "d" + itoa(i), dir: true, ino: uint64(len(name)*100 + i + 1000)}))
	}
	return out, nil
}

func (deepFS) Stat(name string) (fs.FileInfo, error) {
	if name == "." || strings.HasPrefix(name, "d") {
		return loopInfo{path.Base(name), true, uint64(len(name))}, nil
	}
	return nil, fs.ErrNotExist
}

func (d deepFS) Open(name string) (fs.File, error) {
	fi, err := d.Stat(name)
	if err != nil {
		return nil, err
	}
	return &loopFile{info: fi.(loopInfo), r: strings.NewReader("")}, nil
}

func TestWalkEntryCap(t *testing.T) {
	prods, _ := products.All()
	c := FindCandidates(deepFS{}, prods, Limits{MaxEntries: 500})
	if !c.Capped || !strings.Contains(strings.Join(c.Problems, " "), "limit reached") {
		t.Fatalf("entry cap not enforced: capped=%v %v", c.Capped, c.Problems)
	}
}
