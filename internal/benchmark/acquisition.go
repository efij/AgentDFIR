package benchmark

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/diskimage"
)

// Acquisition is the disk-image section: every disk-image fixture in the
// repository opened read-only through the same reader `collect --image`
// uses, every volume enumerated, every regular file read, and the result
// compared with the fixture's own manifest where it has one.
type Acquisition struct {
	Label    string         `json:"label"`
	Fixtures []AcqFixture   `json:"fixtures"`
	Totals   AcqTotals      `json:"totals"`
	Checks   []Check        `json:"checks"`
	Skipped  string         `json:"skipped,omitempty"`
	Seconds  float64        `json:"seconds"`
	Formats  map[string]int `json:"container_formats"`
}

// AcqTotals sums the fixtures.
type AcqTotals struct {
	Fixtures      int `json:"fixtures"`
	Compared      int `json:"compared"` // fixtures with a manifest or reference
	Volumes       int `json:"volumes"`
	FilesFound    int `json:"files_enumerated"`
	FilesRead     int `json:"files_read"`
	Expected      int `json:"manifest_files"`
	Recovered     int `json:"manifest_files_recovered"`
	HashMatch     int `json:"manifest_hash_matches"`
	ManifestUnsup int `json:"manifest_files_unsupported"`
	Unsupported   int `json:"unsupported_reported"`
	ReadOnlyProof int `json:"source_unchanged"`
}

// AcqFixture is one fixture's result.
type AcqFixture struct {
	Name      string   `json:"name"`
	Origin    string   `json:"origin"` // what made it (README)
	Container string   `json:"container,omitempty"`
	Volumes   []AcqVol `json:"volumes,omitempty"`
	OpenError string   `json:"open_error,omitempty"`
	// Comparison: "manifest <file>", "logical disk == <fixture>", or
	// "enumerated, not compared" when the fixture has no manifest.
	Comparison string `json:"comparison"`
	Expected   int    `json:"manifest_files"`
	Recovered  int    `json:"manifest_files_recovered"`
	HashMatch  int    `json:"manifest_hash_matches"`
	// ManifestUnsupported counts manifest files the reader reported
	// UNSUPPORTED instead of reading (e.g. a zstd extent).
	ManifestUnsupported int `json:"manifest_files_unsupported,omitempty"`
	// LogicalMatch is set when the logical disk was compared with a
	// reference image.
	LogicalMatch *bool `json:"logical_disk_match,omitempty"`
	// Unsupported lists every UNSUPPORTED / ENCRYPTED state reported:
	// open errors, volume states, reader problems, unreadable files.
	Unsupported []string `json:"unsupported,omitempty"`
	FilesFound  int      `json:"files_enumerated"`
	FilesRead   int      `json:"files_read"`
	// SourceSHA256 is the fixture file(s) and the decompressed segments,
	// hashed before reading; SourceUnchanged says the hash was the same
	// after every reader was closed.
	SourceSHA256    []string `json:"source_sha256"`
	SourceUnchanged bool     `json:"source_unchanged"`
	Problems        []string `json:"problems,omitempty"`
	MS              int64    `json:"ms"`
	OK              bool     `json:"ok"`
}

// AcqVol is one volume of a fixture.
type AcqVol struct {
	Index  int    `json:"index"`
	Name   string `json:"name,omitempty"`
	Type   string `json:"type"`
	Status string `json:"status"` // read | UNSUPPORTED | ENCRYPTED | CORRUPT | UNKNOWN | lvm2-pv
	Reason string `json:"reason,omitempty"`
	Files  int    `json:"files,omitempty"`
	Dirs   int    `json:"dirs,omitempty"`
	Links  int    `json:"symlinks,omitempty"`
}

// manifestEntry is one expected file (or symlink, Target set).
type manifestEntry struct {
	Path, SHA256, Target string
}

// acqFixture describes one fixture and what it must yield.
type acqFixture struct {
	name   string
	origin string
	files  []string // repo-relative .gz files; the first is opened
	tar    string   // a .tar.gz holding a directory image; open names it inside
	open   string
	format string // expected container format
	// manifest returns the expected files of the readable volume named
	// by vol ("" = the only or first readable one), or nil.
	manifest   func(root string) ([]manifestEntry, string, error)
	vol        string
	sameAs     string   // repo-relative .gz: the logical disk must equal it
	openErr    string   // the open must fail with this kind (UNSUPPORTED / ENCRYPTED) …
	unsup      []string // … and every reported UNSUPPORTED state must match one of these
	minUnsup   int      // at least this many UNSUPPORTED states must be reported
	minFiles   int      // at least this many regular files must be enumerated
	unchecked  bool     // enumerate only: the fixture has no manifest
	notesMatch string   // a reader problem that must be reported
}

const (
	dd     = "internal/diskimage/testdata/"
	ntfsOK = "synthetic content, NTFS made by mkntfs/ntfs-3g (internal/diskimage/testdata/gen.sh)"
	linux  = "real tools in a Debian container (gen-linux.sh)"
	macos  = "hdiutil / diskutil on macOS (gen-macos.sh)"
)

func acqFixtures() []acqFixture {
	gptSame := dd + "disk-gpt.raw.gz"
	apfsGPT := dd + "apfs-gpt.raw.gz"
	xfsMan := coreutilsManifest("internal/diskimage/xfs/testdata/xfs.manifest", "")
	btrMan := coreutilsManifest("internal/diskimage/btrfs/testdata/btrfs.manifest", "")
	apfsMan := shaManifest("internal/diskimage/apfs/testdata/expected.txt", "Users/alice/", appleNames, nil)
	hfsMan := shaManifest("internal/diskimage/hfsplus/testdata/expected.txt", "Users/alice/", appleNames, nil)
	// The images inside the DMG / sparsebundle fixtures hold the same
	// synthetic session and known.bin as the bare APFS volume.
	dmgMan := shaManifest("internal/diskimage/apfs/testdata/expected.txt", "Users/alice/", appleNames, []string{"session.jsonl", "known.bin"})
	ext := func(prefix string) func(string) ([]manifestEntry, string, error) {
		return shaManifest("internal/diskimage/ext4/testdata/expected.txt", "", nil, nil, prefix)
	}
	fat := shaManifest("internal/diskimage/fat/testdata/expected.txt", "", nil, nil)
	return []acqFixture{
		// NTFS and the container formats around it.
		{name: "disk-gpt.raw (GPT + NTFS)", origin: ntfsOK, files: []string{gptSame}, format: diskimage.FormatRaw, unchecked: true, minFiles: 5},
		{name: "disk-mbr.raw (MBR extended + NTFS)", origin: ntfsOK, files: []string{dd + "disk-mbr.raw.gz"}, format: diskimage.FormatRaw, unchecked: true, minFiles: 5},
		{name: "disk-gpt.raw.001-003 (split raw)", origin: ntfsOK, files: []string{dd + "disk-gpt.raw.001.gz", dd + "disk-gpt.raw.002.gz", dd + "disk-gpt.raw.003.gz"}, format: diskimage.FormatSplitRaw, sameAs: gptSame},
		{name: "disk-gpt-alpha.raw.aa-ac (split raw)", origin: ntfsOK, files: []string{dd + "disk-gpt-alpha.raw.aa.gz", dd + "disk-gpt-alpha.raw.ab.gz", dd + "disk-gpt-alpha.raw.ac.gz"}, format: diskimage.FormatSplitRaw, sameAs: gptSame},
		{name: "disk.E01 (EWF)", origin: ntfsOK + ", ewfacquire", files: []string{dd + "disk.E01.gz"}, format: diskimage.FormatEWF, sameAs: gptSame},
		{name: "disk-split.E01-E09 (EWF, 9 segments)", origin: ntfsOK + ", ewfacquire", files: splitE01(), format: diskimage.FormatEWF, sameAs: gptSame},
		{name: "disk-fixed.vhd", origin: ntfsOK + ", qemu-img", files: []string{dd + "disk-fixed.vhd.gz"}, format: diskimage.FormatVHDFixed, sameAs: gptSame},
		{name: "disk-dynamic.vhd", origin: ntfsOK + ", qemu-img", files: []string{dd + "disk-dynamic.vhd.gz"}, format: diskimage.FormatVHDDynamic, sameAs: gptSame},
		{name: "disk.vhdx", origin: ntfsOK + ", qemu-img", files: []string{dd + "disk.vhdx.gz"}, format: diskimage.FormatVHDX, sameAs: gptSame},
		{name: "disk-sparse.vmdk", origin: ntfsOK + ", qemu-img", files: []string{dd + "disk-sparse.vmdk.gz"}, format: diskimage.FormatVMDK, sameAs: gptSame},
		{name: "disk-stream.vmdk", origin: ntfsOK + ", qemu-img", files: []string{dd + "disk-stream.vmdk.gz"}, format: diskimage.FormatVMDK, sameAs: gptSame},
		{name: "disk-flat.vmdk (descriptor + flat extent)", origin: ntfsOK + ", qemu-img", files: []string{dd + "disk-flat.vmdk.gz", dd + "disk-flat-flat.vmdk.gz"}, format: diskimage.FormatVMDK, sameAs: gptSame},
		{name: "usn-deleted.ntfs (NTFS volume, USN journal)", origin: "mkntfs/ntfs-3g volume, synthetic USN records (internal/diskimage/ntfs/testdata/README.md)", files: []string{"internal/diskimage/ntfs/testdata/usn-deleted.ntfs.gz"}, format: diskimage.FormatRaw, unchecked: true, minFiles: 1},
		{name: "vss-synthetic.ntfs (NTFS volume, shadow-copy store)", origin: "mkntfs/ntfs-3g volume, synthetic VSS store (internal/diskimage/ntfs/vss/testdata/README.md)", files: []string{"internal/diskimage/ntfs/vss/testdata/vss-synthetic.ntfs.gz"}, format: diskimage.FormatRaw, unchecked: true, minFiles: 2},
		// ext2/3/4 and FAT / exFAT.
		{name: "ext4.img", origin: "mkfs.ext4 + debugfs (internal/diskimage/ext4/testdata/gen.sh)", files: []string{"internal/diskimage/ext4/testdata/ext4.img.gz"}, format: diskimage.FormatRaw, manifest: ext(""), unsup: []string{"secret"}, minUnsup: 1},
		{name: "ext2.img", origin: "mkfs.ext2 (internal/diskimage/ext4/testdata/gen.sh)", files: []string{"internal/diskimage/ext4/testdata/ext2.img.gz"}, format: diskimage.FormatRaw, manifest: ext("ext2:")},
		{name: "ext4-inline.img", origin: "mkfs.ext4 -O inline_data (internal/diskimage/ext4/testdata/gen.sh)", files: []string{"internal/diskimage/ext4/testdata/ext4-inline.img.gz"}, format: diskimage.FormatRaw, manifest: ext("inline:")},
		{name: "fat12.img", origin: "mkfs.fat + mtools (internal/diskimage/fat/testdata/gen.sh)", files: []string{"internal/diskimage/fat/testdata/fat12.img.gz"}, format: diskimage.FormatRaw, manifest: fat},
		{name: "fat16.img", origin: "mkfs.fat + mtools (internal/diskimage/fat/testdata/gen.sh)", files: []string{"internal/diskimage/fat/testdata/fat16.img.gz"}, format: diskimage.FormatRaw, manifest: fat},
		{name: "fat32.img", origin: "mkfs.fat + mtools (internal/diskimage/fat/testdata/gen.sh)", files: []string{"internal/diskimage/fat/testdata/fat32.img.gz"}, format: diskimage.FormatRaw, manifest: fat},
		{name: "exfat.img", origin: "mkfs.exfat + exfat-fuse (internal/diskimage/fat/testdata/gen.sh)", files: []string{"internal/diskimage/fat/testdata/exfat.img.gz"}, format: diskimage.FormatRaw, manifest: fat},
		// Linux: XFS, Btrfs, QCOW2, LVM2.
		{name: "xfs.img (XFS v5)", origin: linux, files: []string{"internal/diskimage/xfs/testdata/xfs.img.gz"}, format: diskimage.FormatRaw, manifest: xfsMan},
		{name: "xfs4.img (XFS v4)", origin: linux, files: []string{"internal/diskimage/xfs/testdata/xfs4.img.gz"}, format: diskimage.FormatRaw, manifest: xfsMan},
		{name: "btrfs.img (zlib, snapshot, zstd extent)", origin: linux, files: []string{"internal/diskimage/btrfs/testdata/btrfs.img.gz"}, format: diskimage.FormatRaw, manifest: btrMan, unsup: []string{"zstd"}, minUnsup: 1},
		{name: "linux-btrfs.qcow2 (QCOW2 v3)", origin: linux + ", qemu-img convert", files: []string{dd + "linux-btrfs.qcow2.gz"}, format: diskimage.FormatQCOW2, manifest: btrMan, unsup: []string{"zstd"}, minUnsup: 1},
		{name: "linux-btrfs-c.qcow2 (deflate clusters)", origin: linux + ", qemu-img convert -c", files: []string{dd + "linux-btrfs-c.qcow2.gz"}, format: diskimage.FormatQCOW2, manifest: btrMan, unsup: []string{"zstd"}, minUnsup: 1},
		{name: "linux-xfs-v2.qcow2 (QCOW2 v2)", origin: linux + ", qemu-img convert -o compat=0.10", files: []string{dd + "linux-xfs-v2.qcow2.gz"}, format: diskimage.FormatQCOW2, manifest: xfsMan},
		{name: "linux-backed.qcow2 (backing file)", origin: linux + ", qemu-img create -b", files: []string{dd + "linux-backed.qcow2.gz"}, openErr: "UNSUPPORTED", unsup: []string{"backing"}},
		{name: "linux-zstd-type.qcow2 (zstd compression type)", origin: linux + ", qemu-img create -o compression_type=zstd", files: []string{dd + "linux-zstd-type.qcow2.gz"}, openErr: "UNSUPPORTED", unsup: []string{"zstd"}},
		{name: "linux-lvm.img (LVM2: linear + striped/snapshot/raid1/thin)", origin: linux + " (non-linear LV metadata hand-written, see README)", files: []string{dd + "linux-lvm.img.gz"}, format: diskimage.FormatRaw,
			manifest: coreutilsManifest("internal/diskimage/xfs/testdata/xfs.manifest", "home/"), vol: "vgadfir/root",
			unsup: []string{"striped", "snapshot", "raid1", "thin-pool", `"thin"`}, minUnsup: 5},
		// macOS: APFS, HFS+, DMG, sparsebundle.
		{name: "apfs.img (APFS container)", origin: macos, files: []string{"internal/diskimage/apfs/testdata/apfs.img.gz"}, format: diskimage.FormatRaw, manifest: apfsMan, unsup: []string{"compress"}},
		{name: "hfsplus.img (HFS+)", origin: macos, files: []string{"internal/diskimage/hfsplus/testdata/hfsplus.img.gz"}, format: diskimage.FormatRaw, manifest: hfsMan, unsup: []string{"compress"}},
		{name: "hfsx.img (case-sensitive HFS+)", origin: macos, files: []string{"internal/diskimage/hfsplus/testdata/hfsx.img.gz"}, format: diskimage.FormatRaw, unchecked: true, minFiles: 2},
		{name: "apfs-gpt.raw (GPT + APFS)", origin: macos, files: []string{apfsGPT}, format: diskimage.FormatRaw, manifest: dmgMan},
		{name: "apfs-udzo.dmg (UDIF zlib)", origin: macos, files: []string{dd + "apfs-udzo.dmg.gz"}, format: diskimage.FormatDMG, sameAs: apfsGPT, manifest: dmgMan},
		{name: "apfs-udbz.dmg (UDIF bzip2)", origin: macos, files: []string{dd + "apfs-udbz.dmg.gz"}, format: diskimage.FormatDMG, sameAs: apfsGPT, manifest: dmgMan},
		{name: "apfs-ulfo.dmg (UDIF LZFSE)", origin: macos, files: []string{dd + "apfs-ulfo.dmg.gz"}, openErr: "UNSUPPORTED", unsup: []string{"LZFSE"}},
		{name: "apfs.sparsebundle (1 MiB bands)", origin: macos, tar: dd + "apfs.sparsebundle.tar.gz", open: "apfs.sparsebundle", format: diskimage.FormatSparseBundle, sameAs: apfsGPT, manifest: dmgMan},
		{name: "apfs-multi.dmg (3 volumes, one FileVault-encrypted)", origin: macos, files: []string{dd + "apfs-multi.dmg.gz"}, format: diskimage.FormatDMG, unchecked: true, unsup: []string{"encrypted"}, minUnsup: 1, minFiles: 2},
		{name: "hfs-udzo.dmg (UDIF zlib, HFS+)", origin: macos, files: []string{dd + "hfs-udzo.dmg.gz"}, format: diskimage.FormatDMG, manifest: dmgMan},
		{name: "enc-head.dmg (encrypted UDIF header)", origin: macos, files: []string{dd + "enc-head.dmg.gz"}, openErr: "ENCRYPTED", unsup: []string{"encrypted"}},
	}
}

func splitE01() []string {
	var out []string
	for i := 1; i <= 9; i++ {
		out = append(out, fmt.Sprintf("%sdisk-split.E%02d.gz", dd, i))
	}
	return out
}

// appleNames maps the names in the APFS / HFS+ expected.txt to their
// paths under the volume's home (as the readers' own tests do).
var appleNames = map[string]string{"session.jsonl": ".claude/projects/-Users-alice-proj/session.jsonl"}

// coreutilsManifest reads a manifest written by gen-linux-inner.sh
// ("type size sha256|target mtime path"), keeping files and symlinks
// under prefix.
func coreutilsManifest(rel, prefix string) func(string) ([]manifestEntry, string, error) {
	return func(root string) ([]manifestEntry, string, error) {
		f, err := os.Open(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return nil, "", err
		}
		defer f.Close()
		var out []manifestEntry
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<16), 1<<20)
		for sc.Scan() {
			p := strings.SplitN(sc.Text(), " ", 5)
			if len(p) != 5 || !strings.HasPrefix(p[4], prefix) {
				continue
			}
			switch p[0] {
			case "f":
				out = append(out, manifestEntry{Path: p[4], SHA256: p[2]})
			case "l":
				out = append(out, manifestEntry{Path: p[4], Target: p[2]})
			}
		}
		what := "manifest " + strings.TrimPrefix(rel, "internal/diskimage/")
		if prefix != "" {
			what += " (" + prefix + " subtree)"
		}
		return out, what, sc.Err()
	}
}

// shaManifest reads a shasum-style expected.txt ("<sha256>  <path>").
// With prefix set, only lines "prefix<path>" are kept; without, lines
// carrying any "x:" prefix are left out. names renames entries, base is
// prepended, only (when set) keeps just those names.
func shaManifest(rel, base string, names map[string]string, only []string, prefix ...string) func(string) ([]manifestEntry, string, error) {
	pfx := ""
	if len(prefix) > 0 {
		pfx = prefix[0]
	}
	return func(root string) ([]manifestEntry, string, error) {
		f, err := os.Open(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return nil, "", err
		}
		defer f.Close()
		keep := map[string]bool{}
		for _, n := range only {
			keep[n] = true
		}
		var out []manifestEntry
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			sum, p, ok := strings.Cut(sc.Text(), "  ")
			if !ok || len(sum) != 64 {
				continue
			}
			if pfx != "" {
				if p, ok = strings.CutPrefix(p, pfx); !ok {
					continue
				}
			} else if i := strings.IndexByte(p, ':'); i > 0 && !strings.Contains(p[:i], "/") {
				continue
			}
			if len(keep) > 0 && !keep[p] {
				continue
			}
			if n, ok := names[p]; ok {
				p = n
			}
			out = append(out, manifestEntry{Path: base + p, SHA256: sum})
		}
		what := "manifest " + strings.TrimPrefix(rel, "internal/diskimage/")
		if len(only) > 0 {
			what += " (" + strings.Join(only, ", ") + ")"
		}
		return out, what, sc.Err()
	}
}

// Enumeration bounds: the fixtures are small, but the walk is written as
// if they were not.
const (
	acqMaxEntries = 200000
	acqMaxBytes   = 1 << 30
)

func runAcquisition(r *Report, o Options, work string) {
	a := &Acquisition{Label: SuiteLabel, Fixtures: []AcqFixture{}, Checks: []Check{}, Formats: map[string]int{}}
	r.Acquisition = a
	start := time.Now()
	root := repoFinder(o.RepoRoot)
	if root == "" {
		a.Skipped = noCheckout
		r.Suites = append(r.Suites, Suite{Name: "acquisition", Label: SuiteLabel, Status: SuiteSkip, Reason: noCheckout})
		return
	}
	failed := false
	for i, fx := range acqFixtures() {
		dir := filepath.Join(work, fmt.Sprintf("f%02d", i))
		res := acquire(root, dir, fx)
		_ = os.RemoveAll(dir) // decompressed images are large; never keep more than one
		a.Fixtures = append(a.Fixtures, res)
		if res.Container != "" {
			a.Formats[res.Container]++
		}
		t := &a.Totals
		t.Fixtures++
		if res.Comparison != "enumerated, not compared" {
			t.Compared++
		}
		t.Volumes += len(res.Volumes)
		t.FilesFound += res.FilesFound
		t.FilesRead += res.FilesRead
		t.Expected += res.Expected
		t.Recovered += res.Recovered
		t.HashMatch += res.HashMatch
		t.ManifestUnsup += res.ManifestUnsupported
		t.Unsupported += len(res.Unsupported)
		if res.SourceUnchanged {
			t.ReadOnlyProof++
		}
		c := Check{Name: res.Name, Want: "opened read-only, expected contents and states, source unchanged", Got: "ok"}
		if !res.OK {
			c.Got = strings.Join(res.Problems, "; ")
			failed = true
		}
		r.record("acquisition", &c, res.OK)
		a.Checks = append(a.Checks, c)
	}
	a.Seconds = time.Since(start).Seconds()
	t := a.Totals
	sum := fmt.Sprintf("%d fixtures (%d compared with a manifest or reference image), %d volumes, %d files enumerated, manifest files %d/%d recovered and %d/%d hashes match (the other %d reported UNSUPPORTED, as documented), %d UNSUPPORTED states reported in all, source unchanged %d/%d",
		t.Fixtures, t.Compared, t.Volumes, t.FilesFound, t.Recovered, t.Expected, t.HashMatch, t.Expected, t.ManifestUnsup, t.Unsupported, t.ReadOnlyProof, t.Fixtures)
	r.Suites = append(r.Suites, verdict("acquisition", sum, a.Checks, failed))
}

// acquire runs one fixture.
func acquire(root, dir string, fx acqFixture) (res AcqFixture) {
	res = AcqFixture{Name: fx.name, Origin: fx.origin, Comparison: "enumerated, not compared"}
	t0 := time.Now()
	defer func() {
		if p := recover(); p != nil {
			res.Problems = append(res.Problems, fmt.Sprintf("reader panicked: %v", p))
			res.OK = false
		}
		res.MS = time.Since(t0).Milliseconds()
	}()
	problem := func(format string, a ...any) { res.Problems = append(res.Problems, fmt.Sprintf(format, a...)) }
	if err := os.MkdirAll(dir, 0o700); err != nil {
		problem("%v", err)
		return res
	}

	// Stage the fixture: the committed .gz files are decompressed (sparse:
	// the XFS and Btrfs images are 300 MB of mostly zeros), the
	// sparsebundle tarball is extracted.
	var sources []string // committed files
	var first string
	if fx.tar != "" {
		src := filepath.Join(root, filepath.FromSlash(fx.tar))
		sources = append(sources, src)
		if err := untarGz(src, dir); err != nil {
			problem("extract %s: %v", fx.tar, err)
			return res
		}
		first = filepath.Join(dir, fx.open)
	} else {
		for i, rel := range fx.files {
			src := filepath.Join(root, filepath.FromSlash(rel))
			sources = append(sources, src)
			out := filepath.Join(dir, strings.TrimSuffix(path.Base(rel), ".gz"))
			if err := gunzipSparse(src, out); err != nil {
				problem("decompress %s: %v", rel, err)
				return res
			}
			if i == 0 {
				first = out
			}
		}
	}
	before, err := hashAll(sources)
	if err != nil {
		problem("hash fixture: %v", err)
		return res
	}

	im, err := diskimage.Open(first)
	if err != nil {
		res.OpenError = err.Error()
		res.Unsupported = append(res.Unsupported, err.Error())
		kind := ""
		switch {
		case errors.Is(err, diskimage.ErrEncrypted):
			kind = "ENCRYPTED"
		case errors.Is(err, diskimage.ErrUnsupported):
			kind = "UNSUPPORTED"
		}
		if fx.openErr == "" || kind != fx.openErr {
			problem("open: %v (want %s)", err, firstNonEmpty(fx.openErr, "success"))
		}
		res.Comparison = "open refused, as expected"
		after, _ := hashAll(sources)
		res.SourceSHA256, res.SourceUnchanged = before, equalStrings(before, after)
		checkUnsupported(&res, fx, problem)
		res.OK = len(res.Problems) == 0 && res.SourceUnchanged
		return res
	}
	if fx.openErr != "" {
		problem("opened, but the fixture must be refused %s", fx.openErr)
	}
	segs := append([]string(nil), im.Segments...)
	segBefore, err := hashAll(segs)
	if err != nil {
		problem("hash segments: %v", err)
	}
	res.Container = im.Format
	if fx.format != "" && im.Format != fx.format {
		problem("container %s, want %s", im.Format, fx.format)
	}

	if fx.sameAs != "" {
		ok, err := sameLogical(im, filepath.Join(root, filepath.FromSlash(fx.sameAs)))
		if err != nil {
			problem("compare logical disk: %v", err)
		}
		res.LogicalMatch = &ok
		res.Comparison = "logical disk == " + strings.TrimSuffix(path.Base(fx.sameAs), ".gz")
		if !ok {
			problem("logical disk differs from %s", path.Base(fx.sameAs))
		}
	}

	var want []manifestEntry
	if fx.manifest != nil {
		var what string
		want, what, err = fx.manifest(root)
		if err != nil {
			problem("manifest: %v", err)
		}
		if res.Comparison == "enumerated, not compared" {
			res.Comparison = what
		} else {
			res.Comparison += "; " + what
		}
		res.Expected = len(want)
	}

	pt, err := diskimage.Partitions(im, im.Size())
	if err != nil {
		problem("partition table: %v", err)
	} else {
		compared := false
		for _, v := range pt.Volumes {
			av := AcqVol{Index: v.Index, Name: v.Name}
			switch {
			case v.Unsupported != "":
				av.Type, av.Status, av.Reason = v.Type, "UNSUPPORTED", v.Unsupported
				res.Unsupported = append(res.Unsupported, v.Name+": "+v.Unsupported)
			case v.LVM != "":
				av.Type, av.Status, av.Reason = "lvm2-pv", "lvm2-pv", v.LVM
			default:
				fsr := diskimage.OpenFS(v.Section(im), v.Size)
				av.Type = fsr.Type
				if fsr.FS == nil {
					av.Status, av.Reason = errKind(fsr.Err), fsr.Reason
					if av.Status == "UNSUPPORTED" || av.Status == "ENCRYPTED" {
						res.Unsupported = append(res.Unsupported, fsr.Reason)
					}
					break
				}
				av.Status = "read"
				if pr, ok := fsr.FS.(interface{ Problems() []string }); ok {
					for _, p := range pr.Problems() {
						if isUnsupportedText(p) {
							res.Unsupported = append(res.Unsupported, fsr.Type+": "+p)
						}
					}
				}
				w := walkFS(fsr.FS)
				av.Files, av.Dirs, av.Links = w.files, w.dirs, w.links
				res.FilesFound += w.files
				res.FilesRead += w.read
				res.Unsupported = append(res.Unsupported, w.unsupported...)
				for _, e := range w.errors {
					problem("%s volume %d: %s", fsr.Type, v.Index, e)
				}
				if want != nil && !compared && (fx.vol == "" || fx.vol == v.Name) {
					compared = true
					compareManifest(&res, fsr.FS, want)
				}
			}
			res.Volumes = append(res.Volumes, av)
		}
		if want != nil && !compared {
			problem("no readable volume to compare with the manifest")
		}
	}
	im.Close()

	// Read-only proof: every file the image was read from, and the
	// committed fixture, hash the same after every reader closed.
	after, _ := hashAll(sources)
	segAfter, _ := hashAll(segs)
	res.SourceSHA256 = append(before, segBefore...)
	res.SourceUnchanged = equalStrings(before, after) && equalStrings(segBefore, segAfter) && len(segBefore) == len(segs)
	if !res.SourceUnchanged {
		problem("source image hash changed after reading")
	}
	if res.FilesFound < fx.minFiles {
		problem("%d files enumerated, want at least %d", res.FilesFound, fx.minFiles)
	}
	if res.Expected > 0 && res.HashMatch+res.ManifestUnsupported < res.Expected {
		problem("manifest: %d of %d files match", res.HashMatch, res.Expected)
	}
	checkUnsupported(&res, fx, problem)
	res.OK = len(res.Problems) == 0
	return res
}

// checkUnsupported: every UNSUPPORTED state must be one the fixture
// documents, and at least minUnsup must be reported.
func checkUnsupported(res *AcqFixture, fx acqFixture, problem func(string, ...any)) {
	for _, u := range res.Unsupported {
		ok := false
		for _, w := range fx.unsup {
			if strings.Contains(strings.ToLower(u), strings.ToLower(w)) {
				ok = true
				break
			}
		}
		if !ok {
			problem("UNSUPPORTED state the fixture does not document: %s", truncate(u, 160))
		}
	}
	if len(res.Unsupported) < fx.minUnsup {
		problem("%d UNSUPPORTED state(s) reported, want at least %d (%s)", len(res.Unsupported), fx.minUnsup, strings.Join(fx.unsup, ", "))
	}
	if fx.openErr != "" && len(res.Unsupported) == 0 {
		problem("no UNSUPPORTED state reported")
	}
	sort.Strings(res.Unsupported)
}

// compareManifest reads every expected file and symlink.
func compareManifest(res *AcqFixture, fsys fs.FS, want []manifestEntry) {
	for _, e := range want {
		if e.Target != "" {
			rl, ok := fsys.(interface{ ReadLink(string) (string, error) })
			if !ok {
				res.Problems = append(res.Problems, "manifest symlink "+e.Path+": reader cannot read links")
				continue
			}
			t, err := rl.ReadLink(e.Path)
			switch {
			case err != nil:
				res.Problems = append(res.Problems, fmt.Sprintf("manifest symlink %s: %v", e.Path, err))
			case t != e.Target:
				res.Problems = append(res.Problems, fmt.Sprintf("manifest symlink %s: target %q", e.Path, truncate(t, 60)))
			default:
				res.Recovered++
				res.HashMatch++
			}
			continue
		}
		sum, err := hashFSFile(fsys, e.Path)
		switch {
		case err != nil && isUnsupportedErr(err):
			res.ManifestUnsupported++ // the walk reports the state itself
		case err != nil:
			res.Problems = append(res.Problems, fmt.Sprintf("manifest file %s: %v", e.Path, err))
		case sum != e.SHA256:
			res.Recovered++
			res.Problems = append(res.Problems, fmt.Sprintf("manifest file %s: sha256 %s, want %s", e.Path, sum[:12], e.SHA256[:12]))
		default:
			res.Recovered++
			res.HashMatch++
		}
	}
}

type walkResult struct {
	files, dirs, links, read int
	unsupported, errors      []string
}

// walkFS enumerates a volume and reads every regular file.
func walkFS(fsys fs.FS) walkResult {
	var w walkResult
	entries := 0
	var bytesRead int64
	_ = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		entries++
		if entries > acqMaxEntries {
			w.errors = append(w.errors, fmt.Sprintf("walk stopped at %d entries", acqMaxEntries))
			return fs.SkipAll
		}
		if err != nil {
			if isUnsupportedErr(err) {
				w.unsupported = append(w.unsupported, p+": "+err.Error())
			} else if len(w.errors) < 20 {
				w.errors = append(w.errors, p+": "+err.Error())
			}
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		switch {
		case d.IsDir():
			if p != "." {
				w.dirs++
			}
		case d.Type()&fs.ModeSymlink != 0:
			w.links++
		case d.Type().IsRegular():
			w.files++
			if bytesRead > acqMaxBytes {
				return nil
			}
			f, err := fsys.Open(p)
			if err == nil {
				var n int64
				n, err = io.Copy(io.Discard, f)
				f.Close()
				bytesRead += n
			}
			switch {
			case err == nil:
				w.read++
			case isUnsupportedErr(err):
				w.unsupported = append(w.unsupported, p+": "+err.Error())
			case len(w.errors) < 20:
				w.errors = append(w.errors, p+": "+err.Error())
			}
		}
		return nil
	})
	return w
}

func isUnsupportedErr(err error) bool {
	return errors.Is(err, errors.ErrUnsupported) || errors.Is(err, diskimage.ErrUnsupported) ||
		errors.Is(err, diskimage.ErrEncrypted) || isUnsupportedText(err.Error())
}

func isUnsupportedText(s string) bool {
	u := strings.ToUpper(s)
	return strings.Contains(u, "UNSUPPORTED") || strings.Contains(u, "NOT SUPPORTED") || strings.Contains(u, "ENCRYPTED")
}

func errKind(err error) string {
	switch {
	case err == nil:
		return "read"
	case errors.Is(err, diskimage.ErrEncrypted):
		return "ENCRYPTED"
	case errors.Is(err, diskimage.ErrUnsupported):
		return "UNSUPPORTED"
	case errors.Is(err, diskimage.ErrCorrupt):
		return "CORRUPT"
	}
	return "UNKNOWN"
}

func hashFSFile(fsys fs.FS, p string) (string, error) {
	f, err := fsys.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// sameLogical compares the opened image's logical disk with a gzipped
// reference image: equal over the reference's length, zero past it.
func sameLogical(im *diskimage.Image, refGz string) (bool, error) {
	f, err := os.Open(refGz)
	if err != nil {
		return false, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return false, err
	}
	want := sha256.New()
	n, err := io.Copy(want, zr)
	if err != nil {
		return false, err
	}
	if im.Size() < n {
		return false, nil
	}
	got := sha256.New()
	if _, err := io.Copy(got, io.NewSectionReader(im, 0, n)); err != nil {
		return false, err
	}
	if !bytes.Equal(got.Sum(nil), want.Sum(nil)) {
		return false, nil
	}
	buf := make([]byte, 1<<16)
	for off := n; off < im.Size(); {
		k, err := im.ReadAt(buf[:min(int64(len(buf)), im.Size()-off)], off)
		for _, b := range buf[:k] {
			if b != 0 {
				return false, nil
			}
		}
		off += int64(k)
		if err != nil && !errors.Is(err, io.EOF) {
			return false, err
		}
		if k == 0 {
			break
		}
	}
	return true, nil
}

// gunzipSparse decompresses src to dst, seeking over all-zero 4 KiB
// blocks so the output is a sparse file.
func gunzipSparse(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	zr, err := gzip.NewReader(in)
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	const blk = 4096
	buf := make([]byte, blk)
	var size int64
	for {
		n, rerr := io.ReadFull(zr, buf)
		if n > 0 {
			if allZero(buf[:n]) {
				if _, err := out.Seek(int64(n), io.SeekCurrent); err != nil {
					out.Close()
					return err
				}
			} else if _, err := out.Write(buf[:n]); err != nil {
				out.Close()
				return err
			}
			size += int64(n)
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
		if rerr != nil {
			out.Close()
			return rerr
		}
	}
	if err := out.Truncate(size); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// untarGz extracts a gzipped tar of regular files and directories into
// dir, refusing any path that would leave it.
func untarGz(src, dir string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	tr := tar.NewReader(zr)
	for n := 0; ; n++ {
		if n > 10000 {
			return errors.New("too many entries")
		}
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		name := path.Clean(strings.TrimPrefix(h.Name, "./"))
		if !fs.ValidPath(name) || !filepath.IsLocal(filepath.FromSlash(name)) || strings.ContainsAny(h.Name, `\:`) {
			return fmt.Errorf("unsafe path %q", h.Name)
		}
		p := filepath.Join(dir, filepath.FromSlash(name))
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(p, 0o700); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
				return err
			}
			w, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				return err
			}
			_, err = io.Copy(w, io.LimitReader(tr, 64<<20))
			w.Close()
			if err != nil {
				return err
			}
		default:
			// Links and devices could point outside dir; a sparsebundle
			// holds only directories and band files.
			return fmt.Errorf("%q: tar entry type %q refused (regular files and directories only)", h.Name, h.Typeflag)
		}
	}
}

func hashAll(paths []string) ([]string, error) {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		s, err := fileSHA256(p)
		if err != nil {
			return out, err
		}
		out = append(out, s)
	}
	return out, nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
