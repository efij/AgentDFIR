package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v3/internal/casepkg"
	"github.com/efij/AgentDFIR/v3/internal/diskimage"
	"github.com/efij/AgentDFIR/v3/internal/diskimage/ntfs"
	"github.com/efij/AgentDFIR/v3/internal/sanitize"
)

// imageProvenanceName is the sealed sidecar that ties every extracted
// file back to the image, partition, filesystem record and timestamps.
const imageProvenanceName = "image-provenance.jsonl"

type segmentHash struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// imageProvenance is one line of image-provenance.jsonl.
type imageProvenance struct {
	ImagePath       string        `json:"image_path"`
	ImageSegments   []segmentHash `json:"image_segments"`
	ContainerType   string        `json:"container_type"`
	PartitionScheme string        `json:"partition_scheme"`
	PartitionIndex  int           `json:"partition_index"`
	PartitionOffset int64         `json:"partition_offset"`
	PartitionType   string        `json:"partition_type,omitempty"`
	FSType          string        `json:"fs_type"`
	TimeZone        string        `json:"time_zone,omitempty"` // FAT: "local-unknown" (times are wall clock, zone not recorded)
	Inode           uint64        `json:"inode"`               // MFT record number on NTFS
	OriginalPath    string        `json:"original_path"`
	StagedPath      string        `json:"staged_path,omitempty"` // relative to the staging root the import read
	Size            int64         `json:"size"`
	SHA256          string        `json:"sha256,omitempty"`
	MTimeUTC        string        `json:"mtime_utc,omitempty"`
	ATimeUTC        string        `json:"atime_utc,omitempty"`
	CTimeUTC        string        `json:"ctime_utc,omitempty"` // metadata change (NTFS: MFT record change)
	BTimeUTC        string        `json:"btime_utc,omitempty"` // birth
	ADS             []string      `json:"alternate_data_streams,omitempty"`
	E01Verification string        `json:"e01_stored_hash_verification"`
	Problem         string        `json:"problem,omitempty"`
}

// volumeReport is what happened to one volume, for notes and the summary.
type volumeReport struct {
	vol     diskimage.Volume
	fsType  string
	status  string // read | UNSUPPORTED | ENCRYPTED | CORRUPT | UNRECOGNIZED
	reason  string
	files   int
	notes   []string
	staging string
}

// collectImage opens a forensic disk image read-only, extracts only the
// agent evidence the import collector would take, and runs the import
// pipeline over that staging tree. The image is hashed before and after;
// both results, the E01 stored-hash check and every volume's outcome
// (including ones that could not be read) are sealed in the case.
func collectImage(path string, o importOpts, verifyStored bool) int {
	abs, err := filepath.Abs(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if fi, err := os.Stat(abs); err != nil || !fi.Mode().IsRegular() {
		fmt.Fprintf(os.Stderr, "--image: %s is not a readable file\n", sanitize.Terminal(abs))
		return 2
	}
	im, err := diskimage.Open(abs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "--image:", sanitize.Terminal(err.Error()))
		return 1
	}
	imClosed := false
	defer func() {
		if !imClosed {
			im.Close()
		}
	}()
	fmt.Printf("Image: %s (%s, %d bytes logical, %d segment file(s))\n", sanitize.Terminal(abs), im.Format, im.Size(), len(im.Segments))

	before, err := hashSegments(im.Segments)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: hashing image:", err)
		return 1
	}
	for _, s := range before {
		fmt.Printf("  sha256 %s  %s\n", s.SHA256, sanitize.Terminal(filepath.Base(s.Path)))
	}

	e01 := "not applicable (" + im.Format + ")"
	if im.Format == diskimage.FormatEWF {
		switch {
		case !im.HasStoredHashes():
			e01 = "absent (no stored hashes in the image)"
		case !verifyStored:
			e01 = "not verified (--skip-image-verify)"
		default:
			fmt.Println("  verifying stored E01 hashes (full read) …")
			r := im.VerifyStored(nil)
			e01 = fmt.Sprintf("md5=%s sha1=%s", r.MD5, r.SHA1)
			if r.Error != "" {
				e01 = "unverifiable: " + r.Error
			}
		}
		fmt.Printf("  E01 stored hashes: %s\n", e01)
	}

	pt, err := diskimage.Partitions(im, im.Size())
	if err != nil {
		fmt.Fprintln(os.Stderr, "--image: partition table:", sanitize.Terminal(err.Error()))
		return 1
	}
	staging, err := os.MkdirTemp("", "agentdfir-image-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	defer os.RemoveAll(staging)
	if err := os.Chmod(staging, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	// The same discovery set as --import: browser history is extracted
	// from the image only with --include-browser.
	prods, err := discoveryProducts(o.includeBrowser)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	lim := diskimage.DefaultLimits()
	if o.maxFileMB > 0 {
		lim.MaxFileBytes = o.maxFileMB << 20
	}

	var reports []*volumeReport
	var prov []imageProvenance
	for _, v := range pt.Volumes {
		rep := &volumeReport{vol: v}
		reports = append(reports, rep)
		res := diskimage.OpenFS(v.Section(im), v.Size)
		rep.fsType = res.Type
		if res.FS == nil {
			rep.status, rep.reason = errStatus(res.Err), res.Reason
			continue
		}
		rep.status = "read"
		if nv, ok := res.FS.(*ntfs.Volume); ok {
			st := nv.Stats()
			rep.notes = append(rep.notes, fmt.Sprintf("%d deleted MFT records skipped, %d orphans, %d corrupt records, %d parent loops, %d self-parent", st.Deleted, st.Orphans, st.Corrupt, st.ParentLoops, st.SelfParent))
			if st.ShadowStore > 0 {
				rep.notes = append(rep.notes, fmt.Sprintf("volume shadow copy store present (%d file(s) in System Volume Information); shadow copies are NOT parsed", st.ShadowStore))
			}
			for _, p := range st.Problems {
				rep.notes = append(rep.notes, "ntfs: "+p)
			}
		}
		cands := diskimage.FindCandidates(res.FS, prods, lim)
		rep.notes = append(rep.notes, cands.Problems...)
		if len(cands.Files) == 0 {
			continue
		}
		rep.staging = filepath.Join(staging, fmt.Sprintf("vol%d", v.Index))
		ex := diskimage.ExtractFiles(res.FS, cands.Files, rep.staging, lim)
		rep.notes = append(rep.notes, ex.Problems...)
		for _, f := range ex.Files {
			pr := imageProvenance{
				ImagePath: abs, ImageSegments: before, ContainerType: im.Format,
				PartitionScheme: v.Scheme, PartitionIndex: v.Index, PartitionOffset: v.Offset, PartitionType: v.Type,
				FSType: res.Type, OriginalPath: "/" + f.FSPath, Size: f.Size, SHA256: f.SHA256,
				E01Verification: e01, Problem: f.Problem,
			}
			if f.Staged != "" {
				rel, _ := filepath.Rel(staging, f.Staged)
				pr.StagedPath = filepath.ToSlash(rel)
				rep.files++
			}
			fillTimes(&pr, f.Sys)
			// The reader names the exact variant (ext2, fat32, exfat…);
			// FAT stores local wall-clock time with no zone, which the
			// provenance must say rather than imply UTC.
			if v, ok := f.Sys["fs"].(string); ok && v != "" {
				pr.FSType = v
			}
			if v, ok := f.Sys["tz"].(string); ok {
				pr.TimeZone = v
			}
			prov = append(prov, pr)
		}
	}
	for _, p := range pt.Problems {
		fmt.Printf("  partition table: %s\n", sanitize.Terminal(p))
	}
	fmt.Printf("Volumes (%s):\n", pt.Scheme)
	staged := 0
	var withFiles []*volumeReport
	for _, r := range reports {
		line := fmt.Sprintf("  #%d  offset %-10d size %-10d %-10s %s", r.vol.Index, r.vol.Offset, r.vol.Size, r.fsType, r.status)
		if r.status == "read" {
			line += fmt.Sprintf(", %d candidate file(s) extracted", r.files)
		} else {
			line += ": " + r.reason
		}
		fmt.Println(sanitize.Terminal(line))
		for _, n := range r.notes {
			fmt.Printf("        note: %s\n", sanitize.Terminal(n))
		}
		staged += r.files
		if r.files > 0 {
			withFiles = append(withFiles, r)
		}
	}

	// Every read of the image is done: close it and hash it again.
	im.Close()
	imClosed = true
	after, herr := hashSegments(im.Segments)
	rehash := "unchanged"
	if herr != nil {
		rehash = "re-hash failed: " + herr.Error()
	} else if !sameHashes(before, after) {
		rehash = "CHANGED"
	}
	fmt.Printf("Image re-hash after extraction: %s\n", rehash)

	notes := map[string]string{
		"mode":                     "image",
		"image_path":               abs,
		"image_container":          im.Format,
		"image_size":               fmt.Sprint(im.Size()),
		"image_segments":           fmt.Sprint(len(before)),
		"image_sha256":             joinHashes(before),
		"image_rehash_after":       rehash,
		"image_partition_scheme":   pt.Scheme,
		"image_e01_stored_hashes":  e01,
		"image_files_extracted":    fmt.Sprint(staged),
		"image_provenance_sidecar": imageProvenanceName,
	}
	if len(pt.Problems) > 0 {
		notes["image_partition_problems"] = strings.Join(pt.Problems, "; ")
	}
	keys := make([]string, 0, len(im.Meta))
	for k := range im.Meta {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		notes["image_meta_"+k] = im.Meta[k]
	}
	var unread []string
	for _, r := range reports {
		v := fmt.Sprintf("%s offset=%d size=%d type=%s fs=%s status=%s", r.vol.Scheme, r.vol.Offset, r.vol.Size, r.vol.Type, r.fsType, r.status)
		if r.status == "read" {
			v += fmt.Sprintf(" extracted=%d", r.files)
		} else {
			v += " reason=" + r.reason
			unread = append(unread, fmt.Sprintf("#%d %s (%s)", r.vol.Index, r.fsType, r.status))
		}
		if len(r.notes) > 0 {
			v += " notes=" + strings.Join(r.notes, " | ")
		}
		notes[fmt.Sprintf("image_volume_%d", r.vol.Index)] = v
	}
	if len(unread) > 0 {
		notes["image_volumes_not_read"] = strings.Join(unread, "; ")
		fmt.Printf("NOT READ: %s — listed in the case notes; see docs/disk-images.md for the mount-and---import route.\n", sanitize.Terminal(strings.Join(unread, "; ")))
	}

	provFile, err := writeProvenance(prov)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: provenance:", err)
		return 1
	}
	defer os.Remove(provFile)

	if staged == 0 {
		fmt.Fprintln(os.Stderr, "no user profiles with known AI agent products found in any readable volume of", sanitize.Terminal(abs))
		return 1
	}
	o.tree = staging
	if len(withFiles) == 1 {
		// One volume: import from its root so ${SYSTEM_ROOT} entries resolve.
		o.tree = withFiles[0].staging
	}
	o.notes = notes
	o.beforeSeal = func(b *casepkg.Builder) error {
		if err := b.IngestFile(provFile, casepkg.ArtifactRecord{
			SourcePath: provFile, LogicalPath: imageProvenanceName,
			ArtifactType: "image_provenance", Sensitivity: "medium", CollectorRule: "diskimage.provenance",
		}); err != nil {
			return err
		}
		_ = b.Log("image_acquired", map[string]any{
			"image_path": abs, "container": im.Format, "segments": before, "e01_stored_hashes": e01,
			"partition_scheme": pt.Scheme, "volumes": len(reports), "files_extracted": staged,
		})
		return b.Log("image_rehash", map[string]any{"image_path": abs, "result": rehash, "segments_after": after})
	}
	code := collectImport(o)
	if rehash != "unchanged" && code == 0 {
		code = 1
	}
	return code
}

func errStatus(err error) string {
	switch {
	case errors.Is(err, diskimage.ErrEncrypted):
		return "ENCRYPTED"
	case errors.Is(err, diskimage.ErrUnsupported):
		return "UNSUPPORTED"
	case errors.Is(err, diskimage.ErrCorrupt):
		return "CORRUPT"
	}
	return "UNRECOGNIZED"
}

func fillTimes(p *imageProvenance, sys map[string]any) {
	f := func(k string) string {
		if t, ok := sys[k].(time.Time); ok && !t.IsZero() {
			return t.UTC().Format(time.RFC3339Nano)
		}
		return ""
	}
	p.MTimeUTC, p.ATimeUTC, p.CTimeUTC, p.BTimeUTC = f("mtime"), f("atime"), f("ctime"), f("btime")
	switch v := sys["inode"].(type) {
	case uint64:
		p.Inode = v
	case uint32:
		p.Inode = uint64(v)
	}
	if a, ok := sys["ads"].([]string); ok {
		p.ADS = a
	}
}

func hashSegments(paths []string) ([]segmentHash, error) {
	out := make([]segmentHash, 0, len(paths))
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			return nil, err
		}
		h := sha256.New()
		n, err := io.Copy(h, f)
		f.Close()
		if err != nil {
			return nil, err
		}
		out = append(out, segmentHash{Path: p, Size: n, SHA256: hex.EncodeToString(h.Sum(nil))})
	}
	return out, nil
}

func sameHashes(a, b []segmentHash) bool {
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

func joinHashes(s []segmentHash) string {
	parts := make([]string, len(s))
	for i, h := range s {
		parts[i] = filepath.Base(h.Path) + "=" + h.SHA256
	}
	return strings.Join(parts, " ")
}

func writeProvenance(recs []imageProvenance) (string, error) {
	f, err := os.CreateTemp("", "agentdfir-image-provenance-*.jsonl")
	if err != nil {
		return "", err
	}
	enc := json.NewEncoder(f)
	for _, r := range recs {
		if err := enc.Encode(r); err != nil {
			f.Close()
			os.Remove(f.Name())
			return "", err
		}
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}
