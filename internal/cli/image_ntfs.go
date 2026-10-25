package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/efij/AgentDFIR/v4/internal/casepkg"
	"github.com/efij/AgentDFIR/v4/internal/diskimage"
	"github.com/efij/AgentDFIR/v4/internal/diskimage/ntfs"
	"github.com/efij/AgentDFIR/v4/internal/diskimage/ntfs/vss"
)

// imageExtras are the opt-in NTFS extras of collect --image.
type imageExtras struct {
	recoverDeleted bool // --recover-deleted: write recoverable deleted content
	includeVSS     bool // --include-vss: extract agent evidence from each shadow copy
}

// sealedExtra is a file written outside the import tree that is sealed
// into the case as is, under its own logical path.
type sealedExtra struct {
	path, logical, artType, rule, sensitivity string
}

func (x sealedExtra) ingest(b *casepkg.Builder) error {
	return b.IngestFile(x.path, casepkg.ArtifactRecord{
		SourcePath: x.path, LogicalPath: x.logical,
		ArtifactType: x.artType, Sensitivity: x.sensitivity, CollectorRule: x.rule,
	})
}

// ntfsVolumeArtifacts writes the USN journal and the deleted-record list
// of one NTFS volume (plus recovered content with --recover-deleted) into
// dir and returns them for sealing, with notes for the volume report.
// Logical paths: image/vol<N>/ntfs/{usn.jsonl, deleted.jsonl, recovered/…}.
func ntfsVolumeArtifacts(nv *ntfs.Volume, volIdx int, dir string, ex imageExtras, maxFile int64) ([]sealedExtra, []string) {
	var out []sealedExtra
	var notes []string
	prefix := fmt.Sprintf("image/vol%d/ntfs/", volIdx)
	vdir := filepath.Join(dir, fmt.Sprintf("vol%d", volIdx))
	if err := os.MkdirAll(vdir, 0o700); err != nil {
		return nil, []string{"ntfs artifacts: " + err.Error()}
	}

	// USN change journal.
	usnPath := filepath.Join(vdir, "usn.jsonl")
	f, err := os.OpenFile(usnPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		notes = append(notes, "usn journal: "+err.Error())
	} else {
		enc := json.NewEncoder(f)
		st, werr := nv.WalkUSN(func(r ntfs.USNRecord) error { return enc.Encode(r) })
		cerr := f.Close()
		switch {
		case werr != nil || cerr != nil:
			notes = append(notes, fmt.Sprintf("usn journal: not written: %v %v", werr, cerr))
			os.Remove(usnPath)
		case st.Status == "absent":
			notes = append(notes, "usn journal: absent ($Extend\\$UsnJrnl:$J not on this volume)")
			os.Remove(usnPath)
		case st.Status != "read":
			notes = append(notes, fmt.Sprintf("usn journal: %s: %s", st.Status, st.Reason))
			os.Remove(usnPath)
		default:
			notes = append(notes, fmt.Sprintf("usn journal: %d records (v2 %d, v3 %d, v4 %d UNSUPPORTED), %d sparse bytes skipped, %d garbage bytes skipped in %d resyncs; sealed as %susn.jsonl",
				st.Records, st.V2, st.V3, st.V4Unsupported, st.SparseSkipped, st.GarbageSkipped, st.Resyncs, prefix))
			for _, p := range st.Problems {
				notes = append(notes, "usn journal: "+p)
			}
			out = append(out, sealedExtra{usnPath, prefix + "usn.jsonl", "ntfs_usn_journal", "diskimage.ntfs.usn", "medium"})
		}
	}

	// Deleted MFT records.
	dels, err := nv.DeletedFiles()
	if err != nil {
		return out, append(notes, "deleted records: "+err.Error())
	}
	recoverable, recovered := 0, 0
	for i := range dels {
		d := &dels[i]
		if !d.Recoverable {
			continue
		}
		recoverable++
		if !ex.recoverDeleted {
			continue
		}
		name := fmt.Sprintf("%s_%s", d.Ref, recoveredName(d.Name))
		rp := filepath.Join(vdir, "recovered", name)
		n, sum, err := writeRecovered(nv, d.Record, rp, maxFile)
		if err != nil {
			d.Problem = strings.TrimPrefix(d.Problem+"; recovery: "+err.Error(), "; ")
			continue
		}
		d.RecoveredState, d.RecoveredPath, d.RecoveredSHA256, d.RecoveredBytes = ntfs.RecoveredUnverified, prefix+"recovered/"+name, sum, n
		out = append(out, sealedExtra{rp, prefix + "recovered/" + name, "ntfs_recovered_file", "diskimage.ntfs.recovered", "high"})
		recovered++
	}
	if len(dels) == 0 {
		return out, append(notes, "deleted records: none with a name")
	}
	delPath := filepath.Join(vdir, "deleted.jsonl")
	if err := writeJSONL(delPath, dels); err != nil {
		return out, append(notes, "deleted records: "+err.Error())
	}
	out = append(out, sealedExtra{delPath, prefix + "deleted.jsonl", "ntfs_deleted_records", "diskimage.ntfs.deleted", "medium"})
	note := fmt.Sprintf("deleted records: %d listed (%d with recoverable content) in %sdeleted.jsonl", len(dels), recoverable, prefix)
	if ex.recoverDeleted {
		note += fmt.Sprintf("; %d recovered as %s under %srecovered/", recovered, ntfs.RecoveredUnverified, prefix)
	} else if recoverable > 0 {
		note += "; content not written (opt in with --recover-deleted)"
	}
	return out, append(notes, note)
}

// recoveredName keeps a deleted file's name readable but inert on every
// host: only [A-Za-z0-9._-], at most 100 bytes, never empty or dot-led.
func recoveredName(s string) string {
	b := []byte(s)
	out := make([]byte, 0, min(len(b), 100))
	for _, c := range b {
		if len(out) >= 100 {
			break
		}
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			out = append(out, c)
		case c == '.' && len(out) > 0:
			out = append(out, c)
		default:
			out = append(out, '_')
		}
	}
	name := strings.TrimRight(string(out), ".") // Windows drops trailing dots
	if name == "" {
		return "unnamed"
	}
	return name
}

func writeRecovered(nv *ntfs.Volume, rec uint64, dst string, limit int64) (int64, string, error) {
	r, size, err := nv.OpenDeleted(rec)
	if err != nil {
		return 0, "", err
	}
	if size > limit {
		return 0, "", fmt.Errorf("size %d exceeds the per-file limit %d; not written", size, limit)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return 0, "", err
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.NewSectionReader(r, 0, size))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(dst)
		return 0, "", err
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

func writeJSONL[T any](p string, recs []T) error {
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	for _, r := range recs {
		if err := enc.Encode(r); err != nil {
			f.Close()
			os.Remove(p)
			return err
		}
	}
	return f.Close()
}

// vssSnapshotFiles opens every shadow copy of an NTFS volume, extracts
// the same agent evidence as the live volume into
// <volStaging>/vss/<n>-<creation time>/ and returns provenance lines and
// notes. Snapshots the store reader does not understand are reported
// UNSUPPORTED; nothing is extracted from them.
func vssSnapshotFiles(vol diskimage.Volume, r io.ReaderAt, volStaging string, cands func(fsys *ntfs.Volume) []string, lim diskimage.Limits, base imageProvenance) ([]imageProvenance, []string, int) {
	st, err := vss.Open(r, vol.Size)
	if err == vss.ErrNoStore {
		return nil, []string{"vss: no shadow copy header on this volume"}, 0
	}
	if err != nil {
		return nil, []string{"vss: UNSUPPORTED: " + err.Error()}, 0
	}
	notes := []string{fmt.Sprintf("vss: %d shadow cop(ies) in the catalog", len(st.Snapshots))}
	for _, p := range st.Problems {
		notes = append(notes, "vss: "+p)
	}
	var prov []imageProvenance
	files := 0
	for _, sn := range st.Snapshots {
		label := fmt.Sprintf("%d-%s", sn.Index, sn.Created.UTC().Format("20060102T150405Z"))
		desc := fmt.Sprintf("vss snapshot %s (store %s, shadow copy %s)", label, sn.StoreID, sn.ShadowCopyID)
		if sn.Status != vss.StatusOK {
			notes = append(notes, fmt.Sprintf("%s: UNSUPPORTED: %s", desc, sn.Reason))
			continue
		}
		sr, n, err := st.Volume(sn.Index)
		if err != nil {
			notes = append(notes, fmt.Sprintf("%s: UNSUPPORTED: %v", desc, err))
			continue
		}
		sv, err := ntfs.OpenVolume(sr, n)
		if err != nil {
			notes = append(notes, fmt.Sprintf("%s: NTFS not readable in the snapshot: %v", desc, err))
			continue
		}
		list := cands(sv)
		if len(list) == 0 {
			notes = append(notes, desc+": no agent evidence")
			continue
		}
		dest := filepath.Join(volStaging, "vss", label)
		ex := diskimage.ExtractFiles(sv, list, dest, lim)
		notes = append(notes, ex.Problems...)
		got := 0
		for _, f := range ex.Files {
			pr := base
			pr.OriginalPath, pr.Size, pr.SHA256, pr.Problem = "/"+f.FSPath, f.Size, f.SHA256, f.Problem
			pr.FSType, pr.Snapshot = "ntfs", desc
			if f.Staged != "" {
				pr.StagedPath = f.Staged // made relative by the caller
				got++
			}
			fillTimes(&pr, f.Sys)
			prov = append(prov, pr)
		}
		files += got
		notes = append(notes, fmt.Sprintf("%s: %d file(s) extracted to vss/%s/", desc, got, label))
	}
	return prov, notes, files
}
