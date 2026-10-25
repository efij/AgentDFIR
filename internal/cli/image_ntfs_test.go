package cli

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v4/internal/casepkg"
	"github.com/efij/AgentDFIR/v4/internal/diskimage"
	"github.com/efij/AgentDFIR/v4/internal/diskimage/ntfs"
)

func TestCollectImageNTFSArtifacts(t *testing.T) {
	for _, recover := range []bool{false, true} {
		dir := t.TempDir()
		img := imageFixture(t, dir, "disk-gpt.raw")
		pkg := filepath.Join(dir, "case.adfir")
		args := []string{"collect", "--image", img, "--out", pkg, "--no-sign"}
		if recover {
			args = append(args, "--recover-deleted", "--include-vss")
		}
		if code := Main(args); code != 0 {
			t.Fatalf("exit %d", code)
		}
		if code := Main([]string{"verify", pkg}); code != 0 {
			t.Fatalf("verify exit %d", code)
		}
		man, err := casepkg.ReadManifest(pkg)
		if err != nil {
			t.Fatal(err)
		}
		st := casepkg.NewStore(pkg, man)
		var del, rec *casepkg.ArtifactRecord
		for i, a := range man.Artifacts {
			switch {
			case a.LogicalPath == "image/vol1/ntfs/deleted.jsonl":
				del = &man.Artifacts[i]
			case strings.HasPrefix(a.LogicalPath, "image/vol1/ntfs/recovered/"):
				rec = &man.Artifacts[i]
			case strings.HasSuffix(a.LogicalPath, "usn.jsonl"):
				t.Fatal("usn artifact for a volume without a journal")
			}
		}
		if del == nil || del.ArtifactType != "ntfs_deleted_records" {
			t.Fatal("deleted.jsonl not sealed")
		}
		data, _ := st.ReadAll(del.ArtifactID, 1<<20)
		var d ntfs.DeletedFile
		for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
			var x ntfs.DeletedFile
			if err := json.Unmarshal(line, &x); err != nil {
				t.Fatal(err)
			}
			if x.Name == "deleted.txt" {
				d = x
			}
		}
		if d.ParentPath != "/Users/alice" || !d.Recoverable {
			t.Fatalf("deleted.txt entry %+v", d)
		}
		if !recover {
			if rec != nil || d.RecoveredState != "" {
				t.Fatal("content recovered without --recover-deleted")
			}
			continue
		}
		if rec == nil || d.RecoveredState != ntfs.RecoveredUnverified || d.RecoveredPath != rec.LogicalPath {
			t.Fatalf("recovery: %+v %+v", rec, d)
		}
		if c, _ := st.ReadAll(rec.ArtifactID, 1<<20); string(c) != "gone\n" {
			t.Fatalf("recovered content %q", c)
		}
		info, _ := casepkg.ReadCaseInfo(pkg)
		if !strings.Contains(info.Notes["image_volume_1"], "usn journal: absent") || info.Notes["image_recover_deleted"] == "" ||
			!strings.Contains(info.Notes["image_volume_1"], "vss: no shadow copy header") {
			t.Fatalf("notes %v", info.Notes)
		}
	}
}

func TestNTFSArtifactsUSN(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "diskimage", "ntfs", "testdata", "usn-deleted.ntfs.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, _ := gzip.NewReader(f)
	b, _ := io.ReadAll(zr)
	nv, err := ntfs.OpenVolume(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	arts, notes := ntfsVolumeArtifacts(nv, 2, dir, imageExtras{recoverDeleted: true}, 1<<20)
	got := map[string]sealedExtra{}
	for _, a := range arts {
		got[a.logical] = a
	}
	usn, ok := got["image/vol2/ntfs/usn.jsonl"]
	if !ok {
		t.Fatalf("artifacts %v notes %v", arts, notes)
	}
	data, _ := os.ReadFile(usn.path)
	if n := bytes.Count(data, []byte("\n")); n != 9 || !bytes.Contains(data, []byte(`"path":"/Users/alice/proj/keep.txt"`)) {
		t.Fatalf("usn.jsonl: %d lines", n)
	}
	// Two recoverable deleted files; the reallocated one is listed only.
	rec := 0
	for l := range got {
		if strings.HasPrefix(l, "image/vol2/ntfs/recovered/") {
			rec++
			if strings.Contains(l, "overwritten") {
				t.Fatal("reallocated content recovered")
			}
		}
	}
	if rec != 2 || !strings.Contains(strings.Join(notes, " "), "3 listed (2 with recoverable content)") {
		t.Fatalf("recovered %d, notes %v", rec, notes)
	}
}

func TestVSSSnapshotStaging(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "diskimage", "ntfs", "vss", "testdata", "vss-synthetic.ntfs.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, _ := gzip.NewReader(f)
	b, _ := io.ReadAll(zr)
	vol := diskimage.Volume{Index: 1, Size: int64(len(b))}
	staging := t.TempDir()
	cands := func(*ntfs.Volume) []string { return []string{"Users/alice/report.txt"} }
	prov, notes, n := vssSnapshotFiles(vol, bytes.NewReader(b), staging, cands, diskimage.DefaultLimits(), imageProvenance{})
	if n != 2 || len(prov) != 2 {
		t.Fatalf("files %d prov %d notes %v", n, len(prov), notes)
	}
	for i, want := range []string{"1-20260801T090000Z", "2-20260815T090000Z"} {
		p := filepath.Join(staging, "vss", want, "Users", "alice", "report.txt")
		c, err := os.ReadFile(p)
		if err != nil || !bytes.HasPrefix(c, []byte("VERSION-")) || c[8] != byte('1'+i) {
			t.Fatalf("%s: %v %q", p, err, c[:min(len(c), 20)])
		}
		if !strings.Contains(prov[i].Snapshot, want) || prov[i].StagedPath != p {
			t.Fatalf("provenance %+v", prov[i])
		}
	}
	// A volume without a store says so.
	_, notes, n = vssSnapshotFiles(vol, bytes.NewReader(make([]byte, 1<<16)), staging, cands, diskimage.DefaultLimits(), imageProvenance{})
	if n != 0 || !strings.Contains(notes[0], "no shadow copy header") {
		t.Fatalf("%v", notes)
	}
}
