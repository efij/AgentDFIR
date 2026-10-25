package ntfs

import (
	"bytes"
	"io"
	"slices"
	"strings"
	"testing"
	"time"
)

func deletedByName(t *testing.T, v *Volume) map[string]DeletedFile {
	t.Helper()
	ds, err := v.DeletedFiles()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]DeletedFile{}
	for _, d := range ds {
		out[d.Name] = d
	}
	return out
}

func readAll(t *testing.T, r io.ReaderAt, n int64) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := r.ReadAt(b, 0); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	return b
}

func TestDeletedFilesFixture(t *testing.T) {
	v := openUSNFixture(t)
	ds := deletedByName(t, v)
	if len(ds) != 3 {
		t.Fatalf("deleted = %v", ds)
	}

	res := ds["deleted-resident.txt"]
	if !res.Resident || res.ContentState != ContentResident || !res.Recoverable || res.Size != 16 ||
		res.ParentPath != "/Users/alice/proj" || res.PathStatus != "resolved" {
		t.Fatalf("resident %+v", res)
	}
	if res.SI == nil || res.FN == nil || !res.SI.Modified.Equal(time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)) || res.FN.Created.IsZero() {
		t.Fatalf("times %+v %+v", res.SI, res.FN)
	}
	r, n, err := v.OpenDeleted(res.Record)
	if err != nil || string(readAll(t, r, n)) != "resident secret\n" {
		t.Fatalf("resident recovery: %v", err)
	}

	big := ds["deleted-big.txt"]
	if big.Resident || big.ContentState != ContentUnallocated || !big.Recoverable || big.Size != 12288 {
		t.Fatalf("free-cluster file %+v", big)
	}
	r, n, err = v.OpenDeleted(big.Record)
	if err != nil {
		t.Fatal(err)
	}
	data := readAll(t, r, n)
	if len(data) != 12288 || !strings.HasPrefix(string(data), "deleted line kept on free clusters\n") {
		t.Fatalf("recovered %q…", data[:min(len(data), 40)])
	}

	// deleted-overwritten.bin's clusters went to fill.bin after the delete.
	ow := ds["deleted-overwritten.bin"]
	if ow.Recoverable || ow.ContentState != ContentOverwritten || !strings.Contains(ow.ContentReason, "allocated again") {
		t.Fatalf("overwritten %+v", ow)
	}
	if _, _, err := v.OpenDeleted(ow.Record); err == nil {
		t.Fatal("content on reallocated clusters returned")
	}
	if _, _, err := v.OpenDeleted(67); err == nil {
		t.Fatal("in-use record opened as deleted")
	}
	// Deleted records never appear in the tree.
	if _, err := v.Stat("Users/alice/proj/deleted-big.txt"); err == nil {
		t.Fatal("deleted file visible in the tree")
	}
}

func TestDeletedFilesLegacyFixture(t *testing.T) {
	v := openFixture(t)
	d, ok := deletedByName(t, v)["deleted.txt"]
	if !ok || d.ParentPath != "/Users/alice" || d.ContentState != ContentResident {
		t.Fatalf("deleted.txt %+v", d)
	}
	r, n, err := v.OpenDeleted(d.Record)
	if err != nil || string(readAll(t, r, n)) != "gone\n" {
		t.Fatalf("recovery: %v", err)
	}
}

func TestDeletedBitmapBounds(t *testing.T) {
	v := openUSNFixture(t)
	if _, err := v.anyClusterAllocated(v.v.clusters-1, 2); err == nil {
		t.Fatal("run past the volume accepted")
	}
	if _, err := v.anyClusterAllocated(-1, 1); err == nil {
		t.Fatal("negative run accepted")
	}
	// Cluster 0 holds the boot sector: always allocated.
	if used, err := v.anyClusterAllocated(0, 1); err != nil || !used {
		t.Fatalf("boot cluster: %v %v", used, err)
	}
	// Without a readable $Bitmap nothing non-resident is offered.
	v.bitmap, v.bitmapErr = nil, nil
	delete(v.nodes, bitmapRecord)
	ds := deletedByName(t, v)
	if d := ds["deleted-big.txt"]; d.Recoverable || d.ContentState != ContentUnsupported || !strings.Contains(d.ContentReason, "$Bitmap") {
		t.Fatalf("no bitmap: %+v", d)
	}
	if d := ds["deleted-resident.txt"]; !d.Recoverable {
		t.Fatalf("resident content needs no bitmap: %+v", d)
	}
}

func TestDeletedDamagedRecord(t *testing.T) {
	b := usnFixtureBytes(t)
	v, err := OpenVolume(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	d := deletedByName(t, v)["deleted-big.txt"]
	// Locate the record on disk and tear its fixup: it must then be
	// skipped by the walk (no valid FILE record), not misreported.
	off := int64(d.Record) * v.v.recordSize
	r, _ := v.v.mft.lookup(off / v.v.clusterSize)
	phys := (r.lcn+off/v.v.clusterSize-r.vcn)*v.v.clusterSize + off%v.v.clusterSize
	c := slices.Clone(b)
	c[phys+510] ^= 0xFF
	v2, err := OpenVolume(bytes.NewReader(c), int64(len(c)))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := deletedByName(t, v2)["deleted-big.txt"]; ok {
		t.Fatal("torn record listed")
	}
	if v2.Stats().Corrupt == 0 {
		t.Fatal("torn record not counted as corrupt")
	}
}
