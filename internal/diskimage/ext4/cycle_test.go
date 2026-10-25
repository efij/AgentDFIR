package ext4

import (
	"bytes"
	"io/fs"
	"strings"
	"testing"
	"time"
)

// TestDirectoryCycleTerminates patches docs/sub so that it points back to
// docs itself, and in a second image to the root: a walk must end and the
// bad entry must be counted, not listed.
func TestDirectoryCycleTerminates(t *testing.T) {
	for _, target := range []string{"self", "root"} {
		b := loadImage(t, "ext4.img.gz")
		clean := openImage(t, "ext4.img.gz")
		docs, _, err := clean.lookup("stat", "docs")
		if err != nil {
			t.Fatal(err)
		}
		runs, err := clean.mapInode(docs)
		if err != nil || len(runs) == 0 {
			t.Fatalf("docs runs %v %v", runs, err)
		}
		bs := int(clean.sb.blockSize)
		blk := b[int(runs[0].physical)*bs : int(runs[0].physical+1)*bs]
		i := bytes.Index(blk, []byte{3, 2, 's', 'u', 'b'}) // name_len 3, type dir
		if i < 6 {
			t.Fatal("sub entry not found")
		}
		ino := docs.ino
		if target == "root" {
			ino = rootIno
		}
		le.PutUint32(blk[i-6:], ino)

		fsys, err := Open(bytes.NewReader(b), int64(len(b)))
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan int)
		go func() {
			n := 0
			_ = fs.WalkDir(fsys, ".", func(string, fs.DirEntry, error) error {
				n++
				return nil
			})
			done <- n
		}()
		select {
		case n := <-done:
			if n > 200 {
				t.Errorf("%s: walk visited %d entries", target, n)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: walk did not terminate", target)
		}
		if _, err := fs.Stat(fsys, "docs/sub"); err == nil {
			t.Errorf("%s: cyclic docs/sub still resolves", target)
		}
		if s := fsys.(*FS).Stats(); s["corrupt_entries"] < 1 {
			t.Errorf("%s: stats %v", target, s)
		}
	}
}

func TestWorkBudget(t *testing.T) {
	fsys := openImage(t, "ext4.img.gz")
	fsys.workMax = 3
	if _, err := fsys.ReadDir("."); err == nil || !strings.Contains(err.Error(), "work budget") {
		t.Errorf("err = %v", err)
	}
}
