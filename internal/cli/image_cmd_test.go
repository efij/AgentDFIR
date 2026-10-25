package cli

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v4/internal/casepkg"
)

func imageFixture(t *testing.T, dir, name string) string {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "diskimage", "testdata", name+".gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, name)
	b, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestCollectImageEndToEnd(t *testing.T) {
	cases := []struct {
		files []string
		e01   string
		user  string
	}{
		{[]string{"disk.E01"}, "md5=match sha1=match", "alice"},
		{[]string{"disk-split.E01", "disk-split.E02", "disk-split.E03", "disk-split.E04", "disk-split.E05", "disk-split.E06", "disk-split.E07", "disk-split.E08", "disk-split.E09"}, "md5=match sha1=match", "alice"},
		{[]string{"disk.vhdx"}, "not applicable (vhdx)", "alice"},
		{[]string{"disk-mbr.raw"}, "not applicable (raw)", "bob"},
	}
	for _, c := range cases {
		t.Run(c.files[0], func(t *testing.T) {
			dir := t.TempDir()
			var img string
			for i, f := range c.files {
				p := imageFixture(t, dir, f)
				if i == 0 {
					img = p
				}
			}
			before, _ := os.ReadFile(img)
			pkg := filepath.Join(dir, "case.adfir")
			if code := Main([]string{"collect", "--image", img, "--out", pkg, "--no-sign"}); code != 0 {
				t.Fatalf("collect --image exit %d", code)
			}
			after, _ := os.ReadFile(img)
			if !bytes.Equal(before, after) {
				t.Fatal("image modified")
			}
			if code := Main([]string{"verify", pkg}); code != 0 {
				t.Fatalf("verify exit %d", code)
			}
			man, err := casepkg.ReadManifest(pkg)
			if err != nil {
				t.Fatal(err)
			}
			st := casepkg.NewStore(pkg, man)
			var sess, prov *casepkg.ArtifactRecord
			for i, a := range man.Artifacts {
				if a.Status != casepkg.StatusOK {
					continue
				}
				if strings.HasSuffix(a.LogicalPath, "session.jsonl") {
					sess = &man.Artifacts[i]
				}
				if a.LogicalPath == imageProvenanceName {
					prov = &man.Artifacts[i]
				}
			}
			if sess == nil || prov == nil {
				t.Fatalf("session=%v provenance=%v", sess != nil, prov != nil)
			}
			data, _ := st.ReadAll(sess.ArtifactID, 1<<20)
			if !bytes.Contains(data, []byte(`"sessionId":"s1"`)) {
				t.Fatal("session content missing")
			}
			if sess.ModTimeUTC[:16] != "2026-08-30T10:05" {
				t.Fatalf("original mtime not carried: %s", sess.ModTimeUTC)
			}
			pdata, _ := st.ReadAll(prov.ArtifactID, 1<<20)
			found := false
			sc := bufio.NewScanner(bytes.NewReader(pdata))
			for sc.Scan() {
				var p imageProvenance
				if err := json.Unmarshal(sc.Bytes(), &p); err != nil {
					t.Fatal(err)
				}
				if strings.HasSuffix(p.OriginalPath, "/.claude/projects/-Users-"+c.user+"-proj/session.jsonl") {
					found = true
					if p.FSType != "ntfs" || p.Inode == 0 || p.MTimeUTC != "2026-08-30T10:05:00Z" || p.BTimeUTC == "" || p.CTimeUTC == "" || p.ATimeUTC == "" {
						t.Fatalf("provenance: %+v", p)
					}
					if p.E01Verification != c.e01 || len(p.ImageSegments) != len(c.files) || p.SHA256 == "" {
						t.Fatalf("provenance: %+v", p)
					}
				}
			}
			if !found {
				t.Fatalf("no provenance line for the session: %s", pdata)
			}
			info, err := casepkg.ReadCaseInfo(pkg)
			if err != nil {
				t.Fatal(err)
			}
			if info.Notes["mode"] != "image" || info.Notes["image_rehash_after"] != "unchanged" || info.Notes["image_e01_stored_hashes"] != c.e01 {
				t.Fatalf("notes: %v", info.Notes)
			}
			if c.files[0] == "disk-mbr.raw" && !strings.Contains(info.Notes["image_volumes_not_read"], "UNRECOGNIZED") {
				t.Fatalf("empty primary partition not listed: %v", info.Notes)
			}
		})
	}
}

func TestCollectImageErrors(t *testing.T) {
	dir := t.TempDir()
	if code := Main([]string{"collect", "--image", filepath.Join(dir, "missing.E01"), "--out", filepath.Join(dir, "x")}); code != 2 {
		t.Fatalf("missing image: exit %d, want 2", code)
	}
	// Truncated E01: typed error, exit 1, no package.
	p := imageFixture(t, dir, "disk.E01")
	b, _ := os.ReadFile(p)
	os.WriteFile(p, b[:len(b)/2], 0o600)
	out := filepath.Join(dir, "y")
	if code := Main([]string{"collect", "--image", p, "--out", out}); code != 1 {
		t.Fatalf("truncated image: exit %d, want 1", code)
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("package created for an unreadable image")
	}
	// Image without agent evidence (zeros): exit 1 like --import.
	z := filepath.Join(dir, "zeros.raw")
	os.WriteFile(z, make([]byte, 1<<20), 0o600)
	if code := Main([]string{"collect", "--image", z, "--out", filepath.Join(dir, "z")}); code != 1 {
		t.Fatalf("empty image: exit %d, want 1", code)
	}
}

// TestCollectImageExtAndFAT runs collect --image over bare ext and FAT
// filesystem images (no partition table): the registered ext4 and fat
// readers must find the profile and the provenance must name the fs.
func TestCollectImageExtAndFAT(t *testing.T) {
	cases := []struct{ pkgDir, name, fsType string }{
		{"ext4", "ext4.img", "ext4"},
		{"ext4", "ext2.img", "ext2"},
		{"fat", "fat32.img", "fat32"},
		{"fat", "exfat.img", "exfat"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			src, err := os.Open(filepath.Join("..", "diskimage", c.pkgDir, "testdata", c.name+".gz"))
			if err != nil {
				t.Fatal(err)
			}
			defer src.Close()
			zr, err := gzip.NewReader(src)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := io.ReadAll(zr)
			if err != nil {
				t.Fatal(err)
			}
			img := filepath.Join(dir, c.name)
			if err := os.WriteFile(img, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			pkg := filepath.Join(dir, "case.adfir")
			if code := Main([]string{"collect", "--image", img, "--out", pkg, "--no-sign"}); code != 0 {
				t.Fatalf("collect --image exit %d", code)
			}
			if after, _ := os.ReadFile(img); !bytes.Equal(raw, after) {
				t.Fatal("image modified")
			}
			if code := Main([]string{"verify", pkg}); code != 0 {
				t.Fatalf("verify exit %d", code)
			}
			man, err := casepkg.ReadManifest(pkg)
			if err != nil {
				t.Fatal(err)
			}
			st := casepkg.NewStore(pkg, man)
			var sess, prov *casepkg.ArtifactRecord
			for i, a := range man.Artifacts {
				if a.Status != casepkg.StatusOK {
					continue
				}
				if strings.HasSuffix(a.LogicalPath, "session.jsonl") {
					sess = &man.Artifacts[i]
				}
				if a.LogicalPath == imageProvenanceName {
					prov = &man.Artifacts[i]
				}
			}
			if sess == nil || prov == nil {
				t.Fatalf("session=%v provenance=%v", sess != nil, prov != nil)
			}
			pdata, _ := st.ReadAll(prov.ArtifactID, 1<<20)
			if !bytes.Contains(pdata, []byte(`"`+c.fsType+`"`)) {
				t.Fatalf("provenance does not name %s: %s", c.fsType, pdata)
			}
		})
	}
}
