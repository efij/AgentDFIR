package cli

import (
	"archive/tar"
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

func untarFixture(t *testing.T, dir, name string) {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "diskimage", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return
		}
		if err != nil || !filepath.IsLocal(h.Name) {
			t.Fatalf("tar %v %q", err, h.Name)
		}
		p := filepath.Join(dir, filepath.FromSlash(h.Name))
		switch h.Typeflag {
		case tar.TypeDir:
			os.MkdirAll(p, 0o755)
		case tar.TypeReg:
			os.MkdirAll(filepath.Dir(p), 0o755)
			b, _ := io.ReadAll(tr)
			os.WriteFile(p, b, 0o600)
		}
	}
}

// TestCollectImageMacOS runs collect --image over the hdiutil-made macOS
// fixtures (UDIF zlib, raw GPT, sparsebundle, multi-volume APFS with an
// encrypted volume, HFS+): the profile reaches the import pipeline and the
// provenance names the filesystem.
func TestCollectImageMacOS(t *testing.T) {
	cases := []struct {
		name, fsType, container, note string
	}{
		{"apfs-udzo.dmg", "apfs", "dmg", ""},
		{"apfs-gpt.raw", "apfs", "raw", ""},
		{"apfs.sparsebundle", "apfs", "sparsebundle", ""},
		{"apfs-multi.dmg", "apfs", "dmg", "encrypted"},
		{"hfs-udzo.dmg", "hfsplus", "dmg", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			var img string
			if c.container == "sparsebundle" {
				untarFixture(t, dir, "apfs.sparsebundle.tar.gz")
				img = filepath.Join(dir, c.name)
			} else {
				img = imageFixture(t, dir, c.name)
			}
			pkg := filepath.Join(dir, "case.adfir")
			if code := Main([]string{"collect", "--image", img, "--out", pkg, "--no-sign"}); code != 0 {
				t.Fatalf("collect --image exit %d", code)
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
			pdata, _ := st.ReadAll(prov.ArtifactID, 1<<20)
			found := false
			sc := bufio.NewScanner(bytes.NewReader(pdata))
			for sc.Scan() {
				var p imageProvenance
				if err := json.Unmarshal(sc.Bytes(), &p); err != nil {
					t.Fatal(err)
				}
				if strings.HasSuffix(p.OriginalPath, "/session.jsonl") {
					found = true
					if p.FSType != c.fsType || p.ContainerType != c.container || p.Inode == 0 || p.MTimeUTC == "" || p.SHA256 == "" {
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
			if info.Notes["image_rehash_after"] != "unchanged" || info.Notes["image_container"] != c.container {
				t.Fatalf("notes: %v", info.Notes)
			}
			if c.note != "" {
				all, _ := json.Marshal(info.Notes)
				if !strings.Contains(string(all), c.note) {
					t.Fatalf("notes do not mention %q: %s", c.note, all)
				}
			}
		})
	}
}
