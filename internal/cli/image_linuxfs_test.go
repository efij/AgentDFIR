package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v5/internal/casepkg"
)

// collectLinuxImage runs collect --image on a fixture and returns the
// case's provenance lines and notes.
func collectLinuxImage(t *testing.T, name string) ([]imageProvenance, map[string]string, []byte) {
	t.Helper()
	dir := t.TempDir()
	img := imageFixture(t, dir, name)
	before, _ := os.ReadFile(img)
	pkg := filepath.Join(dir, "case.adfir")
	if code := Main([]string{"collect", "--image", img, "--out", pkg, "--no-sign"}); code != 0 {
		t.Fatalf("collect --image exit %d", code)
	}
	if after, _ := os.ReadFile(img); !bytes.Equal(before, after) {
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
	var prov []imageProvenance
	var session []byte
	for _, a := range man.Artifacts {
		if a.Status != casepkg.StatusOK {
			continue
		}
		if strings.HasSuffix(a.LogicalPath, "session.jsonl") {
			session, _ = st.ReadAll(a.ArtifactID, 1<<20)
		}
		if a.LogicalPath == imageProvenanceName {
			data, _ := st.ReadAll(a.ArtifactID, 1<<20)
			sc := bufio.NewScanner(bytes.NewReader(data))
			for sc.Scan() {
				var p imageProvenance
				if err := json.Unmarshal(sc.Bytes(), &p); err != nil {
					t.Fatal(err)
				}
				prov = append(prov, p)
			}
		}
	}
	info, err := casepkg.ReadCaseInfo(pkg)
	if err != nil {
		t.Fatal(err)
	}
	return prov, info.Notes, session
}

func sessionProvenance(prov []imageProvenance) *imageProvenance {
	for i := range prov {
		if strings.HasSuffix(prov[i].OriginalPath, "/home/alice/.claude/projects/-home-alice-proj/session.jsonl") {
			return &prov[i]
		}
	}
	return nil
}

// TestCollectImageQCOW2Btrfs: a deflate-compressed QCOW2 holding a Btrfs
// volume (made by mkfs.btrfs + qemu-img convert -c) reaches the import
// pipeline through the new container and filesystem readers.
func TestCollectImageQCOW2Btrfs(t *testing.T) {
	prov, notes, session := collectLinuxImage(t, "linux-btrfs-c.qcow2")
	if !bytes.Contains(session, []byte(`"sessionId":"s1"`)) {
		t.Fatalf("session content missing: %q", session)
	}
	p := sessionProvenance(prov)
	if p == nil {
		t.Fatalf("no provenance for the session: %+v", prov)
	}
	if p.ContainerType != "qcow2" || p.FSType != "btrfs" || p.Inode == 0 || p.MTimeUTC != "2026-08-30T10:05:00Z" || p.SHA256 != "4128bfda061640530d235560af704ff123cda0600636a0cbeea4a77150d6e32b" {
		t.Fatalf("provenance: %+v", p)
	}
	if notes["image_container"] != "qcow2" || notes["image_meta_qcow2_version"] != "3" {
		t.Fatalf("notes: %v", notes)
	}
}

// TestCollectImageLVM: an MBR disk with two LVM2 PVs; the linear LV holds
// an ext4 with the profile, the other LVs are listed UNSUPPORTED.
func TestCollectImageLVM(t *testing.T) {
	prov, notes, session := collectLinuxImage(t, "linux-lvm.img")
	if !bytes.Contains(session, []byte(`"sessionId":"s1"`)) {
		t.Fatal("session content missing")
	}
	p := sessionProvenance(prov)
	if p == nil || p.PartitionScheme != "lvm" || p.FSType != "ext4" || p.PartitionIndex <= 1000 {
		t.Fatalf("provenance: %+v", p)
	}
	all := ""
	for k, v := range notes {
		if strings.HasPrefix(k, "image_volume_") {
			all += k + "=" + v + "\n"
		}
	}
	for _, want := range []string{"status=LVM-PV", "fs=lvm2-thin status=UNSUPPORTED", "striped over 2 devices", `snapshot of "root"`, "fs=ext4 status=read"} {
		if !strings.Contains(all, want) {
			t.Errorf("volume notes lack %q:\n%s", want, all)
		}
	}
	nr := notes["image_volumes_not_read"]
	if strings.Contains(nr, "lvm2-pv") || !strings.Contains(nr, "UNSUPPORTED") {
		t.Errorf("not-read list: %q", nr)
	}
}
