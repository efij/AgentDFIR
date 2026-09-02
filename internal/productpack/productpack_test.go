package productpack_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/internal/casepkg"
	"github.com/efij/AgentDFIR/internal/collector"
	"github.com/efij/AgentDFIR/internal/parsers/genericchat"
	"github.com/efij/AgentDFIR/internal/productpack"
	"github.com/efij/AgentDFIR/internal/products"
	"github.com/efij/AgentDFIR/internal/schema"
	"github.com/efij/AgentDFIR/internal/seal"
)

// fooPack is a fictional agent whose transcript shape matches none of the
// built-in formats — exactly the case a declarative pack must handle.
const fooPack = `{
  "pack_format": "1",
  "version": "0.1.0",
  "product": {"id":"foo-agent","name":"Foo Agent","config_dirs":[".foo"],"config_files":[],"binaries":["foo"]},
  "manifest": {"product":"foo-agent","entries":[
    {"id":"foo.config","paths":["${CONFIG_ROOT}/config.json"],"category":"product_config","sensitivity":"medium"},
    {"id":"foo.sessions","paths":["${CONFIG_ROOT}/sessions/**"],"category":"agent_session","sensitivity":"high"}
  ]},
  "parser": {"engine":"genericchat","rule_prefix":"foo.","vendor":"foocorp",
    "field_map":{"messages_key":"conversation_log","role":"who","text":"msg","timestamp":"ts",
                 "tool_name":"call.name","tool_args":"call.args",
                 "model_roles":["bot"],"human_roles":["person"]}}
}`

const fooSession = `{"conversation_log":[
  {"who":"person","msg":"clean the build dir","ts":1725000000},
  {"who":"bot","msg":"Running it now.","ts":1725000001},
  {"who":"bot","ts":1725000002,"call":{"name":"shell","args":{"cmd":"rm -rf build/"}}}
]}`

func writePacksDir(t *testing.T, packJSON string) (packsDir, packPath string) {
	t.Helper()
	packsDir = t.TempDir()
	t.Setenv("AGENTDFIR_PACKS_DIR", packsDir)
	dir := filepath.Join(packsDir, "products")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	packPath = filepath.Join(dir, "foo-agent"+productpack.Suffix)
	if err := os.WriteFile(packPath, []byte(packJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	products.ResetRegistered()
	return packsDir, packPath
}

func TestValidateRejectsUnsafePacks(t *testing.T) {
	base := func() *productpack.Pack {
		var p productpack.Pack
		if err := json.Unmarshal([]byte(fooPack), &p); err != nil {
			t.Fatal(err)
		}
		return &p
	}
	if err := productpack.Validate(base()); err != nil {
		t.Fatalf("fixture pack must validate: %v", err)
	}
	cases := map[string]func(p *productpack.Pack){
		"shadow-embedded":  func(p *productpack.Pack) { p.Product.ID = "claude-code"; p.Manifest.Product = "claude-code" },
		"bad-id":           func(p *productpack.Pack) { p.Product.ID = "Foo Agent"; p.Manifest.Product = "Foo Agent" },
		"abs-config-dir":   func(p *productpack.Pack) { p.Product.ConfigDirs = []string{"/etc"} },
		"dotdot-path":      func(p *productpack.Pack) { p.Manifest.Entries[0].Paths = []string{"${CONFIG_ROOT}/../.ssh/id_rsa"} },
		"unrooted-path":    func(p *productpack.Pack) { p.Manifest.Entries[0].Paths = []string{"/etc/passwd"} },
		"bad-category":     func(p *productpack.Pack) { p.Manifest.Entries[0].Category = "whatever" },
		"prefix-mismatch":  func(p *productpack.Pack) { p.Manifest.Entries[0].ID = "bar.config" },
		"unknown-engine":   func(p *productpack.Pack) { p.Parser.Engine = "python" },
		"unsupported-fmt":  func(p *productpack.Pack) { p.PackFormat = "9" },
		"empty-field-map":  func(p *productpack.Pack) { p.Parser.FieldMap = &genericchat.FieldMap{Timestamp: "ts"} },
		"manifest-product": func(p *productpack.Pack) { p.Manifest.Product = "other" },
	}
	for name, mutate := range cases {
		p := base()
		mutate(p)
		err := productpack.Validate(p)
		if name == "shadow-embedded" {
			// Shadowing is caught at registration, not schema validation.
			if err != nil {
				continue
			}
			if rerr := products.Register(p.Product, p.Manifest); rerr == nil {
				t.Fatalf("%s: shadowing an embedded product must be refused", name)
			}
			continue
		}
		if err == nil {
			t.Fatalf("%s: expected validation error", name)
		}
	}
}

func TestUnsignedPackRejectedUnlessDevMode(t *testing.T) {
	writePacksDir(t, fooPack)
	t.Setenv("AGENTDFIR_ALLOW_UNSIGNED_PACKS", "")
	insts := productpack.Scan(seal.VerifyFileSig)
	if len(insts) != 1 || insts[0].Err == nil || !strings.Contains(insts[0].Err.Error(), "unsigned") {
		t.Fatalf("unsigned pack must be rejected by default: %+v", insts)
	}
	acc, rej := productpack.Activate(seal.VerifyFileSig)
	if len(acc) != 0 || len(rej) != 1 {
		t.Fatalf("activate: accepted=%d rejected=%d", len(acc), len(rej))
	}
	if _, err := products.ByID("foo-agent"); err == nil {
		t.Fatal("rejected pack must not register its product")
	}
}

func TestSignedPackAccepted(t *testing.T) {
	packsDir, packPath := writePacksDir(t, fooPack)
	t.Setenv("AGENTDFIR_ALLOW_UNSIGNED_PACKS", "")
	keyDir := t.TempDir()
	priv, pub := filepath.Join(keyDir, "k.key"), filepath.Join(keyDir, "k.pub")
	if err := seal.GenerateKey(priv, pub); err != nil {
		t.Fatal(err)
	}
	if err := seal.SignFile(packPath, priv, packPath+".sig"); err != nil {
		t.Fatal(err)
	}
	pubData, _ := os.ReadFile(pub)
	if err := os.WriteFile(filepath.Join(packsDir, "trusted.pub"), pubData, 0o600); err != nil {
		t.Fatal(err)
	}
	acc, rej := productpack.Activate(seal.VerifyFileSig)
	if len(rej) != 0 || len(acc) != 1 || !acc[0].Signed {
		t.Fatalf("signed pack must be accepted: acc=%+v rej=%+v", acc, rej)
	}
	// Tamper after signing → rejected.
	if err := os.WriteFile(packPath, []byte(strings.Replace(fooPack, "Foo Agent", "Evil Agent", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	products.ResetRegistered()
	acc, rej = productpack.Activate(seal.VerifyFileSig)
	if len(acc) != 0 || len(rej) != 1 || !strings.Contains(rej[0].Err.Error(), "signature") {
		t.Fatalf("tampered pack must fail signature: acc=%d rej=%+v", len(acc), rej)
	}
}

func TestPackEndToEnd_CollectAndNormalize(t *testing.T) {
	writePacksDir(t, fooPack)
	t.Setenv("AGENTDFIR_ALLOW_UNSIGNED_PACKS", "1")
	acc, rej := productpack.Activate(seal.VerifyFileSig)
	if len(acc) != 1 || len(rej) != 0 {
		t.Fatalf("activate: %+v / %+v", acc, rej)
	}

	// Pack product is visible like a built-in.
	prod, err := products.ByID("foo-agent")
	if err != nil || prod.Name != "Foo Agent" {
		t.Fatalf("pack product not registered: %v", err)
	}
	all, _ := products.All()
	found := false
	for _, p := range all {
		if p.ID == "foo-agent" {
			found = true
		}
	}
	if !found {
		t.Fatal("pack product missing from products.All()")
	}

	// Profile with the fictional product's evidence.
	root := t.TempDir()
	for rel, content := range map[string]string{
		".foo/config.json":       `{"model":"foo-large"}`,
		".foo/sessions/s42.json": fooSession,
	} {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	dets, err := products.DetectAll(root)
	if err != nil {
		t.Fatal(err)
	}
	detected := false
	for _, d := range dets {
		if d.Product.ID == "foo-agent" && d.Detected {
			detected = true
		}
	}
	if !detected {
		t.Fatal("pack product not detected from its config dir")
	}

	man, err := products.Manifest("foo-agent")
	if err != nil || man == nil || len(man.Entries) != 2 {
		t.Fatalf("pack manifest: %v %+v", err, man)
	}
	pkg := filepath.Join(t.TempDir(), "foo.adfir")
	b, err := casepkg.New(pkg, "PK-1", casepkg.CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	st, err := collector.Run(b, man, collector.Options{
		ProfileRoot: root, ConfigRoot: filepath.Join(root, ".foo"), SystemRoot: root, Product: "foo-agent",
	})
	if err != nil {
		t.Fatal(err)
	}
	if st.Acquired != 2 {
		t.Fatalf("expected 2 artifacts, got %d", st.Acquired)
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	res, err := genericchat.ParsePackage(pkg)
	if err != nil {
		t.Fatal(err)
	}
	var human, model, tool int
	for _, ev := range res.Events {
		if ev.Product != "foo-agent" || ev.Vendor != "foocorp" {
			t.Fatalf("identity: %s/%s", ev.Product, ev.Vendor)
		}
		if ev.SessionID != "s42" {
			t.Fatalf("session id from file stem expected, got %q", ev.SessionID)
		}
		switch ev.EventType {
		case schema.EventHumanPrompt:
			human++
			if ev.Corroboration != schema.StateObserved || ev.Summary != "clean the build dir" {
				t.Fatalf("human prompt wrong: %+v", ev)
			}
			if !strings.HasPrefix(ev.Timestamp, "2024-08-30") {
				t.Fatalf("epoch-seconds timestamp not converted: %q", ev.Timestamp)
			}
		case schema.EventModelResponse:
			model++
			if ev.Corroboration != schema.StateReported {
				t.Fatal("model narrative must be REPORTED")
			}
		case schema.EventToolCall:
			tool++
			if ev.Tool != "shell" || ev.Command != "rm -rf build/" || ev.Action != "shell_execution" {
				t.Fatalf("tool call not mapped: %+v", ev)
			}
		}
	}
	if human != 1 || model != 1 || tool != 1 {
		t.Fatalf("event mix human=%d model=%d tool=%d (events=%d)", human, model, tool, len(res.Events))
	}
}

func TestTemplateValidatesAndRoundTrips(t *testing.T) {
	tpl := productpack.Template("bar-agent", "Bar", ".bar")
	if err := productpack.Validate(tpl); err != nil {
		t.Fatalf("template must validate: %v", err)
	}
	data, _ := json.Marshal(tpl)
	path := filepath.Join(t.TempDir(), "bar-agent"+productpack.Suffix)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	p, sum, err := productpack.Load(path)
	if err != nil || p.Product.ID != "bar-agent" || len(sum) != 64 {
		t.Fatalf("load: %v %+v %q", err, p, sum)
	}
	// Unknown top-level keys are refused (typos must not pass silently).
	bad := strings.Replace(string(data), `"pack_format"`, `"pack_fromat"`, 1)
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := productpack.Load(path); err == nil {
		t.Fatal("unknown field must be rejected")
	}
}
