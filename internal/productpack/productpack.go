// Package productpack implements declarative product packs: one signed
// JSON file that teaches AgentDFIR a new AI agent product — how to detect
// it, what to collect, and how to normalize its transcripts — with no Go
// change. This is the KAPE-Targets model applied to the agentic layer.
//
// Trust model (plan D5): a pack is loaded only when its detached ed25519
// signature verifies against the trusted key in the packs directory.
// AGENTDFIR_ALLOW_UNSIGNED_PACKS=1 permits unsigned packs for pack
// development; the case records the pack's id, hash and signed state so
// provenance is never ambiguous.
package productpack

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/efij/AgentDFIR/internal/parsers/genericchat"
	"github.com/efij/AgentDFIR/internal/products"
)

// Format is the pack schema version this build understands.
const Format = "1"

// Suffix is the required file suffix for installed packs.
const Suffix = ".product.json"

// Pack is the on-disk pack document.
type Pack struct {
	PackFormat string                     `json:"pack_format"`
	Product    products.Product           `json:"product"`
	Manifest   products.CollectorManifest `json:"manifest"`
	Parser     ParserBinding              `json:"parser"`
	Author     string                     `json:"author,omitempty"`
	Homepage   string                     `json:"homepage,omitempty"`
	Version    string                     `json:"version,omitempty"`
}

// ParserBinding tells the normalizer which engine parses this product's
// session artifacts and how.
type ParserBinding struct {
	Engine     string                `json:"engine"`      // "genericchat" (only engine in format 1)
	RulePrefix string                `json:"rule_prefix"` // collector rule IDs must start with this
	Vendor     string                `json:"vendor"`
	FieldMap   *genericchat.FieldMap `json:"field_map,omitempty"`
}

// Installed describes one pack found in the packs directory.
type Installed struct {
	Pack   *Pack
	Path   string
	SHA256 string
	Signed bool
	Err    error // non-nil when the pack was rejected
}

var (
	idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,63}$`)
	// Vocabulary shared with the embedded manifests; rules key on these.
	validCats = map[string]bool{
		"agent_session": true, "prompt_history": true, "agent_definitions": true,
		"agent_instructions": true, "product_config": true, "managed_config": true,
		"product_state": true, "task_state": true, "credentials": true, "debug_logs": true,
		"file_checkpoints": true, "shell_state": true,
	}
	validSens  = map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
	validPlats = map[string]bool{"darwin": true, "linux": true, "windows": true}
)

// Dir returns the product-pack install directory.
func Dir() string {
	base := products.PacksDir()
	if base == "" {
		return ""
	}
	return filepath.Join(base, "products")
}

// Load reads and validates a pack file (no signature check).
func Load(path string) (*Pack, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	h := sha256.New()
	data, err := io.ReadAll(io.TeeReader(io.LimitReader(f, 4<<20), h))
	if err != nil {
		return nil, "", err
	}
	var p Pack
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, "", fmt.Errorf("invalid pack JSON: %w", err)
	}
	if err := Validate(&p); err != nil {
		return nil, "", err
	}
	return &p, hex.EncodeToString(h.Sum(nil)), nil
}

// Validate checks a pack for structural and safety problems and returns
// the first one found, phrased for a pack author.
func Validate(p *Pack) error {
	if p.PackFormat != Format {
		return fmt.Errorf("pack_format %q not supported (want %q)", p.PackFormat, Format)
	}
	id := p.Product.ID
	if !idRe.MatchString(id) {
		return fmt.Errorf("product.id %q: lowercase letters, digits and dashes only (2-64 chars)", id)
	}
	if strings.TrimSpace(p.Product.Name) == "" {
		return errors.New("product.name is required")
	}
	if len(p.Product.ConfigDirs) == 0 && len(p.Product.ConfigFiles) == 0 {
		return errors.New("product needs at least one config_dirs or config_files entry for detection")
	}
	for _, d := range append(append([]string{}, p.Product.ConfigDirs...), p.Product.ConfigFiles...) {
		if err := safeRel(d); err != nil {
			return fmt.Errorf("product path %q: %w", d, err)
		}
	}
	if p.Manifest.Product != id {
		return fmt.Errorf("manifest.product %q must equal product.id %q", p.Manifest.Product, id)
	}
	if len(p.Manifest.Entries) == 0 {
		return errors.New("manifest.entries is empty — nothing would be collected")
	}
	if p.Parser.Engine != "genericchat" {
		return fmt.Errorf("parser.engine %q not supported (want \"genericchat\")", p.Parser.Engine)
	}
	if !strings.HasSuffix(p.Parser.RulePrefix, ".") || len(p.Parser.RulePrefix) < 2 {
		return fmt.Errorf("parser.rule_prefix %q must end with a dot, e.g. %q", p.Parser.RulePrefix, id+".")
	}
	if strings.TrimSpace(p.Parser.Vendor) == "" {
		return errors.New("parser.vendor is required")
	}
	seen := map[string]bool{}
	for i, e := range p.Manifest.Entries {
		if !strings.HasPrefix(e.ID, p.Parser.RulePrefix) {
			return fmt.Errorf("manifest.entries[%d].id %q must start with parser.rule_prefix %q", i, e.ID, p.Parser.RulePrefix)
		}
		if seen[e.ID] {
			return fmt.Errorf("manifest.entries[%d].id %q is duplicated", i, e.ID)
		}
		seen[e.ID] = true
		if len(e.Paths) == 0 {
			return fmt.Errorf("manifest.entries[%d] (%s) has no paths", i, e.ID)
		}
		for _, pth := range e.Paths {
			if !strings.HasPrefix(pth, "${PROFILE_ROOT}") && !strings.HasPrefix(pth, "${CONFIG_ROOT}") && !strings.HasPrefix(pth, "${SYSTEM_ROOT}") {
				return fmt.Errorf("manifest.entries[%d] (%s) path %q must start with ${PROFILE_ROOT}, ${CONFIG_ROOT} or ${SYSTEM_ROOT}", i, e.ID, pth)
			}
			if strings.Contains(pth, "..") {
				return fmt.Errorf("manifest.entries[%d] (%s) path %q contains '..'", i, e.ID, pth)
			}
		}
		if !validCats[e.Category] {
			return fmt.Errorf("manifest.entries[%d] (%s) category %q unknown", i, e.ID, e.Category)
		}
		if !validSens[e.Sensitivity] {
			return fmt.Errorf("manifest.entries[%d] (%s) sensitivity %q must be low|medium|high|critical", i, e.ID, e.Sensitivity)
		}
		for _, pl := range e.Platforms {
			if !validPlats[pl] {
				return fmt.Errorf("manifest.entries[%d] (%s) platform %q must be darwin|linux|windows", i, e.ID, pl)
			}
		}
	}
	if fm := p.Parser.FieldMap; fm != nil {
		if fm.Role == "" && fm.Text == "" && fm.ToolName == "" {
			return errors.New("parser.field_map must map at least one of role, text, tool_name")
		}
	}
	return nil
}

func safeRel(p string) error {
	if p == "" || filepath.IsAbs(p) || strings.HasPrefix(p, "/") || strings.Contains(p, "..") {
		return errors.New("must be a relative path without '..'")
	}
	return nil
}

// Scan lists every pack in the install directory, verifying signatures
// with verify (injected to avoid a seal dependency cycle). Rejected packs
// are returned with Err set so the CLI can explain, never silently skip.
func Scan(verify func(dataPath, sigPath, trustedPubPath string) error) []Installed {
	dir := Dir()
	if dir == "" {
		return nil
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "*"+Suffix))
	sort.Strings(matches)
	trusted := filepath.Join(products.PacksDir(), "trusted.pub")
	allowUnsigned := os.Getenv("AGENTDFIR_ALLOW_UNSIGNED_PACKS") == "1"
	var out []Installed
	for _, path := range matches {
		inst := Installed{Path: path}
		p, sum, err := Load(path)
		inst.SHA256 = sum
		if err != nil {
			inst.Err = fmt.Errorf("REJECTED (invalid): %w", err)
			out = append(out, inst)
			continue
		}
		inst.Pack = p
		sig := path + ".sig"
		if _, err := os.Stat(sig); err == nil {
			if verr := verify(path, sig, trusted); verr != nil {
				inst.Err = fmt.Errorf("REJECTED (signature): %w", verr)
			} else {
				inst.Signed = true
			}
		} else if !allowUnsigned {
			inst.Err = errors.New("REJECTED (unsigned): sign with `agentdfir sign --file` or set AGENTDFIR_ALLOW_UNSIGNED_PACKS=1 for development")
		}
		out = append(out, inst)
	}
	return out
}

// Activate registers every accepted installed pack with the product
// registry and the genericchat engine. Returns the accepted packs and
// the rejections (for reporting); it never fails the caller.
func Activate(verify func(dataPath, sigPath, trustedPubPath string) error) (accepted, rejected []Installed) {
	for _, inst := range Scan(verify) {
		if inst.Err != nil {
			rejected = append(rejected, inst)
			continue
		}
		if err := Register(inst.Pack); err != nil {
			inst.Err = fmt.Errorf("REJECTED (register): %w", err)
			rejected = append(rejected, inst)
			continue
		}
		accepted = append(accepted, inst)
	}
	return accepted, rejected
}

// Register binds one validated pack into the running process.
func Register(p *Pack) error {
	if err := products.Register(p.Product, p.Manifest); err != nil {
		return err
	}
	return genericchat.Register(genericchat.ProductConfig{
		RulePrefix: p.Parser.RulePrefix, Product: p.Product.ID,
		Vendor: p.Parser.Vendor, FieldMap: p.Parser.FieldMap,
	})
}

// Install validates a pack file and copies it (and its .sig, if given)
// into the install directory. Returns the installed path.
func Install(src, sig string) (string, error) {
	p, _, err := Load(src)
	if err != nil {
		return "", err
	}
	dir := Dir()
	if dir == "" {
		return "", errors.New("cannot resolve packs directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, p.Product.ID+Suffix)
	if err := copyFile(src, dst); err != nil {
		return "", err
	}
	if sig != "" {
		if err := copyFile(sig, dst+".sig"); err != nil {
			return "", err
		}
	}
	return dst, nil
}

// Remove deletes an installed pack and its signature.
func Remove(id string) error {
	dir := Dir()
	if dir == "" || !idRe.MatchString(id) {
		return fmt.Errorf("invalid pack id %q", id)
	}
	path := filepath.Join(dir, id+Suffix)
	if err := os.Remove(path); err != nil {
		return err
	}
	_ = os.Remove(path + ".sig")
	return nil
}

// Template returns a starter pack for a new product ID, ready to edit.
func Template(id, name, configDir string) *Pack {
	prefix := id + "."
	return &Pack{
		PackFormat: Format,
		Version:    "0.1.0",
		Product: products.Product{
			ID: id, Name: name,
			ConfigDirs:  []string{configDir},
			ConfigFiles: []string{},
			Binaries:    []string{id},
		},
		Manifest: products.CollectorManifest{
			Product: id,
			Entries: []products.ManifestEntry{
				{ID: prefix + "config", Paths: []string{"${CONFIG_ROOT}/config.json"}, Category: "product_config", Sensitivity: "medium"},
				{ID: prefix + "sessions", Paths: []string{"${CONFIG_ROOT}/sessions/**"}, Category: "agent_session", Sensitivity: "high"},
			},
		},
		Parser: ParserBinding{
			Engine: "genericchat", RulePrefix: prefix, Vendor: id,
			FieldMap: &genericchat.FieldMap{
				Role: "role", Text: "content", Timestamp: "timestamp",
				ToolName: "tool.name", ToolArgs: "tool.args",
				ModelRoles: []string{"assistant"}, HumanRoles: []string{"user"},
			},
		},
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
