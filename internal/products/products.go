// Package products embeds the product-knowledge pack: which AI agent
// products exist, how to detect them, and their collector manifests.
//
// Forensic rule: detection NEVER executes a discovered binary (a suspect
// host's binaries may be trojaned). Presence, paths and hashes only.
package products

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

//go:embed products.json
var productsJSON []byte

//go:embed claude_manifest.json
var claudeManifestJSON []byte

//go:embed codex_manifest.json
var codexManifestJSON []byte

//go:embed tier23_manifests.json
var tier23ManifestsJSON []byte

// Product describes how to detect one AI agent product.
type Product struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	ConfigDirs  []string `json:"config_dirs"`  // relative to profile root
	ConfigFiles []string `json:"config_files"` // relative to profile root
	ConfigEnv   string   `json:"config_env,omitempty"`
	Binaries    []string `json:"binaries"`
}

// ManifestEntry is one declarative collector rule.
type ManifestEntry struct {
	ID          string   `json:"id"`
	Platforms   []string `json:"platforms,omitempty"` // empty = all
	Paths       []string `json:"paths"`
	Category    string   `json:"category"`
	Sensitivity string   `json:"sensitivity"`
}

// CollectorManifest is a product's full collector manifest.
type CollectorManifest struct {
	Product string          `json:"product"`
	Entries []ManifestEntry `json:"entries"`
}

// extra holds products registered at runtime from installed product
// packs (see internal/productpack). Registration is process-local and
// happens once at CLI start-up, before any lookup.
var (
	extraProducts  []Product
	extraManifests = map[string]CollectorManifest{}
)

// Register adds a product and its collector manifest from a product pack.
// A pack may not shadow an embedded product ID.
func Register(p Product, m CollectorManifest) error {
	embedded, err := All()
	if err != nil {
		return err
	}
	for _, e := range embedded {
		if e.ID == p.ID {
			return fmt.Errorf("product pack %q shadows an embedded product", p.ID)
		}
	}
	if m.Product != p.ID {
		return fmt.Errorf("manifest product %q does not match pack product %q", m.Product, p.ID)
	}
	// Replace an earlier registration of the same ID (idempotent activation).
	for i := range extraProducts {
		if extraProducts[i].ID == p.ID {
			extraProducts[i] = p
			extraManifests[p.ID] = m
			return nil
		}
	}
	extraProducts = append(extraProducts, p)
	extraManifests[p.ID] = m
	return nil
}

// ResetRegistered clears runtime registrations (tests).
func ResetRegistered() {
	extraProducts = nil
	extraManifests = map[string]CollectorManifest{}
}

// All returns the embedded product list followed by pack-registered
// products.
func All() ([]Product, error) {
	var wrap struct {
		Products []Product `json:"products"`
	}
	if err := json.Unmarshal(productsJSON, &wrap); err != nil {
		return nil, err
	}
	return append(wrap.Products, extraProducts...), nil
}

// Manifest returns the collector manifest for a product ID, or nil if no
// collector is implemented yet.
func Manifest(productID string) (*CollectorManifest, error) {
	if m, ok := extraManifests[productID]; ok {
		return filterPlatform(m), nil
	}
	var m CollectorManifest
	switch productID {
	case "claude-code":
		if err := json.Unmarshal(claudeManifestJSON, &m); err != nil {
			return nil, err
		}
	case "codex-cli":
		if err := json.Unmarshal(codexManifestJSON, &m); err != nil {
			return nil, err
		}
	default:
		var wrap struct {
			Manifests []CollectorManifest `json:"manifests"`
		}
		if err := json.Unmarshal(tier23ManifestsJSON, &wrap); err != nil {
			return nil, err
		}
		for _, cand := range wrap.Manifests {
			if cand.Product == productID {
				m = cand
			}
		}
		if m.Product == "" {
			return nil, nil
		}
	}
	return filterPlatform(m), nil
}

// filterPlatform drops entries not applicable to the running OS.
func filterPlatform(m CollectorManifest) *CollectorManifest {
	var entries []ManifestEntry
	for _, e := range m.Entries {
		if len(e.Platforms) == 0 || contains(e.Platforms, runtime.GOOS) {
			entries = append(entries, e)
		}
	}
	m.Entries = entries
	return &m
}

// ByID returns one product definition by its ID.
func ByID(id string) (*Product, error) {
	prods, err := All()
	if err != nil {
		return nil, err
	}
	for i := range prods {
		if prods[i].ID == id {
			return &prods[i], nil
		}
	}
	return nil, fmt.Errorf("unknown product %q", id)
}

// Detection is the result of detecting one product on a host.
type Detection struct {
	Product      Product
	Detected     bool
	ConfigPaths  []string // existing config dirs/files
	BinaryPath   string
	BinarySHA256 string
	InstallHint  string
}

// DetectAll probes the given profile root (typically the current user's
// home) for every known product. It never executes discovered binaries.
func DetectAll(profileRoot string) ([]Detection, error) {
	prods, err := All()
	if err != nil {
		return nil, err
	}
	var out []Detection
	for _, p := range prods {
		d := Detection{Product: p}
		roots := []string{profileRoot}
		if p.ConfigEnv != "" {
			if v := os.Getenv(p.ConfigEnv); v != "" {
				d.ConfigPaths = appendIfExists(d.ConfigPaths, v)
			}
		}
		for _, root := range roots {
			for _, dir := range p.ConfigDirs {
				d.ConfigPaths = appendIfExists(d.ConfigPaths, filepath.Join(root, dir))
			}
			for _, f := range p.ConfigFiles {
				d.ConfigPaths = appendIfExists(d.ConfigPaths, filepath.Join(root, f))
			}
		}
		for _, bin := range p.Binaries {
			if path, err := exec.LookPath(bin); err == nil {
				d.BinaryPath = path
				d.BinarySHA256 = fileSHA256(path)
				d.InstallHint = installHint(path)
				break
			}
		}
		d.Detected = len(d.ConfigPaths) > 0 || d.BinaryPath != ""
		out = append(out, d)
	}
	return out, nil
}

func appendIfExists(list []string, path string) []string {
	if _, err := os.Lstat(path); err == nil {
		return append(list, path)
	}
	return list
}

func fileSHA256(path string) string {
	// Resolve symlinks so we hash the real binary, and record content only.
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func installHint(path string) string {
	switch {
	case strings.Contains(path, "homebrew"):
		return "homebrew"
	case strings.Contains(path, "node_modules") || strings.Contains(path, "npm"):
		return "npm"
	case strings.Contains(path, ".local/bin"):
		return "user-local installer"
	case strings.HasPrefix(path, "/usr/bin") || strings.HasPrefix(path, "/usr/local/bin"):
		return "system"
	default:
		return ""
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// PacksDir returns the knowledge-pack override directory
// ($AGENTDFIR_PACKS_DIR or ~/.agentdfir/packs).
func PacksDir() string {
	if v := os.Getenv("AGENTDFIR_PACKS_DIR"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".agentdfir", "packs")
}

// LoadOverride returns a signed collector-manifest override for a
// product, if one is installed AND its detached signature verifies
// against the trusted key in the packs dir. Invalid or unsigned packs
// are never loaded (plan D5: signed, updatable knowledge packs).
// The verify function is injected to avoid a dependency cycle.
func LoadOverride(productID string, verify func(dataPath, sigPath, trustedPubPath string) error) (*CollectorManifest, string, error) {
	dir := PacksDir()
	if dir == "" {
		return nil, "", nil
	}
	pack := filepath.Join(dir, productID+".json")
	sig := pack + ".sig"
	pub := filepath.Join(dir, "trusted.pub")
	if _, err := os.Stat(pack); err != nil {
		return nil, "", nil // no override installed
	}
	if err := verify(pack, sig, pub); err != nil {
		return nil, pack, fmt.Errorf("pack override REJECTED (signature): %w", err)
	}
	data, err := os.ReadFile(pack)
	if err != nil {
		return nil, pack, err
	}
	var m CollectorManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, pack, fmt.Errorf("pack override REJECTED (invalid JSON): %w", err)
	}
	if m.Product != productID {
		return nil, pack, fmt.Errorf("pack override REJECTED (product mismatch: %q)", m.Product)
	}
	var entries []ManifestEntry
	for _, e := range m.Entries {
		if len(e.Platforms) == 0 || contains(e.Platforms, runtime.GOOS) {
			entries = append(entries, e)
		}
	}
	m.Entries = entries
	return &m, pack, nil
}
