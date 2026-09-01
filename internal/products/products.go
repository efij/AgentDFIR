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

// All returns the embedded product list.
func All() ([]Product, error) {
	var wrap struct {
		Products []Product `json:"products"`
	}
	if err := json.Unmarshal(productsJSON, &wrap); err != nil {
		return nil, err
	}
	return wrap.Products, nil
}

// Manifest returns the collector manifest for a product ID, or nil if no
// collector is implemented yet.
func Manifest(productID string) (*CollectorManifest, error) {
	if productID != "claude-code" {
		return nil, nil
	}
	var m CollectorManifest
	if err := json.Unmarshal(claudeManifestJSON, &m); err != nil {
		return nil, err
	}
	var entries []ManifestEntry
	for _, e := range m.Entries {
		if len(e.Platforms) == 0 || contains(e.Platforms, runtime.GOOS) {
			entries = append(entries, e)
		}
	}
	m.Entries = entries
	return &m, nil
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
