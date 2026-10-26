package export

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/efij/AgentDFIR/v5/internal/seal"
)

// ProductionSignature is the detached ed25519 signature over
// production-manifest.json. The manifest lists every produced file with
// its SHA-256, so the signature covers the whole set; it is written in
// the format `agentdfir sign --file` writes (algorithm, file_sha256,
// signature, public_key), and ed25519 is deterministic, so a signed
// production stays byte-reproducible for the same key.
const ProductionSignature = ProductionManifestJSON + ".sig"

// SignProduction signs a production's manifest with an ed25519 key.
func SignProduction(dir, keyPath string) (string, error) {
	sig := filepath.Join(dir, ProductionSignature)
	if err := seal.SignFile(filepath.Join(dir, ProductionManifestJSON), keyPath, sig); err != nil {
		return "", err
	}
	return seal.PublicKeyHex(keyPath)
}

// ProductionCheck is the result of verifying a production set.
type ProductionCheck struct {
	Files     int      `json:"files_checked"`
	Signature string   `json:"signature"` // none | valid | INVALID
	Signer    string   `json:"signer,omitempty"`
	Problems  []string `json:"problems"`
	Notes     []string `json:"notes"`
}

// IsProduction reports whether dir looks like a production set rather
// than a package.
func IsProduction(dir string) bool {
	_, errM := os.Stat(filepath.Join(dir, ProductionManifestJSON))
	_, errS := os.Stat(filepath.Join(dir, "SHA256SUMS"))
	return errM == nil && os.IsNotExist(errS)
}

const maxProductionManifest = 256 << 20

// VerifyProduction checks a production set: every file the manifest
// lists hashes to its recorded SHA-256 and size, nothing else is in the
// directory, and production-manifest.json.sig, when present, is a valid
// signature over the manifest (by pinnedHex, when set). A missing
// signature is a problem only when a key is pinned.
func VerifyProduction(dir, pinnedHex string) (*ProductionCheck, error) {
	mp := filepath.Join(dir, ProductionManifestJSON)
	fi, err := os.Stat(mp)
	if err != nil {
		return nil, err
	}
	if fi.Size() > maxProductionManifest {
		return nil, fmt.Errorf("%s is larger than %d bytes", ProductionManifestJSON, maxProductionManifest)
	}
	data, err := os.ReadFile(mp)
	if err != nil {
		return nil, err
	}
	var m ProductionManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", ProductionManifestJSON, err)
	}
	c := &ProductionCheck{Signature: "none", Problems: []string{}, Notes: []string{}}
	if m.Schema != ProductionSchema {
		c.Problems = append(c.Problems, fmt.Sprintf("schema %q, want %q", m.Schema, ProductionSchema))
	}
	listed := map[string]bool{ProductionManifestJSON: true, ProductionManifestCSV: true, ProductionSignature: true}
	for _, f := range m.Files {
		rel := f.Path
		if rel == "" || strings.HasPrefix(rel, "/") || strings.Contains(rel, "\\") || hasDotDot(rel) {
			c.Problems = append(c.Problems, fmt.Sprintf("%q: path outside the production", rel))
			continue
		}
		if listed[rel] {
			c.Problems = append(c.Problems, rel+": listed twice")
		}
		listed[rel] = true
		sum, size, err := hashFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			c.Problems = append(c.Problems, rel+": listed but unreadable or missing")
			continue
		}
		c.Files++
		if sum != f.SHA256 || size != f.Size {
			c.Problems = append(c.Problems, rel+": does not match the manifest")
		}
	}
	var extra []string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		if !listed[filepath.ToSlash(rel)] {
			extra = append(extra, filepath.ToSlash(rel))
		}
		return nil
	})
	sort.Strings(extra)
	for _, e := range extra {
		c.Problems = append(c.Problems, e+": present but not listed in the manifest")
	}
	sigPath := filepath.Join(dir, ProductionSignature)
	switch _, err := os.Stat(sigPath); {
	case err == nil:
		pub, verr := seal.VerifyFileSigKey(mp, sigPath, pinnedHex)
		c.Signer = pub
		if verr != nil {
			c.Signature = "INVALID"
			c.Problems = append(c.Problems, ProductionSignature+": "+verr.Error())
		} else {
			c.Signature = "valid"
			if pinnedHex == "" {
				c.Notes = append(c.Notes, "signature valid for key "+pub+"; pin the producer's key (--pubkey) to prove who produced it")
			}
		}
	case pinnedHex != "":
		c.Problems = append(c.Problems, ProductionSignature+": missing, but a signer key was pinned")
	default:
		c.Notes = append(c.Notes, "the production is unsigned (produced before 4.5 or with --no-sign); file hashes are checked against an unauthenticated manifest")
	}
	c.Notes = append(c.Notes, ProductionManifestCSV+" is a convenience copy of the manifest's file list and is not covered by the signature")
	return c, nil
}

func hasDotDot(rel string) bool {
	for _, p := range strings.Split(rel, "/") {
		if p == ".." || p == "." || p == "" {
			return true
		}
	}
	return false
}
