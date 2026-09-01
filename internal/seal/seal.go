// Package seal provides ed25519 detached signatures over a package's
// SHA256SUMS (plan §7, §19). SHA256SUMS already covers the entire sealed
// zone, so signing it authenticates the whole package. Uses only
// crypto/ed25519 from the standard library — no third-party crypto.
package seal

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	sumsFile  = "SHA256SUMS"
	sigFile   = "SEAL.sig"
	pubBlock  = "AGENTDFIR ED25519 PUBLIC KEY"
	privBlock = "AGENTDFIR ED25519 PRIVATE KEY"
)

// GenerateKey writes a new ed25519 keypair as PEM files.
func GenerateKey(privPath, pubPath string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := writePEM(privPath, privBlock, priv, 0o600); err != nil {
		return err
	}
	return writePEM(pubPath, pubBlock, pub, 0o644)
}

// Sign creates SEAL.sig over the package's SHA256SUMS using the private
// key at keyPath. The signature file records the public key so verify is
// self-contained; chain-of-custody records who signed out of band.
func Sign(pkgDir, keyPath string) error {
	priv, err := readKey(keyPath, privBlock)
	if err != nil {
		return err
	}
	if len(priv) != ed25519.PrivateKeySize {
		return errors.New("invalid private key size")
	}
	digest, err := sumsDigest(pkgDir)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(ed25519.PrivateKey(priv), digest)
	pub := ed25519.PrivateKey(priv).Public().(ed25519.PublicKey)

	out := fmt.Sprintf("algorithm: ed25519\nsha256sums_digest: %s\nsignature: %s\npublic_key: %s\n",
		hex.EncodeToString(digest), hex.EncodeToString(sig), hex.EncodeToString(pub))
	return os.WriteFile(filepath.Join(pkgDir, sigFile), []byte(out), 0o644)
}

// VerifyResult reports signature verification.
type VerifyResult struct {
	Present   bool
	Valid     bool
	PublicKey string
	Reason    string
}

// Verify checks SEAL.sig against the current SHA256SUMS. Optionally pins
// an expected public key (hex); if provided and mismatched, fails.
func Verify(pkgDir, expectedPubHex string) (*VerifyResult, error) {
	sigPath := filepath.Join(pkgDir, sigFile)
	data, err := os.ReadFile(sigPath)
	if os.IsNotExist(err) {
		return &VerifyResult{Present: false}, nil
	}
	if err != nil {
		return nil, err
	}
	fields := parseFields(string(data))
	sig, err1 := hex.DecodeString(fields["signature"])
	pub, err2 := hex.DecodeString(fields["public_key"])
	if err1 != nil || err2 != nil || len(pub) != ed25519.PublicKeySize {
		return &VerifyResult{Present: true, Valid: false, Reason: "malformed SEAL.sig"}, nil
	}
	res := &VerifyResult{Present: true, PublicKey: fields["public_key"]}
	if expectedPubHex != "" && expectedPubHex != fields["public_key"] {
		res.Reason = "public key does not match the pinned key"
		return res, nil
	}
	digest, err := sumsDigest(pkgDir)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), digest, sig) {
		res.Reason = "signature does not match SHA256SUMS (package modified or wrong key)"
		return res, nil
	}
	res.Valid = true
	return res, nil
}

func sumsDigest(pkgDir string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(pkgDir, sumsFile))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	return sum[:], nil
}

func writePEM(path, blockType string, key []byte, mode os.FileMode) error {
	b := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: key})
	return os.WriteFile(path, b, mode)
}

func readKey(path, blockType string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != blockType {
		return nil, fmt.Errorf("not a %s PEM file", blockType)
	}
	return block.Bytes, nil
}

func parseFields(s string) map[string]string {
	out := map[string]string{}
	for _, line := range splitLines(s) {
		for i := 0; i < len(line); i++ {
			if line[i] == ':' {
				k := line[:i]
				v := line[i+1:]
				out[trimSpace(k)] = trimSpace(v)
				break
			}
		}
	}
	return out
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
