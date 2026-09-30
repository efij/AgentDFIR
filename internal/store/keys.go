package store

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/efij/AgentDFIR/v3/internal/hashchain"
	"github.com/efij/AgentDFIR/v3/internal/seal"
)

// The machine sealing key.
//
// Every round a machine seals is signed with a key that lives in the
// AgentDFIR home, not in the case. That is what lets the next round prove
// the earlier ones were not rewritten before it builds on them: without a
// signature, anyone who can write the case can regenerate SHA256SUMS and
// both hash chains from scratch and every check passes.
//
// Its limit is stated in SECURITY.md: an attacker who controls this
// account also controls this key. The anchor log and the seal digest
// printed at the end of every run are what survive that.

const (
	keysDir    = "keys"
	sealKey    = "seal.ed25519"
	sealPub    = "seal.ed25519.pub"
	anchorFile = "anchors.jsonl"
)

// MachineKey returns this machine's sealing key, creating it on first use.
func MachineKey() (string, error) {
	home, err := Home()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, keysDir)
	if err := ensureSecureDir(dir); err != nil {
		return "", err
	}
	priv := filepath.Join(dir, sealKey)
	if _, err := os.Lstat(priv); errors.Is(err, os.ErrNotExist) {
		if err := seal.GenerateKey(priv, filepath.Join(dir, sealPub)); err != nil {
			return "", fmt.Errorf("create machine key: %w", err)
		}
	}
	if err := checkKeyFile(priv); err != nil {
		return "", err
	}
	return priv, nil
}

// MachinePublicKey returns the machine key's public half (hex), or "" when
// this machine has none yet. It never creates anything.
func MachinePublicKey() string {
	priv, ok := existingKey()
	if !ok {
		return ""
	}
	pub, err := seal.PublicKeyHex(priv)
	if err != nil {
		return ""
	}
	return pub
}

// CacheKey is the key that authenticates derived caches (the normalized
// overlay's state), derived from the machine key. It is nil when the
// machine has no key; it never creates one, so opening a case somewhere
// else leaves no trace in that machine's home.
func CacheKey() []byte {
	priv, ok := existingKey()
	if !ok {
		return nil
	}
	k, err := seal.LoadPrivateKey(priv)
	if err != nil {
		return nil
	}
	m := hmac.New(sha256.New, k.Seed())
	m.Write([]byte("agentdfir derived-cache authentication v1"))
	return m.Sum(nil)
}

func existingKey() (string, bool) {
	home := os.Getenv(EnvHome)
	if home == "" {
		b, err := defaultBase()
		if err != nil {
			return "", false
		}
		home = b
	}
	priv := filepath.Join(home, keysDir, sealKey)
	if checkKeyFile(priv) != nil {
		return "", false
	}
	return priv, true
}

// checkKeyFile refuses a key that is a symlink, not a regular file, owned
// by someone else, or readable by anyone but its owner.
func checkKeyFile(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file; refusing to use it as a signing key", path)
	}
	if err := checkOwner(path, fi); err != nil {
		return err
	}
	if PermissionsAreReal && fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is accessible to other users (%o); refusing to sign with it", path, fi.Mode().Perm())
	}
	return nil
}

// Anchor is one sealed round, recorded outside the case.
type Anchor struct {
	CaseID      string `json:"case_id"`
	Round       int    `json:"round"`
	SealsDigest string `json:"seals_digest"`
	Signer      string `json:"signer,omitempty"`
	Package     string `json:"package,omitempty"`
	TimeUTC     string `json:"ts_utc"`
}

// RecordAnchor appends a sealed round to the anchor log, a hash chain of
// its own in the AgentDFIR home. Rewriting a case then means rewriting
// this file too, consistently — and the digest printed at the end of the
// run, pasted into a ticket, is out of reach altogether.
func RecordAnchor(a Anchor) error {
	home, err := Home()
	if err != nil {
		return err
	}
	path := filepath.Join(home, anchorFile)
	var w *hashchain.Writer
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		w, err = hashchain.NewWriter(path)
		if err != nil {
			return err
		}
	} else if w, err = hashchain.NewAppender(path); err != nil {
		return fmt.Errorf("anchor log: %w", err)
	}
	if a.TimeUTC == "" {
		a.TimeUTC = time.Now().UTC().Format(time.RFC3339)
	}
	rec := map[string]any{
		"event": "round_sealed", "case_id": a.CaseID, "round": a.Round,
		"seals_digest": a.SealsDigest, "signer": a.Signer, "package": a.Package, "ts_utc": a.TimeUTC,
	}
	if err := w.Append(rec); err != nil {
		w.Close()
		return err
	}
	return w.Close()
}

// LatestAnchor returns the newest anchor recorded for a case at a given
// package path, or nil when there is none (or no anchor log). The path is
// part of the key because a copied case legitimately diverges from the
// original. An anchor log whose own chain is broken is an error: it is
// exactly the file an attacker would edit.
func LatestAnchor(caseID, pkgPath string) (*Anchor, error) {
	home := os.Getenv(EnvHome)
	if home == "" {
		b, err := defaultBase()
		if err != nil {
			return nil, nil
		}
		home = b
	}
	path := filepath.Join(home, anchorFile)
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := hashchain.Verify(f); err != nil {
		return nil, fmt.Errorf("anchor log %s: %w", path, err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		return nil, err
	}
	var latest *Anchor
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		var a Anchor
		if json.Unmarshal(sc.Bytes(), &a) == nil && a.CaseID == caseID && a.Package == pkgPath {
			latest = &a
		}
	}
	return latest, sc.Err()
}
