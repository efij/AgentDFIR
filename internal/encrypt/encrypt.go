// Package encrypt provides full-package encryption for .adfir packages
// (plan §19). A sealed package directory is archived (tar) and encrypted
// to a single .adfir.enc file so logical paths (which can leak
// confidential project/repo names) never appear in the clear.
//
// Crypto is standard library only (honoring the zero-third-party-deps
// policy): AES-256-GCM for the payload, PBKDF2-HMAC-SHA256 for
// passphrase key derivation. The public envelope header carries only
// non-secret parameters (salt, nonce, KDF iterations) — never a key or
// plaintext. This is not a novel construction; it composes reviewed
// standard primitives.
package encrypt

import (
	"archive/tar"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

const (
	magic      = "ADFIRENC"
	version    = 1
	saltLen    = 16
	nonceLen   = 12
	keyLen     = 32
	iterations = 600_000 // OWASP-recommended PBKDF2-SHA256 floor
)

// Encrypt archives the package directory and writes an encrypted file.
func Encrypt(pkgDir, outFile, passphrase string) error {
	plain, err := tarDir(pkgDir)
	if err != nil {
		return err
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	key, err := pbkdf2.Key(sha256.New, passphrase, salt, iterations, keyLen)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	header := buildHeader(salt, nonce)
	// The header is authenticated as additional data so it cannot be
	// altered without failing decryption.
	ciphertext := gcm.Seal(nil, nonce, plain, header)

	out, err := os.Create(outFile)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := out.Write(header); err != nil {
		return err
	}
	_, err = out.Write(ciphertext)
	return err
}

// Decrypt reads an encrypted file and extracts the package into destDir.
func Decrypt(inFile, destDir, passphrase string) error {
	data, err := os.ReadFile(inFile)
	if err != nil {
		return err
	}
	salt, nonce, headerLen, err := parseHeader(data)
	if err != nil {
		return err
	}
	key, err := pbkdf2.Key(sha256.New, passphrase, salt, iterations, keyLen)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	plain, err := gcm.Open(nil, nonce, data[headerLen:], data[:headerLen])
	if err != nil {
		return fmt.Errorf("decryption failed: wrong passphrase or the file was modified")
	}
	return untar(plain, destDir)
}

// buildHeader lays out the public envelope: magic, version, iterations,
// salt, nonce. No secrets.
func buildHeader(salt, nonce []byte) []byte {
	h := make([]byte, 0, len(magic)+1+4+saltLen+nonceLen)
	h = append(h, magic...)
	h = append(h, version)
	var iter [4]byte
	binary.BigEndian.PutUint32(iter[:], iterations)
	h = append(h, iter[:]...)
	h = append(h, salt...)
	h = append(h, nonce...)
	return h
}

func parseHeader(data []byte) (salt, nonce []byte, headerLen int, err error) {
	headerLen = len(magic) + 1 + 4 + saltLen + nonceLen
	if len(data) < headerLen {
		return nil, nil, 0, fmt.Errorf("file too short to be an encrypted package")
	}
	if string(data[:len(magic)]) != magic {
		return nil, nil, 0, fmt.Errorf("not an AgentDFIR encrypted package")
	}
	off := len(magic) + 1 + 4
	salt = data[off : off+saltLen]
	nonce = data[off+saltLen : off+saltLen+nonceLen]
	return salt, nonce, headerLen, nil
}

func tarDir(dir string) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil // never archive symlinks
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	})
	if err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func untar(data []byte, destDir string) error {
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return err
	}
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		// Path-traversal defense (zip-slip): resolve and confine.
		target := filepath.Join(destDir, filepath.Clean("/"+hdr.Name))
		if rel, err := filepath.Rel(destDir, target); err != nil || rel == ".." ||
			(len(rel) >= 3 && rel[:3] == "../") {
			return fmt.Errorf("archive entry escapes destination: %s", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()
		}
	}
	return nil
}
