package benchmark

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/efij/AgentDFIR/v3/internal/casepkg"
	"github.com/efij/AgentDFIR/v3/internal/integrity"
	"github.com/efij/AgentDFIR/v3/internal/seal"
)

// Integrity is the mutation-suite section: one sealed, signed, two-round
// package (plain, gzip and chunked blobs, archived seals and signatures),
// copied once per mutation, each copy changed one way, each copy verified.
// Every mutation must be detected. Anything that is not is a real defect.
type Integrity struct {
	Mutations  []MutationResult `json:"mutations"`
	Detected   int              `json:"detected"`
	Total      int              `json:"total"`
	Undetected []string         `json:"undetected"`
	// Reference describes the package the mutations start from.
	Reference string `json:"reference"`
}

// MutationResult is one mutation.
type MutationResult struct {
	ID       string `json:"id"`
	What     string `json:"what"`
	Mode     string `json:"mode"` // "default" (agentdfir verify) or "pinned" (agentdfir verify --pubkey)
	Detected bool   `json:"detected"`
	Problem  string `json:"first_problem,omitempty"`
}

// Mutation changes one sealed package in place.
type Mutation struct {
	ID   string
	What string
	// Pinned mutations can only be caught with the signer's key pinned
	// (a forger who controls the machine can rewrite and re-sign); they
	// are verified as `agentdfir verify --pubkey <recorded signer>`.
	Pinned bool
	Apply  func(pkg string, ref *Reference) error
}

// Reference is what BuildReference produced.
type Reference struct {
	Signer    string // hex public key both rounds were signed with
	PlainBlob string // raw/<name> of an uncompressed blob
	GzipBlob  string // raw/<name> of a gzip blob
	Chunked   bool   // whether a chunked artifact was produced
}

// BuildReference writes a two-round, signed package at pkg: a small
// transcript stored plain, a large one stored gzip that grows between
// rounds (stored as chunks), seals/ holding round 1's seal and signature.
// keyPath receives the signing key. Content is synthetic.
func BuildReference(pkg, keyPath, srcDir string) (*Reference, error) {
	if err := seal.GenerateKey(keyPath, keyPath+".pub"); err != nil {
		return nil, err
	}
	pub, err := seal.PublicKeyHex(keyPath)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		return nil, err
	}
	small := filepath.Join(srcDir, "session.jsonl")
	big := filepath.Join(srcDir, "big.jsonl")
	s := newSession("bbbbbbbb-0001-4000-8000-000000000001", t0)
	s.user(0, "list the files")
	s.bash(2, "ls -la", "total 0")
	if err := os.WriteFile(small, s.bytes(), 0o644); err != nil {
		return nil, err
	}
	bs := newSession("bbbbbbbb-0002-4000-8000-000000000002", t0)
	for i := 0; i < 40; i++ {
		bs.bash(float64(i*3), fmt.Sprintf("echo step %d", i), "step done")
	}
	if err := os.WriteFile(big, bs.bytes(), 0o644); err != nil {
		return nil, err
	}
	round := func(files ...string) error {
		var b *casepkg.Builder
		var err error
		if _, statErr := os.Stat(pkg); statErr == nil {
			b, err = casepkg.Reopen(pkg, casepkg.CaseInfo{OperatorOSUser: "benchmark"})
		} else {
			b, err = casepkg.New(pkg, "BENCH-REFERENCE", casepkg.CaseInfo{OperatorOSUser: "benchmark"})
		}
		if err != nil {
			return err
		}
		defer b.Close()
		for _, f := range files {
			if err := b.IngestFile(f, casepkg.ArtifactRecord{SourcePath: f, LogicalPath: ".claude/projects/-home-dev-app/" + filepath.Base(f),
				Product: "claude-code", ArtifactType: "agent_session"}); err != nil {
				return err
			}
		}
		b.Signer = pub
		if err := b.Seal(); err != nil {
			return err
		}
		return seal.Sign(pkg, keyPath)
	}
	if err := round(small, big); err != nil {
		return nil, err
	}
	// The big transcript grows; round 2 stores only the tail.
	for i := 40; i < 50; i++ {
		bs.bash(float64(i*3), fmt.Sprintf("echo step %d", i), "step done")
	}
	if err := os.WriteFile(big, bs.bytes(), 0o644); err != nil {
		return nil, err
	}
	if err := round(small, big); err != nil {
		return nil, err
	}
	ref := &Reference{Signer: pub}
	man, err := casepkg.ReadManifest(pkg)
	if err != nil {
		return nil, err
	}
	for _, a := range man.Artifacts {
		if len(a.Chunks) > 0 {
			ref.Chunked = true
		}
	}
	entries, err := os.ReadDir(filepath.Join(pkg, "raw"))
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		switch {
		case strings.HasSuffix(e.Name(), ".gz") && ref.GzipBlob == "":
			ref.GzipBlob = "raw/" + e.Name()
		case !strings.HasSuffix(e.Name(), ".gz") && ref.PlainBlob == "":
			ref.PlainBlob = "raw/" + e.Name()
		}
	}
	if ref.PlainBlob == "" || ref.GzipBlob == "" {
		return nil, fmt.Errorf("reference package lacks a plain or a gzip blob (plain %q, gzip %q)", ref.PlainBlob, ref.GzipBlob)
	}
	return ref, nil
}

// ---- file helpers. Stored files are read-only; an attacker with write
// access to the package clears that, and so do these.

func rewrite(path string, fn func([]byte) ([]byte, error)) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	out, err := fn(data)
	if err != nil {
		return err
	}
	_ = os.Chmod(path, 0o600)
	return os.WriteFile(path, out, 0o600)
}

func lines(data []byte) []string {
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
}

func joinLines(ls []string) []byte { return []byte(strings.Join(ls, "\n") + "\n") }

func dropLine(path string, match func(string) bool) error {
	return rewrite(path, func(b []byte) ([]byte, error) {
		ls := lines(b)
		for i, l := range ls {
			if match(l) {
				return joinLines(append(ls[:i:i], ls[i+1:]...)), nil
			}
		}
		return nil, fmt.Errorf("%s: no matching line", filepath.Base(path))
	})
}

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// resum rewrites SHA256SUMS so it matches the files on disk again: what a
// forger does after editing the sealed zone.
func resum(pkg string) error {
	return rewrite(filepath.Join(pkg, "SHA256SUMS"), func(b []byte) ([]byte, error) {
		ls := lines(b)
		for i, l := range ls {
			rel := l[strings.Index(l, "  ")+2:]
			data, err := os.ReadFile(filepath.Join(pkg, filepath.FromSlash(rel)))
			if err != nil {
				return nil, err
			}
			ls[i] = sha(data) + "  " + rel
		}
		return joinLines(ls), nil
	})
}

// Mutations is the suite, in report order.
func Mutations() []Mutation {
	return []Mutation{
		{ID: "raw-flip-byte", What: "flip one byte in an uncompressed blob", Apply: func(p string, r *Reference) error {
			return rewrite(filepath.Join(p, r.PlainBlob), func(b []byte) ([]byte, error) { b[len(b)/2] ^= 0x01; return b, nil })
		}},
		{ID: "raw-flip-byte-gzip", What: "flip one byte in a gzip blob", Apply: func(p string, r *Reference) error {
			return rewrite(filepath.Join(p, r.GzipBlob), func(b []byte) ([]byte, error) { b[len(b)/2] ^= 0x01; return b, nil })
		}},
		{ID: "raw-truncate", What: "truncate a blob", Apply: func(p string, r *Reference) error {
			return rewrite(filepath.Join(p, r.PlainBlob), func(b []byte) ([]byte, error) { return b[:len(b)/2], nil })
		}},
		{ID: "raw-delete", What: "delete a blob", Apply: func(p string, r *Reference) error {
			return os.Remove(filepath.Join(p, r.GzipBlob))
		}},
		{ID: "raw-plant", What: "add an unlisted blob to raw/", Apply: func(p string, _ *Reference) error {
			data := []byte("{\"planted\":true}\n")
			return os.WriteFile(filepath.Join(p, "raw", sha(data)), data, 0o400)
		}},
		{ID: "manifest-delete-line", What: "delete one artifact record from manifest.jsonl", Apply: func(p string, _ *Reference) error {
			return dropLine(filepath.Join(p, "manifest.jsonl"), func(l string) bool { return strings.Contains(l, `"artifact_id"`) })
		}},
		{ID: "manifest-edit-path", What: "rename an artifact's logical path in manifest.jsonl", Apply: func(p string, _ *Reference) error {
			return rewrite(filepath.Join(p, "manifest.jsonl"), func(b []byte) ([]byte, error) {
				return bytes.Replace(b, []byte("session.jsonl"), []byte("innocent.jsonl"), 1), nil
			})
		}},
		{ID: "manifest-plant-legacy", What: "add an unlisted legacy manifest.json next to manifest.jsonl", Apply: func(p string, _ *Reference) error {
			return os.WriteFile(filepath.Join(p, "manifest.json"), []byte(`{"adfir_version":"0.1","artifacts":[]}`), 0o600)
		}},
		{ID: "chain-reorder", What: "swap two lines of collection.jsonl", Apply: func(p string, _ *Reference) error {
			return rewrite(filepath.Join(p, "collection.jsonl"), func(b []byte) ([]byte, error) {
				ls := lines(b)
				if len(ls) < 3 {
					return nil, errors.New("collection.jsonl too short")
				}
				ls[1], ls[2] = ls[2], ls[1]
				return joinLines(ls), nil
			})
		}},
		{ID: "custody-forged-append", What: "append a custody record with a correct prev and seq", Apply: func(p string, _ *Reference) error {
			return rewrite(filepath.Join(p, "chain-of-custody.jsonl"), func(b []byte) ([]byte, error) {
				ls := lines(b)
				last := ls[len(ls)-1]
				rec, _ := json.Marshal(map[string]any{"event": "transfer", "to": "someone else", "seq": len(ls), "ts_utc": "2026-09-21T00:00:00Z", "prev": sha([]byte(last))})
				return joinLines(append(ls, string(rec))), nil
			})
		}},
		{ID: "custody-drop-last", What: "remove the last custody record", Apply: func(p string, _ *Reference) error {
			return rewrite(filepath.Join(p, "chain-of-custody.jsonl"), func(b []byte) ([]byte, error) {
				ls := lines(b)
				return joinLines(ls[:len(ls)-1]), nil
			})
		}},
		{ID: "seal-archive-replace", What: "replace the archived seal seals/SHA256SUMS.1", Apply: func(p string, _ *Reference) error {
			return rewrite(filepath.Join(p, "seals", "SHA256SUMS.1"), func(b []byte) ([]byte, error) {
				return append([]byte(strings.Repeat("0", 64)+"  raw/forged\n"), b...), nil
			})
		}},
		{ID: "seal-archive-plant", What: "add an unlisted seals/SHA256SUMS.0", Apply: func(p string, _ *Reference) error {
			return os.WriteFile(filepath.Join(p, "seals", "SHA256SUMS.0"), []byte("forged history\n"), 0o400)
		}},
		{ID: "sig-archive-replace", What: "replace the archived signature seals/SEAL.sig.1", Apply: func(p string, _ *Reference) error {
			return rewrite(filepath.Join(p, "seals", "SEAL.sig.1"), func(b []byte) ([]byte, error) {
				return bytes.Replace(b, []byte("signature: "), []byte("signature: 00"), 1), nil
			})
		}},
		{ID: "sig-corrupt", What: "corrupt the signature in SEAL.sig", Apply: func(p string, _ *Reference) error {
			return rewrite(filepath.Join(p, "SEAL.sig"), func(b []byte) ([]byte, error) {
				i := bytes.Index(b, []byte("signature: ")) + len("signature: ")
				if b[i] == 'a' {
					b[i] = 'b'
				} else {
					b[i] = 'a'
				}
				return b, nil
			})
		}},
		{ID: "sig-delete", What: "delete SEAL.sig from a package whose last round recorded its signer", Apply: func(p string, _ *Reference) error {
			return os.Remove(filepath.Join(p, "SEAL.sig"))
		}},
		{ID: "sums-drop-raw-line", What: "remove a blob's line from SHA256SUMS", Apply: func(p string, _ *Reference) error {
			return dropLine(filepath.Join(p, "SHA256SUMS"), func(l string) bool { return strings.Contains(l, "  raw/") })
		}},
		{ID: "sums-drop-case-line", What: "remove case.json's line from SHA256SUMS", Apply: func(p string, _ *Reference) error {
			return dropLine(filepath.Join(p, "SHA256SUMS"), func(l string) bool { return strings.HasSuffix(l, "  case.json") })
		}},
		{ID: "sums-drop-seal-line", What: "remove an archived seal's line from SHA256SUMS", Apply: func(p string, _ *Reference) error {
			return dropLine(filepath.Join(p, "SHA256SUMS"), func(l string) bool { return strings.Contains(l, "  seals/") })
		}},
		{ID: "sums-path-escape", What: "add a SHA256SUMS line naming a path outside the package", Apply: func(p string, _ *Reference) error {
			return rewrite(filepath.Join(p, "SHA256SUMS"), func(b []byte) ([]byte, error) {
				return append(b, []byte(strings.Repeat("0", 64)+"  ../outside\n")...), nil
			})
		}},
		{ID: "sums-duplicate-line", What: "list one file twice in SHA256SUMS", Apply: func(p string, _ *Reference) error {
			return rewrite(filepath.Join(p, "SHA256SUMS"), func(b []byte) ([]byte, error) {
				return append(b, []byte(lines(b)[0]+"\n")...), nil
			})
		}},
		{ID: "case-edit", What: "change the operator in case.json", Apply: func(p string, _ *Reference) error {
			return rewrite(filepath.Join(p, "case.json"), func(b []byte) ([]byte, error) {
				return bytes.Replace(b, []byte(`"benchmark"`), []byte(`"nobody"`), 1), nil
			})
		}},
		{ID: "case-edit-resealed", What: "change case.json and rewrite SHA256SUMS to match (signature left alone)", Apply: func(p string, _ *Reference) error {
			if err := rewrite(filepath.Join(p, "case.json"), func(b []byte) ([]byte, error) {
				return bytes.Replace(b, []byte(`"benchmark"`), []byte(`"nobody"`), 1), nil
			}); err != nil {
				return err
			}
			return resum(p)
		}},
		{ID: "rewrite-resealed-resigned", What: "change case.json (operator and recorded signer), rewrite SHA256SUMS, re-sign with the forger's key", Pinned: true,
			Apply: func(p string, r *Reference) error {
				dir, err := os.MkdirTemp("", "forger-")
				if err != nil {
					return err
				}
				defer os.RemoveAll(dir)
				key := filepath.Join(dir, "forger.key")
				if err := seal.GenerateKey(key, key+".pub"); err != nil {
					return err
				}
				fpub, err := seal.PublicKeyHex(key)
				if err != nil {
					return err
				}
				if err := rewrite(filepath.Join(p, "case.json"), func(b []byte) ([]byte, error) {
					b = bytes.Replace(b, []byte(`"benchmark"`), []byte(`"nobody"`), 1)
					return bytes.ReplaceAll(b, []byte(r.Signer), []byte(fpub)), nil
				}); err != nil {
					return err
				}
				if err := resum(p); err != nil {
					return err
				}
				return seal.Sign(p, key)
			}},
	}
}

func runIntegrity(r *Report, work string) error {
	base := filepath.Join(work, "reference.adfir")
	if err := os.MkdirAll(work, 0o700); err != nil {
		return err
	}
	ref, err := BuildReference(base, filepath.Join(work, "seal.key"), filepath.Join(work, "src"))
	if err != nil {
		return err
	}
	in := &r.Integrity
	in.Undetected = []string{}
	in.Reference = fmt.Sprintf("2 rounds, signed (ed25519), plain + gzip blobs, chunked artifact: %t, seals/ archive", ref.Chunked)
	if c, err := integrity.VerifyPackage(base, ""); err != nil || len(c.Package.Problems) != 0 {
		return fmt.Errorf("reference package does not verify before mutation: %v %v", err, c)
	}
	for i, m := range Mutations() {
		dir := filepath.Join(work, fmt.Sprintf("m%02d", i))
		pkg := filepath.Join(dir, "case.adfir")
		if err := copyTree(base, pkg); err != nil {
			return err
		}
		res := MutationResult{ID: m.ID, What: m.What, Mode: "default"}
		if err := m.Apply(pkg, ref); err != nil {
			return fmt.Errorf("mutation %s: %w", m.ID, err)
		}
		pin := ""
		if m.Pinned {
			res.Mode, pin = "pinned", ref.Signer
		}
		c, err := integrity.VerifyPackage(pkg, pin)
		switch {
		case err != nil:
			// verify refusing to open the package at all is a detection.
			res.Detected, res.Problem = true, err.Error()
		case len(c.Package.Problems) > 0:
			res.Detected, res.Problem = true, c.Package.Problems[0]
		}
		// Problems name the scratch path; the report should not.
		res.Problem = strings.ReplaceAll(res.Problem, pkg, "<pkg>")
		in.Total++
		if res.Detected {
			in.Detected++
		} else {
			in.Undetected = append(in.Undetected, m.ID)
			r.fail("integrity: mutation %s (%s) not detected by verify", m.ID, m.What)
		}
		in.Mutations = append(in.Mutations, res)
		_ = os.RemoveAll(dir)
	}
	sort.Strings(in.Undetected)
	return nil
}

// copyTree copies a package directory, keeping it writable.
func copyTree(src, dst string) error {
	if err := os.CopyFS(dst, os.DirFS(src)); err != nil {
		return err
	}
	return filepath.WalkDir(dst, func(p string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Chmod(p, 0o700)
	})
}
