package cli

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v3/internal/casepkg"
	"github.com/efij/AgentDFIR/v3/internal/encrypt"
	"github.com/efij/AgentDFIR/v3/internal/sanitize"
	"github.com/efij/AgentDFIR/v3/internal/store"
	"github.com/efij/AgentDFIR/v3/internal/unpack"
)

// Moving a case to another computer is two commands:
//
//	agentdfir export <case>          → one file, <case>.adfir.tgz, plus its SHA-256
//	agentdfir open <that file>       → verified, analyzed, open in the browser
//
// The file carries the sealed evidence and the analyst's notes, never the
// analysis overlay: that is regenerable, the importing machine rebuilds it
// with its own binary, and a receiver should not have to trust someone
// else's conclusions to read the evidence.

func isOverlay(name string) bool {
	for _, d := range overlayDirs {
		if d == name {
			return true
		}
	}
	return false
}

// exportCase writes pkg as one gzip'd tar and returns its SHA-256.
func exportCase(pkg, dst string) (string, int64, error) {
	pkg = filepath.Clean(pkg)
	if _, err := os.Stat(filepath.Join(pkg, "manifest.jsonl")); err != nil {
		return "", 0, fmt.Errorf("%s is not an evidence package (no manifest.jsonl)", pkg)
	}
	root := filepath.Base(pkg)
	if !strings.HasSuffix(root, ".adfir") {
		root += ".adfir"
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", 0, err
	}
	h := sha256.New()
	cw := &countWriter{w: io.MultiWriter(out, h)}
	gz, _ := gzip.NewWriterLevel(cw, gzip.BestSpeed)
	tw := tar.NewWriter(gz)
	walkErr := filepath.WalkDir(pkg, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(pkg, p)
		if rel == "." {
			return nil
		}
		first := strings.Split(filepath.ToSlash(rel), "/")[0]
		if isOverlay(first) || strings.HasPrefix(d.Name(), ".") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		// Blobs are hardlinks into the shared store: tar the bytes, not the link.
		if !info.Mode().IsRegular() && !info.IsDir() {
			return nil
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = root + "/" + filepath.ToSlash(rel)
		hdr.Uid, hdr.Gid, hdr.Uname, hdr.Gname = 0, 0, "", ""
		if info.IsDir() {
			hdr.Name += "/"
			hdr.Mode = 0o700
			return tw.WriteHeader(hdr)
		}
		hdr.Mode = 0o600
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		_, err = io.Copy(tw, f)
		f.Close()
		return err
	})
	if walkErr == nil {
		walkErr = tw.Close()
	}
	if walkErr == nil {
		walkErr = gz.Close()
	}
	if cerr := out.Close(); walkErr == nil {
		walkErr = cerr
	}
	if walkErr != nil {
		os.Remove(dst)
		return "", 0, walkErr
	}
	return hex.EncodeToString(h.Sum(nil)), cw.n, nil
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

func cmdExportCase(pkg, out string) int {
	if pkg == "" {
		pkg = defaultCase()
		if pkg == "" {
			fmt.Fprintln(os.Stderr, "usage: agentdfir export <case.adfir> [--out file.adfir.tgz]   (no case given and this machine has none yet: run agentdfir run)")
			return 2
		}
	}
	if out == "" {
		out = strings.TrimSuffix(filepath.Base(filepath.Clean(pkg)), ".adfir") + ".adfir.tgz"
	}
	start := time.Now()
	sum, n, err := exportCase(pkg, out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if err := os.WriteFile(out+".sha256", []byte(sum+"  "+filepath.Base(out)+"\n"), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "warning: could not write the checksum file:", err)
	}
	fmt.Printf("Exported %s → %s (%s, %s)\n", sanitize.Terminal(pkg), sanitize.Terminal(out), humanBytes(n), time.Since(start).Round(time.Millisecond))
	fmt.Printf("SHA-256  %s\n", sum)
	fmt.Println("Sealed evidence and case notes are inside; the analysis is rebuilt on the other computer.")
	fmt.Println("It contains whatever the agents saw, credentials included: move it the way you move any evidence.")
	fmt.Printf("\nOn the other computer:  agentdfir open %s\n", filepath.Base(out))
	return 0
}

// cmdOpen opens a case from anywhere: an exported file, an encrypted
// package or a package directory. It verifies the seal, rebuilds the
// analysis and starts the explorer.
func cmdOpen(args []string) int {
	fs := flag.NewFlagSet("open", flag.ContinueOnError)
	port := fs.Int("port", 0, "TCP port on 127.0.0.1 (default: ephemeral)")
	noBrowser := fs.Bool("no-browser", false, "print the URL instead of opening the browser")
	into := fs.String("into", "", "where to unpack an exported file (default: $AGENTDFIR_HOME/imported)")
	src, rest := splitPositional(args)
	if err := fs.Parse(rest); err != nil || (src == "" && fs.NArg() != 1) {
		fmt.Fprintln(os.Stderr, "usage: agentdfir open <case.adfir.tgz | case.adfir.enc | case.adfir> [--port N] [--no-browser]")
		return 2
	}
	if src == "" {
		src = fs.Arg(0)
	}
	pkg, err := importCase(src, *into)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	res, err := casepkg.Verify(pkg)
	switch {
	case err != nil:
		fmt.Fprintln(os.Stderr, "error: verify:", err)
		return 1
	case len(res.Problems) == 0:
		fmt.Printf("Verified: %d artifacts, %d collection and %d custody records, seal intact.\n", res.ArtifactsOK, res.CollectionRecs, res.CustodyRecs)
	default:
		fmt.Printf("WARNING — this package does NOT verify (%d problem(s)); the evidence changed after it was sealed:\n", len(res.Problems))
		for i, p := range res.Problems {
			if i == 10 {
				fmt.Printf("  … %d more (agentdfir verify %s)\n", len(res.Problems)-10, pkg)
				break
			}
			fmt.Printf("  - %s\n", sanitize.Terminal(p))
		}
		fmt.Println("Opening it anyway so you can see it; do not rely on it as evidence until you know why.")
	}
	sargs := []string{pkg}
	if *port != 0 {
		sargs = append(sargs, "--port", fmt.Sprint(*port))
	}
	if !*noBrowser {
		sargs = append(sargs, "--open")
	}
	return cmdServe(sargs)
}

// importCase returns a package directory for src, unpacking or decrypting
// it first when src is a file. An archive already unpacked (same SHA-256)
// is reused, so opening the same file twice is instant.
func importCase(src, into string) (string, error) {
	fi, err := os.Stat(src)
	if err != nil {
		return "", err
	}
	if fi.IsDir() {
		if _, err := os.Stat(filepath.Join(src, "manifest.jsonl")); err != nil {
			return "", fmt.Errorf("%s is a directory but not an evidence package (no manifest.jsonl)", src)
		}
		return src, nil
	}
	if into == "" {
		home, err := store.Home()
		if err != nil {
			return "", err
		}
		into = filepath.Join(home, "imported")
	}
	if err := os.MkdirAll(into, 0o700); err != nil {
		return "", err
	}
	sum, err := fileSum(src)
	if err != nil {
		return "", err
	}
	base := filepath.Base(src)
	for _, ext := range []string{".tgz", ".tar.gz", ".zip", ".tar", ".enc", ".adfir"} {
		base = strings.TrimSuffix(base, ext)
	}
	dest := filepath.Join(into, base+"-"+sum[:8])
	if pkg, ok := findPackage(dest); ok {
		fmt.Printf("Already imported: %s\n", sanitize.Terminal(pkg))
		return pkg, nil
	}
	tmp := dest + ".partial"
	os.RemoveAll(tmp)
	if strings.HasSuffix(src, ".enc") {
		pass := os.Getenv("AGENTDFIR_PASSPHRASE")
		if pass == "" {
			return "", errors.New("encrypted package: set AGENTDFIR_PASSPHRASE (a passphrase is never taken on the command line)")
		}
		if err := encrypt.Decrypt(src, filepath.Join(tmp, base+".adfir"), pass); err != nil {
			os.RemoveAll(tmp)
			return "", err
		}
	} else {
		fmt.Printf("Unpacking %s (SHA-256 %s…)\n", sanitize.Terminal(src), sum[:16])
		st, err := unpack.ExtractArchive(src, tmp, unpack.Options{MaxEntryBytes: 8 << 30, MaxTotalBytes: 512 << 30})
		if err != nil {
			os.RemoveAll(tmp)
			return "", err
		}
		if st.Refused > 0 {
			fmt.Printf("  note: %d entr(ies) with unsafe paths were refused\n", st.Refused)
		}
	}
	if err := os.Rename(tmp, dest); err != nil {
		os.RemoveAll(tmp)
		return "", err
	}
	pkg, ok := findPackage(dest)
	if !ok {
		return "", fmt.Errorf("%s does not contain an evidence package (no manifest.jsonl inside)", src)
	}
	fmt.Printf("Imported to %s\n", sanitize.Terminal(pkg))
	return pkg, nil
}

// findPackage finds the one directory under dir holding a manifest.
func findPackage(dir string) (string, bool) {
	if _, err := os.Stat(filepath.Join(dir, "manifest.jsonl")); err == nil {
		return dir, true
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return "", false
	}
	for _, e := range ents {
		if e.IsDir() {
			p := filepath.Join(dir, e.Name())
			if _, err := os.Stat(filepath.Join(p, "manifest.jsonl")); err == nil {
				return p, true
			}
		}
	}
	return "", false
}

func fileSum(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
