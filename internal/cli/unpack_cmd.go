package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/efij/AgentDFIR/internal/sanitize"
	"github.com/efij/AgentDFIR/internal/unpack"
)

// collectDocker snapshots a container filesystem (or a saved `docker
// export` tar) into a temp tree holding only agent homes, then runs the
// import-tree collector over it.
func collectDocker(ref string, o importOpts) int {
	tmp, err := os.MkdirTemp("", "agentdfir-docker-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	defer os.RemoveAll(tmp)
	opts := unpack.Options{Filter: unpack.AgentHomeFilter()}
	if o.maxFileMB > 0 {
		opts.MaxEntryBytes = o.maxFileMB << 20
	}
	var st *unpack.Stats
	notes := map[string]string{"mode": "docker"}
	if fi, statErr := os.Stat(ref); statErr == nil && fi.Mode().IsRegular() {
		fmt.Printf("Docker export file: %s\n", sanitize.Terminal(ref))
		st, err = unpack.ExtractArchive(ref, tmp, opts)
		notes["docker_export_file"] = ref
		if st != nil {
			notes["docker_export_sha256"] = st.SHA256
		}
	} else {
		fmt.Printf("Docker container: %s (docker export — read-only, nothing runs inside the container)\n", sanitize.Terminal(ref))
		rc, wait, derr := unpack.DockerExport(ref)
		if derr != nil {
			fmt.Fprintln(os.Stderr, "error:", derr)
			return 1
		}
		st, err = unpack.ExtractTarStream(rc, tmp, opts)
		rc.Close()
		if werr := wait(); werr != nil && err == nil {
			err = werr
		}
		notes["docker_container"] = ref
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("Kept %d agent-related file(s), %d bytes (%d skipped/filtered, %d refused paths)\n", st.Files, st.Bytes, st.Skipped, st.Refused)
	for _, p := range st.Problems {
		fmt.Printf("  note: %s\n", sanitize.Terminal(p))
	}
	if st.Files == 0 {
		fmt.Fprintln(os.Stderr, "no agent configuration or sessions found in the container filesystem")
		return 1
	}
	o.tree, o.notes = tmp, notes
	return collectImport(o)
}

// collectArchive unpacks a zip/tar/tar.gz (CI artifact, support bundle,
// vendor export) and imports whatever agent evidence it holds.
func collectArchive(path string, o importOpts) int {
	tmp, err := os.MkdirTemp("", "agentdfir-archive-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	defer os.RemoveAll(tmp)
	opts := unpack.Options{}
	if o.maxFileMB > 0 {
		opts.MaxEntryBytes = o.maxFileMB << 20
	}
	kind, err := unpack.Kind(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	fmt.Printf("Archive: %s (%s)\n", sanitize.Terminal(filepath.Base(path)), kind)
	st, err := unpack.ExtractArchive(path, tmp, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("Extracted %d file(s), %d bytes (%d skipped, %d refused paths)\n", st.Files, st.Bytes, st.Skipped, st.Refused)
	for _, p := range st.Problems {
		fmt.Printf("  note: %s\n", sanitize.Terminal(p))
	}
	if st.Files == 0 {
		fmt.Fprintln(os.Stderr, "archive contained no regular files")
		return 1
	}
	o.tree = tmp
	o.notes = map[string]string{"mode": "archive", "archive_file": path, "archive_sha256": st.SHA256, "archive_kind": kind}
	o.fallback = true
	return collectImport(o)
}
