package journal

import "os"

// FileID is the device:inode identity the journal records for a file
// ("" where the platform does not expose it from os.FileInfo).
func FileID(fi os.FileInfo) string { return fileID(fi) }

// Prune records that a retention policy is about to delete path: its size
// and full-content SHA-256 at deletion, and why. When the file was
// journaled by this monitor, the record also carries what the journal had
// for it (size and running prefix hash), so verification can tell the
// file was deleted intact rather than edited first. A prune record is the
// only thing that turns a missing capture file from a deletion into an
// accounted-for one; journal entries themselves are never pruned.
func (j *Journal) Prune(path string, size int64, sha256hex, reason string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return
	}
	rec := map[string]any{"kind": "prune", "path": path, "size": size, "sha256": sha256hex, "reason": reason}
	if st, ok := j.files[path]; ok {
		rec["journaled_size"] = st.size
		rec["prefix_sha256"] = sum(st.h)
		delete(j.files, path)
	}
	_ = j.append(rec)
	j.maybeSeal()
}

// PruneFailed records that a prune recorded just before did not delete
// the file (the file is still there and still verifiable).
func (j *Journal) PruneFailed(path, reason string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return
	}
	_ = j.append(map[string]any{"kind": "prune_failed", "path": path, "reason": reason})
}
