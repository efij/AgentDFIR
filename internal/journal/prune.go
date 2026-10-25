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
//
// prefixSize/prefixSHA are the SHA-256 of the file's first prefixSize
// bytes, hashed in the same pass as the whole file, where prefixSize is
// what the journal had recorded for it: verification compares it with the
// journal's running prefix hash, so bytes that were journaled and then
// altered are caught even when more was appended after the last flush.
func (j *Journal) Prune(path string, size int64, sha256hex string, prefixSize int64, prefixSHA, reason string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return
	}
	rec := map[string]any{"kind": "prune", "path": path, "size": size, "sha256": sha256hex, "reason": reason}
	if prefixSHA != "" {
		rec["prune_prefix_size"] = prefixSize
		rec["prune_prefix_sha256"] = prefixSHA
	}
	if st, ok := j.files[path]; ok {
		rec["journaled_size"] = st.size
		rec["prefix_sha256"] = sum(st.h)
		delete(j.files, path)
	}
	_ = j.append(rec)
	j.maybeSeal()
}

// JournaledSize is how many bytes of path this journal recorded in the
// current session (false when it has not journaled the file since it
// opened).
func (j *Journal) JournaledSize(path string) (int64, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if st, ok := j.files[path]; ok {
		return st.size, true
	}
	return 0, false
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
