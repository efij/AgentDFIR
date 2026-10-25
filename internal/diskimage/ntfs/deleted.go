package ntfs

import (
	"errors"
	"fmt"
	"io"
	"time"
)

// Deleted files: MFT records whose IN_USE flag is clear but that still
// carry a valid FILE signature and update-sequence fixups. Metadata comes
// from the record as it is now. Content is offered only when it cannot be
// someone else's data: resident content (it lives in the record itself),
// or non-resident runs whose every cluster is still free in $Bitmap. A
// cluster that is allocated again may belong to another file, so such
// content is reported "overwritten-or-reallocated" and never returned.
// Even recovered content is unverified: free clusters can have been
// rewritten and freed again since the delete.

const (
	maxDeletedListed = 1 << 20
	bitmapRecord     = 6
	maxBitmapRead    = 1 << 20 // bytes of $Bitmap read per step

	// RecoveredUnverified labels content read back from a deleted record.
	RecoveredUnverified = "RECOVERED_UNVERIFIED"
)

// Content states of a deleted record's unnamed $DATA.
const (
	ContentResident     = "resident"                   // recoverable from the record itself
	ContentUnallocated  = "clusters-unallocated"       // every cluster still free: recoverable
	ContentOverwritten  = "overwritten-or-reallocated" // some cluster allocated again: not returned
	ContentNoData       = "no-data"                    // directory, empty file, or no $DATA
	ContentUnsupported  = StatusUnsupported            // see ContentReason
	ContentNoClusters   = "sparse-only"                // non-resident with no allocated cluster (reads as zeros)
	deletedPathFallback = "(unresolved)"
)

// Times are the four NTFS timestamps (UTC).
type Times struct {
	Created    time.Time `json:"btime,omitzero"`
	Modified   time.Time `json:"mtime,omitzero"`
	MFTChanged time.Time `json:"ctime,omitzero"`
	Accessed   time.Time `json:"atime,omitzero"`
}

// DeletedFile is one not-in-use MFT record.
type DeletedFile struct {
	Record        uint64   `json:"mft_record"`
	Seq           uint16   `json:"mft_seq"`
	Ref           string   `json:"mft_ref"` // hex 64-bit reference (sequence << 48 | record)
	Name          string   `json:"name"`
	ParentRecord  uint64   `json:"parent_record"`
	ParentSeq     uint16   `json:"parent_seq"`
	ParentPath    string   `json:"parent_path"`
	PathStatus    string   `json:"path_status"` // resolved | reused-mft-entry | unresolved
	Directory     bool     `json:"directory,omitempty"`
	Size          int64    `json:"size"`
	SI            *Times   `json:"si_times,omitempty"` // $STANDARD_INFORMATION
	FN            *Times   `json:"fn_times,omitempty"` // $FILE_NAME (of the chosen name)
	Attributes    []string `json:"attributes,omitempty"`
	Resident      bool     `json:"resident"`
	ADS           []string `json:"alternate_data_streams,omitempty"`
	ContentState  string   `json:"content_state"`
	ContentReason string   `json:"content_reason,omitempty"`
	Recoverable   bool     `json:"recoverable"`
	Problem       string   `json:"problem,omitempty"`

	// Set by a caller that writes the content out.
	RecoveredState  string `json:"recovered_state,omitempty"` // RECOVERED_UNVERIFIED
	RecoveredPath   string `json:"recovered_path,omitempty"`
	RecoveredSHA256 string `json:"recovered_sha256,omitempty"`
	RecoveredBytes  int64  `json:"recovered_bytes,omitempty"`
}

// DeletedFiles lists every deleted base record that still has a name, in
// MFT order. It never returns content; see OpenDeleted.
func (f *Volume) DeletedFiles() (out []DeletedFile, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("ntfs: deleted records: %v", r)
		}
	}()
	for _, num := range f.deleted {
		d, _ := f.deletedEntry(num)
		out = append(out, d)
	}
	return out, nil
}

// deletedEntry re-reads one record and describes it; the stream is
// returned when the content is recoverable.
func (f *Volume) deletedEntry(num uint64) (DeletedFile, *stream) {
	d := DeletedFile{Record: num, ParentPath: deletedPathFallback, PathStatus: "unresolved"}
	rec, err := f.v.readRecord(num)
	if rec == nil {
		d.Problem = fmt.Sprint(err)
		d.ContentState, d.ContentReason = ContentUnsupported, "record no longer readable"
		return d, nil
	}
	if err != nil {
		d.Problem = err.Error() + " (partial record used)"
	}
	d.Seq = rec.seq
	d.Ref = fmt.Sprintf("%016x", uint64(rec.seq)<<48|num)
	d.Directory = rec.isDir()
	if rec.inUse() || rec.baseRef != 0 {
		// The record was reused between the walk and now (cannot happen on
		// a read-only image, but the reader does not assume it).
		d.ContentState, d.ContentReason = ContentUnsupported, "record is no longer a deleted base record"
		return d, nil
	}
	as := rec.attrs
	if hasAttr(as, atAttributeList) {
		// Extension records of a deleted file may be reused already;
		// withExtensions refuses ones that name another base record.
		all, err := f.v.withExtensions(rec)
		if err != nil {
			d.Problem = joinProblem(d.Problem, "attribute list: "+err.Error())
		}
		as = all
	}
	nd := &node{rec: num, seq: rec.seq, dir: rec.isDir()}
	nd.fill(as)
	if names := nd.linkNames(); len(names) > 0 {
		fn := names[0]
		d.Name = fn.name
		d.ParentRecord, d.ParentSeq = fn.parent, fn.parentSeq
		d.ParentPath, d.PathStatus = f.refPath(fn.parent, fn.parentSeq)
		d.FN = &Times{Created: fn.times[0], Modified: fn.times[1], MFTChanged: fn.times[2], Accessed: fn.times[3]}
	}
	if nd.si.ok {
		d.SI = &Times{Created: nd.si.btime, Modified: nd.si.mtime, MFTChanged: nd.si.ctime, Accessed: nd.si.atime}
		d.Attributes = AttributeNames(nd.si.attrs)
	}
	d.ADS = nd.ads
	d.Size = nd.size
	frags := dataFragments(as, "")
	switch {
	case len(frags) == 0:
		d.ContentState = ContentNoData
		return d, nil
	case frags[0].resident:
		d.Resident = true
	}
	s, err := f.v.newStream(frags)
	if err != nil {
		d.ContentState, d.ContentReason = ContentUnsupported, err.Error()
		return d, nil
	}
	if s.encrypted {
		d.ContentState, d.ContentReason = ContentUnsupported, "EFS-encrypted content"
		return d, nil
	}
	if d.Resident {
		d.ContentState, d.Recoverable = ContentResident, true
		if s.size == 0 {
			d.ContentState, d.Recoverable = ContentNoData, false
		}
		return d, s
	}
	allocated := 0
	for _, r := range s.runs {
		if r.lcn < 0 {
			continue
		}
		allocated++
		used, err := f.anyClusterAllocated(r.lcn, r.length)
		if err != nil {
			d.ContentState, d.ContentReason = ContentUnsupported, "$Bitmap: "+err.Error()
			return d, nil
		}
		if used {
			d.ContentState = ContentOverwritten
			d.ContentReason = fmt.Sprintf("clusters %d-%d are allocated again in $Bitmap", r.lcn, r.lcn+r.length-1)
			return d, nil
		}
	}
	if allocated == 0 {
		d.ContentState = ContentNoClusters
		return d, nil
	}
	d.ContentState, d.Recoverable = ContentUnallocated, true
	return d, s
}

func joinProblem(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

// bitmapStream opens $Bitmap (record 6) once.
func (f *Volume) bitmapStream() (*stream, error) {
	if f.bitmap != nil || f.bitmapErr != nil {
		return f.bitmap, f.bitmapErr
	}
	nd := f.nodes[bitmapRecord]
	if nd == nil {
		f.bitmapErr = errors.New("record 6 ($Bitmap) not in use")
		return nil, f.bitmapErr
	}
	s, err := f.dataStream(nd)
	if err == nil && s.size*8 < f.v.clusters {
		err = fmt.Errorf("%d bytes cover fewer than the volume's %d clusters", s.size, f.v.clusters)
	}
	f.bitmap, f.bitmapErr = s, err
	if err != nil {
		f.bitmap = nil
	}
	return f.bitmap, f.bitmapErr
}

// anyClusterAllocated reports whether any cluster in [lcn, lcn+n) is set
// in $Bitmap. Reads are chunked, so a hostile run length costs time
// bounded by the volume size, not memory.
func (f *Volume) anyClusterAllocated(lcn, n int64) (bool, error) {
	bm, err := f.bitmapStream()
	if err != nil {
		return false, err
	}
	if lcn < 0 || n <= 0 || lcn+n > f.v.clusters || lcn+n < lcn {
		return false, fmt.Errorf("run %d+%d outside the volume", lcn, n)
	}
	end := lcn + n
	buf := make([]byte, min(maxBitmapRead, (n+7)/8+1))
	for c := lcn; c < end; {
		first := c / 8
		want := min(int64(len(buf)), (end+7)/8-first)
		b := buf[:want]
		if _, err := bm.ReadAt(b, first); err != nil && !errors.Is(err, io.EOF) {
			return false, err
		}
		for i := range b {
			byteIdx := first + int64(i)
			for bit := 0; bit < 8; bit++ {
				cl := byteIdx*8 + int64(bit)
				if cl < c || cl >= end {
					continue
				}
				if b[i]&(1<<bit) != 0 {
					return true, nil
				}
			}
		}
		c = (first + want) * 8
	}
	return false, nil
}

// OpenDeleted returns the content of a deleted record when DeletedFiles
// marked it recoverable, with its logical size. Anything else is refused:
// content on reallocated clusters is never returned.
func (f *Volume) OpenDeleted(record uint64) (r io.ReaderAt, size int64, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("ntfs: deleted record %d: %v", record, p)
		}
	}()
	listed := false
	for _, n := range f.deleted {
		if n == record {
			listed = true
			break
		}
	}
	if !listed {
		return nil, 0, fmt.Errorf("ntfs: record %d is not a listed deleted record", record)
	}
	d, s := f.deletedEntry(record)
	if !d.Recoverable || s == nil {
		return nil, 0, fmt.Errorf("ntfs: record %d content not recoverable: %s %s", record, d.ContentState, d.ContentReason)
	}
	return s, s.size, nil
}
