package ntfs

import (
	"fmt"
	"io"
	"math"
	"sort"
	"sync"
)

// stream reads one attribute's content: resident bytes, or non-resident
// data runs (sparse runs and bytes past the initialized size read as
// zeros; LZNT1 compression units are inflated on demand).
type stream struct {
	v          *volume
	resident   []byte
	runs       []run
	size       int64 // logical (data) size
	initSize   int64
	compressed bool
	cuClusters int64 // clusters per compression unit
	encrypted  bool

	mu    sync.Mutex
	cuIdx int64
	cu    []byte
}

// newStream assembles a stream from an attribute's fragments (ordered by
// start VCN). Sizes and flags come from the first fragment.
func (v *volume) newStream(frags []attr) (*stream, error) {
	if len(frags) == 0 {
		return nil, fmt.Errorf("no $DATA attribute")
	}
	f0 := frags[0]
	s := &stream{v: v, cuIdx: -1, encrypted: f0.flags&afEncrypted != 0}
	if f0.resident {
		s.resident = f0.value
		s.size = int64(len(f0.value))
		s.initSize = s.size
		return s, nil
	}
	if f0.startVCN != 0 {
		return nil, fmt.Errorf("first $DATA fragment starts at VCN %d", f0.startVCN)
	}
	s.size, s.initSize = f0.dataSize, f0.initSize
	if s.initSize > s.size {
		s.initSize = s.size
	}
	if f0.flags&afCompressed != 0 && f0.compUnit != 0 {
		if f0.compUnit > 16 || v.clusterSize<<f0.compUnit > maxCompressionUnit {
			return nil, fmt.Errorf("%w: compression unit 2^%d clusters", ErrUnsupported, f0.compUnit)
		}
		s.compressed = true
		s.cuClusters = 1 << f0.compUnit
	}
	next := int64(0)
	for _, fr := range frags {
		if fr.resident || fr.runListErr != nil && len(fr.runs) == 0 {
			if fr.runListErr != nil {
				return nil, fr.runListErr
			}
			return nil, fmt.Errorf("resident fragment after non-resident data")
		}
		if fr.startVCN != next {
			return nil, fmt.Errorf("$DATA fragments leave a gap at VCN %d", next)
		}
		for _, r := range fr.runs {
			if r.vcn+r.length > math.MaxInt64/v.clusterSize {
				return nil, fmt.Errorf("run at VCN %d (+%d) overflows the byte range", r.vcn, r.length)
			}
			if r.lcn >= 0 && (r.lcn+r.length > v.clusters || r.lcn+r.length < r.lcn) {
				return nil, fmt.Errorf("run at LCN %d (+%d) outside the volume", r.lcn, r.length)
			}
			s.runs = append(s.runs, r)
			next = r.vcn + r.length
		}
		if fr.runListErr != nil {
			return nil, fr.runListErr
		}
	}
	if s.size > next*v.clusterSize && s.size > 0 {
		return nil, fmt.Errorf("data size %d exceeds the %d clusters mapped", s.size, next)
	}
	return s, nil
}

// lookup finds the run holding vcn (runs are sorted and contiguous).
func (s *stream) lookup(vcn int64) (run, bool) {
	i := sort.Search(len(s.runs), func(i int) bool { return s.runs[i].vcn+s.runs[i].length > vcn })
	if i < len(s.runs) && s.runs[i].vcn <= vcn {
		return s.runs[i], true
	}
	return run{}, false
}

func (s *stream) ReadAt(p []byte, off int64) (int, error) {
	if s.encrypted {
		return 0, fmt.Errorf("%w: EFS-encrypted content", ErrUnsupported)
	}
	if off < 0 {
		return 0, fmt.Errorf("negative offset")
	}
	if off >= s.size {
		return 0, io.EOF
	}
	want := len(p)
	if rem := s.size - off; int64(len(p)) > rem {
		p = p[:rem]
	}
	if s.resident != nil || s.runs == nil {
		n := copy(p, s.resident[min(off, int64(len(s.resident))):])
		clear(p[n:])
		return s.ret(len(p), want)
	}
	if s.compressed {
		if err := s.readCompressed(p, off); err != nil {
			return 0, err
		}
		return s.ret(len(p), want)
	}
	cs := s.v.clusterSize
	done := 0
	for done < len(p) {
		pos := off + int64(done)
		n := len(p) - done
		if pos >= s.initSize {
			clear(p[done:])
			break
		}
		if rem := s.initSize - pos; int64(n) > rem {
			n = int(rem)
		}
		r, ok := s.lookup(pos / cs)
		if !ok {
			return done, fmt.Errorf("offset %d not mapped by any run", pos)
		}
		in := pos - r.vcn*cs
		if rem := r.length*cs - in; int64(n) > rem {
			n = int(rem)
		}
		if r.lcn < 0 {
			clear(p[done : done+n])
		} else if _, err := s.v.r.ReadAt(p[done:done+n], r.lcn*cs+in); err != nil {
			return done, err
		}
		done += n
	}
	return s.ret(len(p), want)
}

func (s *stream) ret(n, want int) (int, error) {
	if n < want {
		return n, io.EOF
	}
	return n, nil
}

// readCompressed serves p from whole compression units.
func (s *stream) readCompressed(p []byte, off int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cuBytes := s.cuClusters * s.v.clusterSize
	done := 0
	for done < len(p) {
		pos := off + int64(done)
		idx := pos / cuBytes
		if idx != s.cuIdx {
			data, err := s.unit(idx, cuBytes)
			if err != nil {
				return err
			}
			s.cuIdx, s.cu = idx, data
		}
		in := pos - idx*cuBytes
		n := copy(p[done:], s.cu[in:])
		if n == 0 {
			return fmt.Errorf("compression unit %d empty", idx)
		}
		done += n
	}
	return nil
}

// unit returns compression unit idx decompressed. All-sparse → zeros;
// fully allocated → stored uncompressed; partly allocated → LZNT1 data in
// the allocated clusters.
func (s *stream) unit(idx, cuBytes int64) ([]byte, error) {
	cs := s.v.clusterSize
	first := idx * s.cuClusters
	var stored []byte
	allocated := int64(0)
	for vcn := first; vcn < first+s.cuClusters; {
		r, ok := s.lookup(vcn)
		if !ok {
			break
		}
		n := r.vcn + r.length - vcn
		if n > first+s.cuClusters-vcn {
			n = first + s.cuClusters - vcn
		}
		if r.lcn >= 0 {
			buf := make([]byte, n*cs)
			if _, err := s.v.r.ReadAt(buf, (r.lcn+vcn-r.vcn)*cs); err != nil {
				return nil, err
			}
			stored = append(stored, buf...)
			allocated += n
		}
		vcn += n
	}
	out := make([]byte, cuBytes)
	switch {
	case allocated == 0:
		return out, nil
	case allocated == s.cuClusters:
		copy(out, stored)
		return out, nil
	}
	data, err := decompressLZNT1(stored, int(cuBytes))
	if err != nil {
		return nil, fmt.Errorf("compression unit %d: %w", idx, err)
	}
	copy(out, data)
	return out, nil
}
