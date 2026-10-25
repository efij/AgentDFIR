package ntfs

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unicode/utf16"
)

// Builders for USN_RECORD_V2 / V3 / V4 byte images, laid out as
// documented for FSCTL_READ_USN_JOURNAL output. They write the synthetic
// $J content of testdata/usn-deleted.ntfs.gz (see gen_fixture_test.go)
// and the byte-level parser tests.

type usnSpec struct {
	file, parent    uint64 // 64-bit references (seq << 48 | record)
	usn             int64
	ts              time.Time
	reason, source  uint32
	security, attrs uint32
	name            string
	extents         int // V4 only
}

func toFiletime(t time.Time) uint64 {
	if t.IsZero() {
		return 0
	}
	return uint64(t.UnixNano()/100 + 116444736000000000)
}

func utf16Bytes(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

func align8(n int) int { return (n + 7) &^ 7 }

func buildUSNv2(s usnSpec) []byte {
	name := utf16Bytes(s.name)
	b := make([]byte, align8(60+len(name)))
	le := binary.LittleEndian
	le.PutUint32(b[0:], uint32(len(b)))
	le.PutUint16(b[4:], 2)
	le.PutUint64(b[8:], s.file)
	le.PutUint64(b[16:], s.parent)
	le.PutUint64(b[24:], uint64(s.usn))
	le.PutUint64(b[32:], toFiletime(s.ts))
	le.PutUint32(b[40:], s.reason)
	le.PutUint32(b[44:], s.source)
	le.PutUint32(b[48:], s.security)
	le.PutUint32(b[52:], s.attrs)
	le.PutUint16(b[56:], uint16(len(name)))
	le.PutUint16(b[58:], 60)
	copy(b[60:], name)
	return b
}

func buildUSNv3(s usnSpec) []byte {
	name := utf16Bytes(s.name)
	b := make([]byte, align8(76+len(name)))
	le := binary.LittleEndian
	le.PutUint32(b[0:], uint32(len(b)))
	le.PutUint16(b[4:], 3)
	le.PutUint64(b[8:], s.file) // high 64 bits stay zero on NTFS
	le.PutUint64(b[24:], s.parent)
	le.PutUint64(b[40:], uint64(s.usn))
	le.PutUint64(b[48:], toFiletime(s.ts))
	le.PutUint32(b[56:], s.reason)
	le.PutUint32(b[60:], s.source)
	le.PutUint32(b[64:], s.security)
	le.PutUint32(b[68:], s.attrs)
	le.PutUint16(b[72:], uint16(len(name)))
	le.PutUint16(b[74:], 76)
	copy(b[76:], name)
	return b
}

// buildUSNv4: header, two 128-bit refs, USN, reason, source,
// RemainingExtents, NumberOfExtents, ExtentSize (16), extents.
func buildUSNv4(s usnSpec) []byte {
	b := make([]byte, align8(80+16*s.extents))
	le := binary.LittleEndian
	le.PutUint32(b[0:], uint32(len(b)))
	le.PutUint16(b[4:], 4)
	le.PutUint64(b[8:], s.file)
	le.PutUint64(b[24:], s.parent)
	le.PutUint64(b[40:], uint64(s.usn))
	le.PutUint32(b[48:], s.reason)
	le.PutUint32(b[52:], s.source)
	le.PutUint16(b[60:], uint16(s.extents))
	le.PutUint16(b[62:], 16)
	for i := 0; i < s.extents; i++ {
		le.PutUint64(b[64+16*i:], uint64(i)*4096)
		le.PutUint64(b[72+16*i:], 4096)
	}
	return b
}

func mkref(rec uint64, seq uint16) uint64 { return uint64(seq)<<48 | rec }

// usnFixtureBytes returns the USN/deleted volume (4 MiB, ntfs-3g made,
// synthetic $J content patched in; see testdata/README.md).
func usnFixtureBytes(t testing.TB) []byte {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "usn-deleted.ntfs.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func openUSNFixture(t testing.TB) *Volume {
	t.Helper()
	b := usnFixtureBytes(t)
	v, err := OpenVolume(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	return v
}
