package casepkg

import (
	"bytes"
	"compress/gzip"
	"io"
)

// Compression policy. Agent transcripts are JSONL — the most compressible
// evidence there is (measured 5.3x on a real 2.5 MB Claude Code session).
// Everything else is sampled first so already-compressed artifacts
// (archives, images, SQLite, vendored binaries) are stored as-is rather
// than burning CPU on both write and every later read.
//
// gzip, not something denser, is deliberate: it is stdlib, so the tool
// keeps zero runtime dependencies, and an analyst can decompress an
// individual blob with `gunzip` and no AgentDFIR binary in the loop. The
// codec is recorded per blob, so a denser codec can be added later without
// breaking any package written today.

// worthCompressing samples content and reports whether gzip pays for
// itself on it.
func worthCompressing(sample []byte) bool {
	if len(sample) < compressMin {
		return false
	}
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.DefaultCompression)
	if err != nil {
		return false
	}
	if _, err := zw.Write(sample); err != nil {
		return false
	}
	if err := zw.Close(); err != nil {
		return false
	}
	if buf.Len() == 0 {
		return false
	}
	return float64(len(sample))/float64(buf.Len()) >= compressRatio
}

// gzipReader wraps r in a decompressor bounded by the expected plaintext
// size, so a tampered or hostile blob cannot expand without limit before
// the content address would catch it.
func gzipReader(r io.Reader, size int64) (io.ReadCloser, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	return &boundedGzip{zr: zr, rem: size + 1}, nil
}

type boundedGzip struct {
	zr  *gzip.Reader
	rem int64
}

func (b *boundedGzip) Read(p []byte) (int, error) {
	if b.rem <= 0 {
		return 0, errOversize
	}
	if int64(len(p)) > b.rem {
		p = p[:b.rem]
	}
	n, err := b.zr.Read(p)
	b.rem -= int64(n)
	return n, err
}

func (b *boundedGzip) Close() error { return b.zr.Close() }
