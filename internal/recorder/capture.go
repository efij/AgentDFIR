package recorder

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Default capture roll-over: a new file at this size or age, so retention
// can prune old data while recording continues.
var (
	DefaultRollBytes int64 = 64 << 20
	DefaultRollAge         = time.Hour
)

// Capture is an append-only capture file series for one source:
// <dir>/<source>-<UTC>.<ext>, rolled over at a line boundary once it is
// large or old enough. Every flushed byte range is journaled.
type Capture struct {
	mu        sync.Mutex
	dir       string
	source    string
	ext       string
	jn        Journal
	src       *Source
	RollBytes int64
	RollAge   time.Duration
	f         *os.File
	path      string
	written   int64
	journaled int64
	opened    time.Time
	closed    bool
	paths     []string
	now       func() time.Time
}

// NewCapture prepares a capture series. The first file is created on the
// first write, so a source that never produces data leaves no file.
func NewCapture(dir, source, ext string, jn Journal, src *Source) *Capture {
	return &Capture{dir: dir, source: source, ext: ext, jn: jn, src: src,
		RollBytes: DefaultRollBytes, RollAge: DefaultRollAge, now: time.Now}
}

// SetExt changes the extension used for the next file opened.
func (c *Capture) SetExt(ext string) { c.mu.Lock(); c.ext = ext; c.mu.Unlock() }

// Path is the capture file currently (or last) written; "" before any data.
func (c *Capture) Path() string { c.mu.Lock(); defer c.mu.Unlock(); return c.path }

// Paths lists every file this capture created, oldest first.
func (c *Capture) Paths() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.paths...)
}

// Active is the file still open for writing ("" when none), which
// retention must not touch.
func (c *Capture) Active() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.f == nil {
		return ""
	}
	return c.path
}

func (c *Capture) openLocked() error {
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return err
	}
	stamp := c.now().UTC().Format("20060102T150405Z")
	for i := 1; i < 1000; i++ {
		name := fmt.Sprintf("%s-%s%s", c.source, stamp, c.ext)
		if i > 1 {
			name = fmt.Sprintf("%s-%s-%d%s", c.source, stamp, i, c.ext)
		}
		p := filepath.Join(c.dir, name)
		f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return err
		}
		c.f, c.path, c.written, c.journaled, c.opened = f, p, 0, 0, c.now()
		c.paths = append(c.paths, p)
		if c.src != nil {
			c.src.SetCapture(p)
		}
		return nil
	}
	return fmt.Errorf("%s: no free capture name", c.source)
}

// Write appends raw bytes. The file only rolls over at a line boundary:
// after a write that ends with a newline, or, once the file is due, at the
// last newline inside a write.
func (c *Capture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, os.ErrClosed
	}
	if c.f != nil && c.dueLocked() {
		if i := bytes.LastIndexByte(p, '\n'); i >= 0 && i < len(p)-1 {
			n, err := c.writeLocked(p[:i+1])
			if err != nil {
				return n, err
			}
			m, err := c.writeLocked(p[i+1:])
			return n + m, err
		}
	}
	return c.writeLocked(p)
}

func (c *Capture) dueLocked() bool {
	return (c.RollBytes > 0 && c.written >= c.RollBytes) || (c.RollAge > 0 && c.now().Sub(c.opened) >= c.RollAge)
}

func (c *Capture) writeLocked(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.f == nil {
		if err := c.openLocked(); err != nil {
			if c.src != nil {
				c.src.Problem("capture: " + err.Error())
			}
			return 0, err
		}
	}
	n, err := c.f.Write(p)
	c.written += int64(n)
	if c.src != nil {
		c.src.Observe(p[:n])
	}
	if err == nil && p[n-1] == '\n' && c.dueLocked() {
		c.flushLocked()
		_ = c.f.Close()
		c.f = nil
	}
	return n, err
}

// Flush journals the bytes written since the last flush.
func (c *Capture) Flush() { c.mu.Lock(); c.flushLocked(); c.mu.Unlock() }

func (c *Capture) flushLocked() {
	if c.jn != nil && c.path != "" && c.written > c.journaled {
		c.jn.Grow(c.path, c.journaled, c.written)
	}
	c.journaled = c.written
}

// Close flushes and closes the current file.
func (c *Capture) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	c.flushLocked()
	if c.f != nil {
		err := c.f.Close()
		c.f = nil
		return err
	}
	return nil
}
