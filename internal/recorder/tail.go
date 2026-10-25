package recorder

import (
	"errors"
	"io"
	"io/fs"
	"os"
)

// Tailer follows one growing log file read-only (auditd's audit.log, a
// Tetragon/Falco JSON export, a Sysmon XML export) and copies every new
// byte to Out. It follows rotation: when the path is renamed away or
// replaced, the old file is read to its end first, then the new one from
// the start; a file truncated in place (copytruncate) restarts at 0.
type Tailer struct {
	Path      string
	Src       *Source
	Out       io.Writer
	FromStart bool  // also copy what the file already holds at the first open
	MaxPoll   int64 // bytes copied per poll (default 32 MiB): a burst never stalls the loop
	// OnOpen runs after each successful open (format sniffing).
	OnOpen func(path string)
	// Open and Stat are injectable for tests.
	Open func(string) (*os.File, error)
	Stat func(string) (os.FileInfo, error)

	f       *os.File
	fi      os.FileInfo
	off     int64
	opened  bool // has been open at least once
	missing bool
	last    byte // last byte copied
}

func (t *Tailer) open(name string) (*os.File, error) {
	if t.Open != nil {
		return t.Open(name)
	}
	return os.Open(name)
}

func (t *Tailer) stat(name string) (os.FileInfo, error) {
	if t.Stat != nil {
		return t.Stat(name)
	}
	return os.Stat(name)
}

// Poll copies whatever is new since the last poll.
func (t *Tailer) Poll() {
	if t.f == nil && !t.openFile() {
		return
	}
	eof := t.drain()
	cur, err := t.stat(t.Path)
	if err != nil || !os.SameFile(t.fi, cur) {
		// Renamed away (and maybe recreated): finish the old file, then
		// start the new one from its first byte.
		for !eof {
			eof = t.drain()
		}
		t.endLine()
		t.closeFile()
		t.Src.Rotated()
		if t.openFile() {
			t.drain()
		}
		return
	}
	if cur.Size() < t.off {
		t.Src.Rotated()
		t.Src.Note("input truncated in place (copytruncate rotation); bytes written between the last poll and the truncation are not captured")
		t.endLine()
		t.off = 0
		t.fi = cur
		t.drain()
	}
}

// endLine keeps a partial last line of a rotated file from running into
// the first line of the next one in the capture.
func (t *Tailer) endLine() {
	if t.last != 0 && t.last != '\n' {
		_, _ = t.Out.Write([]byte{'\n'})
		t.last = '\n'
	}
}

func (t *Tailer) openFile() bool {
	f, err := t.open(t.Path)
	if err != nil {
		switch {
		case errors.Is(err, fs.ErrPermission):
			t.Src.Problem("permission denied reading " + t.Path + ": run the monitor as root (audit.log is root-only) or grant read access")
			t.Src.SetState("error")
		case errors.Is(err, fs.ErrNotExist):
			if !t.missing {
				t.Src.Note("waiting for " + t.Path + " to appear")
			}
			t.missing = true
			if t.Src.Snapshot().State != "error" {
				t.Src.SetState("waiting")
			}
		default:
			t.Src.Problem("cannot open " + t.Path + ": " + err.Error())
			t.Src.SetState("error")
		}
		return false
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		f.Close()
		t.Src.Problem(t.Path + " is not a regular file")
		t.Src.SetState("error")
		return false
	}
	t.f, t.fi, t.missing = f, fi, false
	t.off = 0
	if !t.opened && !t.FromStart {
		t.off = fi.Size() // existing content is history: collect it with --endpoint
	}
	t.opened = true
	t.Src.SetState("running")
	if t.OnOpen != nil {
		t.OnOpen(t.Path)
	}
	return true
}

func (t *Tailer) closeFile() {
	if t.f != nil {
		_ = t.f.Close()
		t.f = nil
	}
}

// drain copies [off, EOF) of the open file, bounded per poll. It reports
// whether it stopped at the end of the file (or on an error).
func (t *Tailer) drain() bool {
	max := t.MaxPoll
	if max <= 0 {
		max = 32 << 20
	}
	buf := make([]byte, 256<<10)
	var done int64
	for done < max {
		n, err := t.f.ReadAt(buf, t.off)
		if n > 0 {
			if _, werr := t.Out.Write(buf[:n]); werr != nil {
				t.Src.Problem("capture write: " + werr.Error())
				return true
			}
			t.off += int64(n)
			done += int64(n)
			t.last = buf[n-1]
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				t.Src.Problem("read " + t.Path + ": " + err.Error())
			}
			return true
		}
	}
	return false
}

// Close releases the input file.
func (t *Tailer) Close() {
	t.closeFile()
	t.Src.SetState("stopped")
}
