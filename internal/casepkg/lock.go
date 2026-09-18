package casepkg

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// errOversize is returned when decompression exceeds the recorded size.
var errOversize = errors.New("decompressed size exceeds recorded size")

// Package locking. With a stable default package location, two
// collections can easily be started at once — from two terminals, or a
// scheduled run overlapping a manual one. Both would append to the same
// hash-chained logs and to the same manifest, interleaving lines and
// corrupting the chain irrecoverably. A collect→seal cycle therefore holds
// an exclusive lock on the package.
//
// The lock is not evidence: it lives outside the sealed zone and is never
// covered by SHA256SUMS.

type lockInfo struct {
	PID       int    `json:"pid"`
	Host      string `json:"host"`
	StartedAt string `json:"started_at"`
}

type lockHandle struct {
	path     string
	released bool
}

// acquireLock takes the package lock, refusing rather than stealing when
// another live process holds it. A lock left behind by a process that no
// longer exists is reported and reclaimed — a crashed collection must not
// wedge a case forever.
func acquireLock(dir string) (*lockHandle, error) {
	path := filepath.Join(dir, lockFile)
	host, _ := os.Hostname()
	self := lockInfo{PID: os.Getpid(), Host: host, StartedAt: time.Now().UTC().Format(time.RFC3339)}
	data, _ := json.Marshal(self)

	for attempt := 0; attempt < 2; attempt++ {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_, wErr := f.Write(append(data, '\n'))
			cErr := f.Close()
			if wErr != nil {
				os.Remove(path)
				return nil, wErr
			}
			if cErr != nil {
				os.Remove(path)
				return nil, cErr
			}
			return &lockHandle{path: path}, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("lock package: %w", err)
		}
		held, hErr := readLock(path)
		if hErr != nil {
			return nil, fmt.Errorf("package is locked (unreadable lock file %s): %w", path, hErr)
		}
		if held.Host == host && !processAlive(held.PID) {
			// Stale: the owner is gone. Reclaim once, then retry.
			if rErr := os.Remove(path); rErr != nil {
				return nil, fmt.Errorf("package is locked by a dead process (pid %d) and the lock could not be cleared: %w", held.PID, rErr)
			}
			continue
		}
		return nil, fmt.Errorf("package is in use by %s pid %d (since %s); finish or stop that run first",
			held.Host, held.PID, held.StartedAt)
	}
	return nil, fmt.Errorf("could not acquire package lock at %s", path)
}

func readLock(path string) (lockInfo, error) {
	var li lockInfo
	data, err := os.ReadFile(path)
	if err != nil {
		return li, err
	}
	if err := json.Unmarshal(data, &li); err != nil {
		return li, err
	}
	return li, nil
}

func (l *lockHandle) release() {
	if l == nil || l.released {
		return
	}
	l.released = true
	os.Remove(l.path)
}
