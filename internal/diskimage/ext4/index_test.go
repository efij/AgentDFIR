package ext4

import (
	"errors"
	"testing"
)

// Panics must surface in tests and fuzzing instead of becoming errors.
func init() { rethrowPanics = true }

func TestGuardTurnsPanicIntoError(t *testing.T) {
	rethrowPanics = false
	defer func() { rethrowPanics = true }()
	f := func() (err error) {
		defer guard("open", "x", &err)
		var s []byte
		_ = s[3]
		return nil
	}
	if err := f(); !errors.Is(err, errCorrupt) {
		t.Errorf("err = %v", err)
	}
}

func TestLookupUsesIndex(t *testing.T) {
	fsys := openImage(t, "ext4.img.gz")
	in, _, err := fsys.lookup("stat", "frag")
	if err != nil {
		t.Fatal(err)
	}
	dl, err := fsys.entries(in)
	if err != nil || len(dl.idx) != len(dl.ents) || dl.idx["f02"] == 0 {
		t.Errorf("index %v, %v", dl.idx, err)
	}
}
