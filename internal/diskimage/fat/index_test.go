package fat

import (
	"errors"
	"strings"
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

func TestFoldKeyMatchesEqualFold(t *testing.T) {
	pairs := [][2]string{{"Home", "HOME"}, {"straße", "STRASSE"}, {"KelvinK", "kelvink"}, {"ǅ", "ǆ"}, {"a", "b"}}
	for _, p := range pairs {
		if got, want := foldKey(p[0]) == foldKey(p[1]), strings.EqualFold(p[0], p[1]); got != want {
			t.Errorf("%q vs %q: foldKey equal %v, EqualFold %v", p[0], p[1], got, want)
		}
	}
}
