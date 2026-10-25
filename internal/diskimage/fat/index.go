package fat

import (
	"io/fs"
	"unicode"
)

// dirList is a parsed directory with a name index built once, so lookups
// cost O(1) per path component instead of a scan of the directory.
type dirList struct {
	ents  []*entry
	exact map[string]*entry
	fold  map[string]*entry
}

func newDirList(ents []*entry) *dirList {
	dl := &dirList{ents: ents, exact: make(map[string]*entry, len(ents)), fold: make(map[string]*entry, len(ents))}
	for _, e := range ents {
		if _, ok := dl.exact[e.name]; !ok {
			dl.exact[e.name] = e
		}
		if k := foldKey(e.name); dl.fold[k] == nil {
			dl.fold[k] = e
		}
	}
	return dl
}

// find prefers an exact match and falls back to a case-insensitive one.
func (dl *dirList) find(name string) *entry {
	if e, ok := dl.exact[name]; ok {
		return e
	}
	return dl.fold[foldKey(name)]
}

// foldKey maps s to a canonical case-folded form: two strings have the
// same key exactly when strings.EqualFold reports them equal.
func foldKey(s string) string {
	r := []rune(s)
	for i, c := range r {
		m := c
		for f := unicode.SimpleFold(c); f != c; f = unicode.SimpleFold(f) {
			m = min(m, f)
		}
		r[i] = m
	}
	return string(r)
}

// guard turns a panic inside an fs API call into an error. It is a
// backstop only: every malformed structure is meant to be rejected before
// it can index out of range. Tests set rethrowPanics so that fuzzing still
// surfaces the underlying bug.
func guard(op, name string, err *error) {
	if r := recover(); r != nil {
		if rethrowPanics {
			panic(r)
		}
		*err = &fs.PathError{Op: op, Path: name, Err: corrupt("internal error on malformed input: %v", r)}
	}
}

// rethrowPanics makes guard re-panic; set only by tests and fuzzing.
var rethrowPanics bool
