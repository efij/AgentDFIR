package ext4

import "io/fs"

// dirList is a parsed directory with a name index built once, so lookups
// cost O(1) per path component instead of a scan of the directory.
type dirList struct {
	ents []dirent
	idx  map[string]uint32 // first entry wins on duplicate names
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
