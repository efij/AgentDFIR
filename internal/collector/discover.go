package collector

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/efij/AgentDFIR/internal/products"
)

// Profile is a user profile root found inside a triage tree, with the
// products whose configuration is present in it.
type Profile struct {
	Path     string
	User     string   // profile directory name (best-effort attribution)
	Products []string // product IDs detected by config presence
}

// DiscoverProfiles walks a KAPE / Velociraptor / CyLR / disk-image tree and
// returns every directory that looks like a user profile holding at least
// one known AI agent product. Detection is by config presence only —
// nothing is executed and symlinks are never followed. maxDepth bounds
// the walk (triage trees nest: uploads/<client>/C%3A/Users/<u>/…).
func DiscoverProfiles(root string, prods []products.Product, maxDepth int) []Profile {
	root = filepath.Clean(root)
	var out []Profile
	rootDepth := strings.Count(root, string(filepath.Separator))
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return filepath.SkipDir
		}
		if strings.Count(path, string(filepath.Separator))-rootDepth > maxDepth {
			return filepath.SkipDir
		}
		var found []string
		for _, p := range prods {
			if hasProduct(path, p) {
				found = append(found, p.ID)
			}
		}
		if len(found) > 0 {
			sort.Strings(found)
			out = append(out, Profile{Path: path, User: filepath.Base(path), Products: found})
			// A profile's subtree is not itself a profile.
			return filepath.SkipDir
		}
		return nil
	})
	return out
}

func hasProduct(profile string, p products.Product) bool {
	for _, d := range p.ConfigDirs {
		if fi, err := os.Lstat(filepath.Join(profile, filepath.FromSlash(d))); err == nil && fi.IsDir() {
			return true
		}
	}
	for _, f := range p.ConfigFiles {
		if fi, err := os.Lstat(filepath.Join(profile, filepath.FromSlash(f))); err == nil && fi.Mode().IsRegular() {
			return true
		}
	}
	return false
}
