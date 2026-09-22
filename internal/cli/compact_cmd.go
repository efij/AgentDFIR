package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/efij/AgentDFIR/v2/internal/sanitize"
)

// overlayDirs are the directories `analyze` and `report` derive from the
// sealed evidence. Every one of them is excluded from SHA256SUMS by design
// (see package casepkg), which is exactly what makes deleting them safe:
// nothing here is evidence, and `agentdfir verify` proves the same thing
// before and after.
var overlayDirs = []string{"normalized", "detections", "reports", "index"}

// cmdCompact deletes the analysis overlay from a package.
//
// A case package is two things stacked on each other: the sealed evidence,
// and the analysis derived from it. On a real case the sealed zone was
// 525 MB and the overlay on top of it was another ~300 MB — normalized/
// 178 MB, detections/ 120 MB — so the derived half had grown to rival the
// evidence it came from. Storing the overlay compressed shrinks it by
// about an order of magnitude; this command is the other half of the
// answer, for an archived case nobody is working any more: throw the
// derived half away entirely and get it back from `analyze` on the day
// someone reopens the case.
func cmdCompact(args []string) int {
	fs := flag.NewFlagSet("compact", flag.ContinueOnError)
	dryRun := fs.Bool("dry-run", false, "report what would be reclaimed, delete nothing")
	// The package is accepted on either side of the flags, the way analyze
	// does it: `compact <pkg> --dry-run` is what an analyst actually types,
	// and Go's flag package stops parsing at the first positional on its own.
	pkg, rest := splitPositional(args)
	if err := fs.Parse(rest); err != nil || (pkg == "" && fs.NArg() != 1) || (pkg != "" && fs.NArg() != 0) {
		fmt.Fprintln(os.Stderr, "usage: agentdfir compact <package-dir> [--dry-run]")
		return 2
	}
	if pkg == "" {
		pkg = fs.Arg(0)
	}

	// Refuse anything that is not a package. Pointed at a wrong path this
	// command would otherwise silently delete four directories that happen
	// to share those names.
	if _, err := os.Stat(filepath.Join(pkg, "SHA256SUMS")); err != nil {
		fmt.Fprintf(os.Stderr, "not a sealed package (no SHA256SUMS): %s\n", sanitize.Terminal(pkg))
		return 1
	}

	var total int64
	var present []string
	for _, d := range overlayDirs {
		n, err := dirBytes(filepath.Join(pkg, d))
		if err != nil {
			continue
		}
		total += n
		present = append(present, fmt.Sprintf("%s (%s)", d+string(filepath.Separator), humanBytes(n)))
	}
	if len(present) == 0 {
		fmt.Printf("Package:   %s\n", sanitize.Terminal(pkg))
		fmt.Println("Overlay:   none — nothing to reclaim.")
		return 0
	}

	fmt.Printf("Package:   %s\n", sanitize.Terminal(pkg))
	for i, p := range present {
		label := "Overlay:"
		if i > 0 {
			label = "        "
		}
		fmt.Printf("%-10s %s\n", label, p)
	}
	if *dryRun {
		fmt.Printf("Would reclaim %s. Nothing was deleted.\n", humanBytes(total))
		return 0
	}
	for _, d := range overlayDirs {
		if err := os.RemoveAll(filepath.Join(pkg, d)); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
	}
	fmt.Printf("Reclaimed: %s\n", humanBytes(total))
	fmt.Println("The overlay is derived from the sealed evidence and is excluded from")
	fmt.Println("SHA256SUMS, so nothing evidential was touched — `agentdfir verify` proves")
	fmt.Printf("exactly what it did before. It rebuilds on the next `agentdfir analyze %s`.\n", sanitize.Terminal(pkg))
	return 0
}

// dirBytes sums the apparent size of every file under dir. Symlinks are
// counted but never followed: a case directory is evidence-adjacent and
// this command deletes what it measures.
func dirBytes(dir string) (int64, error) {
	fi, err := os.Stat(dir)
	if err != nil {
		return 0, err
	}
	if !fi.IsDir() {
		return 0, os.ErrInvalid
	}
	var total int64
	err = filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil // an unreadable entry is not worth failing the whole count
		}
		if !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	return total, err
}
