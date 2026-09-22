package cli

import (
	"flag"
	"fmt"
	"os"

	"github.com/efij/AgentDFIR/v2/internal/store"
)

// cmdStore inspects and reclaims the per-machine shared evidence store.
//
// Identical evidence is stored once and hardlinked into each case that
// references it. When a case directory is deleted, its blobs lose that
// reference but stay in the store, so without reclamation the store would
// only ever grow — the same disk problem in a new place.
func cmdStore(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: agentdfir store <status|gc> [--delete]")
		return 2
	}
	switch args[0] {
	case "status":
		return storeStatus()
	case "gc":
		return storeGC(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown store subcommand %q (status, gc)\n", args[0])
		return 2
	}
}

func storeStatus() int {
	home, err := store.Home()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	st, err := store.Status()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("Home:          %s\n", home)
	fmt.Printf("Store:         %s\n", st.Dir)
	fmt.Printf("Blobs:         %d (%s)\n", st.Blobs, humanBytes(st.Bytes))
	if !store.LinkCountsAvailable {
		fmt.Println("Unreferenced:  unknown on this platform — the OS does not report how many")
		fmt.Println("               cases link to a blob, so the store never deletes on a guess.")
		fmt.Println("               Delete the whole store directory to reclaim it.")
		return 0
	}
	fmt.Printf("Unreferenced:  %d (%s) — no case links to these any more\n", st.Unreferenced, humanBytes(st.UnreferencedBytes))
	if st.Unreferenced > 0 {
		fmt.Println("\nReclaim them with: agentdfir store gc --delete")
	}
	return 0
}

func storeGC(args []string) int {
	fs := flag.NewFlagSet("store gc", flag.ContinueOnError)
	del := fs.Bool("delete", false, "actually remove the unreferenced blobs (default: report only)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	res, err := store.GC(!*del)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if !res.Supported {
		fmt.Println("This platform does not report how many cases link to a blob, so the shared")
		fmt.Println("store cannot prove one is unreferenced and will not delete on a guess.")
		fmt.Println("Nothing was removed. Delete the store directory itself to reclaim it.")
		return 0
	}
	if res.DryRun {
		fmt.Printf("Would remove %d unreferenced blob(s), reclaiming %s.\n", res.Removed, humanBytes(res.Bytes))
		fmt.Println("Nothing was deleted. Re-run with --delete to reclaim.")
		return 0
	}
	fmt.Printf("Removed %d unreferenced blob(s), reclaimed %s.\n", res.Removed, humanBytes(res.Bytes))
	return 0
}
