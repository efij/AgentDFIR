package cli

import (
	"flag"
	"fmt"
	"os"

	"github.com/efij/AgentDFIR/v5/internal/hashchain"
	"github.com/efij/AgentDFIR/v5/internal/journal"
	"github.com/efij/AgentDFIR/v5/internal/sanitize"
)

// cmdJournal: agentdfir journal verify [path] [--anchor <head>].
func cmdJournal(args []string) int {
	if len(args) == 0 || args[0] != "verify" {
		fmt.Fprintln(os.Stderr, "usage: agentdfir journal verify [journal.jsonl] [--anchor <head>] [--no-files]")
		return 2
	}
	fs := flag.NewFlagSet("journal verify", flag.ContinueOnError)
	anchor := fs.String("anchor", "", "a chain head recorded elsewhere (syslog, --journal-anchor file); must still be in the chain")
	noFiles := fs.Bool("no-files", false, "check the chain only, not the recorder's capture files next to it")
	p, rest := splitPositional(args[1:])
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if p == "" {
		home, _ := os.UserHomeDir()
		p = journal.DefaultPath(home)
	}
	n, err := hashchain.VerifyFile(p)
	if err != nil {
		fmt.Printf("BROKEN  %s: %v (%d records verify before the break)\n", sanitize.Terminal(p), err, n)
		return 1
	}
	head, _ := journal.Head(p)
	fmt.Printf("OK      %s: %d records, chain intact, head %s\n", sanitize.Terminal(p), n, head)
	filesRC := 0
	if !*noFiles {
		// Captures pruned by retention are accounted for by their prune
		// records; a capture that is simply gone is a deletion.
		filesRC = verifyRecordedCaptures(p)
	}
	if *anchor != "" {
		ok, _, err := journal.VerifyAnchor(p, *anchor)
		if err != nil || !ok {
			fmt.Println("ANCHOR  NOT FOUND — the journal was rebuilt after that head was recorded, or the head is from another journal.")
			return 1
		}
		fmt.Println("ANCHOR  found: the chain up to the anchored seal is the one that was recorded.")
	}
	return filesRC
}
