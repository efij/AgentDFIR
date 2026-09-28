package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/efij/AgentDFIR/v3/internal/decode"
	"github.com/efij/AgentDFIR/v3/internal/sanitize"
)

// cmdDecode unwraps encoded payloads offline: base64, base32, hex, gzip,
// zlib, bzip2, UTF-16LE (PowerShell -enc) and String.fromCharCode, nested
// up to four layers. Nothing is executed.
func cmdDecode(args []string) int {
	var r io.Reader = os.Stdin
	if len(args) == 1 && args[0] != "-" {
		if args[0] == "-h" || args[0] == "--help" {
			fmt.Fprintln(os.Stderr, "usage: agentdfir decode [file|-]   decode nested base64/base32/hex/gzip/zlib/bzip2/UTF-16LE payloads offline")
			return 0
		}
		f, err := os.Open(args[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		defer f.Close()
		r = f
	} else if len(args) > 1 {
		fmt.Fprintln(os.Stderr, "usage: agentdfir decode [file|-]")
		return 2
	}
	b, err := io.ReadAll(io.LimitReader(r, 16<<20))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	rs := decode.Find(string(b))
	rs = append(rs, decode.FindInCommand(string(b))...)
	seen := map[string]bool{}
	n := 0
	for _, x := range rs {
		if seen[x.Text] {
			continue
		}
		seen[x.Text] = true
		n++
		at := fmt.Sprintf("at byte %d", x.Offset)
		if x.Offset < 0 {
			at = "(wrapped input)"
		}
		fmt.Printf("── payload %d %s: %s\n%s\n\n", n, at, x.ChainString(), sanitize.Terminal(x.Text))
	}
	if n == 0 {
		fmt.Println("No encoded payload that decodes to readable text.")
		return 1
	}
	return 0
}
