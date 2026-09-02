package cli

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/efij/AgentDFIR/internal/sanitize"
	"github.com/efij/AgentDFIR/internal/serve"
)

// cmdServe hosts the local case explorer for one package.
func cmdServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	port := fs.Int("port", 0, "TCP port on 127.0.0.1 (default: ephemeral)")
	open := fs.Bool("open", false, "open the URL in the default browser")
	maxEvents := fs.Int("max-events", 500000, "events held in memory")
	pkg, rest := splitPositional(args)
	if err := fs.Parse(rest); err != nil || (pkg == "" && fs.NArg() != 1) || (pkg != "" && fs.NArg() != 0) {
		fmt.Fprintln(os.Stderr, "usage: agentdfir serve <package-dir> [--port N] [--open]")
		return 2
	}
	if pkg == "" {
		pkg = fs.Arg(0)
	}
	s, err := serve.Load(pkg, serve.Options{Port: *port, MaxEvents: *maxEvents})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	ln, url, err := s.Listen(*port)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("AgentDFIR case explorer — %s\n", sanitize.Terminal(s.Describe()))
	fmt.Printf("Open %s   (127.0.0.1 only · read-only · no external resources · Ctrl+C to stop)\n", url)
	if *open {
		openBrowser(url)
	}
	if err := s.Serve(ln); err != nil {
		fmt.Fprintln(os.Stderr, "server:", err)
		return 1
	}
	return 0
}

// openBrowser is best-effort; the URL is always printed.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}
