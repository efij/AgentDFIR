// agentdfir — open-source digital forensics and incident response for AI
// agents. See https://github.com/efij/AgentDFIR.
package main

import (
	"os"

	"github.com/efij/AgentDFIR/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:]))
}
