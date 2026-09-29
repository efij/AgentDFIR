package mitigate

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// GuardCommand is the hook command line for the log guard. The binary on
// PATH is preferred over this process's path: a package manager's symlink
// survives upgrades, a Cellar path does not.
func GuardCommand() string {
	p, err := exec.LookPath("agentdfir")
	if err != nil || p == "" {
		p, err = os.Executable()
		if err != nil {
			return ""
		}
	}
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	if strings.ContainsAny(p, " \t'\"") {
		p = `"` + strings.ReplaceAll(p, `"`, `\"`) + `"`
	}
	return p + " guard log"
}

// DefaultEnv is the machine this process runs on: the user's home as the
// profile root, the ledger under the AgentDFIR state directory.
func DefaultEnv(stateRoot string) (Env, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Env{}, err
	}
	return Env{Home: home, StateDir: filepath.Join(stateRoot, "mitigations"), GuardCommand: GuardCommand()}, nil
}
