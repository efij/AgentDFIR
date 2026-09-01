// Package live acquires volatile evidence in RFC 3227 order of
// volatility (plan §6): clock state first, then logged-in users,
// running processes, and network state.
//
// Method disclosure: live acquisition runs OS-supplied utilities (ps,
// who, netstat, …). On a compromised host these can be trojaned; every
// record therefore carries collection_method "live_command" plus the
// exact command line, so analysts can weigh the evidence accordingly.
// Agent processes are never terminated or signaled.
package live

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/efij/AgentDFIR/internal/casepkg"
)

// step is one volatile acquisition: a named artifact and the command
// that produces it. Ordered most-volatile-first.
type step struct {
	name     string
	artifact string // logical path inside the package
	argv     []string
}

func steps() []step {
	switch runtime.GOOS {
	case "darwin":
		return []step{
			{"system_time", "live/system_time.txt", []string{"date", "-u", "+%Y-%m-%dT%H:%M:%SZ %z %Z"}},
			{"uptime", "live/uptime.txt", []string{"uptime"}},
			{"logged_in_users", "live/who.txt", []string{"who", "-a"}},
			{"process_list", "live/ps.txt", []string{"ps", "axww", "-o", "pid,ppid,user,lstart,command"}},
			{"listening_sockets", "live/netstat_listen.txt", []string{"netstat", "-anv", "-p", "tcp"}},
			{"open_files_agents", "live/lsof_agents.txt", []string{"lsof", "-n", "-P", "+c", "0"}},
		}
	case "linux":
		return []step{
			{"system_time", "live/system_time.txt", []string{"date", "-u", "+%Y-%m-%dT%H:%M:%SZ %z %Z"}},
			{"uptime", "live/uptime.txt", []string{"uptime"}},
			{"logged_in_users", "live/who.txt", []string{"who", "-a"}},
			{"process_list", "live/ps.txt", []string{"ps", "axww", "-o", "pid,ppid,user,lstart,cmd"}},
			{"network_connections", "live/ss.txt", []string{"ss", "-tunap"}},
		}
	case "windows":
		return []step{
			{"system_time", "live/system_time.txt", []string{"powershell", "-NoProfile", "-Command", "Get-Date -Format o; (Get-TimeZone).Id"}},
			{"logged_in_users", "live/quser.txt", []string{"quser"}},
			{"process_list", "live/tasklist.txt", []string{"tasklist", "/v", "/fo", "csv"}},
			{"network_connections", "live/netstat.txt", []string{"netstat", "-ano"}},
		}
	default:
		return nil
	}
}

// perStepTimeout bounds each utility so a hung tool cannot stall
// acquisition of later (less volatile) evidence.
const perStepTimeout = 30 * time.Second

// Stats summarizes a live acquisition pass.
type Stats struct {
	Collected int
	Failed    int
}

// Collect runs all volatile steps and ingests output into the builder.
func Collect(b *casepkg.Builder, host, user string) (*Stats, error) {
	st := &Stats{}
	tmpDir, err := os.MkdirTemp("", "adfir-live-*")
	if err != nil {
		return st, err
	}
	defer os.RemoveAll(tmpDir)

	for i, s := range steps() {
		rec := casepkg.ArtifactRecord{
			SourcePath:    "live:" + s.argv[0],
			LogicalPath:   s.artifact,
			Host:          host,
			User:          user,
			Product:       "host",
			CollectorRule: "live." + s.name,
			ArtifactType:  "volatile",
			Sensitivity:   "medium",
			Method:        "live_command",
		}
		out, cmdErr := runBounded(s.argv)
		_ = b.Log("live_step", map[string]any{
			"step": s.name, "argv": s.argv, "order": i,
			"ok": cmdErr == nil,
		})
		if cmdErr != nil {
			rec.Status = casepkg.StatusError
			rec.Error = cmdErr.Error()
			st.Failed++
			if err := b.RecordNonFile(rec); err != nil {
				return st, err
			}
			continue
		}
		// Prefix output with a provenance header so the artifact is
		// self-describing outside the manifest.
		header := fmt.Sprintf("# agentdfir live acquisition\n# command: %v\n# collected_utc: %s\n\n",
			s.argv, time.Now().UTC().Format(time.RFC3339Nano))
		tmp := filepath.Join(tmpDir, s.name)
		if err := os.WriteFile(tmp, append([]byte(header), out...), 0o600); err != nil {
			return st, err
		}
		if err := b.IngestFile(tmp, rec); err != nil {
			return st, err
		}
		st.Collected++
	}
	return st, nil
}

func runBounded(argv []string) ([]byte, error) {
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return nil, fmt.Errorf("%s not found: %w", argv[0], err)
	}
	cmd := exec.Command(path, argv[1:]...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			// Non-zero exit with output is still evidence.
			if out.Len() > 0 {
				return out.Bytes(), nil
			}
			return nil, err
		}
		return out.Bytes(), nil
	case <-time.After(perStepTimeout):
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("timed out after %s", perStepTimeout)
	}
}
