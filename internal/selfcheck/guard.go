// Package selfcheck lets anyone prove, on their own machine, that an
// AgentDFIR collection and analysis opens no network socket, spawns no
// child process, and writes only inside the case and state directories.
//
// It does that by running the AgentDFIR binary itself as the subject, on a
// synthetic profile, under whatever containment the platform offers — a
// network+exec+write sandbox on macOS (sandbox-exec), a network namespace
// and syscall trace on Linux (unshare/strace), and an in-process guard
// everywhere as the floor. The report always states which level of proof
// it reached: kernel-enforced, traced, or in-process.
//
// This file is the in-process guard. When the environment variable
// AGENTDFIR_SELFCHECK is set, a running AgentDFIR process installs dialers
// that refuse and record any connection to a non-loopback address, and
// writes what it observed to the file named by AGENTDFIR_SELFCHECK_LOG.
// It is defence in depth, not a sandbox: a determined caller can dial
// around net.DefaultResolver. The kernel modes above are the real proof;
// the guard is what Windows and a stripped-down host still get.
package selfcheck

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// EnvGuard, when set, makes a process install the in-process guard on
// startup. EnvLog names the file the guard appends its observations to.
const (
	EnvGuard = "AGENTDFIR_SELFCHECK"
	EnvLog   = "AGENTDFIR_SELFCHECK_LOG"
)

// Observation is one thing the in-process guard saw.
type Observation struct {
	Kind    string `json:"kind"` // dial | resolve
	Network string `json:"network,omitempty"`
	Address string `json:"address"`
	Allowed bool   `json:"allowed"` // loopback/unix dials are allowed
	TS      string `json:"ts_utc"`
}

var (
	logMu   sync.Mutex
	logPath string
)

// InstallIfRequested installs the guard when EnvGuard is set. Call it once,
// as early as possible, before any network or collection code runs.
func InstallIfRequested() {
	if os.Getenv(EnvGuard) == "" {
		return
	}
	logPath = os.Getenv(EnvLog)
	guardTransport()
	guardResolver()
	if dialOutOnInstall != nil {
		dialOutOnInstall()
	}
}

// dialOutOnInstall is nil in a normal build. The selfcheck_dialout build
// tag sets it to a function that dials out, for the negative test.
var dialOutOnInstall func()

// loopback reports whether an address is loopback or a unix socket, the
// only destinations the guard permits (a loopback server is how `serve`
// talks to a browser; nothing leaves the machine).
func loopback(network, address string) bool {
	switch network {
	case "unix", "unixgram", "unixpacket":
		return true
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func record(kind, network, address string, allowed bool) {
	if logPath == "" {
		return
	}
	logMu.Lock()
	defer logMu.Unlock()
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	b, _ := json.Marshal(Observation{Kind: kind, Network: network, Address: address, Allowed: allowed, TS: time.Now().UTC().Format(time.RFC3339Nano)})
	f.Write(append(b, '\n'))
}

// guardedDial refuses and records any non-loopback dial.
func guardedDial(network, address string) (net.Conn, error) {
	if loopback(network, address) {
		record("dial", network, address, true)
		return net.Dial(network, address)
	}
	record("dial", network, address, false)
	return nil, fmt.Errorf("agentdfir selfcheck: outbound connection to %s refused (in-process guard)", address)
}

func guardTransport() {
	d := &net.Dialer{Timeout: 5 * time.Second}
	t := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if loopback(network, address) {
				record("dial", network, address, true)
				return d.DialContext(ctx, network, address)
			}
			record("dial", network, address, false)
			return nil, fmt.Errorf("agentdfir selfcheck: outbound connection to %s refused (in-process guard)", address)
		},
	}
	http.DefaultTransport = t
	http.DefaultClient.Transport = t
}

func guardResolver() {
	net.DefaultResolver.PreferGo = true
	net.DefaultResolver.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		// DNS to a loopback resolver is fine; to anything else it is the
		// first step of exfiltration and is refused.
		if loopback(network, address) {
			record("resolve", network, address, true)
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}
		record("resolve", network, address, false)
		return nil, fmt.Errorf("agentdfir selfcheck: DNS to %s refused (in-process guard)", address)
	}
}

// GuardDial is exported so a test build can confirm the guard is wired:
// it is the same refusal the dialers apply.
func GuardDial(network, address string) (net.Conn, error) { return guardedDial(network, address) }
