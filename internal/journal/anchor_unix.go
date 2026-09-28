//go:build !windows && !plan9

package journal

import "log/syslog"

// anchorSyslog writes the chain head to the system log. On macOS that is
// the unified log, which the user whose agent is being watched cannot
// rewrite; on Linux it is journald/rsyslog.
func anchorSyslog(msg string) {
	w, err := syslog.New(syslog.LOG_NOTICE|syslog.LOG_USER, "agentdfir-monitor")
	if err != nil {
		return
	}
	defer w.Close()
	_ = w.Notice(msg)
}
