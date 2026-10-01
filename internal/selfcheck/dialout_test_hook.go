//go:build selfcheck_dialout

package selfcheck

// This file is compiled only with -tags selfcheck_dialout. It makes a
// self-checking binary attempt one outbound connection on startup, so the
// offline self-check can be shown to FAIL when the subject misbehaves.
// It is never part of a release build; it exists for the negative test
// and for anyone who wants to see the check catch a real dial.

import "net/http"

func init() {
	dialOutOnInstall = func() {
		// Routed through the guarded DefaultTransport: refused and recorded
		// as a non-loopback dial, which the offline check reports as a
		// violation.
		_, _ = http.Get("https://" + CanaryTarget[:len(CanaryTarget)-4] + "/")
	}
}
