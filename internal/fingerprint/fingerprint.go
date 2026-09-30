// Package fingerprint names the code that produced a derived result.
//
// A cached overlay or a stored analysis is only reusable if it came from
// the same parsing and detection code the running binary carries. Keying
// on the release number made every release — including ones that touched
// only the explorer or the installer — throw away every cached parse and
// re-analyze every case from scratch. Keying on the code itself does not:
// a release that leaves the parsers alone keeps every overlay, and one
// that changes a parser invalidates all of them, which is the safe side.
//
// The values are generated (go generate ./internal/fingerprint) and a test
// recomputes them, so a parser or rule change cannot ship under a stale
// fingerprint and quietly keep serving results the new code would not
// produce.
package fingerprint

//go:generate go run ./gen

// Parse identifies the code that turns evidence into normalized events:
// every in-module package internal/normalize depends on.
func Parse() string { return parse }

// Analysis identifies the code that turns normalized events into
// findings: every in-module package internal/analysis depends on,
// embedded rule packs included. It is a superset of Parse.
func Analysis() string { return analysis }
