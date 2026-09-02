// Package version holds build/version identity for the agentdfir binary.
package version

// Version is the collector version. Overridable at build time via
// -ldflags "-X github.com/efij/AgentDFIR/internal/version.Version=vX.Y.Z".
var Version = "0.12.0"

// ADFIRVersion is the evidence package format version this binary writes.
const ADFIRVersion = "0.1"

// SchemaVersion is the normalized-event schema version (Phase 2+).
const SchemaVersion = "0.1"
