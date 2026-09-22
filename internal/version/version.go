// Package version holds build/version identity for the agentdfir binary.
package version

// Version is the collector version. Overridable at build time via
// -ldflags "-X github.com/efij/AgentDFIR/v2/internal/version.Version=vX.Y.Z".
var Version = "2.0.1"

// ADFIRVersion is the evidence package format version this binary writes.
//
// 0.2 adds the append-only manifest (manifest.jsonl), per-blob storage
// codecs, chunked artifacts for files that grew, and collection rounds
// with archived seals. Packages written as 0.1 (manifest.json as a JSON
// array, uncompressed blobs) stay readable, verifiable and extensible —
// see internal/compat for the test that enforces it against a package
// built by the released v1.0.0 binary.
const ADFIRVersion = "0.2"

// SchemaVersion is the normalized-event schema version (Phase 2+).
const SchemaVersion = "0.1"
