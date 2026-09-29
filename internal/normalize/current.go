package normalize

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/efij/AgentDFIR/v3/internal/casepkg"
	"github.com/efij/AgentDFIR/v3/internal/fingerprint"
	"github.com/efij/AgentDFIR/v3/internal/overlay"
	"github.com/efij/AgentDFIR/v3/internal/store"
	"github.com/efij/AgentDFIR/v3/internal/version"
)

// hostWitnessType is the artifact type of the host witness record. It is
// read by analysis, not by any parser, so it is not an overlay input: a
// round that only re-asks the host must not rebuild 300 MB of events.
const hostWitnessType = "host_witness"

// InputsDigest identifies the evidence an overlay is built from: every
// current, acquired artifact a parser could read, by everything a parser
// reads off its record (the same fields segKey covers). Two manifests with
// the same digest produce the same overlay.
//
// This replaces comparing the manifest's modification time with the
// overlay's. Every round appends to the manifest — also a round that only
// carried unchanged files forward — so the old test rebuilt the overlay
// and re-ran every detection on a machine where nothing had changed.
func InputsDigest(man *casepkg.Manifest) string {
	var keys []string
	for _, a := range man.Current() {
		if a.Status != casepkg.StatusOK || a.ArtifactType == hostWitnessType {
			continue
		}
		keys = append(keys, segKey(a)+"\x00"+a.SourcePath)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// OverlayStatus describes the overlay a package carries.
type OverlayStatus struct {
	Current bool
	Reason  string // why it is not current
	BuildID string // changes every time events.jsonl is rebuilt
}

// Status reports whether the package's overlay was built by this binary's
// parsing code from the package's current evidence, and is still exactly
// what that build (and the analysis stages that annotate it) wrote.
//
// The overlay is derived data outside the seal. Reusing it round after
// round is what makes a repeat run cheap, and it is also what would let
// an edit to it — an event deleted from events.jsonl — hide from every
// later analysis. So reuse is conditional on the state's MAC (when this
// machine has a key) and on events.jsonl still hashing to what was
// recorded. Hashing it costs a fraction of a second; parsing it again
// costs minutes, and trusting it unchecked costs the analysis.
func Status(pkgDir string) OverlayStatus {
	dir := filepath.Join(pkgDir, "normalized")
	evPath := filepath.Join(dir, "events.jsonl")
	if _, err := overlay.Stat(evPath); err != nil {
		return OverlayStatus{Reason: "no normalized events"}
	}
	st, err := readState(dir, store.CacheKey())
	if err != nil {
		return OverlayStatus{Reason: err.Error()}
	}
	switch {
	case st.SchemaVersion != version.SchemaVersion:
		return OverlayStatus{Reason: "normalized schema changed"}
	case st.ParseFingerprint != fingerprint.Parse():
		return OverlayStatus{Reason: "parsing code changed since the overlay was built"}
	}
	man, err := casepkg.ReadManifest(pkgDir)
	if err != nil {
		return OverlayStatus{Reason: "unreadable manifest"}
	}
	if st.CaseID != man.CaseID || st.Host != man.Host {
		return OverlayStatus{Reason: "overlay belongs to another case"}
	}
	if st.InputsDigest != InputsDigest(man) {
		return OverlayStatus{Reason: "evidence changed since the overlay was built"}
	}
	if sum, err := hashOverlayFile(evPath); err != nil || sum != st.EventsSHA256 {
		return OverlayStatus{Reason: "normalized events were changed outside AgentDFIR; rebuilding them from the sealed evidence"}
	}
	return OverlayStatus{Current: true, BuildID: st.BuildID}
}

// readState reads state.json and, when this machine has a cache key,
// requires its MAC.
func readState(dir string, key []byte) (*overlayState, error) {
	data, err := os.ReadFile(filepath.Join(dir, stateFileName))
	if err != nil {
		return nil, errors.New("no overlay state")
	}
	if len(key) > 0 {
		mac, err := os.ReadFile(filepath.Join(dir, macFileName))
		if err != nil || !hmac.Equal([]byte(strings.TrimSpace(string(mac))), []byte(stateMAC(key, data))) {
			return nil, errors.New("overlay state failed its authentication check; rebuilding from the sealed evidence")
		}
	}
	var st overlayState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, errors.New("unreadable overlay state")
	}
	return &st, nil
}

// RecordEvents re-records events.jsonl's hash after a stage of this
// package's own code rewrote it (the host witness and endpoint
// corroboration annotate events in place), so the rewrite is not mistaken
// for tampering. It does nothing when there is no overlay state.
func RecordEvents(pkgDir string) error {
	dir := filepath.Join(pkgDir, "normalized")
	key := store.CacheKey()
	st, err := readState(dir, key)
	if err != nil {
		return nil
	}
	sum, err := hashOverlayFile(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		return err
	}
	st.EventsSHA256 = sum
	return writeState(dir, *st, key)
}

func hashOverlayFile(path string) (string, error) {
	f, err := overlay.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// writeFileAtomic replaces path with data so a reader never sees a
// partial file.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Refresh brings the package's overlay up to date — re-parsing only what
// changed — and writes the entity and relationship files with it. It is
// what analysis runs, and what acquisition runs before asking the host
// about the agent's claims, so the two share one build instead of each
// parsing the evidence.
func Refresh(pkgDir string, opt OverlayOptions) (*StreamResult, error) {
	dir := filepath.Join(pkgDir, "normalized")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if opt.MACKey == nil {
		opt.MACKey = store.CacheKey()
	}
	sr, err := BuildOverlay(pkgDir, dir, opt)
	if err != nil {
		return nil, err
	}
	if err := overlay.WriteJSONL(filepath.Join(dir, "entities.jsonl"), len(sr.Entities), func(i int) any { return sr.Entities[i] }); err != nil {
		return nil, err
	}
	if err := overlay.WriteJSONL(filepath.Join(dir, "relationships.jsonl"), len(sr.Relationships), func(i int) any { return sr.Relationships[i] }); err != nil {
		return nil, err
	}
	return sr, nil
}
