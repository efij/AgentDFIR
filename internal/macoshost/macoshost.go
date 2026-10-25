// Package macoshost reads the macOS host state collected with
// `collect --include-macos-host` (or `collect --product macos-host`):
//
//	launchd plists     ~/Library/LaunchAgents, /Library/LaunchAgents,
//	                   /Library/LaunchDaemons (*.plist)
//	BTM database       /private/var/db/com.apple.backgroundtaskmanagement/
//	                   BackgroundItems-v*.btm (root only)
//	login items        backgrounditems.btm, com.apple.loginitems.plist
//	TCC.db             user and system (Full Disk Access needed to read)
//	keychain indicators a metadata listing of the keychain files: name,
//	                   size, times. Keychain contents are never opened.
//
// What is parsed: XML property lists (Label, Program, ProgramArguments,
// RunAtLoad, KeepAlive) and the TCC.db access table (service, client,
// client_type, auth_value, last_modified) through sqlitero. What is not:
// binary property lists and the BTM store (an NSKeyedArchiver binary
// plist) are sealed losslessly and reported UNSUPPORTED. A file the
// collector could not read (permission denied, no Full Disk Access) is a
// recorded skip with its reason, from the manifest.
//
// Everything here reads the sealed package, never the live host.
package macoshost

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/casepkg"
	"github.com/efij/AgentDFIR/v4/internal/endpoint"
	"github.com/efij/AgentDFIR/v4/internal/parsers/sqlitero"
)

// Product is the opt-in product id; the categories are what its manifest
// writes.
const (
	Product          = "macos-host"
	CatLaunchd       = "macos_launchd_plist"
	CatBTM           = "macos_btm"
	CatLoginItems    = "macos_login_items"
	CatTCC           = "macos_tcc_db"
	CatKeychainIndex = "macos_keychain_index"
)

// Bounds.
const (
	maxPlistBytes   = 4 << 20
	maxTCCBytes     = 64 << 20
	maxTCCRows      = 50_000
	maxIndexBytes   = 8 << 20
	maxArgs         = 64
	maxKeychainEnts = 2000
	maxKeychainDeep = 3
)

// LaunchItem is one launchd plist.
type LaunchItem struct {
	Path      string   `json:"path"`
	Label     string   `json:"label,omitempty"`
	Program   string   `json:"program,omitempty"`
	Args      []string `json:"program_arguments,omitempty"`
	RunAtLoad bool     `json:"run_at_load,omitempty"`
	KeepAlive bool     `json:"keep_alive,omitempty"`
	ModTime   string   `json:"mtime_utc,omitempty"`
	Status    string   `json:"status"` // parsed | UNSUPPORTED | malformed
	Reason    string   `json:"reason,omitempty"`
}

// KeychainEntry is one keychain file's metadata (never its contents).
type KeychainEntry struct {
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	ModTime string `json:"mtime_utc"`
	Dir     bool   `json:"dir,omitempty"`
}

// State is what one package holds.
type State struct {
	Launchd     []LaunchItem      `json:"launchd,omitempty"`
	TCCRows     []endpoint.Record `json:"tcc_rows,omitempty"`
	Keychains   []KeychainEntry   `json:"keychain_files,omitempty"`
	Unsupported []string          `json:"unsupported,omitempty"`
	Skipped     []string          `json:"skipped,omitempty"` // artifacts the collector could not read, with the reason
	Artifacts   int               `json:"artifacts"`
}

// Empty reports a package without macOS host-state artifacts.
func (s *State) Empty() bool { return s.Artifacts == 0 && len(s.Skipped) == 0 }

func isOurs(cat string) bool {
	switch cat {
	case CatLaunchd, CatBTM, CatLoginItems, CatTCC, CatKeychainIndex:
		return true
	}
	return false
}

// Read inventories the macOS host-state artifacts of a sealed package.
func Read(man *casepkg.Manifest, store *casepkg.Store) *State {
	st := &State{}
	cur := man.Current()
	byPath := map[string]casepkg.ArtifactRecord{}
	for _, a := range cur {
		if a.Status == casepkg.StatusOK && isOurs(a.ArtifactType) {
			byPath[a.LogicalPath] = a
		}
	}
	for _, a := range cur {
		if !isOurs(a.ArtifactType) {
			continue
		}
		if a.Status != casepkg.StatusOK {
			if a.Status != casepkg.StatusNotPresent {
				st.Skipped = append(st.Skipped, fmt.Sprintf("%s: %s %s", a.SourcePath, a.Status, a.Error))
			}
			continue
		}
		st.Artifacts++
		switch a.ArtifactType {
		case CatLaunchd:
			st.Launchd = append(st.Launchd, readLaunchd(store, a))
		case CatTCC:
			if strings.HasSuffix(a.LogicalPath, "-wal") {
				continue
			}
			var wal *casepkg.ArtifactRecord
			if w, ok := byPath[a.LogicalPath+"-wal"]; ok {
				wal = &w
			}
			st.readTCC(store, a, wal)
		case CatBTM:
			st.Unsupported = append(st.Unsupported, fmt.Sprintf("UNSUPPORTED %s: Background Task Management store (NSKeyedArchiver binary plist); sealed, not parsed", a.LogicalPath))
		case CatLoginItems:
			if strings.HasSuffix(a.LogicalPath, ".plist") {
				it := readLaunchd(store, a)
				if it.Status != "parsed" {
					st.Unsupported = append(st.Unsupported, fmt.Sprintf("%s %s: login items list; %s", it.Status, a.LogicalPath, it.Reason))
				} else {
					st.Launchd = append(st.Launchd, it)
				}
			} else {
				st.Unsupported = append(st.Unsupported, fmt.Sprintf("UNSUPPORTED %s: login items store (binary plist); sealed, not parsed", a.LogicalPath))
			}
		case CatKeychainIndex:
			st.readKeychainIndex(store, a)
		}
	}
	for _, it := range st.Launchd {
		if it.Status == "UNSUPPORTED" {
			st.Unsupported = append(st.Unsupported, "UNSUPPORTED "+it.Path+": "+it.Reason)
		}
	}
	sort.SliceStable(st.TCCRows, func(i, j int) bool { return st.TCCRows[i].Time.Before(st.TCCRows[j].Time) })
	return st
}

func readLaunchd(store *casepkg.Store, a casepkg.ArtifactRecord) LaunchItem {
	it := LaunchItem{Path: a.SourcePath, ModTime: a.ModTimeUTC}
	data, err := store.ReadAll(a.ArtifactID, maxPlistBytes)
	if err != nil {
		it.Status, it.Reason = "malformed", "not readable: "+err.Error()
		return it
	}
	parsePlistInto(data, &it)
	return it
}

// parsePlistInto fills a LaunchItem from a property list.
func parsePlistInto(data []byte, it *LaunchItem) {
	if bytes.HasPrefix(data, []byte("bplist")) {
		it.Status, it.Reason = "UNSUPPORTED", "binary property list; sealed, not parsed"
		return
	}
	top, err := parseXMLPlist(data)
	if err != nil {
		it.Status, it.Reason = "malformed", err.Error()
		return
	}
	d, ok := top.(map[string]any)
	if !ok {
		it.Status, it.Reason = "malformed", "top-level value is not a dict"
		return
	}
	it.Status = "parsed"
	it.Label, _ = d["Label"].(string)
	it.Program, _ = d["Program"].(string)
	if arr, ok := d["ProgramArguments"].([]any); ok {
		for _, v := range arr {
			if s, ok := v.(string); ok && len(it.Args) < maxArgs {
				it.Args = append(it.Args, s)
			}
		}
	}
	it.RunAtLoad, _ = d["RunAtLoad"].(bool)
	switch k := d["KeepAlive"].(type) {
	case bool:
		it.KeepAlive = k
	case map[string]any:
		it.KeepAlive = true // conditional keep-alive
	}
}

// parseXMLPlist decodes an XML property list into Go values (dict →
// map, array → slice, string/date/data → string, integer/real → string,
// true/false → bool). Nesting and element counts are bounded.
func parseXMLPlist(data []byte) (v any, err error) {
	defer func() {
		if r := recover(); r != nil {
			v, err = nil, fmt.Errorf("plist: %v", r)
		}
	}()
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = false
	budget := 100_000
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("plist: no plist element (%v)", err)
		}
		if se, ok := tok.(xml.StartElement); ok {
			if se.Name.Local == "plist" {
				continue
			}
			return plistValue(dec, se, 0, &budget)
		}
	}
}

func plistValue(dec *xml.Decoder, se xml.StartElement, depth int, budget *int) (any, error) {
	if depth > 32 {
		return nil, fmt.Errorf("plist: nested deeper than 32")
	}
	if *budget--; *budget < 0 {
		return nil, fmt.Errorf("plist: too many elements")
	}
	switch se.Name.Local {
	case "dict":
		out := map[string]any{}
		key := ""
		for {
			tok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			switch t := tok.(type) {
			case xml.StartElement:
				if t.Name.Local == "key" {
					s, err := text(dec)
					if err != nil {
						return nil, err
					}
					key = s
					continue
				}
				v, err := plistValue(dec, t, depth+1, budget)
				if err != nil {
					return nil, err
				}
				out[key] = v
			case xml.EndElement:
				return out, nil
			}
		}
	case "array":
		var out []any
		for {
			tok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			switch t := tok.(type) {
			case xml.StartElement:
				v, err := plistValue(dec, t, depth+1, budget)
				if err != nil {
					return nil, err
				}
				out = append(out, v)
			case xml.EndElement:
				return out, nil
			}
		}
	case "true", "false":
		if err := dec.Skip(); err != nil {
			return nil, err
		}
		return se.Name.Local == "true", nil
	default: // string, integer, real, date, data
		return text(dec)
	}
}

// text reads character data up to the element's end, bounded.
func text(dec *xml.Decoder) (string, error) {
	var b strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", err
		}
		switch t := tok.(type) {
		case xml.CharData:
			if b.Len() < 64<<10 {
				b.Write(t)
			}
		case xml.StartElement:
			if err := dec.Skip(); err != nil {
				return "", err
			}
		case xml.EndElement:
			return strings.TrimSpace(b.String()), nil
		}
	}
}

// readTCC reads the access table of one TCC.db.
func (st *State) readTCC(store *casepkg.Store, a casepkg.ArtifactRecord, walArt *casepkg.ArtifactRecord) {
	data, err := store.ReadAll(a.ArtifactID, maxTCCBytes)
	if err != nil {
		st.Unsupported = append(st.Unsupported, fmt.Sprintf("%s: TCC.db not readable from the package: %v", a.LogicalPath, err))
		return
	}
	var wal []byte
	if walArt != nil {
		wal, _ = store.ReadAll(walArt.ArtifactID, maxTCCBytes)
	}
	db, err := sqlitero.Open(data, wal)
	if err != nil {
		st.Unsupported = append(st.Unsupported, fmt.Sprintf("UNSUPPORTED %s: not a readable SQLite database (%v); sealed", a.LogicalPath, err))
		return
	}
	t, err := db.Table("access")
	if err != nil {
		st.Unsupported = append(st.Unsupported, fmt.Sprintf("UNSUPPORTED %s: no access table; sealed, not parsed", a.LogicalPath))
		return
	}
	col := func(row []any, name string) any {
		if i := t.Index(name); i >= 0 && i < len(row) {
			return row[i]
		}
		return nil
	}
	authCol := "auth_value"
	if t.Index(authCol) < 0 {
		authCol = "allowed" // pre-Big Sur schema
	}
	n := 0
	_ = db.Each(t, func(rowid int64, row []any) error {
		if n >= maxTCCRows {
			return io.EOF
		}
		n++
		r := endpoint.Record{Kind: endpoint.KindTCC, Source: "tcc-db", Operation: "tcc-db-row",
			Resource: sqlitero.Str(col(row, "service")), Exe: sqlitero.Str(col(row, "client")),
			Ref: fmt.Sprintf("%s access row %d (artifact %.12s)", a.LogicalPath, rowid, a.ArtifactID)}
		r.Message = fmt.Sprintf("%s=%d client_type=%d db=%s", authCol, sqlitero.Int(col(row, authCol)), sqlitero.Int(col(row, "client_type")), a.SourcePath)
		if lm := sqlitero.Int(col(row, "last_modified")); lm > 0 && lm < 1<<40 {
			r.Time = time.Unix(lm, 0).UTC()
		}
		st.TCCRows = append(st.TCCRows, r)
		return nil
	})
	if n >= maxTCCRows {
		st.Unsupported = append(st.Unsupported, fmt.Sprintf("%s: access rows past %d not read (bound)", a.LogicalPath, maxTCCRows))
	}
}

// keychainIndex is the document CollectKeychainIndex writes.
type keychainIndex struct {
	Note    string          `json:"note"`
	Entries []KeychainEntry `json:"entries"`
	Errors  []string        `json:"errors,omitempty"`
}

func (st *State) readKeychainIndex(store *casepkg.Store, a casepkg.ArtifactRecord) {
	data, err := store.ReadAll(a.ArtifactID, maxIndexBytes)
	if err != nil {
		st.Unsupported = append(st.Unsupported, fmt.Sprintf("%s: keychain index not readable: %v", a.LogicalPath, err))
		return
	}
	var idx keychainIndex
	if err := json.Unmarshal(data, &idx); err != nil {
		st.Unsupported = append(st.Unsupported, fmt.Sprintf("UNSUPPORTED %s: keychain index format not recognized (%v)", a.LogicalPath, err))
		return
	}
	st.Keychains = append(st.Keychains, idx.Entries...)
	for _, e := range idx.Errors {
		st.Skipped = append(st.Skipped, "keychain listing: "+e)
	}
}

// CollectKeychainIndex lists keychain files under the profile's and the
// system's Library/Keychains with lstat only (name, size, times; never
// opened, never followed) and seals the listing as one artifact. A
// directory that cannot be listed is recorded in the listing with the
// reason.
func CollectKeychainIndex(b *casepkg.Builder, profileRoot, systemRoot, host, user string) error {
	idx := keychainIndex{Note: "metadata only: keychain files were listed with lstat and never opened; no secret was read"}
	seen := map[string]bool{}
	for _, root := range []string{filepath.Join(profileRoot, "Library", "Keychains"), filepath.Join(systemRoot, "Library", "Keychains")} {
		if !seen[filepath.Clean(root)] {
			seen[filepath.Clean(root)] = true
			walkKeychains(root, 0, &idx)
		}
	}
	tmp, err := os.MkdirTemp("", "adfir-keychain-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	data, _ := json.MarshalIndent(idx, "", "  ")
	p := filepath.Join(tmp, "keychain_index.json")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		return err
	}
	return b.IngestFile(p, casepkg.ArtifactRecord{
		SourcePath: "metadata:" + filepath.Join(profileRoot, "Library", "Keychains"), LogicalPath: "macos-host/keychain_index.json",
		Host: host, User: user, Product: Product, CollectorRule: "macos.keychain_index",
		ArtifactType: CatKeychainIndex, Sensitivity: "low", Method: "metadata_listing",
	})
}

func walkKeychains(dir string, depth int, idx *keychainIndex) {
	if depth > maxKeychainDeep || len(idx.Entries) >= maxKeychainEnts {
		return
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			idx.Errors = append(idx.Errors, fmt.Sprintf("%s: %v", dir, err))
		}
		return
	}
	for _, e := range ents {
		if len(idx.Entries) >= maxKeychainEnts {
			idx.Errors = append(idx.Errors, fmt.Sprintf("%s: listing stopped at %d entries (bound)", dir, maxKeychainEnts))
			return
		}
		p := filepath.Join(dir, e.Name())
		fi, err := os.Lstat(p)
		if err != nil {
			idx.Errors = append(idx.Errors, fmt.Sprintf("%s: %v", p, err))
			continue
		}
		idx.Entries = append(idx.Entries, KeychainEntry{Path: filepath.ToSlash(p), Size: fi.Size(), ModTime: fi.ModTime().UTC().Format(time.RFC3339), Dir: fi.IsDir()})
		if fi.IsDir() {
			walkKeychains(p, depth+1, idx)
		}
	}
}

// Summary is a one-line operator summary.
func (st *State) Summary() string {
	parsed := 0
	for _, it := range st.Launchd {
		if it.Status == "parsed" {
			parsed++
		}
	}
	return fmt.Sprintf("%d artifact(s): %d launchd plist(s) (%d parsed), %d TCC access row(s), %d keychain file(s) listed (metadata only), %d unsupported, %d not readable",
		st.Artifacts, len(st.Launchd), parsed, len(st.TCCRows), len(st.Keychains), len(st.Unsupported), len(st.Skipped))
}

