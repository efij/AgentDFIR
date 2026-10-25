package analysis

import (
	"fmt"
	"path"
	"strings"

	"github.com/efij/AgentDFIR/v4/internal/casepkg"
	"github.com/efij/AgentDFIR/v4/internal/extinv"
	"github.com/efij/AgentDFIR/v4/internal/ioc"
	"github.com/efij/AgentDFIR/v4/internal/mcpaudit"
)

// SimulatedMarker is the file `agentdfir simulate` writes at a synthetic
// profile's root; the Claude manifest collects it, so every case built from
// a simulation says so.
const SimulatedMarker = ".agentdfir-simulated"

// IsSimulated reports whether a package was collected from a simulated profile.
func IsSimulated(man *casepkg.Manifest) bool {
	for _, a := range man.Current() {
		if path.Base(strings.ReplaceAll(a.LogicalPath, `\`, "/")) == SimulatedMarker {
			return true
		}
	}
	return false
}

// HuntOptions selects incidents and extra surfaces for HuntCase.
type HuntOptions struct {
	Incidents      []string // ids; empty = all
	IOCFiles       []string
	RawTranscripts bool
	Path           string
	// Extensions is the case's extension inventory when the caller already
	// has it; nil scans the package when an incident needs it.
	Extensions *extinv.Inventory
}

// ExtRefs turns an extension inventory into hunt inputs.
func ExtRefs(inv *extinv.Inventory) []ioc.ExtRef {
	if inv == nil {
		return nil
	}
	var out []ioc.ExtRef
	for _, x := range inv.Extensions {
		if x.ID == "" {
			continue
		}
		out = append(out, ioc.ExtRef{ID: x.ID, Version: x.Version, Evidence: x.Dir + " (" + x.Editor + " extension)", Time: x.InstalledAt})
	}
	return out
}

// WantsExtensions reports whether any incident carries an extension
// indicator (the extension scan is skipped otherwise).
func WantsExtensions(incs []ioc.Incident) bool {
	for _, inc := range incs {
		for _, ind := range inc.Indicators {
			if ind.Kind == ioc.KindVSCodeExtension {
				return true
			}
		}
	}
	return false
}

// HuntCase runs the incident IOC check over an analyzed package. inv may
// be nil (it is scanned here then).
func HuntCase(pkg string, inv *mcpaudit.Inventory, o HuntOptions) ([]ioc.Verdict, []string, error) {
	incs, err := ioc.Embedded()
	if err != nil {
		return nil, nil, err
	}
	var notes []string
	for _, f := range o.IOCFiles {
		extra, skipped, err := ioc.LoadFile(f)
		if err != nil {
			return nil, nil, fmt.Errorf("ioc feed %s: %w", f, err)
		}
		if skipped > 0 {
			notes = append(notes, fmt.Sprintf("ioc feed %s: %d indicator(s) in unsupported forms were skipped", f, skipped))
		}
		incs = append(incs, extra...)
	}
	incs, err = ioc.Select(incs, o.Incidents)
	if err != nil {
		return nil, nil, err
	}
	man, err := casepkg.ReadManifest(pkg)
	if err != nil {
		return nil, nil, err
	}
	if inv == nil {
		inv, _, _ = mcpaudit.ScanPackage(pkg)
	}
	var pkgs []ioc.PkgRef
	if inv != nil {
		for _, s := range inv.Servers {
			if s.Package == "" {
				continue
			}
			eco := "npm"
			if s.PackageMgr == "uvx" || s.PackageMgr == "pipx" {
				eco = "pypi"
			}
			name, ver := splitSpec(s.Package)
			pkgs = append(pkgs, ioc.PkgRef{Ecosystem: eco, Name: name, Version: ver, Evidence: s.ConfigPath + " (MCP server " + s.Name + ")"})
		}
	}
	var exts []ioc.ExtRef
	if WantsExtensions(incs) {
		ei := o.Extensions
		if ei == nil {
			ei, _ = extinv.ScanPackage(pkg)
		}
		exts = ExtRefs(ei)
		if o.Path != "" {
			exts = append(exts, ExtRefs(extinv.ScanHome(o.Path))...)
		}
	}
	in := ioc.Inputs{
		Events: LoadEvents(pkg), Manifest: man, Store: casepkg.NewStore(pkg, man), Packages: pkgs, Extensions: exts,
		RawTranscripts: o.RawTranscripts, Path: o.Path, Simulated: IsSimulated(man),
	}
	return ioc.Hunt(incs, in), notes, nil
}

func splitSpec(spec string) (string, string) {
	s := strings.ToLower(spec)
	if i := strings.Index(s, "=="); i > 0 {
		return s[:i], s[i+2:]
	}
	if strings.HasPrefix(s, "@") {
		if i := strings.Index(s[1:], "@"); i >= 0 {
			return s[:i+1], s[i+2:]
		}
		return s, ""
	}
	if i := strings.Index(s, "@"); i > 0 {
		return s[:i], s[i+1:]
	}
	return s, ""
}
