package analysis

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/efij/AgentDFIR/v4/internal/casepkg"
	"github.com/efij/AgentDFIR/v4/internal/correlate"
	"github.com/efij/AgentDFIR/v4/internal/extinv"
	"github.com/efij/AgentDFIR/v4/internal/mcpaudit"
	"github.com/efij/AgentDFIR/v4/internal/overlay"
	"github.com/efij/AgentDFIR/v4/internal/schema"
	"github.com/efij/AgentDFIR/v4/internal/supplychain"
)

// SupplyInput assembles what the supply-chain report is built from. Any
// argument may be nil; nil loads it from the stored analysis.
func SupplyInput(pkg string, events []schema.Event, findings []schema.Finding, corr *correlate.EndpointResult,
	mcp *mcpaudit.Inventory, ext *extinv.Inventory) supplychain.Input {
	if events == nil {
		events = LoadEvents(pkg)
	}
	if findings == nil {
		findings = LoadFindings(pkg)
	}
	if corr == nil {
		corr = LoadCorrelation(pkg)
	}
	if mcp == nil {
		mcp = loadMCPInventory(pkg)
	}
	if ext == nil {
		ext = loadExtInventory(pkg)
	}
	in := supplychain.Input{Events: events, Findings: findings, Correlation: corr, MCP: mcp, Ext: ext}
	if man, err := casepkg.ReadManifest(pkg); err == nil {
		in.Manifest, in.Store, in.CaseID, in.Host = man, casepkg.NewStore(pkg, man), man.CaseID, man.Host
	}
	if ci, err := casepkg.ReadCaseInfo(pkg); err == nil {
		in.Rounds = ci.Rounds
		if in.CaseID == "" {
			in.CaseID = ci.CaseID
		}
	}
	return in
}

func loadMCPInventory(pkg string) *mcpaudit.Inventory {
	data, err := overlay.ReadFile(filepath.Join(pkg, "detections", "mcp-audit.json"))
	if err != nil {
		return nil
	}
	var v struct {
		Inventory *mcpaudit.Inventory `json:"inventory"`
	}
	if json.Unmarshal(data, &v) != nil {
		return nil
	}
	return v.Inventory
}

func loadExtInventory(pkg string) *extinv.Inventory {
	data, err := overlay.ReadFile(filepath.Join(pkg, "detections", "extensions.json"))
	if err != nil {
		return nil
	}
	var v struct {
		Inventory *extinv.Inventory `json:"inventory"`
	}
	if json.Unmarshal(data, &v) != nil {
		return nil
	}
	return v.Inventory
}

// supplyOverlay builds the supply-chain report from the inventories and
// findings the earlier stages produced, writes normalized/supplychain.json
// and returns its findings. Like the investigation overlay it cannot fail
// the analysis: an error becomes a stage note.
func supplyOverlay(pkg string, events []schema.Event, findings []schema.Finding, corr *correlate.EndpointResult,
	mcp *mcpaudit.Inventory, ext *extinv.Inventory) (out []schema.Finding, notes []string) {
	defer func() {
		if r := recover(); r != nil {
			out, notes = nil, append(notes, fmt.Sprintf("supply-chain overlay stopped: %v", r))
		}
	}()
	in := SupplyInput(pkg, events, append([]schema.Finding{}, findings...), corr, mcp, ext)
	rep := supplychain.Build(in, supplychain.Options{})
	if err := overlay.WriteJSON(filepath.Join(pkg, "normalized", supplychain.File), rep); err != nil {
		notes = append(notes, "supply-chain report not written: "+err.Error())
	}
	return rep.Findings, notes
}

// LoadSupplyChain reads normalized/supplychain.json, or nil when it is
// missing or unreadable.
func LoadSupplyChain(pkg string) *supplychain.Report {
	data, err := overlay.ReadFile(filepath.Join(pkg, "normalized", supplychain.File))
	if err != nil {
		return nil
	}
	var r supplychain.Report
	if json.Unmarshal(data, &r) != nil || r.Schema != supplychain.Schema {
		return nil
	}
	return &r
}
