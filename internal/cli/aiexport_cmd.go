package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/efij/AgentDFIR/v5/internal/casepkg"
	"github.com/efij/AgentDFIR/v5/internal/collector"
	"github.com/efij/AgentDFIR/v5/internal/parsers/aiexport"
	"github.com/efij/AgentDFIR/v5/internal/parsers/suite"
	"github.com/efij/AgentDFIR/v5/internal/products"
	"github.com/efij/AgentDFIR/v5/internal/sanitize"
	"github.com/efij/AgentDFIR/v5/internal/unpack"
)

// collectAIExport seals an AI-service account export — a ChatGPT,
// Claude.ai, DeepSeek or Google Takeout (Gemini Apps) download, or a
// Cellebrite UFDR — given as a zip/tar archive or an unpacked directory.
// Every file is sealed read-only under its in-export path; export files
// are recognized by structure and parsed into events at analysis time.
func collectAIExport(src string, o importOpts) int {
	fi, err := os.Stat(src)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	root := src
	notes := map[string]string{"mode": "ai-export", "ai_export_source": src}
	if fi.Mode().IsRegular() {
		kind, err := unpack.Kind(src)
		if err != nil {
			fmt.Fprintln(os.Stderr, "--ai-export:", err)
			return 2
		}
		tmp, err := os.MkdirTemp("", "agentdfir-aiexport-")
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		defer os.RemoveAll(tmp)
		opts := unpack.Options{}
		if o.maxFileMB > 0 {
			opts.MaxEntryBytes = o.maxFileMB << 20
		}
		fmt.Printf("AI-service export: %s (%s)\n", sanitize.Terminal(filepath.Base(src)), kind)
		st, err := unpack.ExtractArchive(src, tmp, opts)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		fmt.Printf("Extracted %d file(s), %d bytes (%d skipped, %d refused paths)\n", st.Files, st.Bytes, st.Skipped, st.Refused)
		for _, p := range st.Problems {
			fmt.Printf("  note: %s\n", sanitize.Terminal(p))
		}
		notes["ai_export_sha256"] = st.SHA256
		notes["ai_export_archive_kind"] = kind
		root = tmp
	} else if fi.IsDir() {
		fmt.Printf("AI-service export directory: %s\n", sanitize.Terminal(src))
		notes["ai_export_sha256"] = "n/a (directory input; each file's SHA-256 is in the manifest)"
	} else {
		fmt.Fprintf(os.Stderr, "--ai-export: %s is neither a file nor a directory\n", sanitize.Terminal(src))
		return 2
	}
	pl, err := aiexport.PlanTree(root, aiexport.PlanAll, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if !pl.Found() {
		fmt.Fprintln(os.Stderr, "no ChatGPT, Claude.ai, DeepSeek or Gemini (Takeout) export file, no UFDR report.xml and no forensic-suite export (AXIOM CSV/Case.mfdb, Plaso timeline, Autopsy Files - Text, UFD descriptor) found in", sanitize.Terminal(src))
		return 1
	}
	o.tree, o.notes, o.aiPlan, o.aiOnly = root, notes, pl, true
	return collectImport(o)
}

// detectArchiveExport checks an unpacked --archive tree for an AI-service
// export or a UFDR layout; when one is present the whole archive is sealed
// as one (it is the export).
func detectArchiveExport(root string) *aiexport.Plan {
	pl, err := aiexport.PlanTree(root, aiexport.PlanAll, nil)
	if err != nil || !pl.Found() {
		return nil
	}
	return pl
}

// productDirSkipper reports paths inside the product directories of the
// discovered profiles: the profile collectors read those, so an export
// search of the same tree leaves them alone.
func productDirSkipper(profiles []collector.Profile) func(string) bool {
	var dirs []string
	for _, pr := range profiles {
		for _, pid := range pr.Products {
			prod, err := products.ByID(pid)
			if err != nil {
				continue
			}
			for _, d := range prod.ConfigDirs {
				dirs = append(dirs, filepath.Join(pr.Path, filepath.FromSlash(d)))
			}
		}
	}
	if len(dirs) == 0 {
		return nil
	}
	return func(p string) bool {
		for _, d := range dirs {
			if p == d || strings.HasPrefix(p, d+string(filepath.Separator)) {
				return true
			}
		}
		return false
	}
}

// aiExportNotes adds what was detected to the case notes.
func aiExportNotes(pl *aiexport.Plan, notes map[string]string) {
	if !pl.Found() {
		return
	}
	notes["ai_export_services"] = strings.Join(pl.Services(), ",")
	notes["ai_export_recognized_files"] = fmt.Sprint(pl.Recognized)
	det := pl.Detections()
	const maxNoted = 64
	if len(det) > maxNoted {
		det = append(det[:maxNoted], fmt.Sprintf("… %d more (see manifest)", len(det)-maxNoted))
	}
	notes["ai_export_detected"] = strings.Join(det, "; ")
	notes["ai_export_evidence_class"] = "provider-side records (cloud), not endpoint execution"
	if pl.UFDR {
		notes["ufdr_report"] = pl.UFDRReport
	}
	if pl.Suite > 0 {
		sd := pl.SuiteDetections()
		if len(sd) > maxNoted {
			sd = append(sd[:maxNoted], fmt.Sprintf("… %d more (see manifest)", len(sd)-maxNoted))
		}
		notes["forensic_suite_files"] = fmt.Sprint(pl.Suite)
		notes["forensic_suite_detected"] = strings.Join(sd, "; ")
		notes["forensic_suite_evidence_class"] = "another tool's decoding of the evidence; originals sealed (docs/forensic-suite-interop.md)"
	}
	if pl.UFDR {
		notes["ufdr"] = "UFDR layout import — report.xml read generically (metadata, AI-app and AI-URL models); other models counted and preserved"
	}
	if pl.Truncated {
		notes["ai_export_truncated"] = "tree holds more files than the planner inspects; the rest were not sealed"
	}
}

// ingestAIExport seals a plan's files and prints what was recognized.
func ingestAIExport(b *casepkg.Builder, pl *aiexport.Plan, host string, maxFileMB int64) (*collector.Stats, error) {
	specs := make([]collector.FileSpec, 0, len(pl.Files))
	for _, f := range pl.Files {
		specs = append(specs, collector.FileSpec{Path: f.Path, Product: f.Product,
			Entry: products.ManifestEntry{ID: f.Rule, Category: f.Type, Sensitivity: "high"}})
	}
	opts := collector.Options{ProfileRoot: pl.Root, ConfigRoot: pl.Root, SystemRoot: pl.Root, Host: host}
	if maxFileMB > 0 {
		opts.MaxFileBytes = maxFileMB << 20
	}
	_ = b.Log("ai_export_detected", map[string]any{
		"root": pl.Root, "services": pl.Services(), "recognized": pl.Recognized,
		"files": len(pl.Files), "ufdr": pl.UFDR, "detected": pl.Detections(),
		"forensic_suite": pl.SuiteDetections(),
	})
	fmt.Printf("  AI-service export: %d export file(s) recognized (%s), %d file(s) sealed\n",
		pl.Recognized, strings.Join(pl.Services(), ", "), len(pl.Files))
	for i, d := range pl.Detections() {
		if i == 20 {
			fmt.Printf("    … %d more\n", len(pl.Detections())-20)
			break
		}
		fmt.Printf("    %s\n", sanitize.Terminal(d))
	}
	if pl.UFDR {
		fmt.Printf("  UFDR layout import — %s sealed; read generically at analysis (metadata, AI-app and AI-URL models)\n", sanitize.Terminal(pl.UFDRReport))
	}
	for i, d := range pl.SuiteDetections() {
		if i == 20 {
			fmt.Printf("    … %d more forensic-suite file(s)\n", pl.Suite-20)
			break
		}
		fmt.Printf("    suite: %s\n", sanitize.Terminal(d))
	}
	return collector.IngestFiles(b, specs, opts)
}

// collectSuiteExport seals a forensic-suite export: a UFDR, an AXIOM CSV
// export or Portable Case tree, a Plaso psort timeline, an Autopsy
// "Files - Text" report or a UFD descriptor. Archives and directories go
// through the same planner as --ai-export; a single export file is sealed
// on its own when its content is recognized.
func collectSuiteExport(src string, o importOpts) int {
	fi, err := os.Stat(src)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	if fi.Mode().IsRegular() {
		if _, err := unpack.Kind(src); err != nil {
			abs, err := filepath.Abs(src)
			if err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				return 1
			}
			det, ok := suite.ClassifyFile(abs, filepath.Base(abs))
			if !ok {
				fmt.Fprintln(os.Stderr, "--suite-export: not a recognized forensic-suite export file (AXIOM CSV, Case.mfdb, Plaso json_line/l2tcsv, Autopsy Files - Text, .ufd/.ufdx):", sanitize.Terminal(src))
				return 1
			}
			pl := &aiexport.Plan{Root: filepath.Dir(abs), Suite: 1, Files: []aiexport.PlannedFile{{
				Path: abs, Rel: filepath.Base(abs), Rule: det.Rule, Type: det.Type, Product: det.Product, Suite: &det}}}
			fmt.Printf("Forensic-suite export file: %s (%s)\n", sanitize.Terminal(filepath.Base(abs)), det.String())
			o.tree, o.aiPlan, o.aiOnly = pl.Root, pl, true
			o.notes = map[string]string{"mode": "suite-export", "suite_export_source": src}
			return collectImport(o)
		}
	}
	return collectAIExport(src, o)
}
