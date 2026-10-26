package aiexport

import (
	"bytes"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/efij/AgentDFIR/v5/internal/casepkg"
	"github.com/efij/AgentDFIR/v5/internal/parsers/suite"
)

// Planning decides, before anything is sealed, which files of a tree are
// AI-service export files and under which collector rule each is kept.
// It reads only the head of a file (SniffBytes) and never follows a
// symlink. The same Sniff runs again at parse time on the sealed bytes,
// which is what the events rely on; the plan only routes files and feeds
// the case notes.

// PlanMode selects which files a plan keeps.
type PlanMode int

const (
	// PlanAll keeps every file of the tree: recognized export files under
	// their export rules, everything else as aiexport.file (or ufdr.file
	// inside a UFDR). Used for --ai-export and for archives found to be
	// an export or a UFDR.
	PlanAll PlanMode = iota
	// PlanRecognized keeps only recognized export files. Used when an
	// --import tree is searched for exports among other evidence.
	PlanRecognized
)

// maxPlanFiles bounds how many files a plan inspects.
const maxPlanFiles = 500000

// PlannedFile is one file of the tree and how it is sealed.
type PlannedFile struct {
	Path      string     // absolute path on disk
	Rel       string     // path inside the export (slash separated); the artifact's logical path
	Rule      string     // collector rule
	Type      string     // artifact type
	Product   string     // product id
	Detection *Detection // nil when the file is sealed but not an export file
	// Suite is set for a forensic-suite export file (AXIOM CSV, Case.mfdb,
	// Plaso timeline, Autopsy report, UFD descriptor); internal/parsers/suite
	// reads it.
	Suite *suite.Detection
}

// Plan is the result of planning a tree.
type Plan struct {
	Root       string
	Files      []PlannedFile
	UFDR       bool   // a Cellebrite UFDR report.xml was found at the top of the tree
	UFDRReport string // its in-tree path
	Recognized int    // files with a detection (including UNSUPPORTED ones)
	Suite      int    // forensic-suite export files (see PlannedFile.Suite)
	Truncated  bool   // more than maxPlanFiles files; the rest were not inspected
}

// Found reports whether the tree holds anything this package handles.
func (p *Plan) Found() bool { return p != nil && (p.Recognized > 0 || p.UFDR || p.Suite > 0) }

// SuiteDetections lists "<in-tree path>=<product/kind[/artifact]>" for
// every forensic-suite export file, sorted, for case notes.
func (p *Plan) SuiteDetections() []string {
	var out []string
	for _, f := range p.Files {
		if f.Suite != nil {
			out = append(out, f.Rel+"="+f.Suite.String())
		}
	}
	sort.Strings(out)
	return out
}

// Detections lists "<in-export path>=<service/kind/variant>" for every
// recognized file, sorted, for case notes.
func (p *Plan) Detections() []string {
	var out []string
	for _, f := range p.Files {
		if f.Detection != nil {
			out = append(out, f.Rel+"="+f.Detection.String())
		}
	}
	sort.Strings(out)
	return out
}

// Services lists the distinct services detected, sorted.
func (p *Plan) Services() []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range p.Files {
		if f.Detection != nil && f.Detection.Kind != KindUnsupported && !seen[f.Detection.Service] {
			seen[f.Detection.Service] = true
			out = append(out, f.Detection.Service)
		}
	}
	sort.Strings(out)
	return out
}

// PlanTree walks root and classifies its files. skip, when set, prunes
// paths the caller already collects some other way (for an --import tree,
// the product directories the profile collectors read).
func PlanTree(root string, mode PlanMode, skip func(path string) bool) (*Plan, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	pl := &Plan{Root: root}
	pl.UFDRReport = findUFDRReport(root)
	pl.UFDR = pl.UFDRReport != ""
	if pl.UFDR {
		mode = PlanAll
	}
	n := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if path != root && (casepkg.ExcludedByPolicy(path) || (skip != nil && skip(path))) {
				return fs.SkipDir
			}
			return nil
		}
		if skip != nil && skip(path) {
			return nil
		}
		if n >= maxPlanFiles {
			pl.Truncated = true
			return fs.SkipAll
		}
		n++
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		f := PlannedFile{Path: path, Rel: rel}
		if pl.UFDR && rel == pl.UFDRReport {
			f.Rule, f.Type, f.Product = RuleUFDRReport, TypeUFDRReport, ufdrProduct
			pl.Files = append(pl.Files, f)
			return nil
		}
		if d.Type().IsRegular() && (mode == PlanAll || candidateName(rel)) {
			if det, ok := sniffFile(path, rel); ok {
				det := det
				f.Detection = &det
				f.Product = det.Product()
				switch det.Kind {
				case KindAccount, KindFeedback, KindShared:
					f.Rule, f.Type = RuleMetadata, TypeMetadata
				default:
					f.Rule, f.Type = RuleConversations, TypeConversations
				}
				pl.Recognized++
				pl.Files = append(pl.Files, f)
				return nil
			}
		}
		if d.Type().IsRegular() && suite.Candidate(rel) {
			if sd, ok := suite.ClassifyFile(path, rel); ok {
				sd := sd
				f.Suite = &sd
				f.Rule, f.Type, f.Product = sd.Rule, sd.Type, sd.Product
				pl.Suite++
				pl.Files = append(pl.Files, f)
				return nil
			}
		}
		if mode == PlanAll {
			f.Rule, f.Type, f.Product = RuleFile, TypeFile, genericProduct
			if pl.UFDR {
				f.Rule, f.Type, f.Product = RuleUFDRFile, TypeUFDRFile, ufdrProduct
			}
			pl.Files = append(pl.Files, f)
		}
		return nil
	})
	return pl, err
}

const ufdrProduct = "ufdr"

// candidateName prefilters an --import tree: only JSON and HTML documents
// can be export files, and sniffing every file of a whole disk image's
// tree would read far more than it could find.
func candidateName(rel string) bool {
	l := strings.ToLower(rel)
	return strings.HasSuffix(l, ".json") || strings.HasSuffix(l, ".html") || strings.HasSuffix(l, ".htm")
}

func sniffFile(path, rel string) (Detection, bool) {
	f, err := os.Open(path)
	if err != nil {
		return Detection{}, false
	}
	defer f.Close()
	head := make([]byte, SniffBytes)
	n, _ := io.ReadFull(f, head)
	return Sniff(head[:n], rel)
}

// findUFDRReport looks for a Cellebrite report.xml at the top of the tree
// (or one directory down, when the archive wraps its content in a folder)
// and recognizes it by content: an XML <project> document naming
// Cellebrite. Its semantics are not parsed.
func findUFDRReport(root string) string {
	try := func(rel string) bool {
		f, err := os.Open(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return false
		}
		defer f.Close()
		head := make([]byte, 8192)
		n, _ := io.ReadFull(f, head)
		low := bytes.ToLower(head[:n])
		return bytes.Contains(low, []byte("<project")) && bytes.Contains(low, []byte("cellebrite"))
	}
	if try("report.xml") {
		return "report.xml"
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() && try(e.Name()+"/report.xml") {
			return e.Name() + "/report.xml"
		}
	}
	return ""
}

// Filter drops planned files keep rejects (for an --import tree, files
// inside product directories the profile collectors already read) and
// recounts what remains.
func (p *Plan) Filter(keep func(path string) bool) {
	if p == nil || keep == nil {
		return
	}
	out := p.Files[:0]
	p.Recognized, p.Suite = 0, 0
	for _, f := range p.Files {
		if !keep(f.Path) {
			continue
		}
		if f.Detection != nil {
			p.Recognized++
		}
		if f.Suite != nil {
			p.Suite++
		}
		out = append(out, f)
	}
	p.Files = out
}
