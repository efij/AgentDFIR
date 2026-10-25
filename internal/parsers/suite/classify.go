package suite

import (
	"bytes"
	"io"
	"os"
	"path"
	"strings"

	"github.com/efij/AgentDFIR/v4/internal/parsers/plaso"
)

// Collector rules for forensic-suite export artifacts. RuleUFDRReport is
// the rule the AI-export planner already seals a UFDR report.xml under
// (internal/parsers/aiexport); the string is repeated here because this
// package must not import that one, and a test pins the two together.
const (
	RuleUFDRReport  = "ufdr.report"        // Cellebrite UFDR report.xml
	RuleUFD         = "suite.ufd"          // Cellebrite .ufd / .ufdx extraction descriptor
	RuleAxiomCSV    = "suite.axiom.csv"    // Magnet AXIOM CSV export, one artifact type per file
	RuleAxiomCaseDB = "suite.axiom.casedb" // Magnet AXIOM Case.mfdb: sealed, inventoried, not parsed
	RulePlaso       = "suite.plaso"        // psort json_line / l2tcsv timeline
	RuleAutopsy     = "suite.autopsy"      // Autopsy "Files - Text" (tab/comma delimited) report
)

// Artifact types. None is agent_session: the transcript content rules
// must not read a whole suite export.
const (
	TypeExport = "forensic_suite_export"
	TypeCaseDB = "forensic_suite_db"
)

// Products events and artifacts carry.
const (
	ProductUFDR    = "ufdr"
	ProductAxiom   = "axiom"
	ProductPlaso   = "plaso"
	ProductAutopsy = "autopsy"
)

// Kinds of suite file.
const (
	KindUFD         = "ufd"
	KindUFDX        = "ufdx"
	KindAxiomCSV    = "axiom-csv"
	KindAxiomCaseDB = "axiom-casedb"
	KindPlasoJSON   = "plaso-json_line"
	KindPlasoCSV    = "plaso-l2tcsv"
	KindAutopsy     = "autopsy-files-text"
)

// SniffBytes is the head read to classify a file.
const SniffBytes = 64 << 10

// Detection is what Sniff concluded about one file.
type Detection struct {
	Kind     string
	Rule     string
	Type     string
	Product  string
	Artifact string // AXIOM artifact name (title line or file name)
	Encoding string
	Reason   string // why a recognized file will be reported UNSUPPORTED
}

// String renders the detection for case notes.
func (d Detection) String() string {
	s := d.Product + "/" + d.Kind
	if d.Artifact != "" {
		s += "/" + d.Artifact
	}
	return s
}

// Candidate prefilters file names in a large tree: only these can be
// suite exports, so a whole image's tree is not sniffed file by file.
func Candidate(rel string) bool {
	l := strings.ToLower(rel)
	for _, ext := range []string{".csv", ".tsv", ".txt", ".jsonl", ".json", ".ufd", ".ufdx", ".mfdb", ".l2tcsv", ".plaso.json"} {
		if strings.HasSuffix(l, ext) {
			return true
		}
	}
	return false
}

// ClassifyFile reads the head of a file and classifies it.
func ClassifyFile(p, rel string) (Detection, bool) {
	f, err := os.Open(p)
	if err != nil {
		return Detection{}, false
	}
	defer f.Close()
	head := make([]byte, SniffBytes)
	n, _ := io.ReadFull(f, head)
	return Sniff(head[:n], rel)
}

var sqliteMagic = []byte("SQLite format 3\x00")

// Sniff classifies a file head. The logical path decides only between
// formats whose content alone is ambiguous (descriptor extensions,
// Case.mfdb); every other decision is made on content.
func Sniff(head []byte, rel string) (Detection, bool) {
	base := strings.ToLower(path.Base(strings.ReplaceAll(rel, `\`, "/")))
	ext := path.Ext(base)
	switch ext {
	case ".mfdb":
		d := Detection{Kind: KindAxiomCaseDB, Rule: RuleAxiomCaseDB, Type: TypeCaseDB, Product: ProductAxiom}
		if !bytes.HasPrefix(head, sqliteMagic) {
			d.Reason = "not a SQLite database"
		}
		return d, true
	case ".ufd":
		if t := bytes.TrimLeft(decodeUTF16(head), "\xef\xbb\xbf \t\r\n"); len(t) > 0 && t[0] == '[' {
			return Detection{Kind: KindUFD, Rule: RuleUFD, Type: TypeExport, Product: ProductUFDR}, true
		}
		return Detection{}, false
	case ".ufdx":
		if t := bytes.TrimLeft(head, "\xef\xbb\xbf \t\r\n"); len(t) > 0 && t[0] == '<' {
			return Detection{Kind: KindUFDX, Rule: RuleUFD, Type: TypeExport, Product: ProductUFDR}, true
		}
		return Detection{}, false
	}
	switch plaso.Sniff(head) {
	case plaso.FormatJSONLine:
		return Detection{Kind: KindPlasoJSON, Rule: RulePlaso, Type: TypeExport, Product: ProductPlaso}, true
	case plaso.FormatL2TCSV:
		return Detection{Kind: KindPlasoCSV, Rule: RulePlaso, Type: TypeExport, Product: ProductPlaso}, true
	}
	sh, ok := sniffTable(head)
	if !ok {
		return Detection{}, false
	}
	switch {
	case isAxiomHeader(sh.Header):
		name := sh.Title
		if name == "" {
			name = strings.TrimSuffix(path.Base(strings.ReplaceAll(rel, `\`, "/")), path.Ext(rel))
		}
		return Detection{Kind: KindAxiomCSV, Rule: RuleAxiomCSV, Type: TypeExport, Product: ProductAxiom,
			Artifact: clip(name, 120), Encoding: sh.Encoding}, true
	case isAutopsyHeader(sh.Header):
		return Detection{Kind: KindAutopsy, Rule: RuleAutopsy, Type: TypeExport, Product: ProductAutopsy, Encoding: sh.Encoding}, true
	}
	return Detection{}, false
}

// axiomTrailer are the per-hit columns AXIOM appends to every artifact
// CSV it exports; "Item ID" plus one of them identifies the export.
var axiomTrailer = []string{"Evidence number", "Source", "Location", "Recovery method", "Deleted source", "Artifact type", "Artifact"}

func isAxiomHeader(h []string) bool {
	if column(h, "Item ID") < 0 {
		return false
	}
	return column(h, axiomTrailer...) >= 0
}

// autopsyColumns are the column names of Autopsy's "Files - Text" report
// (FileReportDataTypes in the Autopsy source).
var autopsyColumns = []string{"File Extension", "File Type", "Is Deleted", "Last Accessed", "File Created",
	"Last Modified", "Size", "Address", "Hash Value", "Known Status", "Permissions"}

func isAutopsyHeader(h []string) bool {
	if column(h, "Name") < 0 || column(h, "Full Path") < 0 {
		return false
	}
	n := 0
	for _, c := range autopsyColumns {
		if column(h, c) >= 0 {
			n++
		}
	}
	return n >= 2
}
