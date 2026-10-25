package suite

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/efij/AgentDFIR/v4/internal/parsers/plaso"
)

func plasoRead(r io.Reader, each func()) (plaso.Stats, error) {
	return plaso.Read(r, plaso.FormatJSONLine, func(plaso.Entry) error { each(); return nil })
}

func seed(f *testing.F, paths ...string) {
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil {
			f.Add(b)
		}
	}
}

func FuzzReadUFDRReport(f *testing.F) {
	seed(f, "testdata/ufdr/report.xml", "testdata/ufdr-malformed/report.xml", "testdata/ufdr-xxe/report.xml")
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ReadUFDRReport(bytes.NewReader(b), func(UFDRRecord) {})
	})
}

func FuzzDescriptor(f *testing.F) {
	seed(f, "testdata/ufd/synthetic.ufd", "testdata/ufd/group.ufdx")
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ParseUFD(bytes.NewReader(b))
		_, _ = ParseUFDX(bytes.NewReader(b))
	})
}

func FuzzReadTable(f *testing.F) {
	seed(f, "testdata/axiom/Chrome Web History.csv", "testdata/axiom/ChatGPT Messages.csv", "testdata/autopsy/files.txt")
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = Sniff(b, "x.csv")
		_, _, _ = readTable(bytes.NewReader(b), nil, func([]string, int) error { return nil })
	})
}

func FuzzPlaso(f *testing.F) {
	seed(f, "testdata/plaso/timeline.jsonl", "testdata/plaso/timeline.l2tcsv")
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, format := range []string{plaso.FormatJSONLine, plaso.FormatL2TCSV} {
			_, _ = plaso.Read(bytes.NewReader(b), format, func(plaso.Entry) error { return nil })
		}
	})
}
