package evtx_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"strings"
	"testing"
	"time"

	"github.com/efij/AgentDFIR/v5/internal/endpoint/evtx"
	. "github.com/efij/AgentDFIR/v5/internal/endpoint/evtx/evtxtest"
)

var t0 = time.Date(2026, 8, 30, 10, 0, 7, 123456700, time.UTC)

func parse(t *testing.T, img []byte) ([]*evtx.Event, *evtx.Stats) {
	t.Helper()
	var evs []*evtx.Event
	st, err := evtx.Parse(bytes.NewReader(img), int64(len(img)), func(e *evtx.Event) { evs = append(evs, e) })
	if err != nil {
		t.Fatal(err)
	}
	return evs, st
}

func sysmon1(id uint64, at time.Time, cmd string) Event {
	return Event{
		Provider: "Microsoft-Windows-Sysmon", ProviderGUID: "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}",
		EventID: 1, Qualifiers: -1, Version: 5, Level: 4, Task: 1, Keywords: 0x8000000000000000,
		Time: at, RecordID: id, PID: 3056, TID: 4012,
		Channel: "Microsoft-Windows-Sysmon/Operational", Computer: "DESK-01", UserSID: "S-1-5-18",
		Data: []KV{
			F("UtcTime", String(at.Format("2006-01-02 15:04:05.000"))),
			F("ProcessGuid", GUID("{8E2A1C3B-0000-0000-1000-000000000A00}")),
			F("ProcessId", Uint32(4411)),
			F("Image", String(`C:\Windows\System32\cmd.exe`)),
			F("CommandLine", String(cmd)),
			F("User", String(`DESK\dev`)),
			F("ParentProcessId", Uint32(4400)),
			F("ParentImage", String(`C:\Users\dev\AppData\Local\Programs\cursor\Cursor.exe`)),
		},
	}
}

func TestRoundTripSystemAndEventData(t *testing.T) {
	img := Build(Events([]Event{
		sysmon1(77, t0, "cmd.exe /c rmdir /s /q build"),
		sysmon1(78, t0.Add(time.Second), "cmd.exe /c dir"), // same template: back-reference, names from the chunk table
		{
			Provider: "Microsoft-Windows-Security-Auditing", EventID: 4688, Qualifiers: 0, Version: 2, Level: 0, Task: 13312, Keywords: 0x8020000000000000,
			Time: t0.Add(2 * time.Second), RecordID: 79, PID: 4, TID: 120, Channel: "Security", Computer: "DESK-01",
			Data: []KV{F("NewProcessId", Hex64(0x1a2b)), F("NewProcessName", String(`C:\Windows\System32\whoami.exe`)), F("SubjectUserSid", SID("S-1-5-21-1004336348-1177238915-682003330-512"))},
		},
	}), Options{})
	evs, st := parse(t, img)
	if len(evs) != 3 || st.Records != 3 || st.Chunks != 1 || st.BadChunks != 0 || !st.HeaderChecksumOK || st.MajorVersion != 3 || len(st.Problems) != 0 {
		t.Fatalf("stats %+v, %d events", st, len(evs))
	}
	e := evs[0]
	s := e.System
	if s.Provider != "Microsoft-Windows-Sysmon" || s.ProviderGUID != "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" || s.EventID != "1" || s.Qualifiers != "" ||
		s.Version != "5" || s.Level != "4" || s.Task != "1" || s.Opcode != "0" || s.Keywords != "0x8000000000000000" ||
		s.TimeCreated != "2026-08-30T10:00:07.1234567Z" || s.EventRecordID != "77" || s.ProcessID != "3056" || s.ThreadID != "4012" ||
		s.Channel != "Microsoft-Windows-Sysmon/Operational" || s.Computer != "DESK-01" || s.UserID != "S-1-5-18" || s.ActivityID != "" {
		t.Fatalf("system: %+v", s)
	}
	if e.RecordID != 77 || !e.Written.Equal(t0) || e.Unverified {
		t.Fatalf("record header: %+v", e)
	}
	if e.Data["CommandLine"] != "cmd.exe /c rmdir /s /q build" || e.Data["ProcessId"] != "4411" || e.Data["ProcessGuid"] != "{8E2A1C3B-0000-0000-1000-000000000A00}" ||
		e.Data["ParentImage"] != `C:\Users\dev\AppData\Local\Programs\cursor\Cursor.exe` || e.Data["UtcTime"] != "2026-08-30 10:00:07.123" {
		t.Fatalf("data: %v", e.Data)
	}
	if evs[1].Data["CommandLine"] != "cmd.exe /c dir" || evs[1].System.EventRecordID != "78" {
		t.Fatalf("second record (template reuse): %+v", evs[1])
	}
	sec := evs[2]
	if sec.System.Qualifiers != "0" || sec.Data["NewProcessId"] != "0x1a2b" || sec.Data["SubjectUserSid"] != "S-1-5-21-1004336348-1177238915-682003330-512" || sec.System.Keywords != "0x8020000000000000" {
		t.Fatalf("security: %+v %v", sec.System, sec.Data)
	}
}

func TestAllValueTypes(t *testing.T) {
	ts := time.Date(2026, 1, 2, 3, 4, 5, 678000000, time.UTC)
	data := []KV{
		F("null", Null()), F("str", String("héllo")), F("ansi", Ansi("plain")),
		F("i8", Int8(-5)), F("u8", Uint8(250)), F("i16", Int16(-300)), F("u16", Uint16(65000)),
		F("i32", Int32(-70000)), F("u32", Uint32(4000000000)), F("i64", Int64(-1<<40)), F("u64", Uint64(1<<63)),
		F("r32", Real32(1.5)), F("r64", Real64(-2.25)), F("bool", Bool(true)), F("boolf", Bool(false)),
		F("bin", Binary([]byte{0xde, 0xad, 0xbe, 0xef})), F("guid", GUID("{01234567-89AB-CDEF-0123-456789ABCDEF}")),
		F("sizet", SizeT(0xffff)), F("ft", FileTime(ts)), F("st", SystemTime(ts)),
		F("sid", SID("S-1-5-32-544")), F("h32", Hex32(0xbeef)), F("h64", Hex64(0x1122334455)),
		F("strs", StringArray("a", "bc", "")), F("u16s", Uint16Array(1, 2, 3)),
	}
	want := map[string]string{
		"null": "", "str": "héllo", "ansi": "plain", "i8": "-5", "u8": "250", "i16": "-300", "u16": "65000",
		"i32": "-70000", "u32": "4000000000", "i64": "-1099511627776", "u64": "9223372036854775808",
		"r32": "1.5", "r64": "-2.25", "bool": "true", "boolf": "false", "bin": "DEADBEEF",
		"guid": "{01234567-89AB-CDEF-0123-456789ABCDEF}", "sizet": "0xffff",
		"ft": "2026-01-02T03:04:05.6780000Z", "st": "2026-01-02T03:04:05.6780000Z",
		"sid": "S-1-5-32-544", "h32": "0xbeef", "h64": "0x1122334455", "strs": "a,bc", "u16s": "1,2,3",
	}
	img := Build(Events([]Event{{Provider: "P", EventID: 9, Qualifiers: -1, Time: ts, RecordID: 1, Channel: "C", Computer: "H", Data: data}}), Options{})
	evs, st := parse(t, img)
	if len(evs) != 1 {
		t.Fatalf("%+v", st)
	}
	for k, w := range want {
		if got := evs[0].Data[k]; got != w {
			t.Errorf("%s: got %q want %q", k, got, w)
		}
	}
}

func TestMarkupTokensAndNestedTemplates(t *testing.T) {
	inner := &Template{ID: 50, Body: Elem{Name: "Inner", Children: []Node{Sub{ID: 0, Type: TString}}}}
	body := Elem{Name: "Event", Children: []Node{
		Elem{Name: "System", Children: []Node{
			Elem{Name: "Provider", Attrs: []Attr{{Name: "Name", Value: []Node{Text("A"), EntityRef("amp"), Text("B"), CharRef('!')}}}},
			Elem{Name: "EventID", Children: []Node{Sub{ID: 0, Type: TUint16}}},
		}},
		PI{Target: "xml-stylesheet", Data: "href=x"},
		Elem{Name: "EventData", Children: []Node{
			Elem{Name: "Data", Attrs: []Attr{{Name: "Name", Value: []Node{Text("cdata")}}}, Children: []Node{CDATA("<raw>"), EntityRef("lt")}},
			Elem{Name: "Data", Attrs: []Attr{{Name: "Name", Value: []Node{Text("opt")}}, {Name: "Extra", Value: []Node{Sub{ID: 2, Optional: true, Type: TString}}}}, Children: []Node{Sub{ID: 2, Optional: true, Type: TString}}},
			Elem{Name: "Data", Children: []Node{Sub{ID: 1, Type: TBinXML}}}, // unnamed, nested BinXml carrying a template instance
		}},
	}}
	tmpl := &Template{ID: 7, Body: body}
	recs := []Record{{ID: 1, Written: t0, Template: tmpl, Values: []Value{Uint16(42), BinXML(Instance{Template: inner, Values: []Value{String("deep")}}), Null()}}}
	evs, st := parse(t, Build(recs, Options{}))
	if len(evs) != 1 {
		t.Fatalf("%+v", st)
	}
	e := evs[0]
	if e.System.Provider != "A&B!" || e.System.EventID != "42" {
		t.Fatalf("system: %+v", e.System)
	}
	if e.Data["cdata"] != "<raw><" || e.Data["opt"] != "" || e.Data["Data[2]"] != "" {
		t.Fatalf("data: %q", e.Data)
	}
}

func TestMultipleChunksSlackAndDirty(t *testing.T) {
	var list []Event
	for i := 0; i < 900; i++ {
		list = append(list, sysmon1(uint64(i+1), t0.Add(time.Duration(i)*time.Second), fmt.Sprintf("cmd.exe /c echo %d %s", i, strings.Repeat("x", i%50))))
	}
	img := Build(Events(list), Options{Dirty: true, Slack: true})
	evs, st := parse(t, img)
	if len(evs) != 900 || st.Chunks < 3 || st.BadChunks != 0 || !st.Dirty || st.SlackRecords < 1 { // full chunks rarely have room for the copy
		t.Fatalf("stats %+v events %d", st, len(evs))
	}
	for i, e := range evs {
		if e.RecordID != uint64(i+1) || !strings.HasPrefix(e.Data["CommandLine"], fmt.Sprintf("cmd.exe /c echo %d ", i)) {
			t.Fatalf("record %d: %+v", i, e)
		}
	}
	if evs[len(evs)-1].Chunk == 0 {
		t.Fatal("expected later chunks")
	}
	// Forced small chunks: every chunk re-defines the template and names inline.
	img = Build(Events(list[:10]), Options{RecordsPerChunk: 3, Slack: true})
	evs, st = parse(t, img)
	if len(evs) != 10 || st.Chunks != 4 || st.SlackRecords != 4 {
		t.Fatalf("small chunks: %+v", st)
	}
}

func TestCorruptionIsRecordedNotFatal(t *testing.T) {
	img := Build(Events([]Event{sysmon1(1, t0, "QQa"), sysmon1(2, t0, "b"), sysmon1(3, t0, "c"), sysmon1(4, t0, "d")}), Options{RecordsPerChunk: 2})

	// File header checksum.
	bad := append([]byte(nil), img...)
	bad[24] ^= 0xff
	evs, st := parse(t, bad)
	if len(evs) != 4 || st.HeaderChecksumOK || !strings.Contains(strings.Join(st.Problems, "\n"), "file header checksum mismatch") {
		t.Fatalf("header crc: %+v", st)
	}

	// Event-record bytes in chunk 0 altered: records CRC fails, record is still structurally valid.
	bad = append([]byte(nil), img...)
	i := bytes.Index(bad[4096:4096+65536], []byte{'Q', 0, 'Q', 0, 'a', 0}) + 4096
	bad[i+4] = 'z'
	evs, st = parse(t, bad)
	if len(evs) != 4 || st.BadChunks != 1 || !evs[0].Unverified || evs[2].Unverified || evs[0].Data["CommandLine"] != "QQz" {
		t.Fatalf("records crc: %+v %+v", st, evs[0])
	}

	// Chunk signature destroyed: chunk skipped, next chunk still read.
	bad = append([]byte(nil), img...)
	copy(bad[4096:], "XXXXXXXX")
	evs, st = parse(t, bad)
	if len(evs) != 2 || st.BadChunks != 1 || evs[0].RecordID != 3 {
		t.Fatalf("bad chunk: %+v", st)
	}

	// Record size field broken: rest of that chunk skipped, other chunk fine.
	bad = append([]byte(nil), img...)
	binary.LittleEndian.PutUint32(bad[4096+512+4:], 9)
	evs, st = parse(t, bad)
	if len(evs) != 2 || st.BadRecords != 1 {
		t.Fatalf("bad size: %+v", st)
	}

	// BinXml garbage inside a record with a valid envelope: that record fails, the next one parses.
	bad = append([]byte(nil), img...)
	for j := 4096 + 512 + 24; j < 4096+512+40; j++ {
		bad[j] = 0x07
	}
	evs, st = parse(t, bad)
	if len(evs) != 3 || st.BadRecords != 1 {
		t.Fatalf("binxml garbage: %+v", st)
	}

	// Truncated mid-chunk.
	evs, st = parse(t, img[:4096+65536+3000])
	if len(evs) < 2 || st.ProblemCount == 0 || !strings.Contains(strings.Join(st.Problems, "\n"), "truncated") {
		t.Fatalf("truncated: %d %+v", len(evs), st)
	}

	// Header-only and too-short files.
	if _, st = parse(t, img[:4096]); st.ProblemCount != 0 {
		t.Fatalf("empty log: %+v", st)
	}
	if _, st = parse(t, img[:200]); st.ProblemCount == 0 {
		t.Fatalf("short: %+v", st)
	}
	if _, err := evtx.Parse(bytes.NewReader([]byte("<Events/>")), 9, func(*evtx.Event) {}); !errors.Is(err, evtx.ErrNotEVTX) {
		t.Fatalf("not evtx: %v", err)
	}

	// Unsupported major version is reported, parsing continues.
	bad = append([]byte(nil), img...)
	binary.LittleEndian.PutUint16(bad[38:], 4)
	evs, st = parse(t, bad)
	if len(evs) != 4 || !strings.Contains(strings.Join(st.Problems, "\n"), "UNSUPPORTED evtx format version 4.1") {
		t.Fatalf("version: %+v", st)
	}
}

func TestHostileRecursionBounded(t *testing.T) {
	// A nested BinXml value that nests 100 levels deep must be refused, not overflow.
	var n Node = Elem{Name: "leaf"}
	for i := 0; i < 100; i++ {
		n = Elem{Name: "x", Children: []Node{n}}
	}
	tmpl := &Template{ID: 1, Body: Elem{Name: "Event", Children: []Node{Sub{ID: 0, Type: TBinXML}}}}
	ok := sysmon1(2, t0, "fine")
	img := Build(append([]Record{{ID: 1, Written: t0, Template: tmpl, Values: []Value{BinXML(n)}}}, Events([]Event{ok})...), Options{})
	evs, st := parse(t, img)
	if len(evs) != 1 || st.BadRecords != 1 || !strings.Contains(strings.Join(st.Problems, "\n"), "too deep") {
		t.Fatalf("depth: %+v", st)
	}
}

// Attribute text is charged to the render budgets: one substitution
// repeated thousands of times inside an attribute cannot amplify a
// small record into megabytes per record, or tens of megabytes per chunk.
func TestAttributeAmplificationBounded(t *testing.T) {
	amplifier := func(refs int) *Template {
		parts := make([]Node, refs)
		for i := range parts {
			parts[i] = Sub{ID: 0, Type: TString}
		}
		return &Template{ID: uint32(refs), Body: Elem{Name: "Event", Attrs: []Attr{{Name: "x", Value: parts}}}}
	}
	blob := String(strings.Repeat("A", 1000))

	// Per record: 5000 × 1000 bytes is over the 4 MiB record budget.
	evs, st := parse(t, Build([]Record{{ID: 1, Written: t0, Template: amplifier(5000), Values: []Value{blob}}}, Options{}))
	if len(evs) != 0 || st.BadRecords != 1 || !strings.Contains(strings.Join(st.Problems, "\n"), "budget") {
		t.Fatalf("record budget: %d events %+v", len(evs), st)
	}

	// Per chunk: 2 MB per record stays under the record budget, but the
	// chunk budget stops the rest of the chunk.
	tmpl := amplifier(2000)
	var recs []Record
	for i := 0; i < 25; i++ {
		recs = append(recs, Record{ID: uint64(i + 1), Written: t0, Template: tmpl, Values: []Value{blob}})
	}
	evs, st = parse(t, Build(recs, Options{}))
	if st.Chunks != 1 || len(evs) == 0 || len(evs) >= 25 || st.BadRecords != 25-len(evs) {
		t.Fatalf("chunk budget: %d events %+v", len(evs), st)
	}
}

func FuzzChunk(f *testing.F) {
	img := Build(Events([]Event{sysmon1(1, t0, "cmd.exe /c rmdir /s /q build"), sysmon1(2, t0, "x")}), Options{})
	f.Add(img[4096:])
	f.Add(Build([]Record{{ID: 1, Written: t0, Template: &Template{ID: 1, Body: Elem{Name: "Event", Children: []Node{Sub{ID: 0, Type: TBinXML}}}},
		Values: []Value{BinXML(Elem{Name: "a", NoDep: true, Attrs: []Attr{{Name: "b", Value: []Node{Text("c")}}}})}}}, Options{})[4096:])
	f.Fuzz(func(t *testing.T, chunk []byte) {
		if len(chunk) > evtx.ChunkSize {
			chunk = chunk[:evtx.ChunkSize]
		}
		// Keep the signature and fix both checksums so the fuzzer reaches the BinXml parser.
		file := append(append([]byte(nil), img[:4096]...), chunk...)
		if len(chunk) >= 512 {
			c := file[4096:]
			copy(c, "ElfChnk\x00")
			fixChecksums(c)
		}
		_, _ = evtx.Parse(bytes.NewReader(file), int64(len(file)), func(e *evtx.Event) {
			_ = e.System.EventID
		})
	})
}

func fixChecksums(c []byte) {
	le := binary.LittleEndian
	free := int(le.Uint32(c[48:]))
	if free >= 512 && free <= len(c) {
		le.PutUint32(c[52:], crc(c[512:free]))
	}
	le.PutUint32(c[124:], crc(append(append([]byte(nil), c[:120]...), c[128:512]...)))
}

func crc(b []byte) uint32 { return crc32.ChecksumIEEE(b) }
