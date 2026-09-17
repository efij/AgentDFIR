package notes

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAppendFoldAndChain(t *testing.T) {
	pkg := t.TempDir()
	s := Open(pkg)
	key := FindingKey("ORPHAN_AGENT", []string{"a.jsonl:1 (artifact x, offset 0)"})
	must := func(_ Record, err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.Append(KindVerdict, key, "needs_review", "look again"))
	must(s.Append(KindVerdict, key, "true_positive", "confirmed via auditd"))
	must(s.Append(KindPin, "event:evt-000001", "on", ""))
	must(s.Append(KindPin, "event:evt-000002", "on", ""))
	must(s.Append(KindPin, "event:evt-000001", "off", ""))
	must(s.Append(KindTag, "session:S1", "add", "compromised"))
	must(s.Append(KindTag, "session:S1", "add", "compromised"))
	must(s.Append(KindNote, "session:S1", "", "attacker used vendor docs"))

	// Reopen: chain must continue from the last hash, not restart.
	s2 := Open(pkg)
	must(s2.Append(KindTag, "session:S1", "remove", "compromised"))
	st, recs := s2.Load()
	if !st.ChainOK {
		t.Fatalf("chain broken: %s", st.ChainErr)
	}
	if len(recs) != 9 || recs[8].Seq != 8 {
		t.Fatalf("records=%d lastSeq=%d", len(recs), recs[len(recs)-1].Seq)
	}
	if v := st.Verdicts[key]; v.Verdict != "true_positive" || v.Note != "confirmed via auditd" {
		t.Fatalf("verdict fold wrong: %+v", v)
	}
	if len(st.Pins) != 1 || st.Pins[0].Target != "event:evt-000002" {
		t.Fatalf("pins fold wrong: %+v", st.Pins)
	}
	if len(st.Tags["S1"]) != 0 {
		t.Fatalf("tags fold wrong: %+v", st.Tags)
	}
	if len(st.Notes["session:S1"]) != 1 {
		t.Fatalf("notes fold wrong: %+v", st.Notes)
	}

	// Tamper: edit a middle record → chain reported broken.
	data, _ := os.ReadFile(filepath.Join(pkg, "notes", "notes.jsonl"))
	tampered := []byte(string(data))
	copy(tampered[len(tampered)/2:], []byte("X"))
	os.WriteFile(filepath.Join(pkg, "notes", "notes.jsonl"), tampered, 0o600)
	st3, _ := Open(pkg).Load()
	if st3.ChainOK {
		t.Fatal("tampered notes chain reported OK")
	}
}

func TestEmptyStore(t *testing.T) {
	st, recs := Open(t.TempDir()).Load()
	if !st.ChainOK || len(recs) != 0 || st.Records != 0 {
		t.Fatalf("empty store wrong: %+v", st)
	}
}
