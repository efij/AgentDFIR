package shellshape

import "testing"

func TestStripHeredocs(t *testing.T) {
	in := "cd x && cat > f.md <<'EOF'\nclaude --dangerously-skip-permissions -p x\nDROP DATABASE prod;\nEOF\necho done"
	got := StripHeredocs(in)
	if got != "cd x && cat > f.md <<'EOF'\necho done" {
		t.Errorf("got %q", got)
	}
	if StripHeredocs("python -c \"exec(b64decode('eA=='))\"") != "python -c \"exec(b64decode('eA=='))\"" {
		t.Error("non-heredoc changed")
	}
	if StripHeredocs("grep x <<< \"$v\"\nnext") != "grep x <<< \"$v\"\nnext" {
		t.Error("here-string treated as heredoc")
	}
	code := "bash <<'EOF'\necho H4sI | base64 -d | sh\nEOF"
	if StripHeredocs(code) != code {
		t.Errorf("interpreter heredoc removed: %q", StripHeredocs(code))
	}
	py := "python3 - <<EOF\nimport os\nEOF"
	if StripHeredocs(py) != py {
		t.Errorf("python heredoc removed")
	}
	shift := "python3 -c \"print(1<<X)\"\nrm -rf ./x\nnext"
	if StripHeredocs(shift) != shift {
		t.Errorf("shift swallowed lines: %q", StripHeredocs(shift))
	}
}
