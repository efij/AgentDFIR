package cli

import "testing"

func TestIsProofReport(t *testing.T) {
	for _, c := range []struct {
		args []string
		want bool
	}{
		{[]string{"pkg", "--format", "proof"}, true},
		{[]string{"--format=proof", "pkg"}, true},
		{[]string{"pkg", "--format", "html"}, false},
		{[]string{"pkg", "proof"}, false},
	} {
		if got := isProofReport(c.args); got != c.want {
			t.Errorf("%v: %v", c.args, got)
		}
	}
}
