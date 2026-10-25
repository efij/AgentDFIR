package endpoint

import "testing"

// Record-side host extraction takes the host after userinfo, never before.
func TestHostOfURLUserinfo(t *testing.T) {
	for in, want := range map[string]string{
		"http://trusted.com@evil.com/x":        "evil.com",
		"https://u:p@api.example.org:8443/v1":  "api.example.org",
		"http://evil.com/redirect@trusted.com": "evil.com",
		"http://[2001:db8::5]:8080/a":          "2001:db8::5",
		"example.com:443":                      "example.com",
	} {
		if h, _, _ := hostOfURL(in); h != want {
			t.Errorf("hostOfURL(%q) = %q, want %q", in, h, want)
		}
	}
}
