package netdest

import (
	"reflect"
	"testing"
)

// The URL host is what a client contacts: never the userinfo before '@'.
func TestExtractURLHostsUseNetURL(t *testing.T) {
	for cmd, want := range map[string][]string{
		"curl https://trusted.com@evil.com/x":                         {"evil.com"},
		"curl -s 'https://user:pw@api.example.org:8443/v1'":           {"api.example.org:8443"},
		"curl https://1.2.3.4@evil.com/x":                             {"evil.com"}, // userinfo IP not picked up by the IP pattern either
		"curl http://203.0.113.9:8080/a":                              {"203.0.113.9:8080", "203.0.113.9"},
		"curl http://[2001:db8::5]:8080/a":                            {"[2001:db8::5]:8080"},
		"curl https://ex%61mple.com/p":                                nil, // percent-encoded host: dropped
		"curl https://example.com/a%20b":                              {"example.com"},
		"curl https://$HOST/x":                                        nil, // not a host name
		"curl https://[bad/x":                                         nil, // does not parse
		"wget http://evil.com/redirect@trusted.com":                   {"evil.com"},
		"curl https://Example.COM./x && scp f u@files.example.net:/t": {"example.com", "files.example.net"},
	} {
		if got := Extract(cmd); !reflect.DeepEqual(got, want) {
			t.Errorf("Extract(%q) = %v, want %v", cmd, got, want)
		}
	}
	if h, ok := URLHost("https://a@b.example:99/"); !ok || h != "b.example:99" {
		t.Errorf("URLHost: %q %v", h, ok)
	}
}
