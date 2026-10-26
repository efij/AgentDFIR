package rulepack

import (
	"testing"

	"github.com/efij/AgentDFIR/v5/internal/shellshape"
)

// TestCommunityPackV4RuleSamples: hit/miss table for the rules added in
// community-pack v7 (docs/detection-v4.md). Samples go through the same
// shell-scope normalization the matcher applies.
func TestCommunityPackV4RuleSamples(t *testing.T) {
	p, err := LoadFile("../../rules/community-pack.json")
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]*Rule{}
	for i := range p.Rules {
		byID[p.Rules[i].ID] = &p.Rules[i]
	}
	cases := []struct {
		id   string
		hit  []string
		miss []string
	}{
		{"AGENT_SENSITIVE_DATA_STAGING",
			[]string{
				`base64 -w0 ~/.ssh/id_ed25519 > /tmp/k.txt`,
				`cat ~/.aws/credentials | base64 > /tmp/.c`,
				`cp ~/.aws/credentials /tmp/aws.bak`,
				`cat .env >> /dev/shm/e`,
				`openssl base64 -in ~/.codex/auth.json -out /var/tmp/a.b64 > /var/tmp/log`,
				`gzip -c ~/.kube/config > $TMPDIR/kc.gz`,
			},
			[]string{
				`cp .env.example .env`,
				`cat ~/.aws/config`,
				`base64 build/app.bin > /tmp/app.b64`,
				`cp ~/.ssh/id_ed25519.pub ~/backup/`,
				`cp /tmp/settings.json ~/.claude/settings.json`,
				`grep -c token ~/.netrc`,
			}},
		{"AGENT_AUDIT_COVERAGE_LOSS",
			[]string{
				`jq '.cleanupPeriodDays = 1' ~/.claude/settings.json > /tmp/s`,
				`claude config set -g cleanupPeriodDays 0`,
				`sudo launchctl bootout system /Library/LaunchDaemons/com.crowdstrike.falcond.plist`,
				`sudo systemctl stop rsyslog systemd-journald`,
				`Stop-Service -Name EventLog -Force`,
				`wevtutil sl Microsoft-Windows-Sysmon/Operational /e:false`,
				`auditpol /clear /y`,
				`sudo log config --mode "level:off"`,
				`jq '.env.CLAUDE_CODE_ENABLE_TELEMETRY = "0"' ~/.claude/settings.json > /tmp/s`,
				`export CLAUDE_CODE_ENABLE_TELEMETRY=false`,
			},
			[]string{
				`jq '.cleanupPeriodDays = 30' ~/.claude/settings.json`,
				`systemctl status rsyslog`,
				`launchctl list | grep falcon`,
				`launchctl unload ~/Library/LaunchAgents/com.example.devserver.plist`,
				`Get-Service EventLog`,
				`log show --last 1h`,
				`sudo systemctl restart nginx`,
				`git commit -m "docs: never run systemctl stop rsyslog on prod"`,
				`export CLAUDE_CODE_ENABLE_TELEMETRY=1`,
				`OTEL_SDK_DISABLED=true go test ./...`,
			}},
	}
	for _, c := range cases {
		r := byID[c.id]
		if r == nil {
			t.Fatalf("rule %s missing from the community pack", c.id)
		}
		subject := func(s string) string {
			if r.Match.Scope == "shell" {
				return shellshape.Strip(shellshape.ExpandVars(s))
			}
			return shellshape.StripAllHeredocs(s)
		}
		for _, s := range c.hit {
			if !matches(r, subject(s)) {
				t.Errorf("%s should match %q", c.id, s)
			}
		}
		for _, s := range c.miss {
			if matches(r, subject(s)) {
				t.Errorf("%s should not match %q", c.id, s)
			}
		}
	}
}
