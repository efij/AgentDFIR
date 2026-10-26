package reconstruct

import (
	"regexp"
	"strings"
)

// Attack stages, in kill-chain order. The order is the one the incident is
// read in; it is not a claim that every incident passes through each.
const (
	StageInitialAccess = "initial_access"
	StageExecution     = "execution"
	StagePersistence   = "persistence"
	StagePrivEsc       = "privilege_escalation"
	StageCredential    = "credential_access"
	StageCollection    = "collection"
	StageExfiltration  = "exfiltration"
	StageImpact        = "impact"
	StageAntiForensics = "anti_forensics"
)

// StageOrder lists every stage in reading order.
var StageOrder = []string{StageInitialAccess, StageExecution, StagePersistence, StagePrivEsc,
	StageCredential, StageCollection, StageExfiltration, StageImpact, StageAntiForensics}

var stageRank = func() map[string]int {
	m := map[string]int{}
	for i, s := range StageOrder {
		m[s] = i
	}
	return m
}()

// techniqueStage maps the ATT&CK technique ids the rule packs use to the
// stage they belong to. A technique ATT&CK files under several tactics is
// placed where AgentDFIR's rules use it (T1685 disable or modify tools,
// T1686 disable or modify system firewall and T1070 indicator removal are
// all what an analyst calls anti-forensics). T1562 is revoked in ATT&CK
// v20.0 (internal/mitre/data/migrations.json) and stays mapped only so
// findings stored by earlier releases still stage. A
// technique missing here leaves its finding unstaged, and the report says
// how many were.
var techniqueStage = map[string]string{
	// initial access, and content that arrives from outside
	"T1195": StageInitialAccess, "T1189": StageInitialAccess, "T1566": StageInitialAccess,
	"T1078": StageInitialAccess, "T1105": StageInitialAccess, "T1080": StageInitialAccess,
	"T1557": StageInitialAccess, "T1204": StageInitialAccess,
	// execution
	"T1059": StageExecution, "T1053": StageExecution, "T1106": StageExecution,
	"T1027": StageExecution, "T1140": StageExecution, "T1036": StageExecution,
	"T1611": StageExecution,
	// persistence
	"T1546": StagePersistence, "T1547": StagePersistence, "T1574": StagePersistence,
	"T1098": StagePersistence, "T1136": StagePersistence, "T1543": StagePersistence,
	"T1565": StagePersistence,
	// privilege escalation
	"T1548": StagePrivEsc, "T1222": StagePrivEsc,
	// credential access
	"T1552": StageCredential, "T1555": StageCredential, "T1003": StageCredential,
	// collection and discovery that stages data
	"T1005": StageCollection, "T1074": StageCollection, "T1560": StageCollection,
	"T1115": StageCollection, "T1083": StageCollection, "T1046": StageCollection,
	// exfiltration and command and control
	"T1048": StageExfiltration, "T1567": StageExfiltration, "T1041": StageExfiltration,
	"T1071": StageExfiltration, "T1090": StageExfiltration,
	// impact
	"T1485": StageImpact, "T1486": StageImpact, "T1490": StageImpact,
	"T1561": StageImpact, "T1496": StageImpact,
	// anti-forensics
	"T1070": StageAntiForensics, "T1685": StageAntiForensics, "T1686": StageAntiForensics,
	"T1564": StageAntiForensics, "T1562": StageAntiForensics,
}

// TechniqueStage returns the stage of an ATT&CK technique id ("T1048",
// "T1685.002"), or "" when it is not mapped.
func TechniqueStage(t string) string {
	t = strings.ToUpper(strings.TrimSpace(t))
	if i := strings.IndexByte(t, '.'); i > 0 {
		t = t[:i]
	}
	return techniqueStage[t]
}

// stepRules classify a chain step by its name. Chain step names are
// declarative data (internal/chain/builtins.go and *.chains.json) written
// to say what the step is; the first rule that matches wins, so the more
// specific phrases come first.
var stepRules = []struct {
	re    *regexp.Regexp
	stage string
}{
	{regexp.MustCompile(`(?i)log(s)? (deleted|wiped|tamper)|anti.?forensic|transcript (rewrit|delet)|history (clear|delet)`), StageAntiForensics},
	{regexp.MustCompile(`(?i)injection|poison|untrusted|instructions in|download|fetched content`), StageInitialAccess},
	{regexp.MustCompile(`(?i)permission|privilege|escalat|bypass`), StagePrivEsc},
	{regexp.MustCompile(`(?i)wrote (its own )?(instructions|config)|writes config|self.?modif|persist|hook (written|installed)|orphan agent appears`), StagePersistence},
	{regexp.MustCompile(`(?i)secret|credential|private key|token`), StageCredential},
	{regexp.MustCompile(`(?i)collect|stag(ed|ing)|archive|cross-session message`), StageCollection},
	{regexp.MustCompile(`(?i)upload|exfil|outbound|sends data|left the host|transfer`), StageExfiltration},
	{regexp.MustCompile(`(?i)destructive|delet|wipe|destroy`), StageImpact},
	{regexp.MustCompile(`(?i)shell|execut|command|tool|spawned|commit|push`), StageExecution},
}

// StepStage returns the stage a chain step's name describes, or "".
func StepStage(name string) string {
	for _, r := range stepRules {
		if r.re.MatchString(name) {
			return r.stage
		}
	}
	return ""
}

// collectFor says, per stage, which telemetry would confirm or refute an
// item of that stage that no second witness has confirmed yet.
var collectFor = map[string]string{
	StageInitialAccess: "proxy / DNS logs for the fetched source, and the fetched content or package as it was served",
	StageExecution:     "process telemetry (Sysmon event 1, auditd EXECVE, ES exec via eslogger, EDR process events)",
	StagePersistence:   "file-write telemetry (Sysmon 11, auditd PATH, ES create/write) and the configuration file's earlier versions (baseline round, backups)",
	StagePrivEsc:       "the agent's settings/permission files over time (a baseline round) and process telemetry for the elevated command",
	StageCredential:    "file-open telemetry on the credential path (auditd watch, ES open, Sysmon 11/4663 object access)",
	StageCollection:    "file-create telemetry for the staged archive and process telemetry for the archiver",
	StageExfiltration:  "network telemetry (Sysmon 3, EDR connection events, firewall/proxy logs, DNS logs) for the destination",
	StageImpact:        "cloud audit logs (CloudTrail, Azure Activity Log, GCP Audit Logs) and file-delete telemetry for the affected resource",
	StageAntiForensics: "file-delete telemetry (Sysmon 23/26, auditd unlink, ES unlink) and file-system journals (NTFS $UsnJrnl, APFS snapshots) for the removed logs",
}
