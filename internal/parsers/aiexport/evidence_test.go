package aiexport

import "testing"

func TestClaudeExportToolEvidence(t *testing.T) {
	res, _ := parseFixture(t, "claude")
	const conv = "conversations.json"
	use := one(t, res, conv, "/0/chat_messages/1/content/1")
	r := one(t, res, conv, "/0/chat_messages/1/content/2")
	if use.ArgsDigest == "" {
		t.Fatalf("tool_use without an argument digest: %+v", use)
	}
	if use.ResultRef != r.EventID || r.ResultRef != use.EventID {
		t.Fatalf("pairing: call→%q (result %s), result→%q (call %s)", use.ResultRef, r.EventID, r.ResultRef, use.EventID)
	}
	if r.ResultDigest == "" || r.ResultStatus != "ok" {
		t.Fatalf("result: digest %q status %q", r.ResultDigest, r.ResultStatus)
	}
	if use.ApprovalState != "" || r.ApprovalState != "" {
		t.Fatal("approval set without a record")
	}
	for _, ev := range byPointer(res, conv, "/0/chat_messages/0") {
		if ev.Result == resultAttachment && ev.InputModality == "" {
			t.Fatalf("attachment without a modality: %+v", ev)
		}
	}
	if pr := byPointer(res, "projects.json", "/0/docs/0"); len(pr) != 1 || pr[0].InputModality != "" {
		t.Fatalf("project knowledge document given a turn modality: %+v", pr)
	}
}

func TestAttachmentModality(t *testing.T) {
	for _, c := range []struct{ kind, name, want string }{
		{"image/png", "", "image"},
		{"audio/mpeg", "", "audio"},
		{"application/pdf", "", "document"},
		{"", "shot.JPG", "image"},
		{"file", "notes.txt", "document"},
		{"video/mp4", "", ""},
		{"project document", "runbook.md", ""},
	} {
		if got := attachmentModality(c.kind, c.name); got != c.want {
			t.Errorf("%q %q: %q, want %q", c.kind, c.name, got, c.want)
		}
	}
}
