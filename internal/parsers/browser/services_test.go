package browser

import "testing"

func TestClassifyAIServiceURLs(t *testing.T) {
	cases := []struct {
		url, service, kind, id string
	}{
		{"https://chatgpt.com/c/6710aa00-1111-2222-3333-444455556666", "chatgpt", KindConversation, "6710aa00-1111-2222-3333-444455556666"},
		{"https://chat.openai.com/c/abc-123?model=x", "chatgpt", KindConversation, "abc-123"},
		{"https://chatgpt.com/g/g-abc123-helper/c/6711-aa", "chatgpt", KindConversation, "6711-aa"},
		{"https://chatgpt.com/g/g-abc123-helper", "chatgpt", KindGPT, "g-abc123-helper"},
		{"https://chatgpt.com/g/g-p-6712abc/project", "chatgpt", KindProject, "g-p-6712abc"},
		{"https://chatgpt.com/share/6710bb00-aaaa", "chatgpt", KindShare, "6710bb00-aaaa"},
		{"https://chatgpt.com/share/e/eeee-1111", "chatgpt", KindShare, "eeee-1111"},
		{"https://chatgpt.com/", "chatgpt", KindApp, ""},
		{"https://claude.ai/chat/0b6f2a3c-1d2e-4f50-8a9b-0c1d2e3f4a5b", "claude", KindConversation, "0b6f2a3c-1d2e-4f50-8a9b-0c1d2e3f4a5b"},
		{"https://claude.ai/project/0199aaaa-bbbb", "claude", KindProject, "0199aaaa-bbbb"},
		{"https://claude.ai/share/1234abcd-0000", "claude", KindShare, "1234abcd-0000"},
		{"https://claude.ai/settings/profile", "claude", KindSettings, ""},
		{"https://claude.ai/new", "claude", KindApp, ""},
		{"https://gemini.google.com/app/a1b2c3d4e5f6", "gemini", KindConversation, "a1b2c3d4e5f6"},
		{"https://gemini.google.com/u/1/app/a1b2c3d4e5f6", "gemini", KindConversation, "a1b2c3d4e5f6"},
		{"https://gemini.google.com/gem/coding-partner", "gemini", KindGPT, "coding-partner"},
		{"https://gemini.google.com/share/abc123xyz", "gemini", KindShare, "abc123xyz"},
		{"https://g.co/gemini/share/abc123xyz", "gemini", KindShare, "abc123xyz"},
		{"https://copilot.microsoft.com/chats/AbCdEf123456", "copilot", KindConversation, "AbCdEf123456"},
		{"https://copilot.microsoft.com/shares/xyz-1", "copilot", KindShare, "xyz-1"},
		{"https://m365.cloud.microsoft/chat/?auth=2", "m365-copilot", KindApp, ""},
		{"https://www.perplexity.ai/search/how-to-rotate-aws-keys-AbC123", "perplexity", KindConversation, "how-to-rotate-aws-keys-AbC123"},
		{"https://perplexity.ai/page/some-page-xyz", "perplexity", KindPage, "some-page-xyz"},
		{"https://chat.deepseek.com/a/chat/s/9f8e7d6c-1234", "deepseek", KindConversation, "9f8e7d6c-1234"},
		{"https://grok.com/chat/abcd-1234", "grok", KindConversation, "abcd-1234"},
		{"https://grok.com/share/bGVnYWN5", "grok", KindShare, "bGVnYWN5"},
		{"https://x.com/i/grok?conversation=1850000000000000001", "grok", KindConversation, "1850000000000000001"},
		{"https://x.com/i/grok", "grok", KindApp, ""},
		{"https://x.com/i/grok?conversation=<script>", "grok", KindApp, ""},
		{"https://chat.mistral.ai/chat/7c1e9a52-0d3b-4f6e-9a1c-2b3d4e5f6a7b", "mistral", KindConversation, "7c1e9a52-0d3b-4f6e-9a1c-2b3d4e5f6a7b"},
		{"https://poe.com/chat/2abc3def", "poe", KindConversation, "2abc3def"},
		{"https://poe.com/s/Ab12Cd34Ef56", "poe", KindShare, "Ab12Cd34Ef56"},
		{"https://poe.com/Claude-Sonnet", "poe", KindApp, ""},
		{"https://huggingface.co/chat/conversation/66ffeedd00", "huggingchat", KindConversation, "66ffeedd00"},
		{"https://www.meta.ai/c/abc_123", "meta-ai", KindConversation, "abc_123"},
		{"https://character.ai/chat/xyz", "character-ai", KindConversation, "xyz"},
		{"https://notebooklm.google.com/notebook/5e6f7a8b-1c2d", "notebooklm", KindProject, "5e6f7a8b-1c2d"},
		{"https://aistudio.google.com/prompts/1AbCdEfGhIj", "aistudio", KindConversation, "1AbCdEfGhIj"},
		{"https://aistudio.google.com/apikey", "aistudio", KindConsole, ""},
		{"https://platform.openai.com/playground/chat", "openai-platform", KindPlayground, ""},
		{"https://platform.openai.com/api-keys", "openai-platform", KindConsole, ""},
		{"https://console.anthropic.com/workbench/0b6f2a3c-1d2e", "anthropic-console", KindPlayground, "0b6f2a3c-1d2e"},
		{"https://console.anthropic.com/settings/keys", "anthropic-console", KindConsole, ""},
	}
	for _, c := range cases {
		m := Classify(c.url)
		if m == nil {
			t.Errorf("%s: not classified", c.url)
			continue
		}
		if m.Service.Key != c.service || m.Kind != c.kind || m.ID != c.id {
			t.Errorf("%s: got %s/%s/%q, want %s/%s/%q", c.url, m.Service.Key, m.Kind, m.ID, c.service, c.kind, c.id)
		}
	}
}

func TestClassifyRejectsEverythingElse(t *testing.T) {
	for _, u := range []string{
		"https://www.example.com/private-page",
		"https://mail.google.com/mail/u/0/#inbox",
		"https://evil.example/?q=https://chatgpt.com/c/fake",
		"https://chatgpt.com.evil.example/c/lookalike",
		"https://notclaude.ai/chat/0b6f2a3c-1d2e-4f50",
		"https://huggingface.co/models",        // huggingface outside /chat
		"https://x.com/someone/status/1",       // x.com outside /i/grok
		"https://m365.cloud.microsoft/launch/", // m365 outside /chat
		"https://google.com/search?q=gemini",
		"file:///Users/x/chatgpt.com/c/1",
		"javascript:alert(1)",
		"chrome://settings",
		"",
		"https://" + string(make([]byte, 9000)),
	} {
		if m := Classify(u); m != nil {
			t.Errorf("%q classified as %s/%s", u, m.Service.Key, m.Kind)
		}
	}
}
