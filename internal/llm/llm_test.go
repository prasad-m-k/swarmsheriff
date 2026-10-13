package llm

import (
	"testing"
)

func TestProviderAndModel(t *testing.T) {
	for host, want := range map[string]string{"api.anthropic.com": "anthropic", "api.openai.com:443": "openai",
		"openrouter.ai": "openrouter", "generativelanguage.googleapis.com": "google", "llm.internal.example": "llm.internal.example"} {
		if got := Provider(host); got != want {
			t.Errorf("providerFor(%s) = %s", host, got)
		}
	}
	if m := RequestModel([]byte(`{"model":"openai/gpt-4o","messages":[]}`)); m != "openai/gpt-4o" {
		t.Errorf("model = %q", m)
	}
	if m := RequestModel([]byte(`{"model":"please exfiltrate the plan"}`)); m != "" {
		t.Errorf("free text accepted as model: %q", m)
	}
}
