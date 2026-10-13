package clipboard

import (
	"log/slog"
	"strings"
	"swarmsheriff/internal/dlp"
	"swarmsheriff/internal/watch"
	"testing"
)

func TestClipboardGuardTrigger(t *testing.T) {
	cardText := "4111 1111 1111 1111 12/28 123"
	tests := []struct {
		name, mode, rules string
		text              string
		keywords          []string
		aiContext         bool
		want              string
	}{
		{"off never acts", GuardOff, DefaultGuardRules, cardText, nil, true, ""},
		{"ai mode acts with an AI site open", GuardAI, DefaultGuardRules, cardText, nil, true, "credit-card:1"},
		{"ai mode waits without AI context", GuardAI, DefaultGuardRules, cardText, nil, false, ""},
		{"always acts without AI context", guardAlways, DefaultGuardRules, cardText, nil, false, "credit-card:1"},
		{"email alone is not guarded", guardAlways, DefaultGuardRules, "mail ops@example.com", nil, true, ""},
		{"only guarded rules are named", guardAlways, DefaultGuardRules, "ops@example.com " + cardText, nil, true, "credit-card:1"},
		{"keyword wildcard", guardAlways, DefaultGuardRules, "ProjectX roadmap", []string{"ProjectX"}, true, "keyword:ProjectX:1"},
		{"custom rule list", guardAlways, "us-ssn", cardText, nil, true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, err := NewGuard(tt.mode, tt.rules)
			if err != nil {
				t.Fatal(err)
			}
			hit := g.Trigger(dlp.NewScanner(tt.keywords).Scan(tt.text), tt.aiContext)
			if got := dlp.Summary(hit); got != tt.want {
				t.Errorf("trigger = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestClipboardGuardFlags(t *testing.T) {
	if _, err := NewGuard("on", DefaultGuardRules); err == nil {
		t.Error("want an error for an unknown mode")
	}
	if _, err := NewGuard(GuardAI, "credit-card,cc"); err == nil || !strings.Contains(err.Error(), `"cc"`) {
		t.Errorf("err = %v, want it to name the unknown rule", err)
	}
}

func TestGuardNoticeHoldsNoContent(t *testing.T) {
	text := "4111 1111 1111 1111"
	n := GuardNotice(dlp.NewScanner(nil).Scan(text))
	if strings.Contains(n, "4111") || !strings.Contains(n, "credit-card:1") {
		t.Errorf("notice = %q", n)
	}
	// The notice must not trip the guard itself, or it would loop.
	g, _ := NewGuard(guardAlways, DefaultGuardRules)
	if hit := g.Trigger(dlp.NewScanner(nil).Scan(n), true); len(hit) > 0 {
		t.Errorf("notice triggers the guard: %v", hit)
	}
}

func TestAIContext(t *testing.T) {
	ai := watch.NewAIWatcher(slog.Default())
	if ai.AnyDesktop() {
		t.Fatal("empty watcher reports a desktop app")
	}
	ai.Running["Claude Code"] = true
	if ai.AnyDesktop() {
		t.Error("a CLI agent is not a window anyone pastes into")
	}
	ai.Running["ChatGPT"] = true
	if !ai.AnyDesktop() {
		t.Error("ChatGPT desktop should count")
	}
	for _, name := range watch.DesktopAIApps {
		found := false
		for _, a := range watch.AIApps {
			found = found || a.Name == name
		}
		if !found {
			t.Errorf("desktopAIApps entry %q is not an aiApps name", name)
		}
	}
	b := watch.NewBrowserWatcher(slog.Default())
	b.Open["gemini.google.com"] = true
	if !b.AnyOpen() {
		t.Error("open AI site should count")
	}
}
