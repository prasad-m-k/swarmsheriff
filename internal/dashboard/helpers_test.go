package dashboard

import (
	"database/sql"
	"io"
	"log/slog"
	"path/filepath"
	"swarmsheriff/internal/clipboard"
	"swarmsheriff/internal/dlp"
	"swarmsheriff/internal/metrics"
	"swarmsheriff/internal/policy"
	"testing"
	"time"
)

var metricsBase = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

func at(min int) time.Time { return metricsBase.Add(time.Duration(min) * time.Minute) }

// writeMetrics records events into a fresh store, closes it so every batch is
// committed, and returns the database path.
func writeMetrics(t *testing.T, events []metrics.Event) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "swarmsheriff", "metrics.sqlite3")
	s, err := metrics.OpenStore(path, 0, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		s.Record(e)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func readOnly(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := metrics.OpenDB(path, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func sampleEvents() []metrics.Event {
	dec := func(min int, verdict string, enforced bool, class, rule, dest string, lat time.Duration) metrics.Event {
		e := metrics.Event{At: at(min), Kind: metrics.KindDecision, Verdict: verdict, Applied: "allow", Enforced: enforced,
			Mode: policy.ModeReport, Dest: dest, Category: "public-api", AgentID: "agent-a", AgentIDSource: "declared",
			Classifier: "not-needed", Latency: lat, Confidence: 1}
		if enforced {
			e.Applied, e.Mode = verdict, policy.ModeEnforce
		}
		if class != "" {
			e.Classes = []string{class}
			e.Rules = []dlp.Finding{{Rule: rule, Count: 1}}
		}
		return e
	}
	return []metrics.Event{
		{At: at(0), Kind: metrics.KindAgentStarted},
		{At: at(1), Kind: metrics.KindAIAppStarted, App: "ChatGPT"},
		{At: at(2), Kind: metrics.KindAISiteOpened, App: "gemini.google.com"},
		dec(3, "allow", false, "", "", "api.anthropic.com", 2*time.Millisecond),
		dec(4, "block", false, "source-code", "keyword", "api.anthropic.com", 4*time.Millisecond),
		dec(5, "block", true, "credentials", "rule:aws-access-key", "api.openai.com", 6*time.Millisecond),
		dec(6, "hold", false, "customer-data", "rule:us-ssn", "api.openai.com", 80*time.Millisecond),
		{At: at(7), Kind: metrics.KindClipboard, Bytes: 12},
		{At: at(8), Kind: metrics.KindClipboard, Bytes: 34, Rules: []dlp.Finding{{Rule: "credit-card", Count: 1}}},
		{At: at(9), Kind: metrics.KindClipboardGuard, Bytes: 31, Mode: clipboard.GuardAI, Rules: []dlp.Finding{{Rule: "credit-card", Count: 2}}},
		{At: at(10), Kind: metrics.KindIntake, App: "extension", Dest: "gemini.google.com", Bytes: 99, Rules: []dlp.Finding{{Rule: "email", Count: 3}}},
		{At: at(11), Kind: metrics.KindIntake, App: "extension", Bytes: 5},
		{At: at(12), Kind: metrics.KindPolicyReload},
		{At: at(21), Kind: metrics.KindAIAppStopped, App: "ChatGPT"},
	}
}
