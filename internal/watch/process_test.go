package watch

import (
	"log/slog"
	"swarmsheriff/internal/metrics"
	"testing"
	"time"
)

func TestAntigravityCLIDetected(t *testing.T) {
	for exe, want := range map[string]string{
		"/Users/x/.local/bin/agy":                               "Antigravity CLI",
		"/Applications/Antigravity.app/Contents/MacOS/Electron": "Antigravity",
		"/usr/local/bin/gemini":                                 "Gemini CLI",
	} {
		if got, ok := matchAIApp(process{exe: exe}); !ok || got != want {
			t.Errorf("%s: got %q %v, want %q", exe, got, ok, want)
		}
	}
}

func TestResourceSampling(t *testing.T) {
	rec := &captureRecorder{}
	w := NewAIWatcher(slog.Default())
	w.Rec = rec
	w.resStart = metricsBase
	w.sample("Cursor", []process{{cpu: 10, rssKB: 100}, {cpu: 30, rssKB: 300}})
	w.sample("Cursor", []process{{cpu: 20, rssKB: 500}})
	w.flushResources(metricsBase.Add(30 * time.Second))
	if len(rec.events) != 0 {
		t.Fatal("flushed before the window ended")
	}
	w.flushResources(metricsBase.Add(resourceWindow))
	if len(rec.events) != 1 {
		t.Fatalf("events = %d", len(rec.events))
	}
	e := rec.events[0]
	if e.Kind != metrics.KindResource || e.App != "Cursor" || e.CPUPct != 30 || e.CPUMax != 40 || e.RSSKB != 500 || e.Procs != 2 {
		t.Errorf("sample = %+v", e)
	}
}

func TestParsePSLine(t *testing.T) {
	p, ok := parsePSLine("  4242     1  12.5  204800 /Applications/LM Studio.app/Contents/MacOS/LM Studio")
	if !ok || p.pid != 4242 || p.ppid != 1 || p.cpu != 12.5 || p.rssKB != 204800 || p.exe != "/Applications/LM Studio.app/Contents/MacOS/LM Studio" {
		t.Errorf("parsed %+v ok=%v", p, ok)
	}
	if _, ok := parsePSLine("garbage line"); ok {
		t.Error("garbage parsed")
	}
}
