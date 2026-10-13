package hooks

import (
	"database/sql"
	"io"
	"log/slog"
	"path/filepath"
	"swarmsheriff/internal/metrics"
	"testing"
	"time"
)

func agentReport(t *testing.T, events []metrics.Event, toMin int, nowMin int) metrics.AgentMetrics {
	t.Helper()
	db := readOnly(t, writeMetrics(t, events))
	r, err := metrics.Query(db, metrics.Filters{FromMs: at(0).UnixMilli(), ToMs: at(toMin).UnixMilli()}, metrics.DefaultStallMs, at(nowMin))
	if err != nil {
		t.Fatal(err)
	}
	return r.Agents
}

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

type captureRecorder struct{ events []metrics.Event }

func (c *captureRecorder) Record(e metrics.Event) { c.events = append(c.events, e) }
