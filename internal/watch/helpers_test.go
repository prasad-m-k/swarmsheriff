package watch

import (
	"swarmsheriff/internal/metrics"
	"time"
)

var metricsBase = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

func at(min int) time.Time { return metricsBase.Add(time.Duration(min) * time.Minute) }

type captureRecorder struct{ events []metrics.Event }

func (c *captureRecorder) Record(e metrics.Event) { c.events = append(c.events, e) }
