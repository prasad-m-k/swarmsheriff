package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// SwarmSentinel link. SwarmSentinel issues each MCP agent a credential and
// tracks, per agent and task, the confidentiality labels its tool calls have
// collected (ASP policy "confidentiality"). An agent sends that credential to
// the proxy in headerCredential. The proxy resolves it here, so the agent's
// identity, task and labels come from the engine, not from the agent, and
// reports each decision back to the engine's recorder. Two loopback HTTP calls,
// authenticated with a shared secret that is never logged. No SwarmSentinel
// code is vendored.

const headerCredential = "X-Swarmsheriff-Credential"

type sentinelIdentity struct {
	SessionID string   `json:"sessionId"`
	AgentID   string   `json:"agentId"`
	TaskID    string   `json:"taskId"`
	Labels    []string `json:"labels"`
	Tainted   bool     `json:"tainted"`
	Revoked   bool     `json:"revoked"`
}

type sentinelClient struct {
	base   string
	secret string
	http   *http.Client
}

var errUnknownCredential = errors.New("credential not recognised by SwarmSentinel")

func newSentinelClient(base, secretFile string) (*sentinelClient, error) {
	raw, err := os.ReadFile(secretFile)
	if err != nil {
		return nil, fmt.Errorf("sentinel secret: %w", err)
	}
	secret := strings.TrimSpace(string(raw))
	if secret == "" {
		return nil, errors.New("sentinel secret file is empty")
	}
	return &sentinelClient{base: strings.TrimRight(base, "/"), secret: secret,
		http: &http.Client{Timeout: 2 * time.Second}}, nil
}

func (s *sentinelClient) post(ctx context.Context, path string, in, out any) (int, error) {
	body, err := json.Marshal(in)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.base+path, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Egress-Secret", s.secret)
	resp, err := s.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if out != nil && resp.StatusCode/100 == 2 {
		return resp.StatusCode, json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(out)
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode, nil
}

// resolve returns the engine's view of the agent holding credential.
func (s *sentinelClient) resolve(ctx context.Context, credential string) (sentinelIdentity, error) {
	var id sentinelIdentity
	status, err := s.post(ctx, "/api/swarm/egress/resolve", map[string]string{"credential": credential}, &id)
	switch {
	case err != nil:
		return id, fmt.Errorf("resolve: %w", err)
	case status == http.StatusNotFound:
		return id, errUnknownCredential
	case status != http.StatusOK:
		return id, fmt.Errorf("resolve: HTTP %d", status)
	}
	return id, nil
}

// sentinelEvent mirrors SwarmSentinel's EgressDecisionInput. Labels and counts
// only, like every other event.
type sentinelEvent struct {
	SessionID   string   `json:"sessionId"`
	AgentID     string   `json:"agentId"`
	TaskID      string   `json:"taskId"`
	Verdict     string   `json:"verdict"`
	Applied     string   `json:"applied"`
	Mode        string   `json:"mode"`
	Destination string   `json:"destination"`
	Category    string   `json:"category"`
	Classes     []string `json:"classes"`
	Rules       []string `json:"rules"`
	Model       string   `json:"model"`
	Timestamp   string   `json:"timestamp"`
}

// sentinelSink posts decisions for engine-identified agents to the recorder.
// Emit never blocks a request: a full queue drops the event and counts it.
type sentinelSink struct {
	client  *sentinelClient
	queue   chan sentinelEvent
	logger  *slog.Logger
	dropped atomic.Int64
	failed  atomic.Int64
}

func newSentinelSink(ctx context.Context, c *sentinelClient, logger *slog.Logger) *sentinelSink {
	s := &sentinelSink{client: c, queue: make(chan sentinelEvent, 1024), logger: logger}
	go s.run(ctx)
	return s
}

func (s *sentinelSink) Emit(e Event) error {
	d := e.Decision
	if d.SessionID == "" {
		return nil // no engine identity: nothing to attach the event to
	}
	ev := sentinelEvent{SessionID: d.SessionID, AgentID: d.AgentID, TaskID: d.TaskID,
		Verdict: d.Verdict.String(), Applied: d.Applied.String(), Mode: d.Mode, Destination: d.Destination,
		Category: d.Category, Classes: nonNil(d.Classes), Rules: nonNil(d.Rules), Model: truncate(e.Model, 120),
		Timestamp: e.Time.UTC().Format(time.RFC3339Nano)}
	select {
	case s.queue <- ev:
	default:
		s.dropped.Add(1)
	}
	return nil
}

func (s *sentinelSink) run(ctx context.Context) {
	var lastErr string
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-s.queue:
			status, err := s.client.post(ctx, "/api/swarm/egress/events", ev, nil)
			if err == nil && status != http.StatusCreated {
				err = fmt.Errorf("HTTP %d", status)
			}
			if err != nil {
				s.failed.Add(1)
				if msg := err.Error(); msg != lastErr { // log each distinct failure once
					s.logger.Error("sentinel sink failed", "err", msg)
					lastErr = msg
				}
			}
		}
	}
}

// multiSink fans an event out to every sink and returns the first error.
type multiSink []Sink

func (m multiSink) Emit(e Event) error {
	var first error
	for _, s := range m {
		if err := s.Emit(e); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
