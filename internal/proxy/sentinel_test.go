package proxy

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"swarmsheriff/internal/decide"
	"swarmsheriff/internal/events"
	"swarmsheriff/internal/sentinel"
	"sync"
	"testing"
	"time"
)

const sentinelPolicyJSON = `{
  "version": 1,
  "mode": "enforce",
  "destinations": {"public": ["api.anthropic.com"]},
  "classes": [
    {
      "id": "credentials", "description": "Secrets an agent read through its tools", "owner": "security",
      "detectors": {"source_labels": ["asp:credentials"]},
      "actions": {"public": "block"}
    }
  ]
}`

const testCredential = "ssa_test-credential-value"

// stubSentinel answers resolve from a table and keeps the events posted to it.
type stubSentinel struct {
	mu     sync.Mutex
	ids    map[string]sentinel.Identity
	events []map[string]any
	secret string
}

func (s *stubSentinel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Egress-Secret") != "s3cret" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch r.URL.Path {
	case "/api/swarm/egress/resolve":
		var in struct{ Credential string }
		json.NewDecoder(r.Body).Decode(&in)
		id, ok := s.ids[in.Credential]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(id)
	case "/api/swarm/egress/events":
		var ev map[string]any
		json.NewDecoder(r.Body).Decode(&ev)
		s.mu.Lock()
		s.events = append(s.events, ev)
		s.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	}
}

func (s *stubSentinel) posted() []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]map[string]any(nil), s.events...)
}

// newSentinelProxy returns a proxy linked to a stub SwarmSentinel and an upstream that records what reached it.
func newSentinelProxy(t *testing.T, ids map[string]sentinel.Identity) (*Proxy, *stubSentinel, *bytes.Buffer, string, *http.Header) {
	t.Helper()
	stub := &stubSentinel{ids: ids}
	ss := httptest.NewServer(stub)
	t.Cleanup(ss.Close)
	secret := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(secret, []byte("s3cret\n"), 0o600)
	client, err := sentinel.NewClient(ss.URL, secret)
	if err != nil {
		t.Fatal(err)
	}
	var seen http.Header
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(up.Close)
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	d := decide.New(mustPolicy(t, sentinelPolicyJSON), nil, 50*time.Millisecond, "")
	ctx := t.Context()
	p := New(d, sentinel.MultiSink{events.LogSink{Logger: logger}, sentinel.NewSink(ctx, client, logger)}, logger, 1<<12)
	p.Sentinel = client
	p.transport = up.Client().Transport
	p.allowLoopback = true
	return p, stub, &logs, strings.TrimPrefix(up.URL, "https://"), &seen
}

func waitEvents(t *testing.T, s *stubSentinel, n int) []map[string]any {
	t.Helper()
	for range 100 {
		if ev := s.posted(); len(ev) >= n {
			return ev
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected %d sentinel events, got %d", n, len(s.posted()))
	return nil
}

const sentinelBody = `{"model":"m-1","messages":[{"role":"user","content":"please summarise the build log"}]}`

func TestSentinelLabelsBlockTheModelRequest(t *testing.T) {
	ids := map[string]sentinel.Identity{testCredential: {SessionID: "sess", AgentID: "reader", TaskID: "t1",
		Labels: []string{"asp:credentials"}}}
	p, stub, logs, host, seen := newSentinelProxy(t, ids)
	w := post(p, "/"+host+"/v1/messages", sentinelBody, map[string]string{sentinel.HeaderCredential: testCredential})
	if w.Code != http.StatusForbidden || *seen != nil {
		t.Fatalf("status %d, upstream reached: %v", w.Code, *seen != nil)
	}
	ev := waitEvents(t, stub, 1)[0]
	if ev["sessionId"] != "sess" || ev["agentId"] != "reader" || ev["taskId"] != "t1" || ev["applied"] != "block" ||
		ev["classes"].([]any)[0] != "credentials" || ev["model"] != "m-1" {
		t.Errorf("event = %v", ev)
	}
	raw, _ := json.Marshal(ev)
	if strings.Contains(string(raw), "summarise") || strings.Contains(string(raw), testCredential) {
		t.Errorf("event carries content or the credential: %s", raw)
	}
	if !strings.Contains(logs.String(), "agent_id_source=engine") || strings.Contains(logs.String(), testCredential) {
		t.Errorf("log = %s", logs)
	}
}

func TestSentinelCleanAgentIsForwardedWithoutTheCredential(t *testing.T) {
	ids := map[string]sentinel.Identity{testCredential: {SessionID: "sess", AgentID: "writer", TaskID: "t2"}}
	p, stub, _, host, seen := newSentinelProxy(t, ids)
	w := post(p, "/"+host+"/v1/messages", sentinelBody, map[string]string{sentinel.HeaderCredential: testCredential})
	if w.Code != http.StatusOK || *seen == nil {
		t.Fatalf("status %d", w.Code)
	}
	if seen.Get(sentinel.HeaderCredential) != "" {
		t.Error("credential header reached the upstream")
	}
	if ev := waitEvents(t, stub, 1)[0]; ev["verdict"] != "allow" {
		t.Errorf("event = %v", ev)
	}
}

func TestSentinelFailsClosed(t *testing.T) {
	ids := map[string]sentinel.Identity{"ssa_revoked": {SessionID: "sess", AgentID: "r", TaskID: "t", Revoked: true}}
	p, _, logs, host, seen := newSentinelProxy(t, ids)
	cases := []struct{ cred, rule string }{{"ssa_unknown", "identity:unverified"}, {"ssa_revoked", "sentinel:revoked"}}
	for _, c := range cases {
		w := post(p, "/"+host+"/v1/messages", sentinelBody, map[string]string{sentinel.HeaderCredential: c.cred})
		if w.Code != http.StatusForbidden || *seen != nil || !strings.Contains(logs.String(), c.rule) {
			t.Errorf("%s: status %d, upstream %v, log %s", c.rule, w.Code, *seen != nil, logs)
		}
	}
	// Engine unreachable. A copy, so the sink goroutine still reading the
	// original client does not race with the change.
	unreachable := *p.Sentinel
	unreachable.Base = "http://127.0.0.1:1"
	p.Sentinel = &unreachable
	if w := post(p, "/"+host+"/v1/messages", sentinelBody, map[string]string{sentinel.HeaderCredential: "ssa_any"}); w.Code != http.StatusForbidden {
		t.Errorf("unreachable engine: status %d", w.Code)
	}
}

func TestRequireCredential(t *testing.T) {
	p, _, logs, host, seen := newSentinelProxy(t, nil)
	p.RequireCredential = true
	w := post(p, "/"+host+"/v1/messages", sentinelBody, nil)
	if w.Code != http.StatusForbidden || *seen != nil || !strings.Contains(logs.String(), "identity:missing") {
		t.Fatalf("status %d, upstream %v", w.Code, *seen != nil)
	}
}
