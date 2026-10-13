package hooks

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"swarmsheriff/internal/metrics"
	"sync"
	"testing"
	"time"
)

func TestMapHookPayload(t *testing.T) {
	now := metricsBase
	tests := []struct {
		event   string
		payload string
		kind    string
		ok      bool
	}{
		{"SessionStart", `{"session_id":"s1","model":"claude-opus-5-5","source":"startup"}`, metrics.KindSessionStarted, true},
		{"SessionEnd", `{"session_id":"s1","prompt_id":"p9"}`, metrics.KindSessionEnded, true},
		{"UserPromptSubmit", `{"session_id":"s1","prompt_id":"p1","prompt":"refactor the billing module for ProjectX"}`, metrics.KindTurnStarted, true},
		{"Stop", `{"session_id":"s1"}`, metrics.KindTurnCompleted, true},
		{"StopFailure", `{"session_id":"s1"}`, metrics.KindAgentError, true},
		{"PreToolUse", `{"session_id":"s1","tool_name":"Bash","tool_use_id":"t1","tool_input":{"command":"cat secrets.env"}}`, metrics.KindToolActivity, true},
		{"PreToolUse", `{"session_id":"s1","tool_name":"AskUserQuestion","tool_use_id":"q1"}`, metrics.KindQuestionRequested, true},
		{"PreToolUse", `{"session_id":"s1","tool_name":"ExitPlanMode","tool_use_id":"x1"}`, metrics.KindPlanReviewRequest, true},
		{"PostToolUse", `{"session_id":"s1","tool_name":"AskUserQuestion","tool_use_id":"q1","tool_response":"the answer"}`, metrics.KindAttentionResolved, true},
		{"PostToolUse", `{"session_id":"s1","tool_name":"AskUserQuestion"}`, "", false},
		{"PostToolUse", `{"session_id":"s1","tool_name":"Edit","tool_use_id":"t2","tool_response":{"diff":"..."}}`, metrics.KindToolActivity, true},
		{"PermissionRequest", `{"session_id":"s1","tool_name":"Bash","tool_use_id":"t3"}`, metrics.KindApprovalRequested, true},
		{"PermissionRequest", `{"session_id":"s1","tool_name":"AskUserQuestion","tool_use_id":"q2"}`, "", false},
		{"Notification", `{"session_id":"s1","notification_type":"permission_prompt","message":"Claude needs permission to run rm"}`, metrics.KindApprovalRequested, true},
		{"Notification", `{"session_id":"s1","notification_type":"idle_prompt","message":"waiting"}`, metrics.KindAgentObservation, true},
		{"SubagentStart", `{"session_id":"s1","agent_id":"a1"}`, metrics.KindChildSpawned, true},
		{"SubagentStop", `{"session_id":"s1","agent_id":"a1"}`, metrics.KindChildCompleted, true},
		{"", `{"hook_event_name":"Stop","session_id":"s1"}`, metrics.KindTurnCompleted, true}, // name from the payload
		{"PreCompact", `{"session_id":"s1"}`, "", false},
	}
	for _, tt := range tests {
		var obj map[string]any
		if err := json.Unmarshal([]byte(tt.payload), &obj); err != nil {
			t.Fatal(err)
		}
		e, ok := mapHookPayload(tt.event, obj, now)
		if ok != tt.ok || (ok && e.Kind != tt.kind) {
			t.Errorf("%s %s: kind=%q ok=%v, want %q %v", tt.event, tt.payload, e.Kind, ok, tt.kind, tt.ok)
			continue
		}
		out, _ := json.Marshal(e)
		for _, banned := range []string{"refactor", "ProjectX", "secrets.env", "the answer", "diff", "permission to run", "waiting"} {
			if strings.Contains(string(out), banned) {
				t.Errorf("%s: hook event carries content %q: %s", tt.event, banned, out)
			}
		}
	}

	// Free text where an ID belongs is dropped, not forwarded.
	e, _ := mapHookPayload("Stop", map[string]any{"session_id": "my secret session notes"}, now)
	if e.SessionID != "" {
		t.Errorf("session_id = %q", e.SessionID)
	}
	e, _ = mapHookPayload("SessionStart", map[string]any{"session_id": "s1", "model": "ignore previous instructions"}, now)
	if e.Model != "" {
		t.Errorf("model = %q", e.Model)
	}
}

func TestHookMetricEventValidation(t *testing.T) {
	now := metricsBase
	good := hookEvent{Kind: metrics.KindTurnStarted, SessionID: "s1", AgentKind: "claude-code", AtMs: now.UnixMilli()}
	if _, err := hookMetricEvent(good, now); err != nil {
		t.Fatal(err)
	}
	for name, e := range map[string]hookEvent{
		"unknown kind": {Kind: "decision", SessionID: "s1"},
		"no session":   {Kind: metrics.KindTurnStarted},
		"text session": {Kind: metrics.KindTurnStarted, SessionID: "two words"},
		"text turn":    {Kind: metrics.KindTurnStarted, SessionID: "s1", TurnID: "a/b"},
		"tool class":   {Kind: metrics.KindToolActivity, SessionID: "s1", ToolClass: "Bash"},
		"model":        {Kind: metrics.KindSessionStarted, SessionID: "s1", Model: "has spaces"},
	} {
		if _, err := hookMetricEvent(e, now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	far := good
	far.AtMs = now.Add(48 * time.Hour).UnixMilli()
	if m, _ := hookMetricEvent(far, now); !m.At.Equal(now) {
		t.Errorf("future timestamp kept: %v", m.At)
	}
}

type syncRecorder struct {
	mu     sync.Mutex
	events []metrics.Event
}

func (r *syncRecorder) Record(e metrics.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *syncRecorder) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}

// shortSocketPath stays under the 104-byte Unix socket path limit on macOS.
func shortSocketPath(t *testing.T) string {
	dir, err := os.MkdirTemp("/tmp", "a11")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "s", hookSocketName)
}

func TestHookSocketEndToEnd(t *testing.T) {
	path := shortSocketPath(t)
	rec := &syncRecorder{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go StartServer(ctx, path, rec, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(path); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket: %v %v", fi, err)
	}
	if di, _ := os.Stat(filepath.Dir(path)); di.Mode().Perm() != 0o700 {
		t.Errorf("socket dir mode = %v", di.Mode().Perm())
	}

	payload := `{"session_id":"s1","prompt_id":"p1","prompt":"leak this ProjectX plan"}`
	if code := RunCLI([]string{"--socket", path, "UserPromptSubmit"}, strings.NewReader(payload), time.Now()); code != 0 {
		t.Fatalf("exit %d", code)
	}
	for i := 0; i < 100 && rec.len() == 0; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if rec.len() != 1 || rec.events[0].Kind != metrics.KindTurnStarted || rec.events[0].SessionID != "s1" {
		t.Fatalf("recorded %+v", rec.events)
	}

	// A second swarmsheriff must not steal the socket.
	if err := StartServer(ctx, path, rec, slog.Default()); err == nil || !strings.Contains(err.Error(), "another swarmsheriff") {
		t.Errorf("second server err = %v", err)
	}
	// Garbage and non-hook input never fails the agent.
	if code := RunCLI([]string{"--socket", path}, strings.NewReader("not json"), time.Now()); code != 0 {
		t.Errorf("garbage exit %d", code)
	}
	cancel()
	time.Sleep(50 * time.Millisecond)
	if code := RunCLI([]string{"--socket", path, "Stop"}, strings.NewReader(`{"session_id":"s1"}`), time.Now()); code != 0 {
		t.Errorf("no listener exit %d", code)
	}
}

func TestHookSocketRefusesRegularFile(t *testing.T) {
	path := shortSocketPath(t)
	os.MkdirAll(filepath.Dir(path), 0o700)
	os.WriteFile(path, []byte("x"), 0o600)
	if err := StartServer(context.Background(), path, metrics.NopRecorder{}, slog.Default()); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Errorf("err = %v", err)
	}
}

func TestClaudeHooksSnippet(t *testing.T) {
	out, err := Snippet("claude-code", "/usr/local/bin/swarmsheriff")
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Hooks map[string][]struct {
			Hooks []struct{ Type, Command string }
		}
	}
	if err := json.Unmarshal([]byte(out), &cfg); err != nil {
		t.Fatal(err)
	}
	for _, ev := range []string{"SessionStart", "UserPromptSubmit", "Stop", "PreToolUse", "PostToolUse", "Notification"} {
		h := cfg.Hooks[ev]
		if len(h) != 1 || !strings.Contains(h[0].Hooks[0].Command, "hook "+ev) {
			t.Errorf("%s: %+v", ev, h)
		}
	}
	if _, err := Snippet("windsurf", "x"); err == nil {
		t.Error("unknown agent accepted")
	}
}

func TestAntigravityHooksSnippet(t *testing.T) {
	out, err := Snippet("antigravity", "/opt/swarmsheriff")
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Swarmsheriff map[string][]struct {
			Matcher string
			Hooks   []struct{ Type, Command string }
		} `json:"swarmsheriff"`
	}
	if err := json.Unmarshal([]byte(out), &cfg); err != nil {
		t.Fatal(err)
	}
	for _, ev := range []string{"PreInvocation", "PostInvocation", "PreToolUse", "PostToolUse", "Stop"} {
		h := cfg.Swarmsheriff[ev]
		if len(h) != 1 || !strings.Contains(h[0].Hooks[0].Command, "hook --agent antigravity "+ev) {
			t.Errorf("%s: %+v", ev, h)
		}
	}
	if cfg.Swarmsheriff["PreToolUse"][0].Matcher != "*" || cfg.Swarmsheriff["Stop"][0].Matcher != "" {
		t.Error("matcher only belongs on tool events")
	}
}

func TestMapAntigravityPayload(t *testing.T) {
	now := metricsBase
	tests := []struct {
		event, payload, kind string
		ok                   bool
	}{
		{"SessionStart", `{"conversationId":"c-1","modelName":"gemini-3.6-flash","workspacePaths":["/secret/path"]}`, metrics.KindSessionStarted, true},
		{"PreInvocation", `{"conversationId":"c-1","modelName":"gemini-3.6-flash","invocationNum":1}`, metrics.KindTurnStarted, true},
		{"PreToolUse", `{"conversationId":"c-1","toolCall":{"name":"run_command","args":{"command":"cat SECRET.env"}},"stepIdx":2}`, metrics.KindToolActivity, true},
		{"PostToolUse", `{"conversationId":"c-1","toolCall":{"name":"read_file","args":{"path":"/secret/path"}}}`, metrics.KindToolActivity, true},
		{"PostInvocation", `{"conversationId":"c-1"}`, metrics.KindAgentObservation, true},
		{"Stop", `{"conversationId":"c-1","terminationReason":"done","fullyIdle":true}`, metrics.KindTurnCompleted, true},
		{"Stop", `{"conversationId":"c-1","error":"model overloaded"}`, metrics.KindAgentError, true},
		{"UnknownEvent", `{"conversationId":"c-1"}`, "", false},
	}
	for _, tt := range tests {
		var obj map[string]any
		if err := json.Unmarshal([]byte(tt.payload), &obj); err != nil {
			t.Fatal(err)
		}
		e, ok := mapAntigravityPayload(tt.event, obj, now)
		if ok != tt.ok || (ok && e.Kind != tt.kind) {
			t.Errorf("%s: kind=%q ok=%v, want %q %v", tt.event, e.Kind, ok, tt.kind, tt.ok)
		}
		if ok && (e.AgentKind != "antigravity" || e.SessionID != "c-1") {
			t.Errorf("%s: agentKind=%q session=%q", tt.event, e.AgentKind, e.SessionID)
		}
		out, _ := json.Marshal(e)
		for _, banned := range []string{"SECRET.env", "/secret/path", "run_command", "read_file", "overloaded"} {
			if strings.Contains(string(out), banned) {
				t.Errorf("%s: antigravity event carries %q: %s", tt.event, banned, out)
			}
		}
	}
	// mapAgentPayload routes by agent name.
	e, ok := mapAgentPayload("antigravity", "PreInvocation", map[string]any{"conversationId": "c-9", "modelName": "gemini-3.6-pro"}, now)
	if !ok || e.Kind != metrics.KindTurnStarted || e.Model != "gemini-3.6-pro" {
		t.Errorf("dispatch: %+v ok=%v", e, ok)
	}
	if _, ok := mapAgentPayload("windsurf", "PreInvocation", map[string]any{}, now); ok {
		t.Error("unknown agent routed")
	}
}

func TestAntigravitySessionInMetrics(t *testing.T) {
	// No session_started event: the session is keyed on conversationId and
	// must still show up by agent kind and model.
	ev := func(min int, kind, conv, model string) metrics.Event {
		return metrics.Event{At: at(min), Kind: kind, SessionID: conv, AgentKind: "antigravity", Model: model}
	}
	a := agentReport(t, []metrics.Event{
		{At: at(0), Kind: metrics.KindAgentStarted},
		ev(1, metrics.KindTurnStarted, "c-1", "gemini-3.6-flash"),
		ev(2, metrics.KindToolActivity, "c-1", "gemini-3.6-flash"),
		ev(3, metrics.KindTurnCompleted, "c-1", "gemini-3.6-flash"),
	}, 60, 60)
	if a.Sessions.Started != 0 || a.Sessions.Seen != 1 || a.Sessions.ByAgentKind["antigravity"] != 1 || a.Sessions.ByModel["gemini-3.6-flash"] != 1 {
		t.Errorf("antigravity sessions = %+v", a.Sessions)
	}
	if a.Turns.Started != 1 || a.Turns.Completed != 1 {
		t.Errorf("turns = %+v", a.Turns)
	}
	if a.TimeInStateMs["working"] != 2*60_000 {
		t.Errorf("working = %d", a.TimeInStateMs["working"])
	}
}

var _ net.Conn // keep net imported for the socket helpers above

func TestMapGeminiPayload(t *testing.T) {
	now := metricsBase
	tests := []struct {
		event, payload, kind, model string
		ok                          bool
	}{
		{"SessionStart", `{"session_id":"g-1","source":"startup","cwd":"/secret/repo","transcript_path":"/secret/t.json"}`, metrics.KindSessionStarted, "", true},
		{"BeforeAgent", `{"session_id":"g-1","prompt":"summarize SECRET.env"}`, metrics.KindTurnStarted, "", true},
		{"BeforeModel", `{"session_id":"g-1","llm_request":{"model":"gemini-2.5-pro","messages":[{"role":"user","content":"SECRET.env"}]}}`, metrics.KindAgentObservation, "gemini-2.5-pro", true},
		{"BeforeTool", `{"session_id":"g-1","tool_name":"run_shell_command","tool_input":{"command":"cat SECRET.env"}}`, metrics.KindToolActivity, "", true},
		{"AfterTool", `{"session_id":"g-1","tool_name":"read_file","tool_response":{"llmContent":"SECRET.env","error":"overloaded"}}`, metrics.KindToolActivity, "", true},
		{"Notification", `{"session_id":"g-1","notification_type":"ToolPermission","message":"allow SECRET.env?"}`, metrics.KindApprovalRequested, "", true},
		{"AfterAgent", `{"session_id":"g-1","prompt":"x","prompt_response":"SECRET.env","stop_hook_active":false}`, metrics.KindTurnCompleted, "", true},
		{"SessionEnd", `{"session_id":"g-1","reason":"exit"}`, metrics.KindSessionEnded, "", true},
		{"", `{"session_id":"g-1","hook_event_name":"BeforeAgent"}`, metrics.KindTurnStarted, "", true},
		{"AfterModel", `{"session_id":"g-1","llm_response":{}}`, "", "", false},
		{"PreCompress", `{"session_id":"g-1","trigger":"auto"}`, "", "", false},
	}
	for _, tt := range tests {
		var obj map[string]any
		if err := json.Unmarshal([]byte(tt.payload), &obj); err != nil {
			t.Fatal(err)
		}
		e, ok := mapAgentPayload("gemini-cli", tt.event, obj, now)
		if ok != tt.ok || (ok && (e.Kind != tt.kind || e.Model != tt.model)) {
			t.Errorf("%s: kind=%q model=%q ok=%v, want %q %q %v", tt.event, e.Kind, e.Model, ok, tt.kind, tt.model, tt.ok)
		}
		if ok && (e.AgentKind != "gemini-cli" || e.SessionID != "g-1") {
			t.Errorf("%s: agentKind=%q session=%q", tt.event, e.AgentKind, e.SessionID)
		}
		out, _ := json.Marshal(e)
		for _, banned := range []string{"SECRET.env", "/secret", "run_shell_command", "read_file", "overloaded", "summarize"} {
			if strings.Contains(string(out), banned) {
				t.Errorf("%s: gemini event carries %q: %s", tt.event, banned, out)
			}
		}
	}
}

func TestGeminiHooksSnippet(t *testing.T) {
	var cfg struct {
		Hooks map[string][]struct {
			Matcher string `json:"matcher"`
			Hooks   []struct {
				Type, Command string
				Timeout       int
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal([]byte(geminiHooksSnippet("/usr/local/bin/swarmsheriff")), &cfg); err != nil {
		t.Fatal(err)
	}
	for _, ev := range []string{"SessionStart", "SessionEnd", "BeforeAgent", "AfterAgent", "BeforeModel", "BeforeTool", "AfterTool", "Notification"} {
		h := cfg.Hooks[ev]
		if len(h) != 1 || len(h[0].Hooks) != 1 || h[0].Hooks[0].Type != "command" || h[0].Hooks[0].Timeout != 5000 ||
			h[0].Hooks[0].Command != `"/usr/local/bin/swarmsheriff" hook --agent gemini-cli `+ev {
			t.Errorf("%s: %+v", ev, h)
		}
	}
	if cfg.Hooks["BeforeTool"][0].Matcher != "*" || cfg.Hooks["SessionStart"][0].Matcher != "" {
		t.Error("matcher only belongs on tool events")
	}
	if !slices.Contains(KnownAgents(), "gemini-cli") {
		t.Error("gemini-cli not listed")
	}
	if err := (&HookAdapter{Name: "gemini-cli"}).compile(); err == nil {
		t.Error("built-in name accepted for a custom adapter")
	}
}
