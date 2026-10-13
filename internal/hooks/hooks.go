// Package hooks maps agent lifecycle hook payloads (Claude Code, Antigravity,
// Gemini CLI and declarative adapters) to body-free metric events, and serves
// the hook socket.
package hooks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"swarmsheriff/internal/llm"
	"swarmsheriff/internal/metrics"
	"time"
)

const (
	AgentKindClaude       = "claude-code"
	hookAgentKindAntigrav = "antigravity"
	hookAgentKindGemini   = "gemini-cli"
	hookToolAskUser       = "ask_user_question"
	hookToolExitPlan      = "exit_plan_mode"
	hookToolOther         = "other"
	hookMaxPayload        = 1 << 20 // hook stdin can carry a whole tool output; read it, keep none of it
	hookMaxEventBytes     = 4 << 10
	hookClientTimeout     = time.Second
	hookSocketName        = "hooks.sock"
)

// hookEvent is everything that leaves the hook command. Each string is an
// opaque ID or a fixed name; mapHookPayload drops anything else.
type hookEvent struct {
	Kind      string `json:"kind"`
	AgentKind string `json:"agent_kind"`
	SessionID string `json:"session_id,omitempty"`
	TurnID    string `json:"turn_id,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	ToolClass string `json:"tool_class,omitempty"`
	Model     string `json:"model,omitempty"`
	AtMs      int64  `json:"at_ms"`
}

// opaqueID is c11's rule: printable ASCII without spaces or slashes, at most
// 128 bytes. Anything else, such as free text, becomes absent.
func opaqueID(v any) string {
	s, _ := v.(string)
	if s == "" || len(s) > 128 {
		return ""
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 33 || c > 126 || c == '/' || c == '\\' {
			return ""
		}
	}
	return s
}

// mapHookPayload turns a Claude Code hook payload into a hookEvent, or
// reports false for events with no lifecycle meaning. event is the hook
// name; when empty, the payload's hook_event_name is used.
func mapHookPayload(event string, obj map[string]any, now time.Time) (hookEvent, bool) {
	if event == "" {
		event, _ = obj["hook_event_name"].(string)
	}
	tool, _ := obj["tool_name"].(string)
	e := hookEvent{AgentKind: AgentKindClaude, SessionID: opaqueID(obj["session_id"]),
		TurnID: opaqueID(obj["prompt_id"]), AtMs: now.UnixMilli()}
	toolClass := func() string {
		switch tool {
		case "AskUserQuestion":
			return hookToolAskUser
		case "ExitPlanMode":
			return hookToolExitPlan
		}
		return hookToolOther
	}
	switch strings.ToLower(strings.ReplaceAll(event, "-", "")) {
	case "sessionstart":
		e.Kind, e.Model = metrics.KindSessionStarted, llm.CleanModel(obj["model"])
	case "sessionend":
		e.Kind, e.TurnID = metrics.KindSessionEnded, "" // a later prompt's ID would look stale here (c11 does the same)
	case "userpromptsubmit":
		e.Kind = metrics.KindTurnStarted
	case "stop":
		e.Kind = metrics.KindTurnCompleted
	case "stopfailure":
		e.Kind = metrics.KindAgentError
	case "pretooluse":
		e.RequestID, e.ToolClass = opaqueID(obj["tool_use_id"]), toolClass()
		switch e.ToolClass {
		case hookToolAskUser:
			e.Kind = metrics.KindQuestionRequested
		case hookToolExitPlan:
			e.Kind = metrics.KindPlanReviewRequest
		default:
			e.Kind = metrics.KindToolActivity
		}
	case "posttooluse":
		e.RequestID, e.ToolClass = opaqueID(obj["tool_use_id"]), toolClass()
		if e.ToolClass != hookToolOther {
			if e.RequestID == "" {
				return e, false // an answer that cannot be tied to its question proves nothing
			}
			e.Kind = metrics.KindAttentionResolved
		} else {
			e.Kind = metrics.KindToolActivity
		}
	case "permissionrequest":
		e.RequestID, e.ToolClass = opaqueID(obj["tool_use_id"]), toolClass()
		if e.ToolClass != hookToolOther {
			return e, false // the question or plan review already blocked on PreToolUse
		}
		e.Kind = metrics.KindApprovalRequested
	case "notification":
		if t, _ := obj["notification_type"].(string); t == "permission_prompt" {
			e.Kind = metrics.KindApprovalRequested
		} else {
			e.Kind = metrics.KindAgentObservation
		}
	case "subagentstart":
		e.Kind = metrics.KindChildSpawned
	case "subagentstop":
		e.Kind = metrics.KindChildCompleted
	default:
		return e, false
	}
	return e, true
}

// mapAgentPayload dispatches to the mapper for the named agent. Claude Code is
// the default so an existing "swarmsheriff hook <Event>" config keeps working.
func mapAgentPayload(agent, event string, obj map[string]any, now time.Time) (hookEvent, bool) {
	switch agent {
	case "", AgentKindClaude:
		return mapHookPayload(event, obj, now)
	case hookAgentKindAntigrav:
		return mapAntigravityPayload(event, obj, now)
	case hookAgentKindGemini:
		return mapGeminiPayload(event, obj, now)
	default:
		if a := CustomAdapters[agent]; a != nil {
			return mapWithAdapter(a, event, obj, now.UnixMilli())
		}
		return hookEvent{}, false
	}
}

// CustomAdapters holds declarative agents loaded from the adapters directory.
// It is populated by the short-lived "swarmsheriff hook" and "--print-config"
// invocations; the collector and hook server never map, so no locking is needed.
var CustomAdapters = map[string]*HookAdapter{}

// LoadCustomAdapters merges the adapters directory into the registry.
func LoadCustomAdapters(dir string) []error {
	loaded, errs := loadAdapterDir(dir)
	for name, a := range loaded {
		CustomAdapters[name] = a
	}
	return errs
}

// KnownAgents lists every agent that can be hooked: the built-ins plus any
// loaded custom adapters.
func KnownAgents() []string {
	out := []string{AgentKindClaude, hookAgentKindAntigrav, hookAgentKindGemini}
	for name := range CustomAdapters {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

func IsBuiltinAgent(name string) bool {
	return name == AgentKindClaude || name == hookAgentKindAntigrav || name == hookAgentKindGemini
}

// mapGeminiPayload turns a Gemini CLI hook payload into a hookEvent. Gemini
// CLI sends session_id on every event but no turn or tool-call ID, so tool
// events cannot be paired and all count as plain tool activity. prompt,
// prompt_response, llm_request messages, tool_input, tool_response and
// transcript_path are content or paths and are never read; only the model
// name is taken out of llm_request (a request over hookMaxPayload is dropped
// whole). AfterModel is not mapped: it can fire per
// streamed chunk and adds nothing BeforeModel does not.
func mapGeminiPayload(event string, obj map[string]any, now time.Time) (hookEvent, bool) {
	if event == "" {
		event, _ = obj["hook_event_name"].(string)
	}
	e := hookEvent{AgentKind: hookAgentKindGemini, SessionID: opaqueID(obj["session_id"]), AtMs: now.UnixMilli()}
	switch strings.ToLower(strings.ReplaceAll(event, "-", "")) {
	case "sessionstart":
		e.Kind = metrics.KindSessionStarted
	case "sessionend":
		e.Kind = metrics.KindSessionEnded
	case "beforeagent":
		e.Kind = metrics.KindTurnStarted
	case "afteragent":
		e.Kind = metrics.KindTurnCompleted
	case "beforemodel":
		req, _ := obj["llm_request"].(map[string]any)
		e.Kind, e.Model = metrics.KindAgentObservation, llm.CleanModel(req["model"])
	case "beforetool", "aftertool":
		e.Kind, e.ToolClass = metrics.KindToolActivity, hookToolOther
	case "notification":
		if t, _ := obj["notification_type"].(string); t == "ToolPermission" {
			e.Kind = metrics.KindApprovalRequested
		} else {
			e.Kind = metrics.KindAgentObservation
		}
	default:
		return e, false
	}
	return e, true
}

// mapAntigravityPayload turns a Google Antigravity hook payload (IDE, 2.0
// desktop and the agy CLI share it) into a hookEvent. Sessions are keyed on
// conversationId; SessionStart marks a start where the build sends it, and
// otherwise first-seen does. There is no session end event. toolCall.args,
// transcriptPath, workspacePaths and the artifact directory are content or
// paths and are never read. modelName rides on every event.
func mapAntigravityPayload(event string, obj map[string]any, now time.Time) (hookEvent, bool) {
	e := hookEvent{AgentKind: hookAgentKindAntigrav, SessionID: opaqueID(obj["conversationId"]),
		Model: llm.CleanModel(obj["modelName"]), AtMs: now.UnixMilli()}
	switch strings.ToLower(strings.ReplaceAll(event, "-", "")) {
	case "sessionstart":
		e.Kind = metrics.KindSessionStarted
	case "preinvocation":
		e.Kind = metrics.KindTurnStarted
	case "postinvocation":
		e.Kind = metrics.KindAgentObservation
	case "pretooluse":
		e.Kind, e.ToolClass = metrics.KindToolActivity, hookToolOther
	case "posttooluse":
		e.Kind, e.ToolClass = metrics.KindToolActivity, hookToolOther
	case "stop":
		// terminationReason/error values are not documented; treat any error
		// string as a session failure, otherwise a completed turn.
		if s, _ := obj["error"].(string); s != "" {
			e.Kind = metrics.KindAgentError
		} else {
			e.Kind = metrics.KindTurnCompleted
		}
	default:
		return e, false
	}
	return e, true
}

// DefaultSocket sits beside the metrics database, in the same 0700 directory.
func DefaultSocket() string {
	return filepath.Join(filepath.Dir(metrics.DefaultPath()), hookSocketName)
}

// RunCLI is "swarmsheriff hook [event]". It must never get in the agent's way:
// it prints nothing (some hook outputs are fed back to the model), always
// exits 0, and gives up after a second if swarmsheriff is not listening.
func RunCLI(args []string, stdin io.Reader, now time.Time) int {
	socket := DefaultSocket()
	adaptersDir := DefaultAdaptersDir()
	agent, event := AgentKindClaude, ""
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--socket" && i+1 < len(args):
			socket = args[i+1]
			i++
		case args[i] == "--agent" && i+1 < len(args):
			agent = args[i+1]
			i++
		case args[i] == "--adapters" && i+1 < len(args):
			adaptersDir = args[i+1]
			i++
		case !strings.HasPrefix(args[i], "-"):
			event = args[i]
		}
	}
	if !IsBuiltinAgent(agent) {
		LoadCustomAdapters(adaptersDir) // errors ignored: the hook must stay silent and never fail the agent
	}
	var obj map[string]any
	if err := json.NewDecoder(io.LimitReader(stdin, hookMaxPayload)).Decode(&obj); err != nil {
		return 0
	}
	e, ok := mapAgentPayload(agent, event, obj, now)
	if !ok {
		return 0
	}
	body, _ := json.Marshal(e)
	ctx, cancel := context.WithTimeout(context.Background(), hookClientTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://swarmsheriff/hook", bytes.NewReader(body))
	if err != nil {
		return 0
	}
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
	}}
	if resp, err := client.Do(req); err == nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	return 0
}

// StartServer listens on a Unix socket created 0600 in a 0700 directory,
// so only this user's processes can post lifecycle events.
func StartServer(ctx context.Context, path string, rec metrics.Recorder, logger *slog.Logger) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("hook socket dir: %w", err)
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode().Type() != fs.ModeSocket {
			return fmt.Errorf("hook socket %s: exists and is not a socket", path)
		}
		// A socket left by an earlier run. If something still answers on it,
		// another swarmsheriff owns it.
		if c, err := net.DialTimeout("unix", path, 200*time.Millisecond); err == nil {
			c.Close()
			return fmt.Errorf("hook socket %s: another swarmsheriff is listening", path)
		}
		os.Remove(path)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("hook socket: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return fmt.Errorf("hook socket: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/hook", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var e hookEvent
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, hookMaxEventBytes)).Decode(&e); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		m, err := hookMetricEvent(e, time.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		rec.Record(m)
		w.WriteHeader(http.StatusNoContent)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
	logger.Info("hook socket listening", "path", path)
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Shutdown(shutCtx)
		os.Remove(path)
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// hookMetricEvent re-validates what arrives on the socket: any local process
// of this user can post, so the server applies the same rules as the client.
func hookMetricEvent(e hookEvent, now time.Time) (metrics.Event, error) {
	if !slices.Contains(metrics.LifecycleKinds, e.Kind) {
		return metrics.Event{}, fmt.Errorf("unknown kind %q", e.Kind)
	}
	if e.SessionID == "" || opaqueID(e.SessionID) != e.SessionID {
		return metrics.Event{}, errors.New("session_id must be an opaque ID")
	}
	for _, v := range []string{e.AgentKind, e.TurnID, e.RequestID} {
		if v != "" && opaqueID(v) != v {
			return metrics.Event{}, errors.New("IDs must be opaque")
		}
	}
	if e.ToolClass != "" && e.ToolClass != hookToolAskUser && e.ToolClass != hookToolExitPlan && e.ToolClass != hookToolOther {
		return metrics.Event{}, errors.New("unknown tool_class")
	}
	if e.Model != "" && llm.CleanModel(e.Model) != e.Model {
		return metrics.Event{}, errors.New("bad model")
	}
	at := time.UnixMilli(e.AtMs)
	// Trust the hook's clock only near ours, as c11 bounds emitted times.
	if e.AtMs == 0 || at.Before(now.Add(-24*time.Hour)) || at.After(now.Add(5*time.Minute)) {
		at = now
	}
	agentKind := e.AgentKind
	if agentKind == "" {
		agentKind = AgentKindClaude
	}
	return metrics.Event{At: at, Kind: e.Kind, SessionID: e.SessionID, AgentKind: agentKind, TurnID: e.TurnID,
		RequestID: e.RequestID, ToolClass: e.ToolClass, Model: e.Model}, nil
}

// hookConfigDest says where the named agent's config fragment belongs.
func ConfigDest(agent string) string {
	switch agent {
	case hookAgentKindAntigrav:
		return "Antigravity (IDE, desktop and agy CLI): write to a workspace .agents/hooks.json or the global ~/.gemini/config/hooks.json"
	case hookAgentKindGemini:
		return "Gemini CLI: merge the \"hooks\" object into ~/.gemini/settings.json (or a project .gemini/settings.json)"
	case "", AgentKindClaude:
		return "Claude Code: merge the \"hooks\" object into ~/.claude/settings.json"
	default:
		if a := CustomAdapters[agent]; a != nil {
			return a.configDest()
		}
		return ""
	}
}

// hooksSnippet returns the config fragment that wires every lifecycle hook for
// the named agent to this binary.
func Snippet(agent, binary string) (string, error) {
	switch agent {
	case "", AgentKindClaude:
		return claudeHooksSnippet(binary), nil
	case hookAgentKindAntigrav:
		return antigravityHooksSnippet(binary), nil
	case hookAgentKindGemini:
		return geminiHooksSnippet(binary), nil
	default:
		if a := CustomAdapters[agent]; a != nil {
			return renderHookConfig(a, binary), nil
		}
		return "", fmt.Errorf("unknown agent %q; known: %s", agent, strings.Join(KnownAgents(), ", "))
	}
}

// claudeHooksSnippet is the settings.json fragment for Claude Code. Merge its
// "hooks" into ~/.claude/settings.json.
func claudeHooksSnippet(binary string) string {
	events := []string{"SessionStart", "SessionEnd", "UserPromptSubmit", "Stop", "StopFailure",
		"PreToolUse", "PostToolUse", "PermissionRequest", "Notification", "SubagentStart", "SubagentStop"}
	hooks := map[string]any{}
	for _, ev := range events {
		hooks[ev] = []any{map[string]any{"hooks": []any{map[string]any{
			"type": "command", "command": fmt.Sprintf("%q hook %s", binary, ev), "timeout": 5}}}}
	}
	out, _ := json.MarshalIndent(map[string]any{"hooks": hooks}, "", "  ")
	return string(out)
}

// geminiHooksSnippet is the settings.json fragment for Gemini CLI. Its hook
// timeout is in milliseconds; tool events take a regex matcher, "*" for all.
func geminiHooksSnippet(binary string) string {
	toolEvents := map[string]bool{"BeforeTool": true, "AfterTool": true}
	hooks := map[string]any{}
	for _, ev := range []string{"SessionStart", "SessionEnd", "BeforeAgent", "AfterAgent", "BeforeModel",
		"BeforeTool", "AfterTool", "Notification"} {
		hook := map[string]any{"name": "swarmsheriff", "type": "command",
			"command": fmt.Sprintf("%q hook --agent %s %s", binary, hookAgentKindGemini, ev), "timeout": 5000}
		entry := map[string]any{"hooks": []any{hook}}
		if toolEvents[ev] {
			entry["matcher"] = "*"
		}
		hooks[ev] = []any{entry}
	}
	out, _ := json.MarshalIndent(map[string]any{"hooks": hooks}, "", "  ")
	return string(out)
}

// antigravityHooksSnippet is the hooks.json for Google Antigravity. Write it to
// a workspace .agents/hooks.json or the global ~/.gemini/config/hooks.json.
// Tool events carry a "*" matcher so every tool is seen.
func antigravityHooksSnippet(binary string) string {
	toolEvents := map[string]bool{"PreToolUse": true, "PostToolUse": true}
	entries := map[string]any{}
	for _, ev := range []string{"SessionStart", "PreInvocation", "PostInvocation", "PreToolUse", "PostToolUse", "Stop"} {
		hook := map[string]any{"type": "command",
			"command": fmt.Sprintf("%q hook --agent %s %s", binary, hookAgentKindAntigrav, ev), "timeout": 5}
		entry := map[string]any{"hooks": []any{hook}}
		if toolEvents[ev] {
			entry["matcher"] = "*"
		}
		entries[ev] = []any{entry}
	}
	out, _ := json.MarshalIndent(map[string]any{"swarmsheriff": entries}, "", "  ")
	return string(out)
}
