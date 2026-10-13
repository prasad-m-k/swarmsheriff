package metrics

import (
	"testing"
)

func life(min int, kind, session string) Event {
	return Event{At: at(min), Kind: kind, SessionID: session, AgentKind: "claude-code"}
}

func withReq(e Event, req string) Event { e.RequestID = req; return e }

func agentReport(t *testing.T, events []Event, toMin int, nowMin int) AgentMetrics {
	t.Helper()
	db := readOnly(t, writeMetrics(t, events))
	r, err := Query(db, Filters{FromMs: at(0).UnixMilli(), ToMs: at(toMin).UnixMilli()}, DefaultStallMs, at(nowMin))
	if err != nil {
		t.Fatal(err)
	}
	return r.Agents
}

func TestAgentLifecycleMetrics(t *testing.T) {
	start := life(0, KindSessionStarted, "s1")
	start.Model = "claude-opus-5-5"
	a := agentReport(t, []Event{
		{At: at(0), Kind: KindAgentStarted},
		start,
		life(1, KindTurnStarted, "s1"),
		life(2, KindToolActivity, "s1"),
		life(3, KindApprovalRequested, "s1"),
		life(5, KindToolActivity, "s1"), // the approved tool runs: 2 minute wait
		life(7, KindTurnCompleted, "s1"),
		life(10, KindTurnStarted, "s1"),
		withReq(life(11, KindQuestionRequested, "s1"), "q1"),
		withReq(life(12, KindToolActivity, "s1"), "t9"),      // does not answer a question
		withReq(life(14, KindAttentionResolved, "s1"), "q1"), // 3 minute wait
		life(15, KindToolActivity, "s1"),
		life(40, KindToolActivity, "s1"), // 25 minutes of silence while working: a stall
		life(41, KindTurnCompleted, "s1"),
		life(42, KindSessionStarted, "s2"),
		life(43, KindTurnStarted, "s2"),
		life(44, KindAgentError, "s2"),
		life(50, KindSessionEnded, "s1"),
	}, 60, 60)

	min := func(n int64) int64 { return n * 60_000 }
	want := map[string]int64{"working": min(33), "blocked": min(5), "idle": min(14), "error": min(16), "unknown": 0}
	for k, v := range want {
		if a.TimeInStateMs[k] != v {
			t.Errorf("time_in_state[%s] = %d min, want %d", k, a.TimeInStateMs[k]/60_000, v/60_000)
		}
	}
	if a.BlockedMs["approval"] != min(2) || a.BlockedMs["question"] != min(3) {
		t.Errorf("blocked_ms = %v", a.BlockedMs)
	}
	if a.Turns.Started != 3 || a.Turns.Completed != 2 || a.Turns.Ambiguous != 0 || a.Turns.PerHour == nil || *a.Turns.PerHour != 3 {
		t.Errorf("turns = %+v", a.Turns)
	}
	o := a.OperatorResponse
	if o.WaitCount != 2 || o.WaitMs != min(5) || o.ByReason["approval"] != 1 || o.ByReason["question"] != 1 || o.Status != "available" || o.ResumeMs != nil {
		t.Errorf("operator_response = %+v", o)
	}
	if a.Errors.SessionFailure != 1 {
		t.Errorf("errors = %+v", a.Errors)
	}
	if len(a.Stalls) != 1 || a.Stalls[0].DurationMs != min(25) || a.Stalls[0].Ongoing || a.Stalls[0].SessionID != "s1" {
		t.Errorf("stalls = %+v", a.Stalls)
	}
	if a.Sessions.Started != 2 || a.Sessions.ByModel["claude-opus-5-5"] != 1 || a.Sessions.ByAgentKind["claude-code"] != 2 {
		t.Errorf("sessions = %+v", a.Sessions)
	}
}

func TestAgentLifecycleEdgeCases(t *testing.T) {
	// swarmsheriff crashes while s1 waits on a question; the wait and the interval
	// are censored at the last event, not stretched over the downtime.
	a := agentReport(t, []Event{
		{At: at(0), Kind: KindAgentStarted},
		life(1, KindTurnStarted, "s1"),
		withReq(life(2, KindQuestionRequested, "s1"), "q1"),
		{At: at(4), Kind: KindClipboard},
		{At: at(30), Kind: KindAgentStarted},
		life(31, KindTurnStarted, "s1"), // seen fresh after the restart
		life(32, KindTurnCompleted, "s1"),
	}, 60, 60)
	if a.OperatorResponse.WaitCount != 0 || a.OperatorResponse.Censored != 1 || a.Censored != 1 {
		t.Errorf("crash: waits=%d censored=%d intervals=%d", a.OperatorResponse.WaitCount, a.OperatorResponse.Censored, a.Censored)
	}
	// Working 1-2 and 31-32, blocked 2-4 (cut at the clipboard event, the last
	// sign of life), nothing counted for the 26 minutes swarmsheriff was down.
	if a.TimeInStateMs["working"] != 2*60_000 || a.TimeInStateMs["blocked"] != 2*60_000 || a.BlockedMs["question"] != 2*60_000 ||
		a.TimeInStateMs["unknown"] != 0 || a.TimeInStateMs["idle"] != 28*60_000 {
		t.Errorf("crash time_in_state = %v", a.TimeInStateMs)
	}

	// Duplicate approval signals for one prompt make one wait; a new prompt
	// while working is an ambiguous turn (Claude sends no Stop on interrupt).
	a = agentReport(t, []Event{
		life(0, KindTurnStarted, "s1"),
		life(1, KindApprovalRequested, "s1"),
		withReq(life(1, KindApprovalRequested, "s1"), "t1"),
		life(2, KindToolActivity, "s1"),
		life(3, KindTurnStarted, "s1"),
		life(4, KindTurnCompleted, "s1"),
	}, 60, 60)
	if a.OperatorResponse.WaitCount != 1 || a.Turns.Ambiguous != 1 || a.Turns.Started != 2 {
		t.Errorf("dupes: waits=%d ambiguous=%d started=%d", a.OperatorResponse.WaitCount, a.Turns.Ambiguous, a.Turns.Started)
	}

	// Working with no evidence since minute 5 is an ongoing stall at minute 60.
	a = agentReport(t, []Event{
		life(0, KindTurnStarted, "s1"),
		life(5, KindToolActivity, "s1"),
	}, 60, 60)
	if len(a.Stalls) != 1 || !a.Stalls[0].Ongoing || a.Stalls[0].DurationMs != 55*60_000 {
		t.Errorf("ongoing stall = %+v", a.Stalls)
	}
}

func TestLaunchesAndResources(t *testing.T) {
	dec := func(model, provider string) Event {
		return Event{At: at(5), Kind: KindDecision, Verdict: "allow", Model: model, Provider: provider}
	}
	db := readOnly(t, writeMetrics(t, []Event{
		{At: at(1), Kind: KindAIAppStarted, App: "Cursor", Mode: "initial"}, // already running: not a launch
		{At: at(2), Kind: KindAIAppStarted, App: "ChatGPT"},
		dec("claude-opus-5-5", "anthropic"), dec("claude-opus-5-5", "anthropic"), dec("gpt-5", "openai"),
		{At: at(6), Kind: KindResource, App: "Cursor", CPUPct: 10, CPUMax: 40, RSSKB: 512 * 1024, Procs: 9},
		{At: at(7), Kind: KindResource, App: "Cursor", CPUPct: 20, CPUMax: 30, RSSKB: 1024 * 1024, Procs: 11},
	}))
	r, err := Query(db, Filters{FromMs: at(0).UnixMilli(), ToMs: at(60).UnixMilli()}, DefaultStallMs, at(60))
	if err != nil {
		t.Fatal(err)
	}
	l := r.Launches
	if l.AppStarts["ChatGPT"] != 1 || l.AppStarts["Cursor"] != 0 || l.RequestsByModel["claude-opus-5-5"] != 2 || l.RequestsByProvider["openai"] != 1 {
		t.Errorf("launches = %+v", l)
	}
	if u := r.Resources["Cursor"]; u != (resourceUsage{Samples: 2, CPUAvg: 15, CPUPeak: 40, RSSAvgMB: 768, RSSPeakMB: 1024, ProcsPeak: 11}) {
		t.Errorf("resources = %+v", u)
	}

	f := Filters{FromMs: at(0).UnixMilli(), ToMs: at(60).UnixMilli(), Model: "gpt-5"}
	if r, _ = Query(db, f, DefaultStallMs, at(60)); r.Decisions.Total != 1 {
		t.Errorf("model filter total = %d", r.Decisions.Total)
	}
}
