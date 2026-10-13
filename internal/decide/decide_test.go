package decide

import (
	"context"
	"errors"
	"slices"
	"strings"
	"swarmsheriff/internal/classify"
	"swarmsheriff/internal/policy"
	"testing"
	"time"
)

// fakeClassifier returns fixed probabilities, or an error, and records what
// it was shown.
type fakeClassifier struct {
	probs map[string]float64
	err   error
	delay time.Duration
	calls int
	seen  classify.ClassifierInput
	asked []string
}

func (f *fakeClassifier) Name() string { return "fake" }
func (f *fakeClassifier) Classify(ctx context.Context, in classify.ClassifierInput, cs []*policy.Class) (map[string]float64, error) {
	f.calls++
	f.seen = in
	for _, c := range cs {
		f.asked = append(f.asked, c.ID)
	}
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return f.probs, f.err
}

// testAWSKey builds an access-key-shaped string from the pattern, never a real key.
var testAWSKey = "AKIA" + strings.Repeat("Q", 16)

func TestDecide(t *testing.T) {
	tests := []struct {
		name        string
		req         Request
		clf         *fakeClassifier
		modeFlag    string
		wantVerdict policy.Verdict
		wantApplied policy.Verdict
		wantClasses []string
		wantRule    string
		wantClf     string
	}{
		{
			name:        "clean text is allowed without the classifier when nothing could change",
			req:         Request{Text: "how do I sort a slice", Destination: "api.company-llm.example"},
			clf:         &fakeClassifier{},
			wantVerdict: policy.VerdictAllow, wantClf: "not-needed",
		},
		{
			name:        "source label",
			req:         Request{Text: "hello", Labels: []string{"repo:core"}, Destination: "api.anthropic.com"},
			clf:         &fakeClassifier{},
			wantVerdict: policy.VerdictBlock, wantClasses: []string{"code"}, wantRule: "label:repo:core",
		},
		{
			name:        "path glob",
			req:         Request{Text: "see /src/core-platform/billing/x.go line 3", Destination: "api.anthropic.com"},
			clf:         &fakeClassifier{},
			wantVerdict: policy.VerdictBlock, wantClasses: []string{"code"}, wantRule: "path-glob",
		},
		{
			name:        "keyword is case-insensitive",
			req:         Request{Text: "the projectx launch", Destination: "api.anthropic.com"},
			clf:         &fakeClassifier{},
			wantVerdict: policy.VerdictBlock, wantClasses: []string{"code"}, wantRule: "keyword",
		},
		{
			name:        "built-in rule in an enforce class is applied",
			req:         Request{Text: "key " + testAWSKey, Destination: "api.company-llm.example"},
			clf:         &fakeClassifier{},
			wantVerdict: policy.VerdictBlock, wantApplied: policy.VerdictBlock, wantClasses: []string{"creds"}, wantRule: "rule:aws-access-key",
		},
		{
			name:        "policy regexp rule",
			req:         Request{Text: "ticket INTERNAL-1234", Destination: "api.openai.com"},
			clf:         &fakeClassifier{},
			wantVerdict: policy.VerdictBlock, wantApplied: policy.VerdictBlock, wantClasses: []string{"creds"}, wantRule: "rule:re:\\bINTERNAL-[0-9]{4}\\b",
		},
		{
			name:        "fingerprint of a quoted line",
			req:         Request{Text: "intro\n  " + knownDocLine + "  \nmore", Destination: "api.openai.com"},
			clf:         &fakeClassifier{probs: map[string]float64{}},
			wantVerdict: policy.VerdictHold, wantClasses: []string{"customers"}, wantRule: "fingerprint",
		},
		{
			name:        "approved destination allows a matched class",
			req:         Request{Text: "ProjectX", Destination: "api.company-llm.example"},
			clf:         &fakeClassifier{},
			wantVerdict: policy.VerdictAllow, wantClasses: []string{"code"}, wantRule: "keyword",
		},
		{
			name:        "unlisted destination gets the strictest action",
			req:         Request{Text: "ProjectX", Destination: "unknown-llm.example"},
			clf:         &fakeClassifier{},
			wantVerdict: policy.VerdictBlock, wantClasses: []string{"code"}, wantRule: "keyword",
		},
		{
			name:        "classifier over block_at",
			req:         Request{Text: "some ambiguous code", Destination: "api.anthropic.com"},
			clf:         &fakeClassifier{probs: map[string]float64{"code": 0.95}},
			wantVerdict: policy.VerdictBlock, wantClasses: []string{"code"}, wantRule: "classifier", wantClf: "used",
		},
		{
			name:        "classifier in the hold band",
			req:         Request{Text: "some ambiguous code", Destination: "api.anthropic.com"},
			clf:         &fakeClassifier{probs: map[string]float64{"code": 0.6}},
			wantVerdict: policy.VerdictHold, wantClasses: []string{"code"}, wantRule: "classifier", wantClf: "used",
		},
		{
			name:        "classifier below hold_at",
			req:         Request{Text: "some ambiguous code", Destination: "api.anthropic.com"},
			clf:         &fakeClassifier{probs: map[string]float64{"code": 0.2}},
			wantVerdict: policy.VerdictAllow, wantClf: "used",
		},
		{
			name:        "classifier error without labels falls back to allow",
			req:         Request{Text: "text", Destination: "api.anthropic.com"},
			clf:         &fakeClassifier{err: errors.New("down")},
			wantVerdict: policy.VerdictAllow, wantClf: "unavailable",
		},
		{
			name:        "classifier error with an unmatched label blocks",
			req:         Request{Text: "text", Labels: []string{"share:finance"}, Destination: "api.anthropic.com"},
			clf:         &fakeClassifier{err: errors.New("down")},
			modeFlag:    policy.ModeEnforce,
			wantVerdict: policy.VerdictBlock, wantApplied: policy.VerdictBlock, wantClasses: []string{"labeled-unclassified"},
			wantRule: "classifier-unavailable", wantClf: "unavailable",
		},
		{
			name:        "mode flag enforces classes without their own mode",
			req:         Request{Text: "ProjectX", Destination: "api.anthropic.com"},
			clf:         &fakeClassifier{},
			modeFlag:    policy.ModeEnforce,
			wantVerdict: policy.VerdictBlock, wantApplied: policy.VerdictBlock, wantClasses: []string{"code"}, wantRule: "keyword",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := New(mustPolicy(t, testPolicyJSON), tt.clf, time.Second, tt.modeFlag)
			got := d.Decide(context.Background(), tt.req)
			if got.Verdict != tt.wantVerdict || got.Applied != tt.wantApplied {
				t.Errorf("verdict/applied = %v/%v, want %v/%v", got.Verdict, got.Applied, tt.wantVerdict, tt.wantApplied)
			}
			if !slices.Equal(got.Classes, tt.wantClasses) {
				t.Errorf("classes = %v, want %v", got.Classes, tt.wantClasses)
			}
			if tt.wantRule != "" && !slices.Contains(got.Rules, tt.wantRule) {
				t.Errorf("rules = %v, want %s", got.Rules, tt.wantRule)
			}
			if tt.wantClf != "" && got.Classifier != tt.wantClf {
				t.Errorf("classifier = %s, want %s", got.Classifier, tt.wantClf)
			}
		})
	}
}

func TestDecideSkipsClassifierWhenBlocked(t *testing.T) {
	clf := &fakeClassifier{probs: map[string]float64{"customers": 1}}
	d := New(mustPolicy(t, testPolicyJSON), clf, time.Second, "")
	got := d.Decide(context.Background(), Request{Text: "ProjectX", Destination: "api.anthropic.com"})
	if clf.calls != 0 {
		t.Errorf("classifier called %d times after a deterministic block", clf.calls)
	}
	if got.Verdict != policy.VerdictBlock {
		t.Errorf("verdict = %v", got.Verdict)
	}
}

func TestDecideClassifierTimeoutFallsBack(t *testing.T) {
	clf := &fakeClassifier{probs: map[string]float64{"code": 1}, delay: time.Second}
	d := New(mustPolicy(t, testPolicyJSON), clf, 20*time.Millisecond, "")
	start := time.Now()
	got := d.Decide(context.Background(), Request{Text: "x", Destination: "api.anthropic.com"})
	if el := time.Since(start); el > 500*time.Millisecond {
		t.Errorf("decide took %s; the classifier timeout did not bound it", el)
	}
	if got.Classifier != "unavailable" || got.Verdict != policy.VerdictAllow {
		t.Errorf("classifier/verdict = %s/%v, want unavailable/allow", got.Classifier, got.Verdict)
	}
}

func TestDecideClassifierSeesFeaturesNotContent(t *testing.T) {
	secret := "the merger closes Friday at 41 dollars a share"
	clf := &fakeClassifier{probs: map[string]float64{}}
	d := New(mustPolicy(t, testPolicyJSON), clf, time.Second, "")
	d.Decide(context.Background(), Request{Text: secret + "\nsee /a/core/b.txt CONFIDENTIAL", Destination: "api.anthropic.com"})
	if clf.calls != 1 {
		t.Fatalf("calls = %d", clf.calls)
	}
	if clf.seen.Raw != "" || strings.Contains(clf.seen.Features, "merger") {
		t.Errorf("classifier saw content: %+v", clf.seen)
	}
	for _, want := range []string{"document_markers: confidential", "path_directories: a, core", "length_chars:"} {
		if !strings.Contains(clf.seen.Features, want) {
			t.Errorf("features missing %q:\n%s", want, clf.seen.Features)
		}
	}
}

func TestDecideRawOptIn(t *testing.T) {
	js := strings.Replace(testPolicyJSON, `"block_at": 0.9, "hold_at": 0.5`, `"block_at": 0.9, "hold_at": 0.5, "classifier_raw": true`, 1)
	clf := &fakeClassifier{probs: map[string]float64{}}
	d := New(mustPolicy(t, js), clf, time.Second, "")
	d.Decide(context.Background(), Request{Text: "raw text", Destination: "api.anthropic.com"})
	if clf.seen.Raw != "raw text\n" && clf.seen.Raw != "raw text" {
		t.Errorf("raw = %q, want the text for an opted-in class", clf.seen.Raw)
	}
	if got := mustPolicy(t, js).RawClassifierClasses(); !slices.Equal(got, []string{"code"}) {
		t.Errorf("rawClassifierClasses = %v", got)
	}
}

func TestDecisionCarriesNoContent(t *testing.T) {
	text := "ProjectX " + testAWSKey + " " + knownDocLine
	d := New(mustPolicy(t, testPolicyJSON), &fakeClassifier{}, time.Second, "")
	got := d.Decide(context.Background(), Request{Text: text, Destination: "api.anthropic.com", AgentID: "a1"})
	all := strings.Join(append(append([]string{}, got.Rules...), got.Classes...), " ")
	for _, frag := range []string{testAWSKey, knownDocLine} {
		if strings.Contains(all, frag) {
			t.Errorf("decision leaks %q: %+v", frag, got)
		}
	}
	if got.AgentIDSource != "declared" {
		t.Errorf("agent_id_source = %q, want declared", got.AgentIDSource)
	}
}
