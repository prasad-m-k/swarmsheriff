package eval

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"swarmsheriff/internal/decide"
	"testing"
	"time"
)

func TestSplitSamples(t *testing.T) {
	got := splitSamples("one\nline two\n---\n\n---\nthree\n")
	if len(got) != 2 || got[0] != "one\nline two" || got[1] != "three" {
		t.Errorf("samples = %q", got)
	}
}

func TestRunEval(t *testing.T) {
	dir := t.TempDir()
	write := func(name, data string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("code.positive.txt", "ProjectX plan\n---\nnothing to see")
	write("normal.negative.txt", "hello\n---\nthe projectx thing")
	samples, err := LoadCorpus(dir)
	if err != nil {
		t.Fatal(err)
	}
	d := decide.New(mustPolicy(t, testPolicyJSON), nil, time.Second, "")
	d.Exhaustive = true
	var out bytes.Buffer
	if err := Run(context.Background(), d, samples, &out); err != nil {
		t.Fatal(err)
	}
	// code: 2 positives, 1 missed; 2 normal negatives, 1 false positive.
	if !strings.Contains(out.String(), "code       2          1       50.0%      2          1          50.0%") {
		t.Errorf("output:\n%s", out.String())
	}

	write("nope.positive.txt", "x")
	samples, _ = LoadCorpus(dir)
	if err := Run(context.Background(), d, samples, &out); err == nil {
		t.Error("want an error for a class not in the policy")
	}
	write("bad-name.txt", "x")
	if _, err := LoadCorpus(dir); err == nil {
		t.Error("want an error for a badly named file")
	}
}
