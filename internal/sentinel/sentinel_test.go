package sentinel

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSentinelClientNeedsASecret(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "empty")
	os.WriteFile(empty, nil, 0o600)
	if _, err := NewClient("http://127.0.0.1:8000", empty); err == nil {
		t.Error("empty secret accepted")
	}
}
