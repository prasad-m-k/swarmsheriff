package intake

import (
	"strings"
	"testing"
)

func TestCapLabel(t *testing.T) {
	if got := capLabel(strings.Repeat("x", 500)); len(got) != 64 {
		t.Errorf("len = %d", len(got))
	}
}
