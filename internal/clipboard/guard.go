package clipboard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"swarmsheriff/internal/dlp"
	"swarmsheriff/internal/policy"
	"swarmsheriff/internal/watch"
)

// The clipboard guard replaces a sensitive clipboard with a notice, so a paste
// into an AI chat carries nothing. It is a stopgap until a browser extension
// can block the submit itself, and it has a race: a paste inside one polling
// interval of the copy still goes through. It changes the user's clipboard,
// so it is off unless -clipboard-guard asks for it.

const (
	GuardOff    = "off"
	GuardAI     = "ai"     // only while an AI site is open in Chrome or a desktop AI app runs
	guardAlways = "always" // on every sensitive copy
)

// DefaultGuardRules are the findings worth wiping a clipboard for. Email is
// left out: copying an address is routine and wiping it would be noise.
const DefaultGuardRules = "credit-card,us-ssn,private-key,aws-access-key,gcp-api-key,google-oauth-token," +
	"openai-key,anthropic-key,github-token,slack-token,jwt,keyword:*"

type clipboardGuard struct {
	Mode        string
	rules       map[string]bool
	allKeywords bool // "keyword:*": every -dlp-keywords marker
}

func NewGuard(mode, rules string) (*clipboardGuard, error) {
	if mode != GuardOff && mode != GuardAI && mode != guardAlways {
		return nil, fmt.Errorf("-clipboard-guard %q is not off, ai, or always", mode)
	}
	g := &clipboardGuard{Mode: mode, rules: map[string]bool{}}
	for _, r := range policy.SplitList(rules) {
		switch {
		case r == "keyword:*":
			g.allKeywords = true
		case strings.HasPrefix(r, "keyword:"):
			g.rules[r] = true
		default:
			if _, ok := policy.BuiltinRuleByName[r]; !ok {
				return nil, fmt.Errorf("-guard-rules: %q is not a built-in rule name or keyword:<word>", r)
			}
			g.rules[r] = true
		}
	}
	return g, nil
}

// Trigger returns the findings that should make the guard act: none when the
// guard is off, or in ai mode with no AI context.
func (g *clipboardGuard) Trigger(findings []dlp.Finding, aiContext bool) []dlp.Finding {
	if g.Mode == GuardOff || (g.Mode == GuardAI && !aiContext) {
		return nil
	}
	var out []dlp.Finding
	for _, f := range findings {
		if g.rules[f.Rule] || (g.allKeywords && strings.HasPrefix(f.Rule, "keyword:")) {
			out = append(out, f)
		}
	}
	return out
}

// GuardNotice is what the clipboard holds after the guard acts. It names the
// rules that fired and nothing of what was copied.
func GuardNotice(fs []dlp.Finding) string {
	return fmt.Sprintf("[swarmsheriff cleared the clipboard: it held %s. Sensitive data must not be pasted into AI tools. "+
		"If this is wrong, contact security for an exception.]", dlp.Summary(fs))
}

// clipboardWriteCommands mirrors clipboardCommands for writing; each reads
// the new contents from stdin.
func clipboardWriteCommands() [][]string {
	switch runtime.GOOS {
	case "darwin":
		return [][]string{{"pbcopy"}}
	case "windows":
		return [][]string{{"powershell", "-NoProfile", "-Command", "Set-Clipboard -Value ([Console]::In.ReadToEnd())"}}
	default:
		return [][]string{
			{"wl-copy"},
			{"xclip", "-selection", "clipboard", "-i"},
			{"xsel", "--clipboard", "--input"},
		}
	}
}

func WriteClipboard(ctx context.Context, data []byte) error {
	ctx, cancel := context.WithTimeout(ctx, watch.ReadTimeout)
	defer cancel()

	var errs []error
	for _, args := range clipboardWriteCommands() {
		if _, err := exec.LookPath(args[0]); err != nil {
			errs = append(errs, err)
			continue
		}
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		cmd.Stdin = bytes.NewReader(data)
		if err := cmd.Run(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", args[0], err))
			continue
		}
		return nil
	}
	return fmt.Errorf("no usable clipboard writer: %w", errors.Join(errs...))
}
