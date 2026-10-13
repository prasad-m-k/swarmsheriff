// Package clipboard reads the system clipboard and guards it: the guard
// replaces sensitive clipboard text with a notice.
package clipboard

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"swarmsheriff/internal/watch"
)

// clipboardCommands returns candidate commands for reading the clipboard on
// the current OS, in order of preference.
func clipboardCommands() [][]string {
	switch runtime.GOOS {
	case "darwin":
		return [][]string{{"pbpaste"}}
	case "windows":
		return [][]string{{"powershell", "-NoProfile", "-Command", "Get-Clipboard -Raw"}}
	default:
		return [][]string{
			{"wl-paste", "--no-newline"},
			{"xclip", "-selection", "clipboard", "-o"},
			{"xsel", "--clipboard", "--output"},
		}
	}
}

func ReadClipboard(ctx context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, watch.ReadTimeout)
	defer cancel()

	var errs []error
	for _, args := range clipboardCommands() {
		if _, err := exec.LookPath(args[0]); err != nil {
			errs = append(errs, err)
			continue
		}
		out, err := exec.CommandContext(ctx, args[0], args[1:]...).Output()
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", args[0], err))
			continue
		}
		return out, nil
	}
	return nil, fmt.Errorf("no usable clipboard tool: %w", errors.Join(errs...))
}
