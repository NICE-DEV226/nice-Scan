package output

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// Phase 5 — render-sink regressions: safe truncation and the terminal
// sanitization chain at the last hop before stdout.

func TestTerminalTruncateBoundsAndIdentity(t *testing.T) {
	r := NewTerminal()

	// Identity: content that already fits is untouched.
	if out := r.truncate("short", 78); out != "short" {
		t.Errorf("truncate must not alter fitting content, got %q", out)
	}

	// Overflow: budget holds counting glyphs, not bytes.
	out := r.truncate("0123456789", 5)
	if c := utf8.RuneCountInString(out); c != 5 {
		t.Errorf("expected 5 glyphs, got %q (%d)", out, c)
	}
	if !strings.HasSuffix(out, "…") {
		t.Errorf("overflow is signalled with an ellipsis, got %q", out)
	}

	// Degenerate widths must not panic.
	if out := r.truncate("abcdefgh", 0); out != "" {
		t.Errorf("maxLen 0 must yield empty string, got %q", out)
	}
	if out := r.truncate("abcdefgh", -20); out != "" {
		t.Errorf("negative width must yield empty string, got %q", out)
	}

	// No partial rune ever reaches the terminal.
	uni := r.truncate("éééééé", 4)
	if utf8.RuneCountInString(uni) != 4 || strings.ContainsRune(uni, utf8.RuneError) {
		t.Errorf("rune-aligned truncation broken: %q", uni)
	}
}

func TestOutputSanitizeDelegatesToTypes(t *testing.T) {
	dirty := "\x1b]0;pwned\x07payload" + string(rune(0x202E)) + "evilsuffix"
	clean := Sanitize(dirty)
	if strings.ContainsRune(clean, '\x1b') || strings.ContainsRune(clean, '\x07') || strings.ContainsRune(clean, rune(0x202E)) {
		t.Errorf("output.Sanitize must strip OSC and bidi controls, got %q", clean)
	}
	if !strings.Contains(clean, "payload") {
		t.Errorf("printable content must survive, got %q", clean)
	}
}
