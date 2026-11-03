package output

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// Phase 5 — render-sink regressions: evidence is never truncated away and the
// terminal sanitization chain holds at the last hop before stdout.

func TestWrapTextFoldsWithoutLoss(t *testing.T) {
	// wrapText must only ADD line breaks — every word survives, so no
	// decision-carrying evidence token can be dropped by the folding.
	in := "the quick brown fox jumps over the lazy dog repeatedly forever"
	out := wrapText(in, 20)
	if strings.ContainsRune(out, '…') {
		t.Errorf("wrap must never elide, got %q", out)
	}
	joined := strings.Join(strings.Fields(out), " ")
	if joined != in {
		t.Errorf("wrapping lost/changed words:\n in=%q\nout=%q", in, joined)
	}

	// Degenerate widths must not panic and must still emit the content.
	if got := wrapText("a b c", 1); strings.Join(strings.Fields(got), " ") != "a b c" {
		t.Errorf("width 1 must not lose words, got %q", got)
	}

	// Multibyte content is preserved whole (no partial rune at a break).
	uni := wrapText("ééé ééé ééé", 4)
	if strings.ContainsRune(uni, utf8.RuneError) {
		t.Errorf("multibyte evidence corrupted by wrapping: %q", uni)
	}
}

func TestRenderEvidenceKeepsDecisionCarryingValueWhole(t *testing.T) {
	// Regression: the old r.width-24 cut mangled a HIGH CORS finding's echoed
	// origin to "h…ue" on a narrow/non-TTY terminal, so the operator could not
	// see WHICH origin leaked. A short value IS the finding — it must survive
	// intact regardless of terminal width.
	ev := "Access-Control-Allow-Origin: https://evil.com (verbatim echo of Origin, credentials=true)"

	for _, width := range []int{40, 20, 78} {
		r := NewTerminal()
		r.width = width
		out := r.renderEvidence(ev)
		if !strings.Contains(out, "https://evil.com") {
			t.Errorf("width %d: decisive origin lost from evidence, got %q", width, out)
		}
		if strings.Contains(out, "…") {
			t.Errorf("width %d: short decision-carrying evidence must not be elided, got %q", width, out)
		}
	}

	// A genuinely long blob is now wrapped, never elided — every character of
	// evidence stays reachable on a continuation line.
	long := strings.Repeat("x", 500)
	r := NewTerminal()
	r.width = 78
	out := r.renderEvidence(long)
	if strings.Contains(out, "…") {
		t.Errorf("a long blob must wrap, not elide, got %q", out)
	}
	if strings.Count(out, "x") != 500 {
		t.Errorf("wrapping must preserve all %d chars, got %d", 500, strings.Count(out, "x"))
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
