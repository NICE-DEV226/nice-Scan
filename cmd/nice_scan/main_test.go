package main

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// Phase 5 — regressions for the operator-facing input gates in main.go.

func TestValidateProxy(t *testing.T) {
	valid := []string{"", "http://127.0.0.1:8080", "https://proxy.corp:3128", "socks5://127.0.0.1:9050"}
	for _, p := range valid {
		if err := validateProxy(p); err != nil {
			t.Errorf("proxy %q must be accepted, got %v", p, err)
		}
	}

	invalid := []struct {
		proxy string
		resp  string
	}{
		{"ftp://127.0.0.1:21", "unsupported proxy scheme"},
		{"http://", "missing a host"},
		{"http://:8080", "missing a host"},
		{"://not a url", "proxy"},
	}
	for _, c := range invalid {
		if err := validateProxy(c.proxy); err == nil || !strings.Contains(err.Error(), c.resp) {
			t.Errorf("proxy %q must fail with %q, got %v", c.proxy, c.resp, err)
		}
	}
}

func TestParseHeaderFlags(t *testing.T) {
	got := parseHeaderFlags([]string{
		"Cookie: sid=1; theme=dark:extras", // value keeps inner colon
		"X-Custom:   spaced value  ",
		"no-colon-line",   // malformed: dropped
		"Cookie: sid=999", // last flag wins
	})
	if got["X-Custom"] != "spaced value" {
		t.Errorf("value must be trimmed, got %q", got["X-Custom"])
	}
	if got["Cookie"] != "sid=999" {
		t.Errorf("duplicate flag: last one must win, got %q", got["Cookie"])
	}
	if _, ok := got["no-colon-line"]; ok {
		t.Errorf("malformed line must be dropped: %+v", got)
	}
	if len(got) != 2 {
		t.Errorf("unexpected map contents: %+v", got)
	}
}

func TestNormalizeTarget(t *testing.T) {
	cases := []struct{ in, want string }{
		{"example.com", "https://example.com"},
		{"https://example.com/", "https://example.com"},
		{"HTTP://example.com", "HTTP://example.com"}, // scheme detection is case-insensitive, case preserved
		{"HTTPS://Mixed.Case.ORG", "HTTPS://Mixed.Case.ORG"},
		{"https://t.example.com/path/", "https://t.example.com/path"},
	}
	for _, c := range cases {
		if got := normalizeTarget(c.in); got != c.want {
			t.Errorf("normalizeTarget(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestTruncateStrSanitizesAndBounds(t *testing.T) {
	// Terminal control sequences are sanitized before truncation.
	dirty := "ok\x1b]0;title-steal\x07more"
	got := truncateStr(dirty, 200)
	if strings.ContainsRune(got, '\x1b') || strings.ContainsRune(got, '\x07') {
		t.Errorf("control sequences must be stripped: %q", got)
	}
	if !strings.Contains(got, "ok") || !strings.Contains(got, "more") {
		t.Errorf("sanitization must keep printable content: %q", got)
	}

	// Bounds are rune-aligned: no panic, no corrupted partial rune,
	// never more glyphs than the budget.
	for _, n := range []int{0, -1, 1, 3, 8, 100} {
		out := truncateStr("abcdefgh", n)
		if n <= 0 {
			if out != "" {
				t.Errorf("truncateStr(_, %d) = %q, want empty", n, out)
			}
			continue
		}
		if got := utf8.RuneCountInString(out); got > n {
			t.Errorf("truncateStr(_, %d) = %q has %d glyphs (> %d)", n, out, got, n)
		}
	}

	// Multi-byte runes never end up cut mid-sequence.
	uni := truncateStr("ééééé", 4)
	if c := utf8.RuneCountInString(uni); c != 4 {
		t.Errorf("rune-aligned truncation expected 4 glyphs, got %q (%d)", uni, c)
	}
	if strings.ContainsRune(uni, utf8.RuneError) {
		t.Errorf("partial-rune corruption: %q", uni)
	}
}

// The banner and --version print "v" + version; the BuildInfo fallback
// (go install @vX.Y.Z) arrives already prefixed, so no "vv0.2.1".
func TestDisplayVersionSaysVExactlyOnce(t *testing.T) {
	out := displayV()
	if !strings.HasPrefix(out, "v") {
		t.Fatalf("version output must be v-prefixed, got %q", out)
	}
	if strings.HasPrefix(out[1:], "v") {
		t.Errorf("double v prefix leaked into the version output: %q", out)
	}
}

// Three read-only modules (security headers, JS secrets, source maps) had
// complete implementations and were registered in no action list, so they
// never ran in any scan. The registry is the only thing that makes a module
// real, and a missing entry is silent — hence this assertion.
func TestDefaultHackActionsIncludePassiveModules(t *testing.T) {
	actions := defaultHackActions(types.DefaultConfig())

	got := make(map[string]bool, len(actions))
	for _, a := range actions {
		got[a.Metadata().Name] = true
	}

	for _, want := range []string{"Security Headers", "JS Secret Scan", "Source Map Discovery", "Web Crawler", "Fuzzer"} {
		if !got[want] {
			t.Errorf("%q is not registered — it can never run (registered: %v)", want, got)
		}
	}

	// State-modifying actions must stay out of the default registry; they
	// are appended only under --destructive consent.
	for _, forbidden := range []string{"CMD Shell", "Web Shell Deploy", "Upload Exploitation", "CMD Injection"} {
		if got[forbidden] {
			t.Errorf("%q must not ship in the default action list", forbidden)
		}
	}
}
