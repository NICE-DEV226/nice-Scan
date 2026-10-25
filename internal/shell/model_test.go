package shell

import (
	"testing"
)

// Phase 5 — shell regressions: interactive targets must always normalize to
// an absolute URL and resolve a credential scope the shared client binds
// (OPSEC parity with the CLI commands; see internal/transport credentials).

func TestShellTargetScope(t *testing.T) {
	cases := []struct {
		in         string
		normalized string
		scope      string
	}{
		{"example.com", "https://example.com", "example.com"},
		{"https://example.com/", "https://example.com", "example.com"},
		{"http://USER:PW@host.example.com:8080/p", "http://USER:PW@host.example.com:8080/p", "host.example.com"},
		{"HTTPS://Mixed.Case.ORG", "HTTPS://Mixed.Case.ORG", "mixed.case.org"}, // case-insensitive scheme detection
		{"http://127.0.0.1:8080", "http://127.0.0.1:8080", "127.0.0.1"},
		{"", "https:", ""},         // degenerate input: no scope bound (fail-closed)
		{":::", "https://:::", ""}, // garbage input: no scope bound (fail-closed)
	}
	for _, c := range cases {
		n, s := shellTargetScope(c.in)
		if n != c.normalized || s != c.scope {
			t.Errorf("shellTargetScope(%q) = (%q, %q), want (%q, %q)", c.in, n, s, c.normalized, c.scope)
		}
	}

	// The invariant that matters: every plausible user-typed host resolves
	// a non-empty scope, so operator credentials are always bound for it.
	for _, tIn := range []string{"target.io", "http://target.io/x", "https://sub.target.io"} {
		if _, s := shellTargetScope(tIn); s == "" {
			t.Errorf("target %q must resolve a credential scope", tIn)
		}
	}
}
