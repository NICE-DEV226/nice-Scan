package shell

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
	"github.com/charmbracelet/bubbles/textinput"
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

// The shell used to run `exploit` with a hardcoded module set and drop every
// inline flag. parseRunArgs is the fix: it must recover the target AND the
// operator's flags (--creds/--cookie/--idor/--all) from a typed line, in both
// `--flag value` and `--flag=value` forms, without mistaking a flag for a URL.
func TestParseRunArgs(t *testing.T) {
	cases := []struct {
		in     []string
		target string
		o      runOpts
	}{
		{[]string{"example.com", "--creds", "admin:s3cret", "--idor", "1-50", "--all"}, "example.com", runOpts{creds: "admin:s3cret", idor: "1-50", all: true}},
		{[]string{"https://t/x", "--creds=u:p", "--cookie=sid=Z"}, "https://t/x", runOpts{creds: "u:p", cookie: "sid=Z"}},
		{[]string{"--all"}, "", runOpts{all: true}},
		{[]string{"t.io"}, "t.io", runOpts{}},
	}
	for _, c := range cases {
		tgt, o := parseRunArgs(c.in)
		if tgt != c.target || o != c.o {
			t.Errorf("parseRunArgs(%v) = (%q, %+v), want (%q, %+v)", c.in, tgt, o, c.target, c.o)
		}
	}
}

// Copying styled TUI lines must yield the plain text, not the SGR codes.
func TestStripANSI(t *testing.T) {
	got := stripANSI("\x1b[31;1mFAIL\x1b[0m https://t/admin")
	if got != "FAIL https://t/admin" {
		t.Errorf("stripANSI left escape codes: %q", got)
	}
}

// The `help` line promised ↑↓ history that did not exist. Recall must walk the
// buffer, skip an immediate duplicate on record, and stop at both ends.
func TestHistoryRecall(t *testing.T) {
	m := &Model{input: textinput.New(), histIdx: 0}

	m.pushHistory("scan a")
	m.pushHistory("exploit b --all")
	m.pushHistory("exploit b --all") // immediate repeat must not grow the buffer

	if len(m.history) != 2 {
		t.Fatalf("consecutive duplicate must be deduped, history=%v", m.history)
	}

	m.recallHistory(-1)
	if v := m.input.Value(); v != "exploit b --all" {
		t.Errorf("first ↑ should recall the newest command, got %q", v)
	}
	m.recallHistory(-1)
	if v := m.input.Value(); v != "scan a" {
		t.Errorf("second ↑ should recall the older command, got %q", v)
	}
	m.recallHistory(-1) // already at oldest: must clamp, not error or blank
	if v := m.input.Value(); v != "scan a" {
		t.Errorf("↑ at the oldest entry must stay put, got %q", v)
	}
	m.recallHistory(1)
	m.recallHistory(1) // back past the newest returns to a fresh empty line
	if v := m.input.Value(); v != "" {
		t.Errorf("↓ beyond the newest must clear back to the prompt, got %q", v)
	}
}

// The shell's `exploit` used to be a stale 3-module copy (login, role, IDOR)
// that dropped token reuse and — most importantly — the Admin Access
// differential that answers "what does a session actually reach". Against a
// local fixture it must now run the same chain the CLI runs. Consent is left
// OFF so only the read-only modules fire; their section headers are the proof.
func TestShellExploitRunsCurrentModules(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" && r.Method == http.MethodPost {
			_, _ = w.Write([]byte("<html>Invalid username or password</html>"))
			return
		}
		_, _ = w.Write([]byte(`<html><form action="/login" method="post">` +
			`<input name="user"><input type="password" name="pass"></form></html>`))
	}))
	defer srv.Close()

	client := transport.NewClient(transport.WithRetries(0), transport.WithTimeout(2*time.Second))
	defer func() { _ = client.Close() }()

	m := &Model{cfg: &types.Config{Destructive: false}, client: client}
	msg := m.exec("exploit", srv.URL, runOpts{})()

	lines, ok := msg.(cmdResultMsg)
	if !ok {
		t.Fatalf("expected cmdResultMsg, got %T", msg)
	}
	joined := strings.Join(lines, "\n")
	for _, want := range []string{"IDOR Enumeration", "Token / Session Reuse", "Admin Access Verification"} {
		if !strings.Contains(joined, want) {
			t.Errorf("shell exploit chain missing the %q module (stale copy?):\n%s", want, stripANSI(joined))
		}
	}
	// With consent off, the state-writing login spray must stay withheld.
	if strings.Contains(joined, "Login Bruteforce") {
		t.Errorf("login spray ran without consent:\n%s", stripANSI(joined))
	}
}
