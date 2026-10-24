package hacker

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
)

// Raw echo app + the page's own <script>alert(1)</script>: the OLD battery
// logic credited findings from verbatim payload matches; the canary
// discipline must credit only OUR random token coming back.
func TestXSSActionRawEchoConfirms(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// security-note: raw echo of q plus the targe's own script below —
		// the page carries <script>alert(1)</script> verbatim, which used
		// to be enough to claim an XSS
		_, _ = w.Write([]byte(`<div id="q">value: ` + r.URL.Query().Get("q") + `</div><script>alert(1)</script>`))
	}))
	defer srv.Close()

	client := transport.NewClient(transport.WithRetries(0))
	kb := NewKnowledge(srv.URL)
	kb.AddPage(Page{URL: srv.URL, Forms: 0})

	res := (&XSSAction{}).Execute(context.Background(), srv.URL, kb, client)

	confirmed := 0
	for _, f := range res.Findings {
		switch f.Type {
		case "xss_confirmed":
			confirmed++
		case "xss_reflection_points":
			// documented surface, fine
		default:
			t.Fatalf("raw-echo app must not emit %q findings", f.Type)
		}
	}
	if confirmed == 0 {
		t.Fatal("raw echo of the canary-tagged executable vector must confirm")
	}
	if len(res.Actions) == 0 {
		t.Fatal("confirmed reflection must spawn the PoC action")
	}
	caps := kb.GetCapabilities()
	found := false
	for _, c := range caps {
		if c.Name == "has_xss_exploit" && c.Origin == OriginVerified {
			found = true
		}
	}
	if !found {
		t.Fatal("has_xss_exploit must be verified-origin on executably confirmed reflection")
	}
}

// Escaped echo: reflection (worth a low finding) but never a confirmation.
func TestXSSActionEscapedEchoNeverConfirms(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<div id="q">value: ` + html.EscapeString(r.URL.Query().Get("q")) + `</div>`))
	}))
	defer srv.Close()

	client := transport.NewClient(transport.WithRetries(0))
	kb := NewKnowledge(srv.URL)
	kb.AddPage(Page{URL: srv.URL, Forms: 0})

	res := (&XSSAction{}).Execute(context.Background(), srv.URL, kb, client)

	for _, f := range res.Findings {
		if f.Type == "xss_confirmed" || f.Type == "xss_script_context" {
			t.Fatalf("escaped reflection must not claim %q", f.Type)
		}
	}
	escaped := false
	for _, f := range res.Findings {
		if f.Type == "xss_reflected_escaped" {
			escaped = true
		}
	}
	if !escaped {
		t.Fatal("entity-encoded reflection must be documented as escaped")
	}
	for _, c := range kb.GetCapabilities() {
		if c.Name == "has_xss_exploit" {
			t.Fatal("escaped reflection must not add the exploit capability")
		}
	}
}

// The old FP shape: page whose own scripts coincide with probe payloads
// and nothing reflects. findReflectedParams must stay silent.
func TestXSSActionSilentWhenNothingReflects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// the targe's own rich markup, echoing nothing
		_, _ = w.Write([]byte(`<div class="wrap"><script>alert(1)</script><img src="/x" onerror=alert(1)></div>`))
	}))
	defer srv.Close()

	client := transport.NewClient(transport.WithRetries(0))
	kb := NewKnowledge(srv.URL)
	kb.AddPage(Page{URL: srv.URL, Forms: 0})

	res := (&XSSAction{}).Execute(context.Background(), srv.URL, kb, client)

	if len(res.Findings) != 0 {
		t.Fatalf("non-reflecting app must stay silent; got %d findings — first: %q", len(res.Findings), res.Findings[0].Type)
	}
}
