package engine

import (
	"context"
	"testing"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// A response to the scanner's own quote-break probe that carries an
// anchored DB error is error-surfacing evidence.
func TestSQLiAnalyzerProbeGatedErrorSurfacing(t *testing.T) {
	a := NewSQLiAnalyzer()
	resp := &types.Response{
		StatusCode: 200,
		Body:       []byte(`<b>Warning</b>: pg_query(): Query failed: ERROR:  syntax error at or near "'")`),
		RequestURL: "http://target.local/?id=1%27",
	}
	fs := a.Analyze(context.Background(), resp)
	if len(fs) != 1 {
		t.Fatalf("expected one finding, got %d", len(fs))
	}
	if fs[0].Name != "SQL Error Surfacing (error-based surface)" {
		t.Fatalf("wrong verdict name: %q", fs[0].Name)
	}
	if fs[0].Severity != types.SeverityHigh {
		t.Fatalf("error surfacing must be high, got %q", fs[0].Severity)
	}
	if fs[0].Metadata["request_url"] != resp.RequestURL {
		t.Fatal("probe URL must be retained in metadata")
	}
}

// The same anchored error on a page our probes did NOT cause is a backend
// fingerprint, not an injection claim.
func TestSQLiAnalyzerNonProbeErrorIsDisclosureOnly(t *testing.T) {
	a := NewSQLiAnalyzer()
	resp := &types.Response{
		StatusCode: 200,
		Body:       []byte(`<b>Warning</b>: pg_query(): Query failed: ERROR:  syntax error at or near "'")`),
		RequestURL: "http://target.local/api/status",
	}
	fs := a.Analyze(context.Background(), resp)
	if len(fs) != 1 {
		t.Fatalf("expected one finding, got %d", len(fs))
	}
	if fs[0].Name != "Database Error Text in Response — PostgreSQL" {
		t.Fatalf("wrong verdict name: %q", fs[0].Name)
	}
	if fs[0].Severity != types.SeverityMedium {
		t.Fatalf("non-probe error text must be medium, got %q", fs[0].Severity)
	}
}

// Regression for the old noise: mentions of backend names and generic
// entities on ordinary documentation pages produce nothing.
func TestSQLiAnalyzerSilentOnWordNoise(t *testing.T) {
	a := NewSQLiAnalyzer()
	for _, body := range []string{
		`<h1>PostgreSQL 15 release notes</h1><p>We benchmarked SQLite and Oracle.</p>`,
		`<p>Docs &amp; quotes: &quot;value&quot; &amp; more</p>`,
		`<div>CockroachDB blog post about ORA- style errors they avoid</div>`,
	} {
		resp := &types.Response{
			StatusCode: 200,
			Body:       []byte(body),
			RequestURL: "http://target.local/docs/db",
		}
		if fs := a.Analyze(context.Background(), resp); len(fs) != 0 {
			t.Fatalf("word mention (%s) must stay silent; got %q", body, fs[0].Name)
		}
	}
}
