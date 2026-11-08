package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// Two-identity differential fixture: /orders/42 serves A's order (marked
// with A's private email) to session A and — the vulnerability under test —
// ALSO to session B. /orders/77 correctly refuses B (403). /public/1 is a
// genuinely public object: both sessions get it, and it carries NEITHER
// identity — it must not produce a finding.
func bolaFixture(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>home</body></html>"))
	})
	mux.HandleFunc("/orders/42", func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Cookie") {
		case "sid=A":
			_, _ = w.Write([]byte(`<html>order 42 owner alice@example.com total 10</html>`))
		case "sid=B":
			// The bug: B can read A's order.
			_, _ = w.Write([]byte(`<html>order 42 owner alice@example.com total 10</html>`))
		default:
			w.WriteHeader(401)
		}
	})
	mux.HandleFunc("/orders/77", func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Cookie") {
		case "sid=A":
			_, _ = w.Write([]byte(`<html>order 77 owner alice@example.com</html>`))
		case "sid=B":
			w.WriteHeader(403) // correct enforcement
		default:
			w.WriteHeader(401)
		}
	})
	mux.HandleFunc("/public/1", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html>public doc 1 no owner marker</html>`))
	})
	return httptest.NewServer(mux)
}

func bolaConfig(base string) *types.Config {
	cfg := types.DefaultConfig()
	cfg.Targets = []string{base}
	cfg.IdentityA = "alice@example.com"
	cfg.IdentityB = "bob@example.com"
	cfg.SessionA = map[string]string{"Cookie": "sid=A"}
	cfg.SessionB = map[string]string{"Cookie": "sid=B"}
	return cfg
}

func TestBOLADiffFindsCrossSessionAccess(t *testing.T) {
	srv := bolaFixture(t)
	defer srv.Close()

	client := transport.NewClient(transport.WithTargetScope(srv.URL), transport.WithPrivateNetworkAllowed(true))
	defer func() { _ = client.Close() }()

	scanner := NewScanner(bolaConfig(srv.URL), client)

	// Seed the candidate directly: the pass replays URLs the scan already
	// saw, so simulate the /orders/42 hit having happened.
	result := &ScanResult{
		Results: []*types.Result{
			{
				Request:  &types.Request{Method: "GET", URL: srv.URL + "/orders/42"},
				Response: &types.Response{StatusCode: 200},
			},
		},
	}
	scanner.runBOLADiff(context.Background(), result)

	var bola *types.Finding
	for i := range result.Findings {
		if strings.Contains(result.Findings[i].Name, "BOLA") {
			bola = &result.Findings[i]
		}
	}
	if bola == nil {
		t.Fatalf("expected a BOLA finding, got %d findings", len(result.Findings))
	}
	if bola.Severity != types.SeverityHigh {
		t.Errorf("severity = %s, want high", bola.Severity)
	}
	if bola.Prov == nil || bola.Prov.RequestURL != srv.URL+"/orders/42" {
		t.Errorf("provenance must cite the replayed URL, got %+v", bola.Prov)
	}
	if types.GradeOf(*bola) != types.GradeProven {
		t.Errorf("grade = %s, want proven (identity marker echoed to the wrong session)", types.GradeOf(*bola))
	}
}

func TestBOLADiffStaysSilentWhenAccessControlHolds(t *testing.T) {
	srv := bolaFixture(t)
	defer srv.Close()

	client := transport.NewClient(transport.WithTargetScope(srv.URL), transport.WithPrivateNetworkAllowed(true))
	defer func() { _ = client.Close() }()

	scanner := NewScanner(bolaConfig(srv.URL), client)

	// /orders/77 refuses B (403): correct enforcement, no finding.
	// /public/1 is public and carries no identity marker: no finding.
	result := &ScanResult{
		Results: []*types.Result{
			{
				Request:  &types.Request{Method: "GET", URL: srv.URL + "/orders/77"},
				Response: &types.Response{StatusCode: 200},
			},
			{
				Request:  &types.Request{Method: "GET", URL: srv.URL + "/public/1"},
				Response: &types.Response{StatusCode: 200},
			},
		},
	}
	scanner.runBOLADiff(context.Background(), result)

	for _, f := range result.Findings {
		if strings.Contains(f.Name, "BOLA") {
			t.Fatalf("false positive on enforced/public object: %+v", f)
		}
	}
}

func TestBOLADiffRequiresFullConfiguration(t *testing.T) {
	cfg := types.DefaultConfig()
	cfg.IdentityA = "alice@example.com"
	// IdentityB and sessions missing: the pass must not run at all.
	scanner := NewScanner(cfg, transport.NewClient())
	defer func() { _ = scanner.client.Close() }()

	if scanner.bolaArmed() {
		t.Fatal("partial identity config must not arm the differential")
	}
}

func TestBOLACandidatesFilters(t *testing.T) {
	results := []*types.Result{
		{Request: &types.Request{Method: "GET", URL: "https://t.example/orders/42"}, Response: &types.Response{StatusCode: 200}},
		{Request: &types.Request{Method: "POST", URL: "https://t.example/orders/43"}, Response: &types.Response{StatusCode: 200}},
		{Request: &types.Request{Method: "GET", URL: "https://t.example/orders/44"}, Response: &types.Response{StatusCode: 404}},
		{Request: &types.Request{Method: "GET", URL: "https://t.example/about"}, Response: &types.Response{StatusCode: 200}},
		{Request: &types.Request{Method: "GET", URL: "https://t.example/users/a1b2c3d4-e5f6-7890-abcd-ef1234567890"}, Response: &types.Response{StatusCode: 200}},
	}
	got := bolaCandidates(results)
	want := []string{
		"https://t.example/orders/42",
		"https://t.example/users/a1b2c3d4-e5f6-7890-abcd-ef1234567890",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("candidates = %v, want %v", got, want)
	}
}
