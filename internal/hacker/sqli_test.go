package hacker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// Boolean-injectable app: ?id= drives real content — OR 1=1 dumps rows,
// AND 1=2 returns nothing, benign value returns one row. The replayed
// boolean differential must confirm and mark verified origin.
func TestSQLiBooleanDifferentialConfirms(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("id")
		switch {
		case strings.Contains(v, "OR 1=1"):
			_, _ = w.Write([]byte(strings.Repeat("<row>dump</row>", 80)))
		case strings.Contains(v, "AND 1=2"):
			_, _ = w.Write([]byte("<p>no results</p>"))
		default:
			_, _ = w.Write([]byte("<p>" + v + "</p>" + strings.Repeat("<row>item</row>", 3)))
		}
	}))
	defer srv.Close()

	client := transport.NewClient(transport.WithRetries(0))
	kb := NewKnowledge(srv.URL)
	kb.AddEndpoint(Endpoint{Path: srv.URL + "/item?id=7", Method: "GET", Status: 200})

	res := (&SQLiAction{}).Execute(context.Background(), srv.URL, kb, client)

	boolean := false
	for _, f := range res.Findings {
		if f.Type == "sqli_boolean" {
			boolean = true
		}
	}
	if !boolean {
		t.Fatalf("boolean differential must confirm on a content-controlling endpoint; findings: %+v", findingsOf(res))
	}
	verified := false
	for _, c := range kb.GetCapabilities() {
		if c.Name == "has_sqli_exploit" && c.Origin == OriginVerified {
			verified = true
		}
	}
	if !verified {
		t.Fatal("boolean confirmation must add verified-origin sqli exploit capability")
	}
	if len(res.Actions) == 0 {
		t.Fatal("confirmation must spawn the data extraction action")
	}
}

// Static app: every value returns the same page. Nothing may be claimed.
func TestSQLiSilentOnStaticEchoApp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<p>static page " + r.URL.Query().Get("id") + "</p>"))
	}))
	defer srv.Close()

	client := transport.NewClient(transport.WithRetries(0))
	kb := NewKnowledge(srv.URL)
	kb.AddEndpoint(Endpoint{Path: srv.URL + "/item?id=7", Method: "GET", Status: 200})

	res := (&SQLiAction{}).Execute(context.Background(), srv.URL, kb, client)

	for _, f := range res.Findings {
		if strings.HasPrefix(f.Type, "sqli_") && f.Type != "sqli_error_surfaces" {
			t.Fatalf("static app must not produce %q findings", f.Type)
		}
	}
	for _, c := range kb.GetCapabilities() {
		if c.Name == "has_sqli_exploit" {
			t.Fatal("static app must not gain the exploit capability")
		}
	}
}

// Error-surface differential: the backend error message counts only when
// the benign baseline page does not already carry the same text.
func TestSQLiErrorSurfacingGatedByBaseline(t *testing.T) {
	quoteError := func() http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.RawQuery, "%27") || strings.Contains(r.URL.RawQuery, "'") {
				_, _ = w.Write([]byte("<b>Warning</b>: pg_query(): Query failed: syntax error at or near \"1'\""))
				return
			}
			_, _ = w.Write([]byte("<p>ok</p>"))
		}
	}
	srv := httptest.NewServer(quoteError())
	defer srv.Close()

	client := transport.NewClient(transport.WithRetries(0))
	kb := NewKnowledge(srv.URL)
	kb.AddEndpoint(Endpoint{Path: srv.URL + "/search?q=cup", Method: "GET", Status: 200})

	res := (&SQLiAction{}).Execute(context.Background(), srv.URL, kb, client)
	surfaced := false
	for _, f := range res.Findings {
		if f.Type == "sqli_error_surfaces" {
			surfaced = true
		}
	}
	if !surfaced {
		t.Fatal("baseline-clean app surfacing a DB error on the quote-break probe must document it")
	}

	// Same backend but the error text on EVERY response: the message is
	// the failure shape, not a leak caused by our input.
	srvAll := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<b>Warning</b>: pg_query(): Query failed: syntax error at or near \"1'\""))
	}))
	defer srvAll.Close()

	kb2 := NewKnowledge(srvAll.URL)
	kb2.AddEndpoint(Endpoint{Path: srvAll.URL + "/search?q=cup", Method: "GET", Status: 200})
	res2 := (&SQLiAction{}).Execute(context.Background(), srvAll.URL, kb2, client)
	for _, f := range res2.Findings {
		if f.Type == "sqli_error_surfaces" {
			t.Fatal("error text present in the baseline must not be attributed to our input")
		}
	}
}

// Time-based: two delayed samples above a fast baseline confirm; constant
// sub-gate latency never does — the previous code measured one sample
// against nothing.
func TestSQLiTimeGateBaselineDiscipline(t *testing.T) {
	slowOnlyOnSleep := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "SLEEP") || strings.Contains(r.URL.RawQuery, "pg_sleep") {
			time.Sleep(2600 * time.Millisecond)
		}
		_, _ = w.Write([]byte("<p>ok</p>"))
	}))
	defer slowOnlyOnSleep.Close()

	client := transport.NewClient(transport.WithTimeout(10*time.Second), transport.WithRetries(0))
	kb := NewKnowledge(slowOnlyOnSleep.URL)
	kb.AddEndpoint(Endpoint{Path: slowOnlyOnSleep.URL + "/item?id=3", Method: "GET", Status: 200})

	res := (&SQLiAction{}).Execute(context.Background(), slowOnlyOnSleep.URL, kb, client)
	timeConfirmed := false
	for _, f := range res.Findings {
		if f.Type == "sqli_time" {
			timeConfirmed = true
		}
	}
	if !timeConfirmed {
		t.Fatal("2-of-2 delayed samples above a fast baseline must confirm time-based injection")
	}
}

// A pipe that adds steady latency to every request stays under the sleep
// gate floor: velocity-only differences are never time-based evidence.
func TestSQLiTimeGateBlocksSubFloorJitter(t *testing.T) {
	jitter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(900 * time.Millisecond)
		_, _ = w.Write([]byte("<p>ok</p>"))
	}))
	defer jitter.Close()

	client := transport.NewClient(transport.WithTimeout(10*time.Second), transport.WithRetries(0))
	kb := NewKnowledge(jitter.URL)
	kb.AddEndpoint(Endpoint{Path: jitter.URL + "/item?id=3", Method: "GET", Status: 200})
	res := (&SQLiAction{}).Execute(context.Background(), jitter.URL, kb, client)
	for _, f := range res.Findings {
		if f.Type == "sqli_time" {
			t.Fatal("steady sub-floor latency must not produce time-based findings")
		}
	}
}

// sleepGateLatency: absolute floor dominates a fast baseline; a slow
// baseline scales the gate so jitter cannot slip through.
func TestSleepGateLatencyRules(t *testing.T) {
	if got := sleepGateLatency(nil); got != 2300*time.Millisecond {
		t.Fatalf("nil baseline must default to the floor, got %v", got)
	}
	if got := sleepGateLatency(&types.Response{Duration: 200 * time.Millisecond}); got != 2300*time.Millisecond {
		t.Fatalf("fast baseline must keep the floor, got %v", got)
	}
	if got := sleepGateLatency(&types.Response{Duration: 2600 * time.Millisecond}); got <= 2600*time.Millisecond {
		t.Fatalf("slow baseline must raise the gate above its own latency, got %v", got)
	}
}

func findingsOf(res ActionResult) []string {
	out := make([]string, 0, len(res.Findings))
	for _, f := range res.Findings {
		out = append(out, f.Type)
	}
	return out
}
