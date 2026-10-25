package hacker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
)

const fakePasswd Record = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"

// Record keeps the fake passwd legally-typed without importing noise.
type Record string

// ── Wave D: LFI claims are structural records minus the baseline ─────────

// A traversal that actually returns /etc/passwd yields the critical
// finding and spawns the reader.
func TestLFIRequiresStructuralRecord(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get("file")
		if strings.Contains(val, "etc/passwd") {
			_, _ = w.Write([]byte("line1<br>" + string(fakePasswd) + "<br>footer"))
			return
		}
		_, _ = w.Write([]byte("<html>reader page about files</html>"))
	}))
	defer srv.Close()

	_, kb := kbForTest(srv.URL)
	kb.AddEndpoint(Endpoint{Path: srv.URL + "/read?file=x", Method: "GET", Status: 200})
	client := transport.NewClient(transport.WithRetries(0), transport.WithTimeout(10*time.Second))
	defer func() { _ = client.Close() }()

	res := (&LFIAction{}).Execute(context.Background(), srv.URL, kb, client)

	found := false
	for _, f := range res.Findings {
		if f.Type == "lfi_confirmed" {
			if f.Severity != SevCritical {
				t.Errorf("structural read stays critical: %+v", f)
			}
			if !strings.Contains(f.Description, "root:x:0:0:") {
				t.Errorf("evidence must quote the structural record, got %q", f.Description)
			}
			found = true
		}
	}
	if !found || len(res.Actions) == 0 {
		t.Fatalf("real traversal must confirm and spawn the reader, got %+v", res)
	}
}

// The tutorial-page guard: a page that PRINTS passwd records in plain
// text (baseline included) must not produce a traversal claim when its
// own content is re-served for any value.
func TestLFISilentWhenRecordsAreBaselineNoise(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The page itself legitimately carries the records (a UNIX
		// tutorial); the traversal responds with the SAME page.
		_, _ = w.Write([]byte("<html>tutorial: root:x:0:0:root:/root:/bin/bash is /etc/passwd's first record</html>"))
	}))
	defer srv.Close()

	_, kb := kbForTest(srv.URL)
	kb.AddEndpoint(Endpoint{Path: srv.URL + "/docs?file=x", Method: "GET", Status: 200})
	client := transport.NewClient(transport.WithRetries(0), transport.WithTimeout(10*time.Second))
	defer func() { _ = client.Close() }()

	res := (&LFIAction{}).Execute(context.Background(), srv.URL, kb, client)
	for _, f := range res.Findings {
		if f.Type == "lfi_confirmed" {
			t.Fatalf("baseline-carried records must not confirm a traversal: %+v", f)
		}
	}
}

// The reader side: same rules — a config-dump echo without real shape is
// not a read even if the endpoint returns a 200 with the URL echoed.
func TestLFIReaderRejectsPlainEchoes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>search echo: " + r.URL.RawQuery + "</html>"))
	}))
	defer srv.Close()

	_, kb := kbForTest(srv.URL)
	client := transport.NewClient(transport.WithRetries(0), transport.WithTimeout(10*time.Second))
	defer func() { _ = client.Close() }()

	a := &LFIReadAction{vulnURL: srv.URL + "/read?file=../../etc/passwd", param: "file"}
	res := a.Execute(context.Background(), srv.URL, kb, client)
	for _, f := range res.Findings {
		if f.Type == "lfi_file_read" {
			t.Fatalf("plain echo must not be claimed as a read: %+v", f)
		}
	}
	if len(kb.GetSecrets()) != 0 {
		t.Errorf("no real capture: secrets must stay empty, got %v", kb.GetSecrets())
	}
}

// And a real read lifts the risk-floor secret tier through AddSecret.
func TestLFIReaderRealContentCaptures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get("file")
		if strings.Contains(val, "etc/passwd") {
			_, _ = w.Write([]byte(string(fakePasswd)))
			return
		}
		_, _ = w.Write([]byte("<html>plain page</html>"))
	}))
	defer srv.Close()

	_, kb := kbForTest(srv.URL)
	client := transport.NewClient(transport.WithRetries(0), transport.WithTimeout(10*time.Second))
	defer func() { _ = client.Close() }()

	a := &LFIReadAction{vulnURL: srv.URL + "/read?file=../../etc/passwd", param: "file"}
	res := a.Execute(context.Background(), srv.URL, kb, client)

	found := false
	for _, f := range res.Findings {
		if f.Type == "lfi_file_read" && f.Severity == SevCritical {
			found = true
		}
	}
	if !found {
		t.Fatalf("real passwd content must be claimed, got %+v", res.Findings)
	}
	// /etc/passwd does NOT carry secrets (hashes live in shadow, which the
	// narrow isSecretFile list reflects): the capture must not lift the
	// secret risk tier without real credential material.
	if len(kb.GetSecrets()) != 0 {
		t.Errorf("passwd-only capture must stay out of the secret tier, got %v", kb.GetSecrets())
	}
}
