package hacker

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
)

// lastQuery reads the LAST value of a repeated param — the detector appends
// its payload beside the page's original parameter.
func lastQuery(r *http.Request, key string) string {
	vals := r.URL.Query()[key]
	if len(vals) == 0 {
		return ""
	}
	return vals[len(vals)-1]
}

// The keyword differential alone must never claim RCE: the old detector
// returned SevCritical for ANY body containing "root"/"uid=" — including
// pages that merely echo the query string or mention the words.
func TestCMDDetectorSuspectsOnEchoOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.RawQuery
		switch {
		case strings.Contains(q, "echo"):
			// Echo-only server: reflects the raw query. URL-encoded quotes
			// inside the payload can never form the CLEAN open marker.
			_, _ = w.Write([]byte("reflected request: " + q))
		case strings.Contains(q, "id"):
			_, _ = w.Write([]byte("usage: id prints uid=NNN(name) gid=NNN — see docs"))
		default:
			_, _ = w.Write([]byte("<html>plain page</html>"))
		}
	}))
	defer srv.Close()

	client := transport.NewClient(transport.WithRetries(0), transport.WithTimeout(5*time.Second))
	defer func() { _ = client.Close() }()

	f, vulnURL := testCMDPayload(testCtx(), client, srv.URL+"/view?file=intro", "file")
	if f == nil {
		t.Fatal("an indicator appearing only with the payload must still surface a suspect finding")
	}
	if f.Severity == SevCritical {
		t.Errorf("echo-only differential claimed critical: %q", f.Name)
	}
	if !strings.Contains(f.Type, "suspect") {
		t.Errorf("finding type = %q, want the suspect class", f.Type)
	}
	if vulnURL != "" {
		t.Error("shell action queued on an echo-only differential")
	}
}

// Marker window + real uid line = executed fact: critical, and the shell
// module may be dispatched (consent still applies at the planner).
func TestCMDDetectorConfirmsMarkedExecution(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file := lastQuery(r, "file")
		switch {
		case strings.Contains(file, `nsxCMDE7BE"GIN"`):
			_, _ = w.Write([]byte("nsxCMDE7BEG uid=33(www-data) gid=33(www-data) groups=33(www-data)\nnsxCMDE7END"))
		case strings.Contains(file, "id"):
			_, _ = w.Write([]byte("uid=33(www-data) gid=33(www-data)"))
		default:
			_, _ = w.Write([]byte("<html>plain page</html>"))
		}
	}))
	defer srv.Close()

	client := transport.NewClient(transport.WithRetries(0), transport.WithTimeout(5*time.Second))
	defer func() { _ = client.Close() }()

	f, vulnURL := testCMDPayload(testCtx(), client, srv.URL+"/view?file=intro", "file")
	if f == nil {
		t.Fatal("marker-confirmed execution must produce a finding")
	}
	if f.Severity != SevCritical {
		t.Errorf("marker window held a real uid line but severity = %q", f.Severity)
	}
	if vulnURL == "" {
		t.Error("marker-confirmed injection must queue the shell action")
	}
}
