package recon

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/NICE-DEV226/nice-Scan/internal/exploit"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// gated answers one path differently to the anonymous round and the session
// round, and 404s everything else — the shape an access check is supposed to
// report on.
func gated(hits *int32, cookieName, secretPath, privilegedBody string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		if r.URL.Path != secretPath {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		if _, err := r.Cookie(cookieName); err == nil {
			_, _ = w.Write([]byte(privilegedBody))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden"))
	})
}

func TestVerifyAccessRefusesWithoutAnIdentity(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(gated(&hits, "sid", "/api/internal/metrics", "requests_total 42"))
	defer srv.Close()

	svc, err := New(Options{Config: types.DefaultConfig(), Scope: []string{srv.URL}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = svc.Close() }()

	_, err = svc.VerifyAccess(context.Background(), srv.URL, Session{})
	if !errors.Is(err, ErrNoSession) {
		t.Fatalf("err = %v, want ErrNoSession", err)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Errorf("an identity-less check put %d requests on the wire, want 0", atomic.LoadInt32(&hits))
	}
}

func TestVerifyAccessGradesTheLiftByItsDifferential(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(gated(&hits, "sid", "/api/internal/metrics", "requests_total 42 sessions_active 7"))
	defer srv.Close()

	svc, err := New(Options{Config: types.DefaultConfig(), Scope: []string{srv.URL}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = svc.Close() }()

	report, err := svc.VerifyAccess(context.Background(), srv.URL,
		Session{Cookie: "sid=hunter2-short"}, "/api/internal/metrics")
	if err != nil {
		t.Fatalf("VerifyAccess: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("access check made %d requests, want the two rounds of one path", got)
	}
	if len(report.Paths) != 1 || !report.Paths[0].Lifted {
		t.Fatalf("paths = %+v, want the one lifted row", report.Paths)
	}
	if report.Paths[0].AnonymousStatus != http.StatusForbidden || report.Paths[0].SessionStatus != http.StatusOK {
		t.Errorf("row = %+v, want 403 anonymous → 200 with session", report.Paths[0])
	}

	if len(report.Findings) != 1 {
		t.Fatalf("findings = %+v, want exactly the lift", report.Findings)
	}
	f := report.Findings[0]
	if got := types.GradeOf(f); got != types.GradeProven {
		t.Errorf("grade = %q, want %q: the control and the experiment differ by the presenting principal alone", got, types.GradeProven)
	}
	if f.Prov.PathOrigin != types.PathObserved {
		t.Errorf("path_origin = %q, want %q: the caller named this path, the wordlist did not", f.Prov.PathOrigin, types.PathObserved)
	}
	if f.Prov.RequestMethod != "GET" || f.Prov.RequestURL != srv.URL+"/api/internal/metrics" {
		t.Errorf("provenance does not say which exchange earned it: %+v", f.Prov)
	}
	if !strings.Contains(f.Prov.BaselineRef, "403") {
		t.Errorf("baseline_ref = %q, want the anonymous control recorded", f.Prov.BaselineRef)
	}

	// The session value is a credential. The report describes it; it never
	// carries it.
	blob, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(blob), "hunter2") {
		t.Errorf("the report leaks the session value: %s", blob)
	}
	if report.Session != "sid=… (13 chars)" {
		t.Errorf("session = %q, want the name kept and the value reduced to its length", report.Session)
	}
}

// With no paths the check runs the tool's own wordlist, and the findings must
// say so: a conclusion about a path the tool invented is a different claim from
// one about a path the target advertised.
func TestVerifyAccessMarksWordlistPathsAsSynthesized(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(gated(&hits, "sid", "/admin", "<html><body><h1>admin panel</h1><table>user list</table></body></html>"))
	defer srv.Close()

	svc, err := New(Options{Config: types.DefaultConfig(), Scope: []string{srv.URL}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = svc.Close() }()

	report, err := svc.VerifyAccess(context.Background(), srv.URL, Session{Cookie: "sid=x"})
	if err != nil {
		t.Fatalf("VerifyAccess: %v", err)
	}
	if len(report.Paths) != len(exploit.CommonAdminPaths)-2 {
		t.Fatalf("paths = %d, want the wordlist minus the two login surfaces it refuses to compare", len(report.Paths))
	}
	var lift *types.Finding
	for i := range report.Findings {
		if strings.Contains(report.Findings[i].Name, "/admin") {
			lift = &report.Findings[i]
		}
	}
	if lift == nil {
		t.Fatalf("findings = %+v, want the /admin lift", report.Findings)
	}
	if lift.Prov.PathOrigin != types.PathSynthesized {
		t.Errorf("path_origin = %q, want %q for a wordlist path", lift.Prov.PathOrigin, types.PathSynthesized)
	}
}

// The other identity source: a credential, proven through a login the target
// publishes. The password must survive the round trip nowhere in the report.
func TestVerifyAccessThroughALoginKeepsThePasswordOut(t *testing.T) {
	const (
		user  = "operator"
		pass  = "Planted-P4ssw0rd-Never-Reported"
		field = "pass"
	)
	var hits int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if r.Method == http.MethodPost && r.URL.Path == "/login" {
			raw, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
			vals, _ := url.ParseQuery(string(raw))
			if vals.Get("user") == user && vals.Get(field) == pass {
				w.Header().Set("Set-Cookie", "sid=REAL-SESSION")
				_, _ = w.Write([]byte(`<h1>signed in</h1>`))
				return
			}
			_, _ = w.Write([]byte(`Invalid username or password`))
			return
		}
		if r.URL.Path == "/api/internal/metrics" {
			if _, err := r.Cookie("sid"); err == nil {
				_, _ = w.Write([]byte(`requests_total 42`))
				return
			}
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`forbidden`))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><form action="/login" method="post">` +
			`<input name="user"><input type="password" name="pass"></form></html>`))
	}))
	defer srv.Close()

	svc, err := New(Options{Config: types.DefaultConfig(), Scope: []string{srv.URL}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = svc.Close() }()

	report, err := svc.VerifyAccess(context.Background(), srv.URL,
		Session{Credential: &exploit.Credential{User: user, Pass: pass}}, "/api/internal/metrics")
	if err != nil {
		t.Fatalf("VerifyAccess: %v", err)
	}
	if !strings.Contains(report.Identity, user) {
		t.Errorf("identity = %q, want the login recorded as the session source", report.Identity)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("findings = %+v, want the metrics lift", report.Findings)
	}

	blob, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(blob), pass) {
		t.Errorf("the report carries the password: %s", blob)
	}
	if strings.Contains(string(blob), "REAL-SESSION") {
		t.Errorf("the report carries the harvested session value: %s", blob)
	}
}
