package engine

import (
	"context"
	"testing"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// role="img" is ARIA accessibility markup, not a leaked privilege; a genuine
// admin/owner/is_admin=true disclosure is. The role indicator must fire only
// on the latter.
func TestAuthRoleIndicatorIgnoresARIARequiresPrivilege(t *testing.T) {
	a := NewAuthAnalyzer()

	fs := a.Analyze(context.Background(), respWithBody(
		`<figure class="session" role="img" aria-label="chart"></figure>`+
			`<span role="presentation">decorative</span>`))
	for _, f := range fs {
		if f.Name == "Privilege/Role Information Exposed" {
			t.Errorf("ARIA role attribute is not a privilege leak: %+v", f)
		}
	}

	fs2 := a.Analyze(context.Background(), respWithBody(
		`{"user":"bob","role":"administrator","is_admin":true}`))
	var found bool
	for _, f := range fs2 {
		if f.Name == "Privilege/Role Information Exposed" {
			found = true
		}
	}
	if !found {
		t.Errorf("a real admin-role binding should raise the privilege finding: %+v", fs2)
	}
}

func respAt(rawURL, body string) *types.Response {
	return &types.Response{
		StatusCode: 200,
		Body:       []byte(body),
		FinalURL:   rawURL,
		RequestURL: rawURL,
	}
}

// Returns the admin-surface finding (keyword or URL) if one was raised.
func adminFinding(fs []types.Finding) *types.Finding {
	for i := range fs {
		n := fs[i].Name
		if n == "Admin Panel Keyword in Content (unverified)" || n == "Possible Admin Surface in URL (unverified)" {
			return &fs[i]
		}
	}
	return nil
}

const loginFormHTML = `<form method="post" action="/login"><input name="user"><input type="password" name="p"></form>`

// A keyword is not a panel: bare admin/manager prose must be INFO, not Medium.
func TestAdminKeywordIsInfoNotMedium(t *testing.T) {
	a := NewAuthAnalyzer()

	fs := a.Analyze(context.Background(), respAt(
		"https://example.com/pricing",
		`Our channel manager and dashboard make admins`))
	f := adminFinding(fs)
	if f == nil {
		t.Fatal("keyword prose should still raise the unverified admin note")
	}
	if f.Severity != types.SeverityInfo {
		t.Errorf("unverified keyword admin hit must be Info, got %v", f.Severity)
	}
}

// A URL path that itself names an admin endpoint is a stronger signal → Low.
func TestAdminURLPathIsLow(t *testing.T) {
	a := NewAuthAnalyzer()

	fs := a.Analyze(context.Background(), respAt(
		"https://example.com/admin/settings", "Welcome back"))
	f := adminFinding(fs)
	if f == nil {
		t.Fatal("an /admin path should raise the URL admin note")
	}
	if f.Name != "Possible Admin Surface in URL (unverified)" || f.Severity != types.SeverityLow {
		t.Errorf("admin path wants the URL variant at Low, got name=%q sev=%v", f.Name, f.Severity)
	}
}

// Dedupe: when a real login form is detected here, the weaker keyword admin
// signal must not stack a second finding on the same page.
func TestLoginFormSuppressesKeywordAdminFinding(t *testing.T) {
	a := NewAuthAnalyzer()

	fs := a.Analyze(context.Background(), respAt(
		"https://example.com/admin/login",
		`Admin dashboard `+loginFormHTML))

	var sawLogin bool
	for _, f := range fs {
		if f.Name == "Login Form Detected" {
			sawLogin = true
		}
	}
	if !sawLogin {
		t.Fatal("the login form should be reported")
	}
	if f := adminFinding(fs); f != nil {
		t.Errorf("keyword/URL admin note must be suppressed when a real login form proves the surface: %+v", *f)
	}
}
