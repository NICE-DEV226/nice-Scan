package engine

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

var (
	// (?s) so the lazy ".*?" between <form> and </form> crosses NEWLINES:
	// a real login/registration form is written across many lines, and
	// without the dotall flag this regex matched almost nothing in the wild
	// (it only caught single-line minified forms).
	rxLoginForm     = regexp.MustCompile(`(?is)<form[^>]*>.*?<input[^>]*type=["']?password["'\]].*?</form>`)
	rxPasswordField = regexp.MustCompile(`(?i)<input[^>]*type=["']?password["' ][^>]*>`)
	rxUsernameField = regexp.MustCompile(`(?i)<input[^>]*(?:name|id)["']?\s*=\s*["']?(?:user|email|login|username|log)["'][^>]*>`)
	rxLoginAction   = regexp.MustCompile(`(?i)<form[^>]*action=["']([^"']+)["']`)

	rxAdminPanel = regexp.MustCompile(`(?i)(admin|dashboard|panel|backend|cpanel|administrator|wp-admin|manager)`)

	// Strong admin surface in the URL PATH (not body prose). A path that names
	// an admin endpoint is a real, checkable surface worth a Low; a bare
	// "dashboard"/"panel"/"manager" word in the body is marketing copy and only
	// justifies Info.
	rxAdminPath = regexp.MustCompile(`(?i)/(?:admin|administrator|wp-admin|wp-login|cpanel|phpmyadmin|manager|backend|console)(?:[/?#]|$)`)

	rxRegisterForm = regexp.MustCompile(`(?is)<form[^>]*>.*?(?:register|signup|create-account|create account).*?</form>`)

	rxForgotPassword = regexp.MustCompile(`(?i)\b(?:forgot|reset|recover|lost)\b[\s\S]{0,20}?\b(?:password|pwd)\b`)

	rxUserEnumError = regexp.MustCompile(`(?i)(user|account|email|username).{0,20}(not found|doesn't exist|invalid|does not exist|incorrect|unknown)`)

	// A role is only LEAKED when a privilege KEY is bound to a PRIVILEGED
	// VALUE. Word boundaries + ":"/"=" alone still matched ARIA markup such as
	// role="img" (a plain page fired "Privilege Information Exposed" on an
	// image's accessibility role), and role="user" is not a secret. Require the
	// value to be a real authority token (admin/root/owner/…) or a boolean
	// grant (is_admin=true), so only a genuine privilege disclosure matches.
	rxRoleIndicator = regexp.MustCompile(`(?i)["'` + "`" + `]?(\b(?:role|access_level|permission|privilege|user_role|user_type|account_type|is_admin|is_superuser)\b)["'` + "`" + `]?\s*[:=]\s*["'` + "`" + `]?(?:admin(?:istrator)?|superuser|super_admin|root|owner|moderator|privileged|true|1)\b`)
)

type AuthAnalyzer struct{}

func NewAuthAnalyzer() *AuthAnalyzer {
	return &AuthAnalyzer{}
}

func (a *AuthAnalyzer) Name() string {
	return "auth"
}

func (a *AuthAnalyzer) Analyze(ctx context.Context, resp *types.Response) []types.Finding {
	if resp == nil || len(resp.Body) == 0 {
		return nil
	}
	// A probe that re-served the homepage shell (soft-404 / SPA catch-all) is
	// the same page already analyzed at the root, reached via a path WE
	// synthesized. Conclusions from its body keywords or from that path ("admin"
	// in /wp-admin, "dashboard" in the shared bundle) are false evidence, so
	// the whole auth pass is skipped; the honest read happened on the homepage.
	if resp.Soft404 {
		return nil
	}

	var findings []types.Finding
	body := string(resp.Body)
	url := resp.FinalURL

	loginFormFound := rxLoginForm.MatchString(body)

	if loginFormFound {
		action := ""
		if m := rxLoginAction.FindStringSubmatch(body); len(m) > 1 {
			action = m[1]
		}

		fields := []string{}
		if rxPasswordField.MatchString(body) {
			fields = append(fields, "password")
		}
		if rxUsernameField.MatchString(body) {
			fields = append(fields, "username/email")
		}

		findings = append(findings, types.Finding{
			Type:        types.FindingMisconfig,
			Name:        "Login Form Detected",
			Severity:    types.SeverityInfo,
			Description: fmt.Sprintf("Authentication form found at %s", url),
			Evidence:    fmt.Sprintf("Fields: %s | Action: %s", strings.Join(fields, ", "), action),
			Confidence:  0.95,
			Metadata: map[string]string{
				"fields": strings.Join(fields, ","),
				"action": action,
				"url":    url,
			},
		})

		if !strings.HasPrefix(url, "https") {
			findings = append(findings, types.Finding{
				Type:        types.FindingMisconfig,
				Name:        "Login Form Over HTTP",
				Severity:    types.SeverityCritical,
				Description: "Login form submitted over unencrypted HTTP — credentials sent in plaintext",
				Evidence:    fmt.Sprintf("Login at: %s", url),
				Confidence:  0.95,
			})
		}

		if action == "" || action == "#" {
			findings = append(findings, types.Finding{
				Type:        types.FindingMisconfig,
				Name:        "Login Form No Action URL",
				Severity:    types.SeverityLow,
				Description: "Login form has no action attribute — may submit to current page or vulnerable endpoint",
				Evidence:    "Form action empty or #",
				Confidence:  0.7,
			})
		}
	}

	if rxRegisterForm.MatchString(body) {
		findings = append(findings, types.Finding{
			Type:        types.FindingMisconfig,
			Name:        "Registration Form Detected",
			Severity:    types.SeverityInfo,
			Description: "User registration form found — potential attack surface for account creation abuse",
			Evidence:    fmt.Sprintf("URL: %s", url),
			Confidence:  0.85,
		})
	}

	if rxForgotPassword.MatchString(body) {
		findings = append(findings, types.Finding{
			Type:        types.FindingMisconfig,
			Name:        "Password Reset Functionality",
			Severity:    types.SeverityLow,
			Description: "Password reset form found — check for user enumeration via timing/error messages",
			Evidence:    fmt.Sprintf("URL: %s", url),
			Confidence:  0.8,
		})
	}

	if rxUserEnumError.MatchString(body) {
		findings = append(findings, types.Finding{
			Type:        types.FindingMisconfig,
			Name:        "User Enumeration Possible",
			Severity:    types.SeverityMedium,
			Description: "Error message reveals whether a user/email exists — allows username enumeration",
			Evidence:    fmt.Sprintf("Response contains distinguishing message: %s", extractSnippet(body, rxUserEnumError.String(), 60)),
			Confidence:  0.8,
		})
	}

	if rxRoleIndicator.MatchString(body) {
		findings = append(findings, types.Finding{
			Type:        types.FindingMisconfig,
			Name:        "Privilege/Role Information Exposed",
			Severity:    types.SeverityMedium,
			Description: "Response contains role or permission information — potential privilege escalation target",
			Evidence:    fmt.Sprintf("Found: %s", extractSnippet(body, rxRoleIndicator.String(), 60)),
			Confidence:  0.6,
		})
	}

	// A keyword is not a panel. Report the weakest form of evidence at the
	// lowest defensible level, and never alongside the concrete login-form
	// detection above — that already proves an authenticated surface at this
	// URL with real evidence. Admin prose that only names a management feature
	// ("dashboard", "channel manager") would otherwise stack a second, weaker
	// "admin" signal on the same page and inflate the count.
	if !loginFormFound {
		adminInPath := rxAdminPath.MatchString(url)
		if adminInPath || rxAdminPanel.MatchString(body) {
			severity := types.SeverityInfo
			name := "Admin Panel Keyword in Content (unverified)"
			desc := "The page text contains admin/panel keywords but no authenticated surface was detected here. No access test was performed — treat as a lead to verify, not a finding."
			confidence := 0.3
			if adminInPath {
				severity = types.SeverityLow
				name = "Possible Admin Surface in URL (unverified)"
				desc = "The URL path names an admin-style endpoint. Its accessibility was not tested — verify manually whether it is restricted or public."
				confidence = 0.4
			}
			findings = append(findings, types.Finding{
				Type:        types.FindingMisconfig,
				Name:        name,
				Severity:    severity,
				Description: desc,
				Evidence:    fmt.Sprintf("URL: %s", url),
				Confidence:  confidence,
			})
		}
	}

	return findings
}
