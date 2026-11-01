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

	var findings []types.Finding
	body := string(resp.Body)
	url := resp.FinalURL

	if rxLoginForm.MatchString(body) {
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

	// The old finding sold "Admin Panel Found" at HIGH confidence for any
	// page whose URL or body contained an admin keyword — a blog post about
	// admins qualified. A keyword is not a panel: demoted to a medium
	// unverified-surface notice; real panels surface through actions that
	// actually access them.
	if rxAdminPanel.MatchString(url) || rxAdminPanel.MatchString(body) {
		findings = append(findings, types.Finding{
			Type:        types.FindingMisconfig,
			Name:        "Possible Admin Panel (keyword match — unverified)",
			Severity:    types.SeverityMedium,
			Description: "The URL or page content contains admin-panel keywords. No access test was performed — verify manually whether an actual restricted panel exists",
			Evidence:    fmt.Sprintf("URL: %s", url),
			Confidence:  0.45,
		})
	}

	return findings
}
