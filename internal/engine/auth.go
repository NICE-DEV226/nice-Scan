package engine

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

var (
	rxLoginForm     = regexp.MustCompile(`(?i)<form[^>]*>.*?<input[^>]*type=["']?password["'\]].*?</form>`)
	rxPasswordField = regexp.MustCompile(`(?i)<input[^>]*type=["']?password["' ][^>]*>`)
	rxUsernameField = regexp.MustCompile(`(?i)<input[^>]*(?:name|id)["']?\s*=\s*["']?(?:user|email|login|username|log)["'][^>]*>`)
	rxLoginAction   = regexp.MustCompile(`(?i)<form[^>]*action=["']([^"']+)["']`)

	rxAdminPanel = regexp.MustCompile(`(?i)(admin|dashboard|panel|backend|cpanel|administrator|wp-admin|manager)`)

	rxRegisterForm = regexp.MustCompile(`(?i)<form[^>]*>.*?(?:register|signup|create-account).*?</form>`)

	rxForgotPassword = regexp.MustCompile(`(?i)(forgot|reset|recover|lost)\s*(password|pwd)`)

	rxUserEnumError = regexp.MustCompile(`(?i)(user|account|email|username).{0,20}(not found|doesn't exist|invalid|does not exist|incorrect|unknown)`)

	rxRoleIndicator = regexp.MustCompile(`(?i)(role|admin|moderator|editor|manager|superuser|privilege|permission|access_level)`)
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


	
	if rxAdminPanel.MatchString(url) || rxAdminPanel.MatchString(body) {
		findings = append(findings, types.Finding{
			Type:        types.FindingMisconfig,
			Name:        "Admin Panel Found",
			Severity:    types.SeverityHigh,
			Description: "Administrative panel or restricted area discovered",
			Evidence:    fmt.Sprintf("URL: %s", url),
			Confidence:  0.85,
		})
	}

	return findings
}
