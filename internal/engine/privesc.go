package engine

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/nice-scan/nice_scan/internal/types"
)

var (
	rxIDOR       = regexp.MustCompile(`(?i)(id|user_id|account_id|uid|pid|order_id|profile_id|item_id)=(\d+)`)
	rxIDORUUID   = regexp.MustCompile(`(?i)(id|user_id|uid|token)=([a-f0-9\-]{32,})`)
	rxRoleMod    = regexp.MustCompile(`(?i)(role|user_type|account_type|access|level|priv|permission)=(\w+)`)
	rxStatusMod  = regexp.MustCompile(`(?i)(status|state|active|enabled|verified)=(0|1|true|false|yes|no)`)

	rxUserProfile = regexp.MustCompile(`(?i)(/profile/|/user/|/account/|/users/|/members/)(\d+)`)

	rxAPITokenInURL = regexp.MustCompile(`(?i)(token|api_key|apikey|secret|jwt)=([A-Za-z0-9\-_.]+)`)

	commonRoles = []string{"admin", "root", "superuser", "administrator", "moderator", "editor", "manager", "owner", "super_admin", "pro", "premium", "vip"}
)

type PrivilegeEscalationAnalyzer struct{}

func NewPrivilegeEscalationAnalyzer() *PrivilegeEscalationAnalyzer {
	return &PrivilegeEscalationAnalyzer{}
}

func (a *PrivilegeEscalationAnalyzer) Name() string {
	return "privesc"
}

func (a *PrivilegeEscalationAnalyzer) Analyze(ctx context.Context, resp *types.Response) []types.Finding {
	if resp == nil {
		return nil
	}

	var findings []types.Finding
	url := resp.FinalURL
	body := string(resp.Body)

	if m := rxIDOR.FindStringSubmatch(url); len(m) > 2 {
		param := m[1]
		val := m[2]
		findings = append(findings, types.Finding{
			Type:        types.FindingMisconfig,
			Name:        fmt.Sprintf("Potential IDOR — Numeric %s", param),
			Severity:    types.SeverityMedium,
			Description: fmt.Sprintf("Numeric identifier found in URL parameter '%s' — increment/decrement to test for Insecure Direct Object Reference", param),
			Evidence:    fmt.Sprintf("URL: %s", url),
			Confidence:  0.6,
			Metadata: map[string]string{
				"parameter": param,
				"value":     val,
				"type":      "numeric_idor",
			},
		})
	}

	if m := rxUserProfile.FindStringSubmatch(url); len(m) > 2 {
		findings = append(findings, types.Finding{
			Type:        types.FindingMisconfig,
			Name:        "User Profile with Numeric ID",
			Severity:    types.SeverityHigh,
			Description: fmt.Sprintf("User profile endpoint uses sequential numeric ID: %s — test by modifying ID to access other users' profiles", m[2]),
			Evidence:    fmt.Sprintf("URL: %s", url),
			Confidence:  0.75,
			Metadata: map[string]string{
				"endpoint": m[1],
				"id":       m[2],
			},
		})
	}

	if m := rxRoleMod.FindStringSubmatch(url); len(m) > 2 {
		findings = append(findings, types.Finding{
			Type:        types.FindingMisconfig,
			Name:        "Role/Privilege Parameter in URL",
			Severity:    types.SeverityCritical,
			Description: fmt.Sprintf("Role or privilege parameter '%s' found in URL with value '%s' — try modifying to escalate privileges", m[1], m[2]),
			Evidence:    fmt.Sprintf("URL: %s", url),
			Confidence:  0.8,
			Metadata: map[string]string{
				"parameter": m[1],
				"value":     m[2],
			},
		})
	}

	if m := rxStatusMod.FindStringSubmatch(url); len(m) > 2 {
		findings = append(findings, types.Finding{
			Type:        types.FindingMisconfig,
			Name:        fmt.Sprintf("Status/State Parameter in URL — %s", m[1]),
			Severity:    types.SeverityHigh,
			Description: fmt.Sprintf("Status parameter '%s' in URL (value: %s) — may allow bypassing email verification, account suspension, etc.", m[1], m[2]),
			Evidence:    fmt.Sprintf("URL: %s", url),
			Confidence:  0.7,
		})
	}

	if m := rxAPITokenInURL.FindStringSubmatch(url); len(m) > 2 {
		findings = append(findings, types.Finding{
			Type:        types.FindingSecret,
			Name:        fmt.Sprintf("Token in URL Query String — %s", m[1]),
			Severity:    types.SeverityCritical,
			Description: "Authentication token transmitted in URL query string — leaked via Referer header, browser history, server logs",
			Evidence:    fmt.Sprintf("Parameter: %s | Value: %s", m[1], truncate(m[2], 20)),
			Confidence:  0.9,
		})
	}

	for _, role := range commonRoles {
		pattern := fmt.Sprintf(`(?i)(role["']?\s*[:=]\s*["'])%s(["'])`, regexp.QuoteMeta(role))
		re := regexp.MustCompile(pattern)
		if m := re.FindStringSubmatch(body); len(m) > 0 {
			findings = append(findings, types.Finding{
				Type:        types.FindingMisconfig,
				Name:        fmt.Sprintf("Privileged Role Found in Response: %s", role),
				Severity:    types.SeverityHigh,
				Description: fmt.Sprintf("Response contains '%s' role assignment — check if privilege escalation is possible via role modification", role),
				Evidence:    extractSnippet(body, pattern, 60),
				Confidence:  0.7,
				Metadata: map[string]string{
					"role": role,
					"pattern": pattern,
				},
			})
		}
	}

	if strings.Contains(body, "admin") || strings.Contains(body, "administrator") {
		findings = append(findings, types.Finding{
			Type:        types.FindingMisconfig,
			Name:        "Admin Reference in Response",
			Severity:    types.SeverityInfo,
			Description: "Response body references 'admin' — may indicate admin functionality is accessible or referenced client-side",
			Evidence:    extractSnippet(body, `(?i)(admin|administrator)`, 60),
			Confidence:  0.5,
		})
	}

	return findings
}
