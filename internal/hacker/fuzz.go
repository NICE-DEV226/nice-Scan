package hacker

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

type FuzzAction struct{}

func (a *FuzzAction) Metadata() ActionMetadata {
	return ActionMetadata{
		Name:        "Fuzzer",
		Description: "Directory + parameter fuzzing — find hidden endpoints",
		Priority:    20,
		Requires:    []string{"has_pages"},
		Provides:    []string{"has_api", "has_admin", "has_graphql", "has_upload", "has_s3"},
	}
}

var commonPaths = []string{
	"/admin", "/api", "/api/v1", "/api/v2", "/graphql",
	"/.git/config", "/.env", "/.htaccess", "/.well-known/security.txt",
	"/backup", "/config", "/dashboard", "/debug", "/health",
	"/info", "/internal", "/logs", "/metrics", "/monitor",
	"/phpinfo.php", "/robots.txt", "/sitemap.xml",
	"/static", "/status", "/swagger", "/swagger-resources",
	"/test", "/uploads", "/vendor", "/version",
	"/webhook", "/ws", "/wp-admin", "/wp-content",
	"/api/graphql", "/api/health", "/api/status",
	"/api/users", "/api/admin", "/api/docs",
	"/api/swagger.json", "/api/openapi.json",
	"/actuator", "/actuator/health",
	"/.git/HEAD", "/console", "/manage",
	"/shell", "/cmd", "/exec",
}

var commonParams = []string{
	"id", "user_id", "user", "uid", "username",
	"file", "path", "page", "role", "admin",
	"debug", "token", "api_key", "secret",
	"cmd", "command", "exec", "action",
}

func (a *FuzzAction) Execute(ctx context.Context, target string, kb *Knowledge, client *transport.Client) ActionResult {
	baseURL := strings.TrimRight(target, "/")
	var findings []Finding

	for _, path := range commonPaths {
		select {
		case <-ctx.Done():
			return ActionResult{Findings: findings}
		default:
		}

		u := baseURL + path
		if kb.IsChecked(u) {
			continue
		}
		kb.MarkChecked(u)

		resp, err := client.Do(ctx, &types.Request{
			Method: "GET",
			URL:    u,
		})
		if err != nil {
			continue
		}

		if isInterestingPath(resp, path) {
			ep := Endpoint{
				Path:        path,
				Method:      "GET",
				Status:      resp.StatusCode,
				BodyLen:     len(resp.Body),
				ContentType: resp.ContentType,
			}
			kb.AddEndpoint(ep)

			sev := classifyPathSeverity(path, resp.StatusCode)

			findings = append(findings, Finding{
				Type:        "endpoint",
				Name:        fmt.Sprintf("Endpoint: %s (%d)", path, resp.StatusCode),
				Severity:    sev,
				Description: fmt.Sprintf("Discovered %s returns %d (%d bytes)", path, resp.StatusCode, len(resp.Body)),
				Evidence:    u,
			})
		}
	}

	if len(findings) > 3 {
		findings = append(findings, Finding{
			Type:        "fuzz_complete",
			Name:        "Fuzzing complete — multiple endpoints discovered",
			Severity:    SevInfo,
			Description: fmt.Sprintf("Discovered %d hidden endpoints", len(findings)),
		})
	}

	u, _ := url.Parse(baseURL)
	if u != nil {
		for _, param := range commonParams {
			select {
			case <-ctx.Done():
				return ActionResult{Findings: findings}
			default:
			}

			q := u.Query()
			q.Set(param, "1")
			u.RawQuery = q.Encode()
			paramURL := u.String()
			u.RawQuery = ""

			resp, err := client.Do(ctx, &types.Request{
				Method: "GET",
				URL:    paramURL,
			})
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 && len(resp.Body) > 50 {
				findings = append(findings, Finding{
					Type:        "parameter",
					Name:        fmt.Sprintf("Parameter accepted: %s", param),
					Severity:    SevLow,
					Description: fmt.Sprintf("Endpoint accepts %s parameter", param),
					Evidence:    paramURL,
				})
			}
		}
	}

	return ActionResult{Findings: findings}
}

func isInterestingPath(resp *types.Response, path string) bool {
	if resp.StatusCode == 404 {
		return false
	}
	if resp.StatusCode >= 500 {
		return true
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if len(resp.Body) > 20 {
			return true
		}
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return true
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return true
	}
	if resp.ContentLength > 0 {
		return true
	}
	return false
}

func classifyPathSeverity(path string, status int) Severity {
	sensitive := []string{
		".git", ".env", ".htaccess", "config", "backup",
		"admin", "dashboard", "console", "manage",
		"shell", "cmd", "exec", "phpinfo",
		"swagger", "graphql", "api",
	}

	lowBody := strings.ToLower(path)

	if status == 200 || status == 201 {
		for _, s := range sensitive {
			if strings.Contains(lowBody, s) {
				return SevCritical
			}
		}
		return SevHigh
	}

	if status == 401 || status == 403 {
		for _, s := range sensitive {
			if strings.Contains(lowBody, s) {
				return SevHigh
			}
		}
		return SevMedium
	}

	if status >= 300 && status < 400 {
		return SevMedium
	}

	if status >= 500 {
		return SevHigh
	}

	return SevLow
}
