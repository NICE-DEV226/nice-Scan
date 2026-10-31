package hacker

import (
	"bytes"
	"context"
	"crypto/sha256"
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

// fuzzBaseline is the control response a target gives to a path that does
// not exist. Without it every catch-all SPA answers 200 with the same
// index.html for all 50 fuzz paths and the report claims 50 "hidden
// endpoints". Captured once per run.
type fuzzBaseline struct {
	status      int
	length      int
	contentType string
	hash        [32]byte
}

func captureBaseline(ctx context.Context, client *transport.Client, probeURL string) *fuzzBaseline {
	resp, err := client.Do(ctx, &types.Request{Method: "GET", URL: probeURL})
	if err != nil || resp == nil {
		return nil
	}
	return &fuzzBaseline{
		status:      resp.StatusCode,
		length:      len(resp.Body),
		contentType: resp.ContentType,
		hash:        sha256.Sum256(resp.Body),
	}
}

// matches reports whether resp looks like the not-found control. A target
// whose control really is 404/410 has standard not-found semantics, so
// nothing is suppressed for it: only "200 for everything" masks findings.
func (b *fuzzBaseline) matches(resp *types.Response) bool {
	if b == nil || resp == nil {
		return false
	}
	if b.status == 404 || b.status == 410 {
		return false
	}
	if resp.StatusCode != b.status || resp.ContentType != b.contentType {
		return false
	}
	if sha256.Sum256(resp.Body) == b.hash {
		return true
	}
	return nearlySameLength(len(resp.Body), b.length)
}

func nearlySameLength(a, b int) bool {
	if b == 0 {
		return a == 0
	}
	d := a - b
	if d < 0 {
		d = -d
	}
	return float64(d)/float64(b) <= 0.02
}

// changedMaterially reports whether a response differs in size or status
// from the control page. A parameter the server ignores (python -m
// http.server, most static hosts) returns the byte-identical page; that is
// not "the endpoint accepts the parameter".
func changedMaterially(resp *types.Response, ref *fuzzBaseline) bool {
	if ref == nil || resp == nil {
		return true
	}
	if resp.StatusCode != ref.status {
		return true
	}
	d := len(resp.Body) - ref.length
	if d < 0 {
		d = -d
	}
	return d > ref.length/50 && d > 32
}

// isDirectoryListing recognises the server-generated index page. A listing
// is a configuration-hygiene finding, not a discovered application
// endpoint: it was being reported HIGH because its path was 200.
func isDirectoryListing(body []byte) bool {
	head := body
	if len(head) > 64*1024 {
		head = head[:64*1024]
	}
	low := bytes.ToLower(head)
	return bytes.Contains(low, []byte("<title>index of /")) ||
		bytes.Contains(low, []byte("directory listing for")) ||
		bytes.Contains(low, []byte("[to parent directory]"))
}

func (a *FuzzAction) Execute(ctx context.Context, target string, kb *Knowledge, client *transport.Client) ActionResult {
	baseURL := strings.TrimRight(target, "/")
	var findings []Finding

	// One control request: what does this target answer for a path that
	// cannot exist? A random suffix keeps it out of any real route.
	control := captureBaseline(ctx, client, baseURL+"/nice-scan-not-found-8f3a2c1b.html")
	// The unparameterised page is the control for parameter probing.
	home := captureBaseline(ctx, client, baseURL)

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

		if control.matches(resp) {
			// The target answers this path exactly like a non-existent
			// one: there is no endpoint to report.
			continue
		}

		if isInterestingPath(resp) {
			ep := Endpoint{
				Path:        path,
				Method:      "GET",
				Status:      resp.StatusCode,
				BodyLen:     len(resp.Body),
				ContentType: resp.ContentType,
			}
			kb.AddEndpoint(ep)

			if isDirectoryListing(resp.Body) {
				findings = append(findings, Finding{
					Type:        "directory_listing",
					Name:        fmt.Sprintf("Directory listing enabled: %s", path),
					Severity:    SevLow,
					Description: fmt.Sprintf("The server renders an index of %s instead of returning 404 — file names are enumerable, but this is a hygiene issue, not a hidden application endpoint", path),
					Evidence:    u,
				})
				continue
			}

			sev, detail := classifyPathSeverity(path, resp)

			findings = append(findings, Finding{
				Type:        "endpoint",
				Name:        fmt.Sprintf("Endpoint: %s (%d)", path, resp.StatusCode),
				Severity:    sev,
				Description: fmt.Sprintf("Discovered %s returns %d (%d bytes%s)", path, resp.StatusCode, len(resp.Body), detail),
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

			if resp.StatusCode == 200 && len(resp.Body) > 50 &&
				changedMaterially(resp, home) && !home.matches(resp) {
				findings = append(findings, Finding{
					Type:        "parameter",
					Name:        fmt.Sprintf("Parameter changes the response: %s", param),
					Severity:    SevLow,
					Description: fmt.Sprintf("Adding %s changes the response size or status versus the unparameterised page — the value reaches application logic", param),
					Evidence:    paramURL,
				})
			}
		}
	}

	return ActionResult{Findings: findings}
}

func isInterestingPath(resp *types.Response) bool {
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

// classifyPathSeverity grades a discovered path on what the response
// actually shows, not on the path's name alone. A 200 on /health or /static
// is a reachable resource, not a vulnerability; a sensitive path only earns
// High when the body contains the artifact's own signature.
func classifyPathSeverity(path string, resp *types.Response) (Severity, string) {
	lowBody := strings.ToLower(path)
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		// Authentication is doing its job: the path exists, nothing was
		// disclosed.
		if isSensitivePath(lowBody) {
			return SevMedium, ", access controlled"
		}
		return SevLow, ", access controlled"
	}
	if resp.StatusCode >= 500 {
		return SevMedium, ", server error (possible information disclosure)"
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return SevInfo, ""
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if isSensitivePath(lowBody) {
			if confirmsSensitivePath(lowBody, resp.Body) {
				return SevHigh, ", body contains the artifact's own signature"
			}
			return SevMedium, ", body does not confirm the artifact"
		}
		return SevLow, ""
	}
	return SevInfo, ""
}

func isSensitivePath(lowPath string) bool {
	sensitive := []string{
		".git", ".env", ".htaccess", "config", "backup",
		"admin", "dashboard", "console", "manage",
		"shell", "cmd", "exec", "phpinfo",
		"swagger", "graphql", "api",
	}
	for _, s := range sensitive {
		if strings.Contains(lowPath, s) {
			return true
		}
	}
	return false
}

// confirmsSensitivePath requires content the artifact itself would emit.
// A soft-404 page mentioning "admin" in its markup must not turn /admin
// into a High finding.
func confirmsSensitivePath(lowPath string, body []byte) bool {
	head := body
	if len(head) > 128*1024 {
		head = head[:128*1024]
	}
	low := bytes.ToLower(head)
	has := func(markers ...string) bool {
		for _, m := range markers {
			if bytes.Contains(low, []byte(m)) {
				return true
			}
		}
		return false
	}

	switch {
	case strings.Contains(lowPath, ".git"):
		return has("[core]", "ref: refs/", "repositoryformatversion")
	case strings.Contains(lowPath, ".env"):
		return has("=") && has("key", "secret", "password", "token", "db_")
	case strings.Contains(lowPath, ".htaccess"):
		return has("rewriteengine", "<files", "authuserfile", "order deny")
	case strings.Contains(lowPath, "phpinfo"):
		return has("php version", "phpinfo()")
	case strings.Contains(lowPath, "swagger") || strings.Contains(lowPath, "openapi"):
		return has("\"swagger\"", "\"openapi\"", "swagger-ui")
	case strings.Contains(lowPath, "graphql"):
		return has("\"errors\"", "\"data\"", "__schema")
	case strings.Contains(lowPath, "backup") || strings.Contains(lowPath, "config"):
		// Archives and config dumps have recognisable containers.
		return bytes.HasPrefix(body, []byte("PK\x03\x04")) || has("[core]", "<?php", "password", "secret")
	default:
		// admin/dashboard/console/manage/shell/cmd: a real console behind
		// auth shows a credential field or a signed-in control. Prose
		// mentioning "sign in" is what any page says before login, so it
		// cannot upgrade the finding to High.
		return has("type=\"password\"", "type=password", "type='password'", "logout", "log out", "sign out", "admin panel", "dashboard")
	}
}
