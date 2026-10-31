package engine

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// ExposureAnalyzer reports a file as exposed only when the response body
// proves it. A status code and a size are not proof: any SPA or catch-all
// handler answers 200 with a few kilobytes of HTML for every unknown path,
// and the previous patterns turned that into "Exposed Backup File — High"
// and "Exposed .gitignore — Medium" on ordinary modern sites.
//
// The rule enforced here (and covered by TestExposurePatternsRequireProof):
// every built-in pattern must carry either a byte-level prefix (MagicPrefix)
// or a content regex (BodyPattern) that a generic error page cannot satisfy.
// Paths that could not be proven are gone — .gitignore among them, since an
// exposed .gitignore reveals nothing that /.git/config does not prove.
type ExposureAnalyzer struct {
	patterns []ExposurePattern
}

type ExposurePattern struct {
	Name        string
	Severity    types.Severity
	Description string
	Path        string
	StatusCodes []int
	// BodyPattern entries must ALL match the body.
	BodyPattern []*regexp.Regexp
	// MagicPrefix must be the first bytes of the body (file format proof).
	MagicPrefix []byte
	// NoHTML rejects bodies that are an HTML document, i.e. a soft-404 or a
	// catch-all page answering the probe instead of the requested file.
	NoHTML  bool
	MinSize int
}

// zipLocalHeader is the magic number of a ZIP archive (PK\x03\x04): an HTML
// error page can never start with it.
var zipLocalHeader = []byte{'P', 'K', 0x03, 0x04}

func NewExposureAnalyzer() *ExposureAnalyzer {
	return &ExposureAnalyzer{
		patterns: []ExposurePattern{
			{
				Name:        "Exposed .env File",
				Severity:    types.SeverityCritical,
				Description: ".env file is publicly accessible, potentially exposing secrets and API keys",
				Path:        "/.env",
				StatusCodes: []int{200},
				BodyPattern: []*regexp.Regexp{
					// A real dotenv assignment line: KEY=value, own line.
					regexp.MustCompile(`(?m)^[A-Za-z_][A-Za-z0-9_.]*[ \t]*=[ \t]*\S`),
					// ...whose key carries secret material. A page that merely
					// contains "=" no longer qualifies.
					regexp.MustCompile(`(?i)(DB_|DATABASE_|APP_|API_|SECRET|PASSWORD|PASSWD|TOKEN|_KEY|ACCESS_KEY|PRIVATE_KEY|AWS_|REDIS_|SMTP_|MAIL_)`),
				},
				NoHTML:  true,
				MinSize: 10,
			},
			{
				Name:        "Exposed .git Directory",
				Severity:    types.SeverityCritical,
				Description: ".git directory is publicly accessible, source code and history may be exposed",
				Path:        "/.git/config",
				StatusCodes: []int{200},
				BodyPattern: []*regexp.Regexp{
					regexp.MustCompile(`(?i)\[core\]`),
					regexp.MustCompile(`(?i)repositoryformatversion`),
				},
				NoHTML:  true,
				MinSize: 10,
			},
			{
				Name:        "Exposed Source Map",
				Severity:    types.SeverityHigh,
				Description: "Source map file is accessible, exposing application source code",
				Path:        "/static/js/main.js.map",
				StatusCodes: []int{200},
				BodyPattern: []*regexp.Regexp{
					regexp.MustCompile(`"version"`),
					regexp.MustCompile(`"sources"`),
				},
				NoHTML:  true,
				MinSize: 100,
			},
			{
				Name:        "Directory Listing Enabled",
				Severity:    types.SeverityMedium,
				Description: "Directory listing is enabled on the server",
				Path:        "/",
				StatusCodes: []int{200},
				BodyPattern: []*regexp.Regexp{
					regexp.MustCompile(`<title>Index of /`),
					regexp.MustCompile(`Parent Directory`),
				},
			},
			{
				Name:        "Exposed robots.txt",
				Severity:    types.SeverityInfo,
				Description: "robots.txt is accessible, may reveal hidden paths",
				Path:        "/robots.txt",
				StatusCodes: []int{200},
				BodyPattern: []*regexp.Regexp{
					regexp.MustCompile(`(?i)Disallow:`),
				},
			},
			{
				Name:        "Sitemap.xml Accessible",
				Severity:    types.SeverityInfo,
				Description: "sitemap.xml is accessible, may reveal all site URLs",
				Path:        "/sitemap.xml",
				StatusCodes: []int{200},
				BodyPattern: []*regexp.Regexp{
					regexp.MustCompile(`<urlset|<sitemapindex`),
				},
			},
			{
				Name:        "Exposed Backup File",
				Severity:    types.SeverityHigh,
				Description: "Backup file is publicly accessible",
				Path:        "/backup.zip",
				StatusCodes: []int{200},
				// Proof is the file format itself: the body must begin with
				// the ZIP local-file signature, so a 200 HTML page is never
				// reported as a backup.
				MagicPrefix: zipLocalHeader,
				NoHTML:      true,
				MinSize:     len(zipLocalHeader),
			},
		},
	}
}

func (a *ExposureAnalyzer) Name() string {
	return "exposures"
}

func (a *ExposureAnalyzer) Analyze(ctx context.Context, resp *types.Response) []types.Finding {
	if resp == nil {
		return nil
	}

	path := requestPath(resp.RequestURL)
	if path == "" {
		return nil
	}

	size := resp.BodySize
	if size == 0 {
		size = int64(len(resp.Body))
	}
	bodyStr := string(resp.Body)

	var findings []types.Finding

	for _, pattern := range a.patterns {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		if !strings.HasSuffix(path, pattern.Path) {
			continue
		}

		if !a.matchesStatus(resp.StatusCode, pattern.StatusCodes) {
			continue
		}

		if pattern.MinSize > 0 && size < int64(pattern.MinSize) {
			continue
		}

		if !a.provesBody(pattern, resp.Body, bodyStr) {
			continue
		}

		findings = append(findings, types.Finding{
			Type:        types.FindingExposure,
			Name:        pattern.Name,
			Severity:    pattern.Severity,
			Description: pattern.Description,
			Evidence:    fmt.Sprintf("%s (%d bytes, status %d; %s)", resp.RequestURL, size, resp.StatusCode, proofText(pattern)),
			Confidence:  0.9,
			Metadata: map[string]string{
				"path":        pattern.Path,
				"url":         resp.RequestURL,
				"status":      fmt.Sprintf("%d", resp.StatusCode),
				"size":        fmt.Sprintf("%d", size),
				"verified_by": proofText(pattern),
			},
		})
	}

	return findings
}

// provesBody is the proof gate: shape, then file format, then content.
func (a *ExposureAnalyzer) provesBody(pattern ExposurePattern, body []byte, bodyStr string) bool {
	if pattern.NoHTML && looksLikeHTML(body) {
		return false
	}
	if len(pattern.MagicPrefix) > 0 && !bytes.HasPrefix(body, pattern.MagicPrefix) {
		return false
	}
	for _, p := range pattern.BodyPattern {
		if !p.MatchString(bodyStr) {
			return false
		}
	}
	return true
}

// proofText names the evidence that justified the finding, so the report
// carries the reason and not just the verdict.
func proofText(pattern ExposurePattern) string {
	if len(pattern.MagicPrefix) > 0 {
		return fmt.Sprintf("body starts with %q", pattern.MagicPrefix)
	}
	if len(pattern.BodyPattern) > 0 {
		return "body matched content signature, not an error page"
	}
	return "status matched"
}

// requestPath returns the URL path, ignoring query and fragment, so a probe
// answered with redirects or a query string still matches its own pattern.
func requestPath(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	if u, err := url.Parse(rawURL); err == nil && u.Path != "" {
		return u.Path
	}
	return rawURL
}

// looksLikeHTML reports whether the body is an HTML document. Used to reject
// soft-404 / catch-all pages that answer 200 for any path.
func looksLikeHTML(body []byte) bool {
	head := body
	if len(head) > 1024 {
		head = head[:1024]
	}
	s := strings.TrimPrefix(string(head), "\xef\xbb\xbf")
	s = strings.ToLower(strings.TrimLeft(s, " \t\r\n"))

	for _, marker := range []string{"<!doctype html", "<!doctype", "<html", "<head", "<body", "<meta"} {
		if strings.HasPrefix(s, marker) {
			return true
		}
	}
	return false
}

func (a *ExposureAnalyzer) matchesStatus(status int, expected []int) bool {
	if len(expected) == 0 {
		return true
	}
	for _, s := range expected {
		if s == status {
			return true
		}
	}
	return false
}

func (a *ExposureAnalyzer) LoadCustom(pattern ExposurePattern) {
	a.patterns = append(a.patterns, pattern)
}
