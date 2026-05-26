package engine

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/nice-scan/nice_scan/internal/types"
)

type ExposureAnalyzer struct {
	patterns []ExposurePattern
}

type ExposurePattern struct {
	Name        string
	Severity    types.Severity
	Description string
	Path        string
	StatusCodes []int
	BodyPattern []*regexp.Regexp
	MinSize     int
}

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
					regexp.MustCompile(`(?i)(DB_|APP_|API_|SECRET|PASSWORD|TOKEN|KEY)_`),
					regexp.MustCompile(`(?i)=`),
				},
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
				MinSize:     1000,
			},
			{
				Name:        "Exposed .gitignore",
				Severity:    types.SeverityMedium,
				Description: ".gitignore file is publicly accessible, may reveal project structure",
				Path:        "/.gitignore",
				StatusCodes: []int{200},
				MinSize:     5,
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

	var findings []types.Finding

	for _, pattern := range a.patterns {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		if !strings.HasSuffix(resp.RequestURL, pattern.Path) {
			continue
		}

		if !a.matchesStatus(resp.StatusCode, pattern.StatusCodes) {
			continue
		}

		if pattern.MinSize > 0 && resp.BodySize < int64(pattern.MinSize) {
			continue
		}

		if len(pattern.BodyPattern) > 0 {
			body := string(resp.Body)
			matched := true
			for _, p := range pattern.BodyPattern {
				if !p.MatchString(body) {
					matched = false
					break
				}
			}
			if !matched {
				continue
			}
		}

		findings = append(findings, types.Finding{
			Type:        types.FindingExposure,
			Name:        pattern.Name,
			Severity:    pattern.Severity,
			Description: pattern.Description,
			Evidence:    fmt.Sprintf("%s (%d bytes, status %d)", resp.RequestURL, resp.BodySize, resp.StatusCode),
			Confidence:  0.9,
			Metadata: map[string]string{
				"path":   pattern.Path,
				"url":    resp.RequestURL,
				"status": fmt.Sprintf("%d", resp.StatusCode),
				"size":   fmt.Sprintf("%d", resp.BodySize),
			},
		})
	}

	return findings
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
