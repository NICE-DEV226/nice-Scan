package engine

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

var (
	rxXSSReflected = regexp.MustCompile(`(?i)<script>alert\(1\)<\/script>`)

	xssPatterns = []struct {
		name    string
		pattern *regexp.Regexp
		context string
	}{
		{`<script>`, regexp.MustCompile(`(?i)<script[\s>]`), "html"},
		{`onerror`, regexp.MustCompile(`(?i)onerror\s*=`), "event"},
		{`onload`, regexp.MustCompile(`(?i)onload\s*=`), "event"},
		{`javascript:`, regexp.MustCompile(`(?i)javascript:`), "uri"},
		{`alert()`, regexp.MustCompile(`alert\s*\(`), "js"},
		{`prompt()`, regexp.MustCompile(`prompt\s*\(`), "js"},
		{`confirm()`, regexp.MustCompile(`confirm\s*\(`), "js"},
		{`eval()`, regexp.MustCompile(`eval\s*\(`), "js"},
		{`<img`, regexp.MustCompile(`(?i)<img[\s>]`), "html"},
		{`<svg`, regexp.MustCompile(`(?i)<svg[\s/>]`), "html"},
		{`<iframe`, regexp.MustCompile(`(?i)<iframe[\s>]`), "html"},
		{`<body`, regexp.MustCompile(`(?i)<body[\s>]`), "html"},
		{`<input`, regexp.MustCompile(`(?i)<input[\s>]`), "html"},
		{`<link`, regexp.MustCompile(`(?i)<link[\s>]`), "html"},
		{`<table`, regexp.MustCompile(`(?i)<table[\s>]`), "html"},
		{`<div`, regexp.MustCompile(`(?i)<div[\s>]`), "html"},
		{`<math`, regexp.MustCompile(`(?i)<math[\s>]`), "html"},
		{`<details`, regexp.MustCompile(`(?i)<details[\s>]`), "html"},
		{`srcdoc`, regexp.MustCompile(`srcdoc\s*=`), "attr"},
		{`data:`, regexp.MustCompile(`data:\s*text\/html`), "uri"},
	}
)

type XSSAnalyzer struct{}

func NewXSSAnalyzer() *XSSAnalyzer {
	return &XSSAnalyzer{}
}

func (a *XSSAnalyzer) Name() string {
	return "xss"
}

func (a *XSSAnalyzer) Analyze(ctx context.Context, resp *types.Response) []types.Finding {
	if resp == nil || len(resp.Body) == 0 {
		return nil
	}

	var findings []types.Finding
	body := string(resp.Body)

	if resp.ContentType != "" && !strings.Contains(resp.ContentType, "html") {
		return nil
	}

	for _, p := range xssPatterns {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		if p.pattern.MatchString(body) {
			name := fmt.Sprintf("Potential XSS Vector: %s", p.name)
			desc := fmt.Sprintf("Cross-Site Scripting indicator detected in HTML response body — context: %s", p.context)

			finding := types.Finding{
				Type:        types.FindingMisconfig,
				Name:        name,
				Severity:    types.SeverityHigh,
				Description: desc,
				Confidence:  0.6,
				Metadata: map[string]string{
					"context":    p.context,
					"pattern":    p.pattern.String(),
					"content-type": resp.ContentType,
				},
			}

			if p.name == `<script>` {
				finding.Severity = types.SeverityCritical
				finding.Confidence = 0.75
				finding.Evidence = fmt.Sprintf("Script tag found: %s", extractSnippet(body, p.pattern.String(), 60))
			}

			if p.name == `onerror` || p.name == `onload` {
				finding.Severity = types.SeverityHigh
				finding.Confidence = 0.7
				finding.Evidence = fmt.Sprintf("Event handler found: %s", extractSnippet(body, p.pattern.String(), 60))
			}

			if p.name == `<img` {
				finding.Confidence = 0.55
			}

			findings = append(findings, finding)
		}
	}

	return findings
}

func extractSnippet(body, pattern string, width int) string {
	re := regexp.MustCompile(pattern)
	loc := re.FindStringIndex(body)
	if loc == nil {
		return ""
	}
	start := loc[0] - width/2
	if start < 0 {
		start = 0
	}
	end := loc[1] + width/2
	if end > len(body) {
		end = len(body)
	}
	snippet := body[start:end]
	return strings.ReplaceAll(snippet, "\n", " ")
}
