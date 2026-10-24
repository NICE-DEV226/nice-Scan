package engine

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/NICE-DEV226/nice-Scan/internal/detect"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// XSSAnalyzer renders XSS opinions only for responses to this scan's own
// canary-tagged probes. The previous keyword matcher flagged every page
// containing <script>, <div> or <img> — that is, every modern web page —
// producing confidence scores instead of evidence. A finding now requires
// the scan-canary to round-trip through the wire, and the verdict follows
// the classification (executable markup / escaped / neutralized / script
// context), never single-word matching.
type XSSAnalyzer struct {
	canary string
}

// NewXSSAnalyzer builds the analyzer against the scan's canary so probe
// responses are recognizable. An empty canary self-generates one — that
// mode can only label items it has no probes for, which is honest noise.
func NewXSSAnalyzer(canary string) *XSSAnalyzer {
	if canary == "" {
		canary = detect.NewCanary()
	}
	return &XSSAnalyzer{canary: canary}
}

func (a *XSSAnalyzer) Name() string {
	return "xss"
}

func (a *XSSAnalyzer) Analyze(ctx context.Context, resp *types.Response) []types.Finding {
	if resp == nil || len(resp.Body) == 0 || a.canary == "" {
		return nil
	}

	ct := strings.ToLower(resp.ContentType)
	if ct != "" && !strings.Contains(ct, "text") &&
		!strings.Contains(ct, "html") && !strings.Contains(ct, "json") &&
		!strings.Contains(ct, "xml") {
		return nil
	}

	// Only responses to this scan's probes carry the opinion; pages
	// fetched for other reasons stay silent.
	if !strings.Contains(resp.RequestURL, a.canary) {
		return nil
	}

	rx, reflected := detect.ClassifyXss(resp.Body, a.canary)
	if !reflected {
		return nil
	}

	param := probeParam(resp.RequestURL, a.canary)
	base := types.Finding{
		Type: types.FindingMisconfig,
		Metadata: map[string]string{
			"param":  param,
			"method": "canary-reflection-differential",
		},
	}
	if rx.Snippet != "" {
		base.Evidence = rx.Snippet
	}

	switch {
	case rx.Executable:
		f := base
		f.Name = "XSS Reflection (executable markup)"
		f.Severity = types.SeverityHigh
		f.Confidence = 0.85
		f.Description = fmt.Sprintf(
			"Probed parameter %q echoed the scan canary with raw executable markup (<svg onload>), outside markup-neutralizing containers; random canary proves reflection of our input", param)
		return []types.Finding{f}
	case rx.InScript:
		f := base
		f.Name = "XSS Reflection (script context)"
		f.Severity = types.SeverityMedium
		f.Confidence = 0.6
		f.Description = fmt.Sprintf(
			"Probed parameter %q landed inside a <script> block; JS-context injection depends on surrounding code, classified reflexively", param)
		return []types.Finding{f}
	case rx.Encoded:
		f := base
		f.Name = "XSS Reflection (escaped)"
		f.Severity = types.SeverityLow
		f.Confidence = 0.45
		f.Description = fmt.Sprintf(
			"Probed parameter %q reflects input but HTML-entity encodes the markup neighbors; payload does not execute as reflected", param)
		return []types.Finding{f}
	case rx.Neutralized:
		f := base
		f.Name = "XSS Reflection (neutralized container)"
		f.Severity = types.SeverityInfo
		f.Confidence = 0.35
		f.Description = fmt.Sprintf(
			"Probed parameter %q echoes raw markup inside a comment/textarea/title — browsers do not parse it there", param)
		return []types.Finding{f}
	default:
		// Raw text echo with no dangerous markup and no encoding — a
		// reflection point, not an XSS claim.
		f := base
		f.Name = "XSS Reflection (plain echo)"
		f.Severity = types.SeverityInfo
		f.Confidence = 0.35
		f.Description = fmt.Sprintf(
			"Probed parameter %q echoes raw input without markup; reflection point documented", param)
		return []types.Finding{f}
	}
}

// probeParam extracts the reflected parameter name from the probe URL.
func probeParam(rawURL, canary string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	for k, vals := range u.Query() {
		for _, v := range vals {
			if strings.Contains(v, canary) {
				return k
			}
		}
	}
	return ""
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
