package engine

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/NICE-DEV226/nice-Scan/internal/detect"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// SQLiAnalyzer works on anchored, error-message-shaped signatures only
// (internal/detect). Product-name mentions, brand text or `&quot;` HTML
// entities never qualify. The verdict splits in two levels:
//
//   - a response to the scanner's own quote-break probe (a parameter
//     value of exactly `1'`) that carries an anchored DB error: the error
//     shape is attributable to our input — error-based injection surface;
//   - any other response carrying an anchored DB error: a backend
//     fingerprint disclosure, not an injection claim.
type SQLiAnalyzer struct{}

func NewSQLiAnalyzer() *SQLiAnalyzer {
	return &SQLiAnalyzer{}
}

func (a *SQLiAnalyzer) Name() string {
	return "sqli"
}

func (a *SQLiAnalyzer) Analyze(ctx context.Context, resp *types.Response) []types.Finding {
	if resp == nil || len(resp.Body) == 0 {
		return nil
	}
	select {
	case <-ctx.Done():
		return nil
	default:
	}

	body := string(resp.Body)
	db, idx, ok := detect.SQLErrorMatch(body)
	if !ok {
		return nil
	}

	meta := map[string]string{
		"database":    db,
		"request_url": resp.RequestURL,
	}

	if isOwnSQLiProbe(resp) {
		return []types.Finding{
			{
				Type:       types.FindingMisconfig,
				Name:       "SQL Error Surfacing (error-based surface)",
				Severity:   types.SeverityHigh,
				Confidence: 0.7,
				Description: fmt.Sprintf(
					"An anchored %s error message surfaced on the scanner's own quote-break probe — the error shape is attributable to our input", db),
				Evidence: fmt.Sprintf("DB %s: %s", db, centeredSnippet(body, idx, 100)),
				Metadata: meta,
			},
		}
	}

	return []types.Finding{
		{
			Type:       types.FindingMisconfig,
			Name:       fmt.Sprintf("Database Error Text in Response — %s", db),
			Severity:   types.SeverityMedium,
			Confidence: 0.55,
			Description: fmt.Sprintf(
				"An anchored %s error message is present on a response our probes did not trigger — backend fingerprint, not an injection claim", db),
			Evidence: fmt.Sprintf("DB %s: %s", db, centeredSnippet(body, idx, 100)),
			Metadata: meta,
		},
	}
}

// isOwnSQLiProbe decodes the request URL and recognizes the quote-break
// probe value (`1'`) that buildProbes injects.
func isOwnSQLiProbe(resp *types.Response) bool {
	u, err := url.Parse(resp.RequestURL)
	if err != nil {
		return false
	}
	for _, vals := range u.Query() {
		for _, v := range vals {
			if v == "1'" {
				return true
			}
		}
	}
	return false
}

// centeredSnippet cuts a readable evidence window around idx.
func centeredSnippet(body string, idx, radius int) string {
	start := idx - 60
	if start < 0 {
		start = 0
	}
	end := idx + radius
	if end > len(body) {
		end = len(body)
	}
	return strings.ReplaceAll(body[start:end], "\n", " ")
}
