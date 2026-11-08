package engine

import (
	"strings"
	"testing"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

func TestRenderClientHTML(t *testing.T) {
	r := &Report{
		Target:    "https://app.example.com",
		ScanTime:  time.Now(),
		Duration:  5 * time.Second,
		TotalReqs: 42,
		Findings: []types.Finding{
			{
				Type:        types.FindingExposure,
				Name:        `Exposed <script>alert(1)</script>`,
				Severity:    types.SeverityHigh,
				Description: "Debug endpoint reachable",
				Evidence:    "HTTP 200 on /debug with stack trace",
				Prov: &types.Provenance{
					Grade:         types.GradeProven,
					RequestURL:    "https://app.example.com/debug",
					RequestMethod: "GET",
				},
			},
			{
				Type:     types.FindingSecret,
				Name:     "Exposed API key",
				Severity: types.SeverityCritical,
				Evidence: "key=sk-live-abc123 found",
			},
		},
	}
	r.Summary = r.buildSummary()

	html := r.RenderClientHTML()

	// XSS: finding name must be escaped, not injected.
	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Error("unescaped finding name injected into HTML")
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Error("escaped finding name missing")
	}
	// Grade + severity present.
	if !strings.Contains(html, "proven") {
		t.Error("provenance grade not rendered")
	}
	if !strings.Contains(html, "Remediation") {
		t.Error("remediation guidance missing")
	}
	// Critical finding sorted first.
	if strings.Index(html, "Exposed API key") > strings.Index(html, "Debug endpoint") {
		t.Error("findings not ordered by severity")
	}
}

func TestRenderClientHTMLEmpty(t *testing.T) {
	r := &Report{Target: "https://clean.example", ScanTime: time.Now()}
	r.Summary = r.buildSummary()
	html := r.RenderClientHTML()
	if !strings.Contains(html, "No findings") {
		t.Error("empty scan must say so explicitly")
	}
}
