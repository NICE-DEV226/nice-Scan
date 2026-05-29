package engine

import (
	"fmt"
	"strings"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

type Report struct {
	Target      string
	ScanTime    time.Time
	Duration    time.Duration
	TotalReqs   int
	FailedReqs  int
	Findings    []types.Finding
	SeverityMap map[types.Severity]int
	TechFound   []types.Finding
	Secrets     []types.Finding
	Risks       []types.Finding
	Exposures   []types.Finding
	Summary     ReportSummary
}

type ReportSummary struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
	Total    int
	Score    string
	Risk     string
}

func GenerateReport(result *ScanResult) *Report {
	r := &Report{
		Target:      result.Target,
		ScanTime:    time.Now(),
		Duration:    result.Stats.Duration,
		TotalReqs:   result.Stats.Total,
		FailedReqs:  result.Stats.Failed,
		Findings:    result.Findings,
		SeverityMap: make(map[types.Severity]int),
	}

	for _, f := range result.Findings {
		r.SeverityMap[f.Severity]++
		switch f.Type {
		case types.FindingTech:
			r.TechFound = append(r.TechFound, f)
		case types.FindingSecret:
			r.Secrets = append(r.Secrets, f)
		case types.FindingExposure, types.FindingMisconfig:
			r.Exposures = append(r.Exposures, f)
		default:
			r.Risks = append(r.Risks, f)
		}
	}

	r.Summary = r.buildSummary()
	return r
}

func (r *Report) buildSummary() ReportSummary {
	s := ReportSummary{
		Critical: r.SeverityMap[types.SeverityCritical],
		High:     r.SeverityMap[types.SeverityHigh],
		Medium:   r.SeverityMap[types.SeverityMedium],
		Low:      r.SeverityMap[types.SeverityLow],
		Info:     r.SeverityMap[types.SeverityInfo],
		Total:    len(r.Findings),
	}

	score := s.Critical*10 + s.High*5 + s.Medium*2 + s.Low*1
	switch {
	case score >= 20:
		s.Score = fmt.Sprintf("%d/100 — CRITICAL", score*5)
		s.Risk = "Critical — Immediate action required"
	case score >= 10:
		s.Score = fmt.Sprintf("%d/100 — HIGH", score*5)
		s.Risk = "High — Requires prompt remediation"
	case score >= 5:
		s.Score = fmt.Sprintf("%d/100 — MEDIUM", score*5)
		s.Risk = "Medium — Should be addressed"
	case score > 0:
		s.Score = fmt.Sprintf("%d/100 — LOW", score*5)
		s.Risk = "Low — Informational only"
	default:
		s.Score = "0/100 — CLEAN"
		s.Risk = "No issues detected"
	}

	return s
}

func (r *Report) RenderHTML() string {
	var b strings.Builder

	b.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NICE_SCAN Security Report — `)
	b.WriteString(r.Target)
	b.WriteString(`</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif;
    background: #0f1117; color: #e1e4eb; line-height: 1.6;
    padding: 40px;
  }
  .container { max-width: 1100px; margin: 0 auto; }
  .header {
    background: linear-gradient(135deg, #1a1b2e 0%, #24283b 100%);
    border: 1px solid #2f3346; border-radius: 12px;
    padding: 32px; margin-bottom: 24px;
  }
  .header h1 { color: #7dcfff; font-size: 28px; margin-bottom: 8px; }
  .header .meta { color: #565f89; font-size: 14px; }
  .header .meta span { color: #c0caf5; }
  .score-card {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 16px; margin-bottom: 24px;
  }
  .score-item {
    background: #1a1b2e; border: 1px solid #2f3346; border-radius: 8px;
    padding: 20px; text-align: center;
  }
  .score-item .num { font-size: 32px; font-weight: 700; }
  .score-item .lbl { font-size: 12px; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; color: #565f89; }
  .critical { color: #f7768e; } .high { color: #f7768e; }
  .medium { color: #ffb347; } .low { color: #7dcfff; } .info { color: #565f89; }
  .summary-box {
    background: #1a1b2e; border: 1px solid #2f3346; border-radius: 8px;
    padding: 24px; margin-bottom: 24px;
  }
  .summary-box h2 { color: #c0caf5; font-size: 18px; margin-bottom: 12px; }
  .summary-box .row { display: flex; justify-content: space-between; padding: 6px 0; }
  .summary-box .row .lbl { color: #565f89; } .summary-box .row .val { color: #c0caf5; }
  .section { margin-bottom: 32px; }
  .section h2 {
    font-size: 20px; color: #c0caf5; margin-bottom: 16px;
    padding-bottom: 8px; border-bottom: 1px solid #2f3346;
  }
  .finding {
    background: #1a1b2e; border: 1px solid #2f3346; border-radius: 8px;
    padding: 16px 20px; margin-bottom: 12px;
  }
  .finding .f-name { font-size: 15px; font-weight: 600; margin-bottom: 4px; }
  .finding .f-desc { font-size: 13px; color: #565f89; margin-bottom: 6px; }
  .finding .f-evidence {
    background: #0f1117; border: 1px solid #2f3346; border-radius: 4px;
    padding: 8px 12px; font-family: 'SF Mono', 'Fira Code', monospace;
    font-size: 12px; color: #7dcfff; overflow-x: auto;
  }
  .finding .f-meta { font-size: 11px; color: #3b4261; margin-top: 6px; }
  .tag {
    display: inline-block; padding: 2px 8px; border-radius: 4px;
    font-size: 10px; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  .tag-tech { background: #1a3a4a; color: #7dcfff; }
  .tag-secret { background: #3a1a2a; color: #f7768e; }
  .tag-misconfig { background: #3a2a1a; color: #ffb347; }
  .tag-exposure { background: #2a1a3a; color: #bb9af7; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; margin-left: 8px; }
  .severity-critical { background: #3a1a1a; color: #f7768e; }
  .severity-high { background: #3a1a1a; color: #f7768e; }
  .severity-medium { background: #3a2a1a; color: #ffb347; }
  .severity-low { background: #1a2a3a; color: #7dcfff; }
  .severity-info { background: #1a1a1a; color: #565f89; }
  .footer { text-align: center; color: #3b4261; font-size: 12px; margin-top: 40px; padding: 20px; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>🔍 NICE_SCAN — Security Report</h1>
    <div class="meta">
      Target: <span>`)
	b.WriteString(r.Target)
	b.WriteString(`</span><br>
      Scan Time: <span>`)
	b.WriteString(r.ScanTime.Format("2006-01-02 15:04:05"))
	b.WriteString(`</span><br>
      Duration: <span>`)
	b.WriteString(r.Duration.Round(time.Millisecond).String())
	b.WriteString(`</span> | Requests: <span>`)
	b.WriteString(fmt.Sprintf("%d/%d", r.TotalReqs-r.FailedReqs, r.TotalReqs))
	b.WriteString(`</span>
    </div>
  </div>

  <div class="score-card">
    <div class="score-item"><div class="num critical">`)
	b.WriteString(fmt.Sprintf("%d", r.Summary.Critical))
	b.WriteString(`</div><div class="lbl">Critical</div></div>
    <div class="score-item"><div class="num high">`)
	b.WriteString(fmt.Sprintf("%d", r.Summary.High))
	b.WriteString(`</div><div class="lbl">High</div></div>
    <div class="score-item"><div class="num medium">`)
	b.WriteString(fmt.Sprintf("%d", r.Summary.Medium))
	b.WriteString(`</div><div class="lbl">Medium</div></div>
    <div class="score-item"><div class="num low">`)
	b.WriteString(fmt.Sprintf("%d", r.Summary.Low))
	b.WriteString(`</div><div class="lbl">Low</div></div>
    <div class="score-item"><div class="num info">`)
	b.WriteString(fmt.Sprintf("%d", r.Summary.Info))
	b.WriteString(`</div><div class="lbl">Info</div></div>
    <div class="score-item"><div class="num `)
	if r.Summary.Critical > 0 || r.Summary.High > 0 {
		b.WriteString("critical")
	} else if r.Summary.Medium > 0 {
		b.WriteString("medium")
	} else {
		b.WriteString("info")
	}
	b.WriteString(`">`)
	b.WriteString(r.Summary.Score)
	b.WriteString(`</div><div class="lbl">Risk Score</div></div>
  </div>

  <div class="summary-box">
    <h2>📋 Assessment Summary</h2>
    <div class="row"><span class="lbl">Risk Level</span><span class="val">`)
	b.WriteString(r.Summary.Risk)
	b.WriteString(`</span></div>
    <div class="row"><span class="lbl">Total Findings</span><span class="val">`)
	b.WriteString(fmt.Sprintf("%d", r.Summary.Total))
	b.WriteString(`</span></div>
    <div class="row"><span class="lbl">Technologies Detected</span><span class="val">`)
	b.WriteString(fmt.Sprintf("%d", len(r.TechFound)))
	b.WriteString(`</span></div>
    <div class="row"><span class="lbl">Secrets / Credentials</span><span class="val">`)
	b.WriteString(fmt.Sprintf("%d", len(r.Secrets)))
	b.WriteString(`</span></div>
    <div class="row"><span class="lbl">Active Requests</span><span class="val">`)
	b.WriteString(fmt.Sprintf("%d", r.TotalReqs))
	b.WriteString(`</span></div>
  </div>`)

	r.renderSection(&b, "🔴 Critical & High", r.filterBySeverity(types.SeverityCritical, types.SeverityHigh))
	r.renderSection(&b, "🟡 Medium", r.filterBySeverity(types.SeverityMedium))
	r.renderSection(&b, "🔵 Low & Info", r.filterBySeverity(types.SeverityLow, types.SeverityInfo))
	r.renderSection(&b, "🖥️ Technologies Detected", r.TechFound, "tech")
	r.renderSection(&b, "🔑 Secrets & Credentials", r.Secrets, "secret")

	b.WriteString(`<div class="footer">NICE_SCAN — Generated by NICE_SCAN Security Reconnaissance Engine</div>
</div>
</body>
</html>`)

	return b.String()
}

func (r *Report) filterBySeverity(sevs ...types.Severity) []types.Finding {
	var out []types.Finding
	for _, f := range r.Findings {
		for _, s := range sevs {
			if f.Severity == s && f.Type != types.FindingTech && f.Type != types.FindingSecret {
				out = append(out, f)
			}
		}
	}
	return out
}

func (r *Report) renderSection(b *strings.Builder, title string, findings []types.Finding, typeTags ...string) {
	if len(findings) == 0 {
		return
	}

	tagClass := "tag-misconfig"
	if len(typeTags) > 0 {
		switch typeTags[0] {
		case "tech":
			tagClass = "tag-tech"
		case "secret":
			tagClass = "tag-secret"
		case "exposure":
			tagClass = "tag-exposure"
		}
	}

	b.WriteString(`<div class="section"><h2>`)
	b.WriteString(title)
	b.WriteString(fmt.Sprintf(` <span style="color:#565f89;font-size:14px;">(%d)</span></h2>`, len(findings)))

	for _, f := range findings {
		sevClass := "severity-" + string(f.Severity)
		b.WriteString(`<div class="finding"><div class="f-name">`)
		b.WriteString(`<span class="tag `)
		b.WriteString(tagClass)
		b.WriteString(`">`)
		b.WriteString(string(f.Type))
		b.WriteString(`</span> `)
		b.WriteString(escapeHTML(f.Name))
		b.WriteString(` <span class="badge `)
		b.WriteString(sevClass)
		b.WriteString(`">`)
		b.WriteString(string(f.Severity))
		b.WriteString(`</span>`)
		if f.Confidence > 0 {
			b.WriteString(fmt.Sprintf(` <span style="color:#565f89;font-size:11px;">%.0f%% confidence</span>`, f.Confidence*100))
		}
		b.WriteString(`</div>`)

		if f.Description != "" {
			b.WriteString(`<div class="f-desc">`)
			b.WriteString(escapeHTML(f.Description))
			b.WriteString(`</div>`)
		}

		if f.Evidence != "" {
			b.WriteString(`<div class="f-evidence">`)
			b.WriteString(escapeHTML(f.Evidence))
			b.WriteString(`</div>`)
		}

		if f.Metadata != nil {
			var metaParts []string
			for k, v := range f.Metadata {
				metaParts = append(metaParts, k+": "+v)
			}
			if len(metaParts) > 0 {
				b.WriteString(`<div class="f-meta">`)
				b.WriteString(escapeHTML(strings.Join(metaParts, " | ")))
				b.WriteString(`</div>`)
			}
		}

		b.WriteString(`</div>`)
	}

	b.WriteString(`</div>`)
}

func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

func (r *Report) Save(path string) error {
	return nil
}
