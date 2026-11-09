package engine

import (
	"fmt"
	"html"
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
	// Stacks: the fingerprint-first read the path probes were conditioned
	// on — the report must explain why a family probe is ABSENT.
	Stacks []StackReport
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
		Stacks:      result.Stacks,
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

// RenderHTML renders the operator-facing technical report. Same design
// language as the client document — paper, ink, serif headlines — but
// denser: full evidence, metadata, stack-conditioning notes, and every
// finding type kept visible. No emojis, no gradients, no external assets.
func (r *Report) RenderHTML() string {
	var b strings.Builder

	b.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NICE_SCAN Technical Report — `)
	b.WriteString(html.EscapeString(r.Target))
	b.WriteString(`</title>
<style>
:root {
  --ink: #1c1a17; --ink-soft: #4a463f; --ink-faint: #8a857a;
  --rule: #d8d4c8; --paper: #fdfcf8; --accent: #8c2f1b;
  --sev-critical: #8c2f1b; --sev-high: #a05a12; --sev-medium: #7a6210;
  --sev-low: #4d6b2f; --sev-info: #5c5648;
}
* { box-sizing: border-box; }
body {
  font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
  color: var(--ink); background: var(--paper);
  max-width: 960px; margin: 0 auto; padding: 40px 36px 56px;
  font-size: 13px; line-height: 1.55;
}
h1, h2, h3 { font-family: Georgia, "Times New Roman", serif; font-weight: 600; }
h1 { font-size: 26px; margin: 0 0 2px; }
h2 {
  font-size: 15px; margin: 34px 0 4px; padding-bottom: 7px;
  border-bottom: 2px solid var(--ink);
}
h2 .count { color: var(--ink-faint); font-family: Georgia, serif;
            font-size: 12px; letter-spacing: .1em; margin-left: 8px; }
.sub { color: var(--ink-faint); font-size: 11px; letter-spacing: .05em;
       text-transform: uppercase; }

.cover { border-top: 5px solid var(--accent); padding-top: 16px; margin-bottom: 8px; }
.cover .doc-kind { color: var(--accent); font-size: 10.5px; font-weight: 700;
                   letter-spacing: .18em; text-transform: uppercase; }
.meta-grid {
  display: grid; grid-template-columns: repeat(4, 1fr); gap: 1px;
  background: var(--rule); border: 1px solid var(--rule); margin-top: 20px;
}
.meta-grid > div { background: var(--paper); padding: 9px 11px; }
.meta-grid dt { font-size: 9.5px; text-transform: uppercase; letter-spacing: .1em;
                color: var(--ink-faint); margin-bottom: 2px; }
.meta-grid dd { margin: 0; font-size: 12.5px; font-weight: 600; }

/* severity tiles */
.tiles { display: grid; grid-template-columns: repeat(6, 1fr); gap: 1px;
         background: var(--rule); border: 1px solid var(--rule); margin: 20px 0; }
.tile { background: var(--paper); padding: 12px 8px; text-align: center; }
.tile .num { font-family: Georgia, serif; font-size: 24px; font-weight: 700; }
.tile .lbl { font-size: 9px; text-transform: uppercase; letter-spacing: .1em;
             color: var(--ink-faint); margin-top: 2px; }
.t-critical .num { color: var(--sev-critical); }
.t-high .num { color: var(--sev-high); }
.t-medium .num { color: var(--sev-medium); }
.t-low .num { color: var(--sev-low); }
.t-info .num { color: var(--sev-info); }
.t-score .num { color: var(--ink); font-size: 15px; line-height: 1.5; }
.t-score .lbl { color: var(--accent); }

.stack {
  border: 1px solid var(--rule); border-left: 3px solid var(--accent);
  background: #f6f4ee; padding: 10px 14px; margin: 16px 0; font-size: 12px;
}
.stack b { font-weight: 600; }
.stack .kv { display: flex; gap: 10px; margin-top: 3px; }
.stack .kv .k { color: var(--ink-faint); min-width: 52px; font-size: 10px;
                text-transform: uppercase; letter-spacing: .08em; padding-top: 2px; }

.finding {
  border: 1px solid var(--rule); padding: 12px 15px; margin: 0 0 10px;
  border-left: 3px solid var(--rule);
}
.f-critical { border-left-color: var(--sev-critical); }
.f-high { border-left-color: var(--sev-high); }
.f-medium { border-left-color: var(--sev-medium); }
.f-low { border-left-color: var(--sev-low); }
.f-info { border-left-color: var(--sev-info); }
.f-head { display: flex; align-items: baseline; gap: 9px; flex-wrap: wrap; }
.f-name { font-weight: 600; font-size: 13.5px; }
.tag {
  font-size: 9px; font-weight: 700; letter-spacing: .08em;
  text-transform: uppercase; padding: 1px 6px;
  border: 1px solid var(--rule); color: var(--ink-soft);
}
.tag-tech { color: #2f5d7a; border-color: #b8cdd8; }
.tag-secret { color: var(--sev-critical); border-color: #d9b3a8; }
.tag-misconfig { color: var(--sev-medium); border-color: #d9cfa8; }
.tag-exposure { color: #4d6b2f; border-color: #c4cfae; }
.sev {
  font-size: 9.5px; font-weight: 700; letter-spacing: .1em;
  text-transform: uppercase; margin-left: auto;
}
.sev-critical { color: var(--sev-critical); }
.sev-high { color: var(--sev-high); }
.sev-medium { color: var(--sev-medium); }
.sev-low { color: var(--sev-low); }
.sev-info { color: var(--sev-info); }
.conf { font-size: 10.5px; color: var(--ink-faint); }
.f-desc { color: var(--ink-soft); font-size: 12.5px; margin: 6px 0 0; }
.f-evidence {
  background: #f6f4ee; border: 1px solid var(--rule);
  font-family: "SF Mono", Menlo, Consolas, monospace;
  font-size: 11px; line-height: 1.5; color: var(--ink-soft);
  padding: 8px 11px; margin-top: 8px; white-space: pre-wrap;
  word-break: break-word; overflow-x: auto;
}
.f-meta { font-size: 10.5px; color: var(--ink-faint); margin-top: 6px;
          font-family: "SF Mono", Menlo, Consolas, monospace; }

.footer {
  margin-top: 44px; padding-top: 12px; border-top: 1px solid var(--rule);
  color: var(--ink-faint); font-size: 10.5px; text-align: center;
}
@media print {
  body { padding: 0; max-width: none; font-size: 11px; }
  .finding { page-break-inside: avoid; }
}
</style>
</head>
<body>

<div class="cover">
  <div class="doc-kind">Technical Report</div>
  <h1>Security Scan — Operator View</h1>
  <div class="sub">`)
	b.WriteString(html.EscapeString(r.Target))
	b.WriteString(`</div>
  <dl class="meta-grid">
    <div><dt>Target</dt><dd>` + html.EscapeString(hostOnly(r.Target)) + `</dd></div>
    <div><dt>Scan time</dt><dd>` + r.ScanTime.Format("2006-01-02 15:04") + `</dd></div>
    <div><dt>Duration</dt><dd>` + r.Duration.Round(time.Millisecond).String() + `</dd></div>
    <div><dt>Requests</dt><dd>` + fmt.Sprintf("%d/%d ok", r.TotalReqs-r.FailedReqs, r.TotalReqs) + `</dd></div>
  </dl>
</div>

<div class="tiles">
  <div class="tile t-critical"><div class="num">`)
	fmt.Fprintf(&b, "%d", r.Summary.Critical)
	b.WriteString(`</div><div class="lbl">Critical</div></div>
  <div class="tile t-high"><div class="num">`)
	fmt.Fprintf(&b, "%d", r.Summary.High)
	b.WriteString(`</div><div class="lbl">High</div></div>
  <div class="tile t-medium"><div class="num">`)
	fmt.Fprintf(&b, "%d", r.Summary.Medium)
	b.WriteString(`</div><div class="lbl">Medium</div></div>
  <div class="tile t-low"><div class="num">`)
	fmt.Fprintf(&b, "%d", r.Summary.Low)
	b.WriteString(`</div><div class="lbl">Low</div></div>
  <div class="tile t-info"><div class="num">`)
	fmt.Fprintf(&b, "%d", r.Summary.Info)
	b.WriteString(`</div><div class="lbl">Info</div></div>
  <div class="tile t-score"><div class="num">`)
	b.WriteString(html.EscapeString(r.Summary.Score))
	b.WriteString(`</div><div class="lbl">Risk</div></div>
</div>
`)

	for _, st := range r.Stacks {
		conditioned := "full probe set kept — no stack signal to condition on"
		if st.Conditioned {
			conditioned = "stack-conditioned — family-specific probes limited to the detected stack"
		}
		b.WriteString(`<div class="stack"><b>Target stack</b>
    <div class="kv"><span class="k">Detected</span><span>`)
		b.WriteString(html.EscapeString(st.Detail))
		b.WriteString(`</span></div>
    <div class="kv"><span class="k">Probes</span><span>`)
		b.WriteString(conditioned)
		b.WriteString(`</span></div></div>` + "\n")
	}

	b.WriteString(`<h2>Summary<span class="count">`)
	b.WriteString(html.EscapeString(r.Summary.Risk))
	b.WriteString(`</span></h2>
<div class="stack" style="border-left-color: var(--rule);">
  <div class="kv"><span class="k">Risk level</span><span>`)
	b.WriteString(html.EscapeString(r.Summary.Risk))
	b.WriteString(`</span></div>
  <div class="kv"><span class="k">Total findings</span><span>`)
	fmt.Fprintf(&b, "%d", r.Summary.Total)
	b.WriteString(`</span></div>
  <div class="kv"><span class="k">Technologies</span><span>`)
	fmt.Fprintf(&b, "%d", len(r.TechFound))
	b.WriteString(`</span></div>
  <div class="kv"><span class="k">Secrets / creds</span><span>`)
	fmt.Fprintf(&b, "%d", len(r.Secrets))
	b.WriteString(`</span></div>
  <div class="kv"><span class="k">Active requests</span><span>`)
	fmt.Fprintf(&b, "%d", r.TotalReqs)
	b.WriteString(`</span></div>
</div>`)

	r.renderSection(&b, "Critical & High", r.filterBySeverity(types.SeverityCritical, types.SeverityHigh))
	r.renderSection(&b, "Medium", r.filterBySeverity(types.SeverityMedium))
	r.renderSection(&b, "Low & Info", r.filterBySeverity(types.SeverityLow, types.SeverityInfo))
	r.renderSection(&b, "Technologies Detected", r.TechFound, "tech")
	r.renderSection(&b, "Secrets & Credentials", r.Secrets, "secret")

	b.WriteString(`<div class="footer">NICE_SCAN — technical report · evidence-first · generated `)
	b.WriteString(r.ScanTime.Format("2006-01-02 15:04"))
	b.WriteString(`</div>
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

	b.WriteString(`<h2>`)
	b.WriteString(title)
	fmt.Fprintf(b, `<span class="count">(%d)</span></h2>`, len(findings))

	for _, f := range findings {
		// Same redaction rule as the JSON sink: this HTML leaves the
		// machine too, so credential-shaped values must not be recopied.
		f = types.RedactFinding(f)
		sevClass := "sev-" + string(f.Severity)
		borderClass := "f-" + string(f.Severity)
		b.WriteString(`<div class="finding `)
		b.WriteString(borderClass)
		b.WriteString(`"><div class="f-head"><span class="tag `)
		b.WriteString(tagClass)
		b.WriteString(`">`)
		b.WriteString(string(f.Type))
		b.WriteString(`</span> <span class="f-name">`)
		b.WriteString(escapeHTML(f.Name))
		b.WriteString(`</span> <span class="sev `)
		b.WriteString(sevClass)
		b.WriteString(`">`)
		b.WriteString(string(f.Severity))
		b.WriteString(`</span>`)
		if f.Confidence > 0 {
			fmt.Fprintf(b, ` <span class="conf">%.0f%% confidence</span>`, f.Confidence*100)
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
