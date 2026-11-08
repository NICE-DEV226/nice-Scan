package engine

import (
	"fmt"
	"html"
	"sort"
	"strings"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// RenderClientHTML produces the deliverable a pentester hands to a client:
// executive summary, scope and methodology, findings ordered by severity
// with their proof and a remediation line, and an evidence-grade legend.
//
// It is deliberately a DIFFERENT document from RenderHTML: that one is the
// operator's technical record (every probe, every stack read); this one is
// the report that leaves the building. Every finding still goes through
// RedactFinding — a client report must not leak credentials either.
//
// Print-friendly CSS: "Save as PDF" from a browser produces a clean
// deliverable without shipping a PDF engine.
func (r *Report) RenderClientHTML() string {
	var b strings.Builder
	esc := func(s string) string { return html.EscapeString(s) }

	sevRank := map[types.Severity]int{
		types.SeverityCritical: 0, types.SeverityHigh: 1,
		types.SeverityMedium: 2, types.SeverityLow: 3, types.SeverityInfo: 4,
	}
	findings := append([]types.Finding(nil), r.Findings...)
	sort.SliceStable(findings, func(i, j int) bool {
		if sevRank[findings[i].Severity] != sevRank[findings[j].Severity] {
			return sevRank[findings[i].Severity] < sevRank[findings[j].Severity]
		}
		return findings[i].Name < findings[j].Name
	})

	b.WriteString(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>Security Assessment — `)
	b.WriteString(esc(r.Target))
	b.WriteString(`</title><style>
@page { margin: 18mm; }
body { font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
       color: #1a1a1a; max-width: 860px; margin: 0 auto; padding: 32px 24px;
       line-height: 1.55; font-size: 14px; }
h1 { font-size: 26px; margin: 0 0 4px; }
h2 { font-size: 18px; margin: 32px 0 12px; border-bottom: 2px solid #333; padding-bottom: 6px; }
h3 { font-size: 15px; margin: 20px 0 6px; }
.meta { color: #555; font-size: 13px; margin-bottom: 24px; }
.score { display: inline-block; padding: 8px 18px; border-radius: 6px;
         font-weight: 700; font-size: 16px; }
.score-critical { background: #7f1d1d; color: #fff; }
.score-high { background: #b45309; color: #fff; }
.score-medium { background: #a16207; color: #fff; }
.score-low { background: #3f6212; color: #fff; }
.score-clean { background: #166534; color: #fff; }
table { border-collapse: collapse; width: 100%; margin: 12px 0; font-size: 13px; }
th, td { border: 1px solid #ccc; padding: 6px 10px; text-align: left; vertical-align: top; }
th { background: #f0f0f0; }
.sev { font-weight: 700; text-transform: uppercase; font-size: 11px; letter-spacing: .04em; }
.s-critical { color: #b91c1c; } .s-high { color: #c2410c; }
.s-medium { color: #a16207; } .s-low { color: #4d7c0f; }
.s-info { color: #57534e; }
.grade { font-size: 11px; background: #e7e5e4; border-radius: 3px; padding: 1px 6px; }
.proof { background: #f6f6f4; border-left: 3px solid #a8a29e; padding: 8px 12px;
        font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
        font-size: 12px; white-space: pre-wrap; word-break: break-word; }
.finding { page-break-inside: avoid; margin-bottom: 22px; }
.remediation { color: #444; font-style: italic; }
ul.tight { margin: 6px 0; padding-left: 22px; }
.footer { margin-top: 40px; padding-top: 12px; border-top: 1px solid #ccc;
          color: #777; font-size: 12px; }
@media print { body { padding: 0; } h2 { page-break-after: avoid; }
               .finding { page-break-inside: avoid; } }
</style></head><body>`)

	// ── Cover / executive summary ──────────────────────────────────────
	b.WriteString(`<h1>Security Assessment Report</h1>`)
	b.WriteString(`<div class="meta">`)
	b.WriteString(fmt.Sprintf("<strong>Target:</strong> %s<br>", esc(r.Target)))
	b.WriteString(fmt.Sprintf("<strong>Date:</strong> %s<br>",
		r.ScanTime.Format("2006-01-02 15:04 MST")))
	b.WriteString(fmt.Sprintf("<strong>Duration:</strong> %s &middot; <strong>Requests:</strong> %d (%d failed)<br>",
		r.Duration.Round(time.Second), r.TotalReqs, r.FailedReqs))
	b.WriteString("</div>")

	scoreClass := "score-clean"
	switch {
	case r.Summary.Critical > 0:
		scoreClass = "score-critical"
	case r.Summary.High > 0:
		scoreClass = "score-high"
	case r.Summary.Medium > 0:
		scoreClass = "score-medium"
	case r.Summary.Total > 0:
		scoreClass = "score-low"
	}
	b.WriteString(fmt.Sprintf(`<div class="score %s">%s</div>`, scoreClass, esc(r.Summary.Risk)))
	b.WriteString(`<p>Overall risk score: <strong>` + esc(r.Summary.Score) + `</strong></p>`)

	b.WriteString(`<h2>Summary</h2><table><tr>
<th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th><th>Total</th></tr><tr>
<td>` + fmt.Sprint(r.Summary.Critical) + `</td><td>` + fmt.Sprint(r.Summary.High) +
		`</td><td>` + fmt.Sprint(r.Summary.Medium) + `</td><td>` + fmt.Sprint(r.Summary.Low) +
		`</td><td>` + fmt.Sprint(r.Summary.Info) + `</td><td><strong>` +
		fmt.Sprint(r.Summary.Total) + `</strong></td></tr></table>`)

	// ── Methodology ────────────────────────────────────────────────────
	b.WriteString(`<h2>Scope &amp; Methodology</h2><ul class="tight">
<li><strong>Target:</strong> ` + esc(r.Target) + `</li>
<li><strong>Method:</strong> automated grey-box assessment — crawling, technology fingerprinting, header/TLS configuration analysis, and targeted exposure probing</li>
<li><strong>Constraint:</strong> destination scope enforced at the transport layer; out-of-scope hosts refused</li>
<li><strong>Evidence standard:</strong> every finding carries a provenance grade — <em>proven</em> (artifact recognized), <em>corroborated</em> (independent sources agree), <em>indicated</em> (single real signal)</li>
<li><strong>Requests issued:</strong> ` + fmt.Sprint(r.TotalReqs) + `</li></ul>`)

	// ── Findings ───────────────────────────────────────────────────────
	b.WriteString(`<h2>Findings</h2>`)
	if len(findings) == 0 {
		b.WriteString(`<p>No findings. The assessed surface showed no issues within the scanner's coverage.</p>`)
	} else {
		for i, f := range findings {
			f = types.RedactFinding(f)
			grade := ""
			if f.Prov != nil && f.Prov.Grade != "" {
				grade = fmt.Sprintf(` <span class="grade">%s</span>`, esc(string(f.Prov.Grade)))
			}
			sevClass := "s-" + strings.ToLower(string(f.Severity))
			b.WriteString(fmt.Sprintf(`<div class="finding"><h3>%d. %s <span class="sev %s">%s</span>%s</h3>`,
				i+1, esc(f.Name), sevClass, esc(string(f.Severity)), grade))
			if f.Description != "" {
				b.WriteString(`<p>` + esc(f.Description) + `</p>`)
			}
			if f.Evidence != "" {
				b.WriteString(`<div class="proof">` + esc(f.Evidence) + `</div>`)
			}
			if f.Prov != nil && f.Prov.RequestURL != "" {
				b.WriteString(`<p><small>Exercised at: <code>` +
					esc(f.Prov.RequestMethod+" "+f.Prov.RequestURL) + `</code></small></p>`)
			}
			if rem := remediationFor(f); rem != "" {
				b.WriteString(`<p class="remediation"><strong>Remediation:</strong> ` + esc(rem) + `</p>`)
			}
			b.WriteString(`</div>`)
		}
	}

	// ── Footer ─────────────────────────────────────────────────────────
	b.WriteString(`<div class="footer">
<p>Generated by <strong>nice-Scan</strong> — an evidence-first security scanner.
Findings are reported with their proof; nothing is asserted without observed evidence.
This report reflects automated testing at the stated date and does not replace a full manual penetration test.</p>
</div></body></html>`)

	return b.String()
}

// remediationFor maps the finding type to the standard fix guidance a
// client expects. Unknown types get no line rather than invented advice.
func remediationFor(f types.Finding) string {
	switch f.Type {
	case types.FindingSecret:
		return "Remove the exposed secret from the repository/artifact, rotate it immediately, and purge it from git history. Add secret-scanning to CI."
	case types.FindingExposure:
		return "Restrict access to the exposed resource (authentication, network ACL, or removal). Review access logs for prior exposure."
	case types.FindingMisconfig:
		return "Apply the secure configuration baseline for the identified component and re-scan to confirm."
	case types.FindingTech:
		return "Ensure the detected component is at a supported, patched version."
	default:
		if strings.Contains(strings.ToLower(f.Name), "bola") || strings.Contains(strings.ToLower(f.Name), "idor") {
			return "Enforce object-level authorization server-side on every request; never trust client-supplied identifiers."
		}
		return ""
	}
}
