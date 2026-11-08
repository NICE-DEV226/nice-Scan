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
// cover block, executive summary, scope & methodology, numbered findings
// (F-001…) each carrying severity, confidence, provenance grade, the proof
// exchange and a remediation line, then a footer disclaimer.
//
// Design discipline: this is a printed document first. Restrained palette
// (ink + one accent + severity codes), no gradients, no emoji, serif
// headlines over a clean sans body, findings that survive page breaks.
// Every finding passes through RedactFinding; the file keeps 0600.
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

	b.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Assessment — `)
	b.WriteString(esc(r.Target))
	b.WriteString(`</title>
<style>
:root {
  --ink: #1c1a17;
  --ink-soft: #4a463f;
  --ink-faint: #8a857a;
  --rule: #d8d4c8;
  --paper: #fdfcf8;
  --accent: #8c2f1b;
  --sev-critical: #8c2f1b;
  --sev-high: #a05a12;
  --sev-medium: #7a6210;
  --sev-low: #4d6b2f;
  --sev-info: #5c5648;
}
* { box-sizing: border-box; }
html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
body {
  font-family: "Helvetica Neue", Helvetica, Arial, "Segoe UI", sans-serif;
  color: var(--ink); background: var(--paper);
  max-width: 800px; margin: 0 auto; padding: 48px 40px 64px;
  font-size: 13.5px; line-height: 1.6;
}
h1, h2, h3 { font-family: Georgia, "Times New Roman", serif; font-weight: 600; }
h1 { font-size: 30px; letter-spacing: -0.01em; margin: 0 0 2px; }
h2 {
  font-size: 17px; margin: 40px 0 4px; padding-bottom: 8px;
  border-bottom: 2px solid var(--ink);
}
h2 .num { color: var(--ink-faint); font-family: Georgia, serif; font-size: 13px;
          letter-spacing: .12em; text-transform: uppercase; margin-right: 10px; }
h3 { font-size: 14.5px; margin: 26px 0 6px; }
.sub { color: var(--ink-faint); font-size: 12px; letter-spacing: .04em;
       text-transform: uppercase; }

/* ── Cover block ─────────────────────────────────────────── */
.cover {
  border-top: 5px solid var(--accent);
  padding-top: 18px; margin-bottom: 28px;
}
.cover .doc-kind { color: var(--accent); font-size: 11px; font-weight: 700;
                   letter-spacing: .18em; text-transform: uppercase; }
.meta-grid {
  display: grid; grid-template-columns: repeat(4, 1fr);
  gap: 1px; background: var(--rule); border: 1px solid var(--rule);
  margin: 22px 0 0;
}
.meta-grid > div { background: var(--paper); padding: 10px 12px; }
.meta-grid dt { font-size: 10px; text-transform: uppercase; letter-spacing: .1em;
                color: var(--ink-faint); margin-bottom: 2px; }
.meta-grid dd { margin: 0; font-size: 13px; font-weight: 600; }

/* ── Risk banner ─────────────────────────────────────────── */
.risk {
  display: flex; align-items: baseline; gap: 14px;
  border: 1px solid var(--rule); padding: 14px 18px; margin: 24px 0;
}
.risk .label { font-size: 11px; text-transform: uppercase; letter-spacing: .12em;
               color: var(--ink-faint); }
.risk .verdict { font-family: Georgia, serif; font-size: 20px; font-weight: 700; }
.risk .score { margin-left: auto; font-size: 12px; color: var(--ink-soft); }
.r-critical { border-left: 4px solid var(--sev-critical); }
.r-critical .verdict { color: var(--sev-critical); }
.r-high { border-left: 4px solid var(--sev-high); }
.r-high .verdict { color: var(--sev-high); }
.r-medium { border-left: 4px solid var(--sev-medium); }
.r-medium .verdict { color: var(--sev-medium); }
.r-low { border-left: 4px solid var(--sev-low); }
.r-low .verdict { color: var(--sev-low); }
.r-clean { border-left: 4px solid var(--sev-low); }
.r-clean .verdict { color: var(--sev-low); }

/* ── Severity table ──────────────────────────────────────── */
table { border-collapse: collapse; width: 100%; margin: 12px 0; font-size: 12.5px; }
th {
  text-align: left; font-size: 10.5px; text-transform: uppercase;
  letter-spacing: .08em; color: var(--ink-faint); font-weight: 600;
  padding: 6px 10px; border-bottom: 2px solid var(--ink);
}
td { padding: 7px 10px; border-bottom: 1px solid var(--rule); }
td.num { font-variant-numeric: tabular-nums; text-align: right; }
.sev-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%;
           margin-right: 7px; vertical-align: 1px; }
.dot-critical { background: var(--sev-critical); }
.dot-high { background: var(--sev-high); }
.dot-medium { background: var(--sev-medium); }
.dot-low { background: var(--sev-low); }
.dot-info { background: var(--sev-info); }

/* ── Findings ────────────────────────────────────────────── */
.finding { margin: 0 0 30px; }
.finding .fid {
  font-family: Georgia, serif; font-size: 12px; color: var(--ink-faint);
  letter-spacing: .08em; margin-right: 8px;
}
.finding h3 { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; }
.finding h3 .sev {
  font-family: "Helvetica Neue", sans-serif; font-size: 10px; font-weight: 700;
  letter-spacing: .1em; text-transform: uppercase;
}
.finding .sev.s-critical { color: var(--sev-critical); }
.finding .sev.s-high { color: var(--sev-high); }
.finding .sev.s-medium { color: var(--sev-medium); }
.finding .sev.s-low { color: var(--sev-low); }
.finding .sev.s-info { color: var(--sev-info); }
.finding .grade {
  font-size: 10px; color: var(--ink-faint); border: 1px solid var(--rule);
  padding: 1px 7px; letter-spacing: .06em; text-transform: uppercase;
}
.finding .desc { color: var(--ink-soft); margin: 6px 0 10px; }
.evidence {
  border-left: 3px solid var(--accent); background: #f6f4ee;
  padding: 10px 14px; font-family: "SF Mono", Menlo, Consolas, monospace;
  font-size: 11.5px; line-height: 1.55; white-space: pre-wrap;
  word-break: break-word; margin: 8px 0;
}
.evidence .ev-label {
  display: block; font-family: "Helvetica Neue", sans-serif;
  font-size: 9.5px; text-transform: uppercase; letter-spacing: .12em;
  color: var(--accent); margin-bottom: 4px;
}
.remediation {
  border: 1px solid var(--rule); border-left: 3px solid var(--sev-low);
  background: #faf9f4; padding: 9px 13px; font-size: 12.5px;
  color: var(--ink-soft); margin-top: 10px;
}
.remediation b { color: var(--ink); font-weight: 600; }
.req-ref { font-size: 11.5px; color: var(--ink-faint); margin-top: 6px; }
.req-ref code { font-family: "SF Mono", Menlo, Consolas, monospace; font-size: 11px; }

ul.tight { margin: 8px 0; padding-left: 20px; }
ul.tight li { margin: 4px 0; }

.footer {
  margin-top: 48px; padding-top: 14px; border-top: 1px solid var(--rule);
  color: var(--ink-faint); font-size: 11px; line-height: 1.55;
}
.footer strong { color: var(--ink-soft); }

@page { margin: 16mm; }
@media print {
  body { padding: 0; max-width: none; font-size: 11.5px; }
  h2 { page-break-after: avoid; }
  .finding { page-break-inside: avoid; }
  .cover, .risk, table { page-break-inside: avoid; }
}
</style>
</head>
<body>

<div class="cover">
  <div class="doc-kind">Security Assessment Report</div>
  <h1>Web Application Security Review</h1>
  <div class="sub">`)
	b.WriteString(esc(r.Target))
	b.WriteString(`</div>
  <dl class="meta-grid">
    <div><dt>Target</dt><dd>` + esc(hostOnly(r.Target)) + `</dd></div>
    <div><dt>Assessment date</dt><dd>` + r.ScanTime.Format("2006-01-02") + `</dd></div>
    <div><dt>Duration</dt><dd>` + r.Duration.Round(time.Second).String() + `</dd></div>
    <div><dt>Requests issued</dt><dd>` + fmt.Sprint(r.TotalReqs) + `</dd></div>
  </dl>
</div>

<div class="risk `)
	riskClass := "r-clean"
	switch {
	case r.Summary.Critical > 0:
		riskClass = "r-critical"
	case r.Summary.High > 0:
		riskClass = "r-high"
	case r.Summary.Medium > 0:
		riskClass = "r-medium"
	case r.Summary.Total > 0:
		riskClass = "r-low"
	}
	b.WriteString(riskClass)
	b.WriteString(`"><span class="label">Overall risk</span><span class="verdict">`)
	b.WriteString(esc(r.Summary.Risk))
	b.WriteString(`</span><span class="score">score ` + esc(r.Summary.Score) + `</span></div>

<h2><span class="num">01</span>Findings overview</h2>
<table>
<tr><th>Severity</th><th>Findings</th></tr>`)
	sevRows := []struct {
		name  string
		count int
		dot   string
	}{
		{"Critical", r.Summary.Critical, "dot-critical"},
		{"High", r.Summary.High, "dot-high"},
		{"Medium", r.Summary.Medium, "dot-medium"},
		{"Low", r.Summary.Low, "dot-low"},
		{"Informational", r.Summary.Info, "dot-info"},
	}
	for _, row := range sevRows {
		if row.count == 0 {
			continue
		}
		fmt.Fprintf(&b, `<tr><td><span class="sev-dot %s"></span>%s</td><td class="num">%d</td></tr>`,
			row.dot, row.name, row.count)
	}
	fmt.Fprintf(&b, `<tr><td><strong>Total</strong></td><td class="num"><strong>%d</strong></td></tr></table>`, r.Summary.Total)

	b.WriteString(`<h2><span class="num">02</span>Scope &amp; methodology</h2>
<ul class="tight">
<li><strong>Target:</strong> ` + esc(r.Target) + `</li>
<li><strong>Method:</strong> automated grey-box assessment — surface crawling, technology fingerprinting, transport-security analysis, and targeted exposure probing</li>
<li><strong>Boundary:</strong> destination scope enforced at the transport layer; requests to out-of-scope hosts are refused</li>
<li><strong>Evidence standard:</strong> every finding carries a provenance grade — <em>proven</em> (artifact recognized), <em>corroborated</em> (independent signals agree), <em>indicated</em> (single real signal)</li>
<li><strong>Requests issued:</strong> ` + fmt.Sprint(r.TotalReqs) + ` (` + fmt.Sprint(r.FailedReqs) + ` failed)</li>
</ul>`)

	b.WriteString(`<h2><span class="num">03</span>Detailed findings</h2>`)
	if len(findings) == 0 {
		b.WriteString(`<p>No findings. The assessed surface showed no issues within the scanner's coverage.</p>`)
	} else {
		for i, f := range findings {
			f = types.RedactFinding(f)
			fid := fmt.Sprintf("F-%03d", i+1)
			sevClass := "s-" + strings.ToLower(string(f.Severity))
			fmt.Fprintf(&b, `<div class="finding"><h3><span class="fid">%s</span>%s <span class="sev %s">%s</span>`,
				fid, esc(f.Name), sevClass, esc(string(f.Severity)))
			if f.Prov != nil && f.Prov.Grade != "" {
				fmt.Fprintf(&b, ` <span class="grade">%s</span>`, esc(string(f.Prov.Grade)))
			}
			if f.Confidence > 0 {
				fmt.Fprintf(&b, ` <span class="grade">%.0f%% confidence</span>`, f.Confidence*100)
			}
			b.WriteString(`</h3>`)
			if f.Description != "" {
				b.WriteString(`<p class="desc">` + esc(f.Description) + `</p>`)
			}
			if f.Evidence != "" {
				b.WriteString(`<div class="evidence"><span class="ev-label">Evidence</span>` + esc(f.Evidence) + `</div>`)
			}
			if f.Prov != nil && f.Prov.RequestURL != "" {
				fmt.Fprintf(&b, `<p class="req-ref">Exercised at <code>%s %s</code></p>`,
					esc(f.Prov.RequestMethod), esc(f.Prov.RequestURL))
			}
			if rem := remediationFor(f); rem != "" {
				b.WriteString(`<div class="remediation"><b>Remediation.</b> ` + esc(rem) + `</div>`)
			}
			b.WriteString(`</div>`)
		}
	}

	b.WriteString(`<div class="footer">
<p><strong>About this report.</strong> Generated by <strong>nice-Scan</strong>, an evidence-first
security scanner: findings are reported with their proof — nothing is asserted without
observed evidence, and unproven signals stay out of the risk score. Automated testing
reflects the state of the target at the stated date and does not replace a full manual
penetration test.</p>
</div>
</body>
</html>`)

	return b.String()
}

// hostOnly strips the scheme for the cover grid — the full URL stays in
// the methodology section where precision matters.
func hostOnly(target string) string {
	if i := strings.Index(target, "://"); i >= 0 {
		rest := target[i+3:]
		if j := strings.IndexAny(rest, "/?#"); j >= 0 {
			return rest[:j]
		}
		return rest
	}
	return target
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
