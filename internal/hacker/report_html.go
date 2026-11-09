package hacker

import (
	"bytes"
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// RenderHTMLReport builds a self-contained, single-file HTML report.
//
// Same design language as the engine client/technical reports — paper,
// ink, serif headlines, one accent — but denser: it keeps the operator
// affordances (severity filter, copy-evidence) and every section the
// engagement produced. No emojis, no gradients, no external assets: the
// file opens offline, prints cleanly, and cannot be altered by a CDN.
func RenderHTMLReport(r *Report) string {
	var buf bytes.Buffer

	buf.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NICE_SCAN — Engagement Report</title>
<style>
:root {
  --ink: #1c1a17; --ink-soft: #4a463f; --ink-faint: #8a857a;
  --rule: #d8d4c8; --paper: #fdfcf8; --accent: #8c2f1b; --accent-soft: #f6f4ee;
  --sev-critical: #8c2f1b; --sev-high: #a05a12; --sev-medium: #7a6210;
  --sev-low: #4d6b2f; --sev-info: #5c5648;
}
* { box-sizing: border-box; }
html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
body {
  font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
  color: var(--ink); background: var(--paper);
  max-width: 900px; margin: 0 auto; padding: 44px 36px 60px;
  font-size: 13px; line-height: 1.55;
}
h1, h2, h3 { font-family: Georgia, "Times New Roman", serif; font-weight: 600; }
h2 {
  font-size: 15px; margin: 36px 0 4px; padding-bottom: 7px;
  border-bottom: 2px solid var(--ink);
}
h2 .count { color: var(--ink-faint); font-family: Georgia, serif;
            font-size: 12px; letter-spacing: .1em; margin-left: 8px; }
.mono, code, pre { font-family: "SF Mono", Menlo, Consolas, monospace; }
code { font-size: .92em; background: var(--accent-soft); padding: 0 4px; }

/* Cover */
.cover { border-top: 5px solid var(--accent); padding-top: 16px; margin-bottom: 10px; }
.cover .doc-kind { color: var(--accent); font-size: 10.5px; font-weight: 700;
                   letter-spacing: .18em; text-transform: uppercase; }
.cover h1 { font-size: 26px; margin: 0 0 2px; }
.sub { color: var(--ink-faint); font-size: 11px; letter-spacing: .05em;
       text-transform: uppercase; }
.meta-grid {
  display: grid; grid-template-columns: repeat(4, 1fr); gap: 1px;
  background: var(--rule); border: 1px solid var(--rule); margin-top: 20px;
}
.meta-grid > div { background: var(--paper); padding: 9px 11px; }
.meta-grid dt { font-size: 9.5px; text-transform: uppercase; letter-spacing: .1em;
                color: var(--ink-faint); margin-bottom: 2px; }
.meta-grid dd { margin: 0; font-size: 12.5px; font-weight: 600; }
.dd-risk-critical { color: var(--sev-critical); }
.dd-risk-high { color: var(--sev-high); }
.dd-risk-medium { color: var(--sev-medium); }
.dd-risk-low { color: var(--sev-low); }

/* Impact */
.impact {
  border: 1px solid var(--rule); border-left: 3px solid var(--accent);
  background: var(--accent-soft); padding: 12px 15px; margin: 20px 0;
  color: var(--ink-soft); font-size: 13px;
}

/* Attack chains */
.chain {
  border: 1px solid var(--rule); border-left: 3px solid var(--sev-critical);
  background: var(--accent-soft); padding: 11px 14px; margin: 0 0 10px;
}
.chain .c-name { font-weight: 600; font-size: 13.5px; color: var(--sev-critical); }
.chain .c-risk { font-size: 11.5px; color: var(--ink-faint); margin-top: 2px; }
.chain .c-arrow { font-size: 12px; color: var(--ink-soft); margin-top: 5px;
                 white-space: pre-wrap; }

/* Findings */
.findings { display: flex; flex-direction: column; gap: 10px; margin-top: 12px; }
.finding {
  border: 1px solid var(--rule); border-left: 3px solid var(--rule);
  padding: 11px 14px;
}
.finding.critical { border-left-color: var(--sev-critical); }
.finding.high { border-left-color: var(--sev-high); }
.finding.medium { border-left-color: var(--sev-medium); }
.finding.low { border-left-color: var(--sev-low); }
.finding.info { border-left-color: var(--sev-info); }
.f-head { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; }
.sev {
  font-size: 9.5px; font-weight: 700; letter-spacing: .1em;
  text-transform: uppercase;
}
.sev-critical { color: var(--sev-critical); }
.sev-high { color: var(--sev-high); }
.sev-medium { color: var(--sev-medium); }
.sev-low { color: var(--sev-low); }
.sev-info { color: var(--sev-info); }
.copy {
  margin-left: auto; font-size: 10px; color: var(--accent);
  cursor: pointer; text-decoration: underline dotted; background: none;
  border: none; padding: 0; font-family: inherit;
}
.copy:hover { color: var(--sev-critical); }
.copy:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.f-name { font-weight: 600; font-size: 13.5px; }
.f-desc { color: var(--ink-soft); font-size: 12.5px; margin: 5px 0 0; }
.f-evid {
  background: var(--accent-soft); border: 1px solid var(--rule);
  font-size: 11px; line-height: 1.5; color: var(--ink-soft);
  padding: 8px 11px; margin-top: 8px; white-space: pre-wrap;
  word-break: break-word; overflow-x: auto;
}
.filters { display: flex; flex-wrap: wrap; gap: 6px; margin: 14px 0 4px; }
.filter-btn {
  background: var(--paper); border: 1px solid var(--rule); color: var(--ink-soft);
  font-size: 10.5px; font-weight: 600; letter-spacing: .05em;
  text-transform: uppercase; padding: 4px 11px; cursor: pointer;
}
.filter-btn:hover { border-color: var(--accent); color: var(--accent); }
.filter-btn.active { background: var(--ink); color: var(--paper); border-color: var(--ink); }
.rs-hidden { display: none !important; }

/* Credentials */
.cred {
  border: 1px solid var(--rule); padding: 9px 13px; margin: 0 0 8px;
}
.cred .pair { font-family: "SF Mono", Menlo, Consolas, monospace;
              font-size: 12.5px; font-weight: 600; word-break: break-all; }
.cred .meta { color: var(--ink-faint); font-size: 10.5px; margin-top: 2px; }

/* Endpoints */
.endpoint {
  display: flex; align-items: center; gap: 10px;
  border: 1px solid var(--rule); padding: 6px 11px; margin: 0 0 6px;
  font-family: "SF Mono", Menlo, Consolas, monospace; font-size: 11.5px;
}
.method {
  min-width: 52px; text-align: center; font-size: 9.5px; font-weight: 700;
  letter-spacing: .06em; padding: 2px 6px; border: 1px solid var(--rule);
  color: var(--ink-soft);
}
.method-GET { color: #2f5d7a; border-color: #b8cdd8; }
.method-POST { color: var(--sev-medium); border-color: #d9cfa8; }
.method-PUT { color: #8a6210; border-color: #d9cfa8; }
.method-DELETE { color: var(--sev-critical); border-color: #d9b3a8; }
.path { flex: 1; word-break: break-all; }
.status { color: var(--ink-faint); font-size: 10.5px; }

/* Pages */
.page {
  display: flex; justify-content: space-between; gap: 10px;
  border-bottom: 1px solid var(--rule); padding: 5px 0;
  font-family: "SF Mono", Menlo, Consolas, monospace; font-size: 11px;
}
.page .url { color: var(--accent); word-break: break-all; }
.page .meta { color: var(--ink-faint); white-space: nowrap; }

/* Capabilities */
.caps { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px; }
.cap {
  font-size: 10.5px; border: 1px solid var(--rule); color: var(--ink-soft);
  padding: 3px 9px; letter-spacing: .03em;
}
.cap-hint { color: var(--ink-faint); border-style: dashed; }
.cap-observed { color: var(--sev-low); border-color: #c4cfae; }

/* Withheld */
.withheld { display: flex; flex-direction: column; gap: 8px; margin-top: 10px; }
.withheld-item {
  border: 1px dashed var(--rule); padding: 8px 12px;
}
.withheld-name { font-weight: 600; font-size: 12.5px; }
.withheld-hint { color: var(--ink-faint); font-size: 11px; }

/* Footer */
.footer {
  margin-top: 44px; padding-top: 12px; border-top: 1px solid var(--rule);
  color: var(--ink-faint); font-size: 10.5px; text-align: center;
}

@page { margin: 16mm; }
@media print {
  body { padding: 0; max-width: none; font-size: 11px; }
  .finding, .chain, .cred, .endpoint { page-break-inside: avoid; }
  .filters, .copy { display: none !important; }
}
</style>
</head>
<body>

<div class="cover">
  <div class="doc-kind">Autonomous Engagement Report</div>
  <h1>Security Assessment — Deep Run</h1>
  <div class="sub">generated ` + fmt.Sprintf("%s · %d steps · %.0fs", time.Now().Format("2006-01-02 15:04"), r.Steps, r.Duration.Seconds()) + `</div>
  <dl class="meta-grid">
    <div><dt>Target</dt><dd>` + html.EscapeString(r.Target) + `</dd></div>
    <div><dt>Duration</dt><dd>` + fmt.Sprintf("%.0fs", r.Duration.Seconds()) + `</dd></div>
    <div><dt>Steps executed</dt><dd>` + fmt.Sprintf("%d", r.Steps) + `</dd></div>
    <div><dt>Risk score</dt><dd class="dd-risk-` + riskClass(r.RiskScore) + `">` + fmt.Sprintf("%.1f / 10", r.RiskScore) + `</dd></div>
  </dl>
</div>

<section>
  <h2>Impact Summary</h2>
  <div class="impact">` + html.EscapeString(r.Impact) + `</div>
</section>
`)

	if len(r.AttackChains) > 0 {
		buf.WriteString(`<section>
  <h2>Attack Chain Hypotheses<span class="count">not executed</span></h2>`)
		for _, chain := range r.AttackChains {
			fmt.Fprintf(&buf,
				`  <div class="chain">
    <div class="c-name">%s</div>
    <div class="c-risk">Risk if executed: %.0f/10</div>
    <div class="c-arrow">→ %s</div>
  </div>
`,
				html.EscapeString(chain.Name),
				chain.RiskScore,
				html.EscapeString(chain.Impact),
			)
		}
		buf.WriteString(`</section>
`)
	}

	if len(r.Findings) > 0 {
		buf.WriteString(`<section>
  <h2>Findings<span class="count">` + fmt.Sprintf("%d", len(r.Findings)) + `</span></h2>
  <div class="filters" role="group" aria-label="Filter findings by severity">
    <button class="filter-btn active" data-severity="all">All</button>
    <button class="filter-btn" data-severity="critical">Critical</button>
    <button class="filter-btn" data-severity="high">High</button>
    <button class="filter-btn" data-severity="medium">Medium</button>
    <button class="filter-btn" data-severity="low">Low</button>
    <button class="filter-btn" data-severity="info">Info</button>
  </div>
  <div class="findings" id="findings-list">`)
		for _, f := range r.Findings {
			// The HTML report leaves the machine and lands in a browser:
			// remote text is redacted here exactly as in the JSON sink,
			// not merely escaped.
			f = redactFinding(f)
			sev := strings.ToLower(string(f.Severity))
			fmt.Fprintf(&buf,
				`    <div class="finding %s" data-severity="%s">
      <div class="f-head">
        <span class="sev sev-%s">%s</span>
        <button class="copy" title="Copy evidence to clipboard" onclick="copyToClipboard(this)">Copy</button>
      </div>
      <div class="f-name">%s</div>
      <div class="f-desc">%s</div>
      <div class="f-evid">%s</div>
    </div>
`,
				sev, sev,
				sev, string(f.Severity),
				html.EscapeString(f.Name),
				html.EscapeString(f.Description),
				html.EscapeString(f.Evidence),
			)
		}
		buf.WriteString(`  </div>
</section>
`)
	}

	if len(r.Credentials) > 0 {
		buf.WriteString(`<section>
  <h2>Credentials Obtained<span class="count">` + fmt.Sprintf("%d", len(r.Credentials)) + `</span></h2>`)
		for _, c := range r.Credentials {
			valid := "tested"
			if c.Valid {
				valid = "valid"
			}
			fmt.Fprintf(&buf,
				`  <div class="cred">
    <div class="pair">%s:%s</div>
    <div class="meta">source: %s · status: %s</div>
  </div>
`,
				html.EscapeString(types.RedactText(c.Username)),
				html.EscapeString(types.MaskSecret(c.Password)),
				html.EscapeString(c.Source),
				valid,
			)
		}
		buf.WriteString(`</section>
`)
	}

	if len(r.Endpoints) > 0 {
		buf.WriteString(`<section>
  <h2>Endpoints Discovered<span class="count">` + fmt.Sprintf("%d", len(r.Endpoints)) + `</span></h2>`)
		for _, e := range r.Endpoints {
			fmt.Fprintf(&buf,
				`  <div class="endpoint">
    <span class="method method-%s">%s</span>
    <span class="path">%s</span>
    <span class="status">[%d]</span>
  </div>
`,
				html.EscapeString(e.Method), html.EscapeString(e.Method),
				html.EscapeString(e.Path), e.Status,
			)
		}
		buf.WriteString(`</section>
`)
	}

	if len(r.Pages) > 0 {
		fmt.Fprintf(&buf, `<section>
  <h2>Pages Crawled<span class="count">%d</span></h2>
`, len(r.Pages))
		for _, p := range r.Pages {
			fmt.Fprintf(&buf,
				`  <div class="page">
    <span class="url">%s</span>
    <span class="meta">%d bytes · %d forms · %d links · %d JS</span>
  </div>
`,
				html.EscapeString(p.URL), p.BodyLen, p.Forms, len(p.Links), len(p.JSFiles),
			)
		}
		buf.WriteString(`</section>
`)
	}

	if len(r.Capabilities) > 0 {
		buf.WriteString(`<section>
  <h2>Engine Knowledge<span class="count">verified · observed · hint</span></h2>
  <div class="caps">`)
		for _, c := range r.Capabilities {
			label := c.Name
			cls := "cap"
			switch c.Origin {
			case OriginHint:
				label = "?" + c.Name
				cls = "cap cap-hint"
			case OriginObserved:
				label = "≈" + c.Name
				cls = "cap cap-observed"
			}
			fmt.Fprintf(&buf, `    <span class="%s">%s</span>\n`, cls, html.EscapeString(label))
		}
		buf.WriteString(`  </div>
</section>
`)
	}

	if len(r.PendingDestructive) > 0 {
		buf.WriteString(`<section>
  <h2>Withheld — Consent Required</h2>
  <p style="color: var(--ink-faint); font-size: 12px; margin: 8px 0 0;">Modules that met their evidence requirements but write to or bulk-read the target. Run with <code>--destructive</code> to execute them.</p>
  <div class="withheld">`)
		for _, name := range r.PendingDestructive {
			fmt.Fprintf(&buf,
				`  <div class="withheld-item">
    <div class="withheld-name">%s</div>
    <div class="withheld-hint">withheld for lack of --destructive consent</div>
  </div>
`,
				html.EscapeString(name),
			)
		}
		buf.WriteString(`  </div>
</section>
`)
	}

	fmt.Fprintf(&buf, `<div class="footer">
  NICE_SCAN — engagement complete · %d steps · %.0f seconds · evidence-first reporting
</div>

<script>
  // Severity filter — vanilla JS, no dependency.
  (function () {
    var buttons = document.querySelectorAll('.filter-btn');
    var items = document.querySelectorAll('.finding');
    buttons.forEach(function (btn) {
      btn.addEventListener('click', function () {
        buttons.forEach(function (b) { b.classList.remove('active'); });
        btn.classList.add('active');
        var sev = btn.dataset.severity;
        items.forEach(function (item) {
          if (sev === 'all' || item.dataset.severity === sev) {
            item.classList.remove('rs-hidden');
          } else {
            item.classList.add('rs-hidden');
          }
        });
      });
    });
  })();

  // Copy evidence text to clipboard.
  function copyToClipboard(btn) {
    var finding = btn.closest('.finding');
    var text = finding.querySelector('.f-evid').innerText;
    navigator.clipboard.writeText(text).then(function () {
      var old = btn.innerText;
      btn.innerText = 'Copied';
      setTimeout(function () { btn.innerText = old; }, 1200);
    });
  }
</script>
</body>
</html>`, r.Steps, r.Duration.Seconds())

	return buf.String()
}

// riskClass maps the numeric risk score to the CSS severity bucket.
func riskClass(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 5.0:
		return "medium"
	default:
		return "low"
	}
}
