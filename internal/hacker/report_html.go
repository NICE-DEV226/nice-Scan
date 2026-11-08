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
// Architecture (three layers):
//
//  1. Tailwind CSS (CDN) — utility-first layout library. No build step, no
//     external asset to ship: the <script> processes every utility class
//     present in the generated markup at render time.
//  2. Custom <style> — brand design tokens + component base styles. Tokens
//     mirror internal/output/ui.go so the terminal and HTML reports share
//     one visual language (same accent, same semantic severities).
//  3. Semantic HTML5 — header/main/section, definition lists for meta data,
//     tables for tabular evidence, ARIA labels everywhere.
//
// The output is a standalone file: open it offline, print it, or archive it —
// the layout survives Tailwind not loading because every component has its
// own base CSS class.
func RenderHTMLReport(r *Report) string {
	var buf bytes.Buffer

	buf.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NICE HACKER — Attack Report</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<script src="https://cdn.tailwindcss.com"></script>
<style>
  /* ========================================================================
     Design tokens — shared with internal/output/ui.go (terminal design system)
     ======================================================================== */
  :root {
    --ds-ink: #d3d6e0;
    --ds-muted: #828a9c;
    --ds-faint: #515769;
    --ds-line: #303541;
    --ds-accent: #7aa6dc;
    --ds-good: #8fbc8f;
    --ds-warn: #d2a56c;
    --ds-fail: #e06b6b;
    --ds-bg: #1a1b26;
    --ds-surface: #24283b;
    --ds-surface-hover: #2a2f44;
    --ds-text: #c0caf5;
    --ds-radius: 8px;
    --ds-shadow: 0 1px 3px 0 rgb(0 0 0 / 0.3), 0 1px 2px -1px rgb(0 0 0 / 0.2);
  }

  * { box-sizing: border-box; }
  html { scroll-behavior: smooth; }
  body {
    background-color: var(--ds-bg);
    color: var(--ds-text);
    font-family: "Inter", ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    font-size: 14px;
    line-height: 1.6;
    -webkit-font-smoothing: antialiased;
    margin: 0;
  }
  mono { font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }

  /* Layout shell */
  .rs-shell { max-width: 1100px; margin: 0 auto; padding: 2.5rem 1.5rem; }

  /* Header */
  .rs-header { border-bottom: 1px solid var(--ds-line); padding-bottom: 1.5rem; margin-bottom: 2rem; }
  .rs-title { color: var(--ds-accent); font-size: 1.75rem; font-weight: 700; letter-spacing: -0.025em; margin: 0 0 0.5rem 0; }
  .rs-subtitle { color: var(--ds-muted); font-size: 0.875rem; }

  /* Meta grid */
  .rs-meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .rs-card { background: var(--ds-surface); border: 1px solid var(--ds-line); border-radius: var(--ds-radius); padding: 1rem; }
  .rs-label { color: var(--ds-faint); font-size: 0.7rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em; display: block; margin-bottom: 0.35rem; }
  .rs-value { color: var(--ds-ink); font-size: 1.25rem; font-weight: 600; word-break: break-all; }

  /* Sections */
  section.rs-section { margin-bottom: 2rem; }
  section.rs-section:last-child { margin-bottom: 0; }
  .rs-section-title { color: var(--ds-accent); font-size: 1.125rem; font-weight: 600; margin: 0 0 1rem 0; padding-bottom: 0.5rem; border-bottom: 1px solid var(--ds-line); display: flex; align-items: center; gap: 0.5rem; }
  .rs-section-note { color: var(--ds-muted); font-size: 0.8125rem; margin-bottom: 1rem; }

  /* Severity chip */
  .rs-sev { display: inline-block; font-size: 0.65rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; padding: 0.15rem 0.5rem; border-radius: 9999px; }
  .rs-sev.critical, .rs-sev.high { background: rgba(224, 107, 107, 0.15); color: #fca5a5; border: 1px solid rgba(224, 107, 107, 0.35); }
  .rs-sev.medium { background: rgba(210, 165, 108, 0.15); color: #fcd34d; border: 1px solid rgba(210, 165, 108, 0.35); }
  .rs-sev.low, .rs-sev.info { background: rgba(122, 166, 220, 0.15); color: #93c5fd; border: 1px solid rgba(122, 166, 220, 0.35); }

  /* Findings */
  .rs-findings { display: flex; flex-direction: column; gap: 0.75rem; }
  .rs-finding { background: var(--ds-surface); border: 1px solid var(--ds-line); border-radius: var(--ds-radius); padding: 1rem; border-left: 3px solid var(--ds-line); }
  .rs-finding.critical { border-left-color: var(--ds-fail); }
  .rs-finding.high { border-left-color: var(--ds-fail); }
  .rs-finding.medium { border-left-color: var(--ds-warn); }
  .rs-finding.low { border-left-color: var(--ds-good); }
  .rs-finding.info { border-left-color: var(--ds-muted); }
  .rs-finding-head { display: flex; align-items: baseline; gap: 0.5rem; margin-bottom: 0.35rem; }
  .rs-finding-name { color: var(--ds-ink); font-size: 0.9375rem; font-weight: 600; word-break: break-word; }
  .rs-finding-desc { color: var(--ds-muted); font-size: 0.8125rem; margin: 0 0 0.5rem 0; }
  .rs-finding-evid { color: var(--ds-faint); font-size: 0.75rem; font-family: "JetBrains Mono", ui-monospace, monospace; background: rgba(0,0,0,0.25); padding: 0.35rem 0.5rem; border-radius: 6px; word-break: break-all; max-width: 100%; }
  .rs-copy { color: var(--ds-accent); font-size: 0.7rem; cursor: pointer; text-decoration: underline; text-decoration-style: dotted; }
  .rs-copy:hover { color: #93c5fd; }
  .rs-copy:focus { outline: 2px solid var(--ds-accent); outline-offset: 2px; }
  .rs-filter-buttons { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 1rem; }
  .rs-filter-btn { background: var(--ds-surface); border: 1px solid var(--ds-line); color: var(--ds-muted); font-size: 0.75rem; padding: 0.2rem 0.6rem; border-radius: 6px; cursor: pointer; }
  .rs-filter-btn:hover { border-color: var(--ds-accent); color: var(--ds-accent); }
  .rs-filter-btn.active { background: var(--ds-accent); color: var(--ds-bg); border-color: var(--ds-accent); }
  .rs-hidden { display: none !important; }

  /* Attack chains */
  .rs-chains { display: flex; flex-direction: column; gap: 0.75rem; }
  .rs-chain { background: linear-gradient(135deg, var(--ds-surface) 0%, #2a1e3a 100%); border: 1px solid var(--ds-fail); border-radius: var(--ds-radius); padding: 1rem; }
  .rs-chain-name { color: var(--ds-fail); font-weight: 600; font-size: 0.9375rem; margin: 0 0 0.5rem 0; }
  .rs-chain-risk { color: var(--ds-muted); font-size: 0.8125rem; margin-bottom: 0.5rem; }
  .rs-chain-arrow { color: var(--ds-muted); font-size: 0.8125rem; margin-top: 0.5rem; white-space: pre-wrap; }

  /* Capabilities */
  .rs-caps { display: flex; flex-wrap: wrap; gap: 0.5rem; }
  .rs-cap { background: rgba(45, 90, 58, 0.4); color: var(--ds-good); border: 1px solid rgba(45, 90, 58, 0.35); border-radius: 9999px; padding: 0.25rem 0.75rem; font-size: 0.75rem; font-weight: 500; }

  /* Credentials */
  .rs-creds { display: flex; flex-direction: column; gap: 0.5rem; }
  .rs-cred { background: var(--ds-surface); border: 1px solid var(--ds-line); border-radius: var(--ds-radius); padding: 0.75rem 1rem; }
  .rs-cred-pair { font-family: "JetBrains Mono", ui-monospace, monospace; font-size: 0.875rem; font-weight: 600; color: var(--ds-ink); word-break: break-all; }
  .rs-cred-meta { color: var(--ds-muted); font-size: 0.75rem; }

  /* Endpoints */
  .rs-endpoints { display: flex; flex-direction: column; gap: 0.25rem; }
  .rs-endpoint { background: var(--ds-surface); border: 1px solid var(--ds-line); border-radius: var(--ds-radius); padding: 0.5rem 0.75rem; font-family: "JetBrains Mono", ui-monospace, monospace; font-size: 0.8125rem; display: flex; align-items: center; gap: 0.5rem; }
  .rs-method { display: inline-block; min-width: 34px; text-align: center; font-weight: 700; font-size: 0.68rem; border-radius: 4px; padding: 0.1rem 0.3rem; }
  .rs-method-GET { background: rgba(31, 41, 55, 0.5); color: var(--ds-accent); border: 1px solid rgba(122, 166, 220, 0.25); }
  .rs-method-POST { background: rgba(58, 58, 26, 0.3); color: var(--ds-warn); border: 1px solid rgba(210, 165, 108, 0.25); }
  .rs-method-PUT { background: rgba(58, 42, 26, 0.3); color: #fbbf24; border: 1px solid rgba(251, 191, 36, 0.25); }
  .rs-method-DELETE { background: rgba(58, 26, 26, 0.3); color: var(--ds-fail); border: 1px solid rgba(224, 107, 107, 0.25); }
  .rs-path { color: var(--ds-ink); flex: 1; }
  .rs-status { color: var(--ds-faint); margin-left: auto; }

  /* Pages */
  .rs-pages { display: flex; flex-direction: column; gap: 0.25rem; }
  .rs-page { background: var(--ds-surface); border: 1px solid var(--ds-line); border-radius: var(--ds-radius); padding: 0.5rem 0.75rem; display: flex; justify-content: space-between; align-items: baseline; gap: 0.5rem; }
  .rs-page-url { color: var(--ds-accent); font-family: "JetBrains Mono", ui-monospace, monospace; font-size: 0.8125rem; word-break: break-all; }
  .rs-page-meta { color: var(--ds-muted); font-size: 0.72rem; font-family: "JetBrains Mono", ui-monospace, monospace; }

  /* Withheld (consent) */
  .rs-withheld { display: flex; flex-direction: column; gap: 0.5rem; }
  .rs-withheld-item { background: rgba(128, 128, 128, 0.06); border: 1px dashed var(--ds-line); border-radius: var(--ds-radius); padding: 0.5rem 0.75rem; }
  .rs-withheld-name { color: var(--ds-ink); font-size: 0.875rem; font-weight: 500; }
  .rs-withheld-hint { color: var(--ds-muted); font-size: 0.75rem; }

  /* Footer */
  .rs-footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--ds-line); color: var(--ds-muted); font-size: 0.75rem; text-align: center; }

  /* Accessibility: focus visible */
  :focus-visible { outline: 2px solid var(--ds-accent); outline-offset: 2px; }

  /* Print */
  @media print {
    body { background: #fff; color: #111; padding: 0; }
    .rs-shell { max-width: none; padding: 0; }
    .rs-section-title { color: #111; border-bottom-color: #999; }
    .rs-card, .rs-finding, .rs-chain, .rs-cred, .rs-endpoint, .rs-page, .rs-withheld-item { background: #fff !important; border-color: #999 !important; color: #111 !important; }
    .rs-cap { background: #f0f0f0 !important; color: #111 !important; border-color: #999 !important; }
    .rs-sev.critical, .rs-sev.high { background: #fee2e2 !important; color: #991b1b !important; border-color: #fca5a5 !important; }
    .rs-sev.medium { background: #fef3c7 !important; color: #92400e !important; border-color: #fcd34d !important; }
    .rs-sev.low, .rs-sev.info { background: #eff6ff !important; color: #1e3a8a !important; border-color: #93c5fd !important; }
    .rs-copy, .rs-filter-buttons, .rs-footer { display: none !important; }
  }
</style>
</head>
<body>
<div class="rs-shell">

  <header class="rs-header">
    <h1 class="rs-title">NICE HACKER — Attack Report</h1>
    <p class="rs-subtitle">Autonomous penetration test · generated ` + fmt.Sprintf("on %s", time.Now().Format("January 2, 2006 at 15:04")) + `</p>
  </header>

  <div class="rs-meta">
    <div class="rs-card"><span class="rs-label">Target</span><span class="rs-value">` + html.EscapeString(r.Target) + `</span></div>
    <div class="rs-card"><span class="rs-label">Duration</span><span class="rs-value">` + fmt.Sprintf("%.0f", r.Duration.Seconds()) + `s</span></div>
    <div class="rs-card"><span class="rs-label">Steps</span><span class="rs-value">` + fmt.Sprintf("%d", r.Steps) + `</span></div>
    <div class="rs-card"><span class="rs-label">Risk Score</span><span class="rs-value rs-sev ` + riskSeverityClass(r.RiskScore) + `">` + fmt.Sprintf("%.1f", r.RiskScore) + ` / 10</span></div>
  </div>

  <section class="rs-section" aria-labelledby="impact-heading">
    <h2 id="impact-heading" class="rs-section-title">Impact Summary</h2>
    <p class="rs-section-note">` + html.EscapeString(r.Impact) + `</p>
  </section>
`)

	if len(r.AttackChains) > 0 {
		buf.WriteString(`  <section class="rs-section" aria-labelledby="chains-heading">
    <h2 id="chains-heading" class="rs-section-title">⚡ Attack Chain Hypotheses</h2>
    <p class="rs-section-note">Compound attack hypotheses — not executed against the target.</p>
    <div class="rs-chains">`)
		for _, chain := range r.AttackChains {
			fmt.Fprintf(&buf,
				`      <div class="rs-chain">
        <div class="rs-chain-name">%s</div>
        <div class="rs-chain-risk">Risk: %.0f/10 if executed</div>
        <div class="rs-chain-arrow">→ %s</div>
      </div>
`,
				html.EscapeString(chain.Name),
				chain.RiskScore,
				html.EscapeString(chain.Impact),
			)
		}
		buf.WriteString(`    </div>
  </section>
`)
	}

	if len(r.Findings) > 0 {
		buf.WriteString(`  <section class="rs-section" aria-labelledby="findings-heading">
    <h2 id="findings-heading" class="rs-section-title">🔎 Findings</h2>
    <div class="rs-filter-buttons" role="group" aria-label="Filter findings by severity">
      <button class="rs-filter-btn active" data-severity="all">All</button>
      <button class="rs-filter-btn" data-severity="critical">Critical</button>
      <button class="rs-filter-btn" data-severity="high">High</button>
      <button class="rs-filter-btn" data-severity="medium">Medium</button>
      <button class="rs-filter-btn" data-severity="low">Low</button>
      <button class="rs-filter-btn" data-severity="info">Info</button>
    </div>
    <div class="rs-findings" id="findings-list">`)
		for _, f := range r.Findings {
			// The HTML report leaves the machine and lands in a browser:
			// remote text is redacted here exactly as in the JSON sink,
			// not merely escaped.
			f = redactFinding(f)
			sev := string(f.Severity)
			fmt.Fprintf(&buf,
				`      <div class="rs-finding %s" data-severity="%s">
        <div class="rs-finding-head">
          <span class="rs-sev %s">%s</span>
          <button class="rs-copy" title="Copy evidence to clipboard" onclick="copyToClipboard(this)">Copy</button>
        </div>
        <div class="rs-finding-name">%s</div>
        <div class="rs-finding-desc">%s</div>
        <div class="rs-finding-evid">%s</div>
      </div>
`,
				sev, strings.ToLower(sev),
				sevClass(f.Severity), sev,
				html.EscapeString(f.Name),
				html.EscapeString(f.Description),
				html.EscapeString(f.Evidence),
			)
		}
		buf.WriteString(`    </div>
  </section>
`)
	}

	if len(r.Credentials) > 0 {
		buf.WriteString(`  <section class="rs-section" aria-labelledby="credentials-heading">
    <h2 id="credentials-heading" class="rs-section-title">🔑 Credentials Obtained</h2>
    <div class="rs-creds">`)
		for _, c := range r.Credentials {
			valid := "tested"
			if c.Valid {
				valid = "valid"
			}
			fmt.Fprintf(&buf,
				`      <div class="rs-cred">
        <div class="rs-cred-pair">%s:%s</div>
        <div class="rs-cred-meta">source: %s · status: %s</div>
      </div>
`,
				html.EscapeString(types.RedactText(c.Username)),
				html.EscapeString(types.MaskSecret(c.Password)),
				html.EscapeString(c.Source),
				valid,
			)
		}
		buf.WriteString(`    </div>
  </section>
`)
	}

	if len(r.Endpoints) > 0 {
		buf.WriteString(`  <section class="rs-section" aria-labelledby="endpoints-heading">
    <h2 id="endpoints-heading" class="rs-section-title">🌐 Endpoints Discovered</h2>
    <div class="rs-endpoints">`)
		for _, e := range r.Endpoints {
			fmt.Fprintf(&buf,
				`      <div class="rs-endpoint">
        <span class="rs-method rs-method-%s">%s</span>
        <span class="rs-path">%s</span>
        <span class="rs-status">[%d]</span>
      </div>
`,
				html.EscapeString(e.Method), html.EscapeString(e.Method),
				html.EscapeString(e.Path), e.Status,
			)
		}
		buf.WriteString(`    </div>
  </section>
`)
	}

	if len(r.Pages) > 0 {
		fmt.Fprintf(&buf, `  <section class="rs-section" aria-labelledby="pages-heading">
    <h2 id="pages-heading" class="rs-section-title">📄 Pages Crawled (%d)</h2>
    <div class="rs-pages">`, len(r.Pages))
		for _, p := range r.Pages {
			fmt.Fprintf(&buf,
				`      <div class="rs-page">
        <span class="rs-page-url">%s</span>
        <span class="rs-page-meta">%d bytes · %d forms · %d links · %d JS</span>
      </div>
`,
				html.EscapeString(p.URL), p.BodyLen, p.Forms, len(p.Links), len(p.JSFiles),
			)
		}
		buf.WriteString(`    </div>
  </section>
`)
	}

	if len(r.Capabilities) > 0 {
		buf.WriteString(`  <section class="rs-section" aria-labelledby="capabilities-heading">
    <h2 id="capabilities-heading" class="rs-section-title">🧠 Engine Knowledge (verified · observed · hint)</h2>
    <div class="rs-caps">`)
		for _, c := range r.Capabilities {
			label := c.Name
			switch c.Origin {
			case OriginHint:
				label = "?" + c.Name
			case OriginObserved:
				label = "≈" + c.Name
			}
			fmt.Fprintf(&buf,
				`      <span class="rs-cap">%s</span>
`,
				html.EscapeString(label),
			)
		}
		buf.WriteString(`    </div>
  </section>
`)
	}

	if len(r.PendingDestructive) > 0 {
		buf.WriteString(`  <section class="rs-section" aria-labelledby="withheld-heading">
    <h2 id="withheld-heading" class="rs-section-title">🔒 Withheld — consent required</h2>
    <p class="rs-section-note">Modules that met their evidence requirements but write to or bulk-read the target. Run with <code class="bg-white/5 px-1 py-0.5 rounded">--destructive</code> to execute them.</p>
    <div class="rs-withheld">`)
		for _, name := range r.PendingDestructive {
			fmt.Fprintf(&buf,
				`      <div class="rs-withheld-item">
        <div class="rs-withheld-name">%s</div>
        <div class="rs-withheld-hint">withheld for lack of --destructive consent</div>
      </div>
`,
				html.EscapeString(name),
			)
		}
		buf.WriteString(`    </div>
  </section>
`)
	}

	fmt.Fprintf(&buf, `  <footer class="rs-footer">
    NICE HACKER — Attack Complete &mdash; %d steps in %.0f seconds
  </footer>
</div>

<script>
  // Severity filter — vanilla JS, no dependency.
  (function () {
    var buttons = document.querySelectorAll('.rs-filter-btn');
    var items = document.querySelectorAll('.rs-finding');
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
    var finding = btn.closest('.rs-finding');
    var text = finding.querySelector('.rs-finding-evid').innerText;
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

// riskSeverityClass returns the Tailwind-adjacent chip class for a numeric risk score.
func riskSeverityClass(score float64) string {
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

func sevClass(s Severity) string {
	switch s {
	case SevCritical:
		return "sev-critical"
	case SevHigh:
		return "sev-high"
	case SevMedium:
		return "sev-medium"
	case SevLow:
		return "sev-low"
	default:
		return "sev-info"
	}
}
