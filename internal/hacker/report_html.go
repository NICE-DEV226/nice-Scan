package hacker

import (
	"bytes"
	"fmt"
	"html"
	"time"
)

func RenderHTMLReport(r *Report) string {
	var buf bytes.Buffer

	buf.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NICE HACKER — Attack Report</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { 
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #1a1b26; color: #c0caf5; padding: 40px; line-height: 1.6;
  }
  .container { max-width: 1100px; margin: 0 auto; }
  
  .header {
    border-bottom: 2px solid #3B4261; padding-bottom: 20px; margin-bottom: 30px;
  }
  .header h1 { color: #7DCFFF; font-size: 28px; margin-bottom: 5px; }
  .header .subtitle { color: #565F89; font-size: 14px; }
  
  .meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }
  .meta-card {
    background: #24283B; border: 1px solid #3B4261; border-radius: 8px; padding: 15px;
  }
  .meta-card .label { color: #565F89; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }
  .meta-card .value { color: #C0CAF5; font-size: 18px; font-weight: bold; margin-top: 5px; }
  
  .risk-critical { color: #F7768E; }
  .risk-high { color: #FF9E64; }
  .risk-medium { color: #E0AF68; }
  .risk-low { color: #7DCFFF; }
  
  section { margin-bottom: 30px; }
  section h2 { color: #7DCFFF; font-size: 18px; margin-bottom: 15px; padding-bottom: 8px; border-bottom: 1px solid #3B4261; }
  
  .finding {
    background: #24283B; border-left: 3px solid #3B4261; border-radius: 6px; padding: 12px 16px; margin-bottom: 10px;
  }
  .finding.critical { border-left-color: #F7768E; }
  .finding.high { border-left-color: #FF9E64; }
  .finding.medium { border-left-color: #E0AF68; }
  .finding.low { border-left-color: #7DCFFF; }
  .finding.info { border-left-color: #565F89; }
  .finding .sev { font-weight: bold; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }
  .finding .name { font-size: 14px; margin: 3px 0; }
  .finding .desc { color: #9AA5CE; font-size: 12px; }
  .finding .evid { color: #565F89; font-size: 11px; margin-top: 5px; word-break: break-all; }
  
  .chain {
    background: linear-gradient(135deg, #24283B 0%, #2a1e3a 100%);
    border: 1px solid #F7768E; border-radius: 8px; padding: 15px; margin-bottom: 10px;
  }
  .chain .chain-name { color: #F7768E; font-weight: bold; font-size: 15px; }
  .chain .chain-risk { font-size: 13px; margin: 5px 0; }
  
  .cap-grid { display: flex; flex-wrap: wrap; gap: 8px; }
  .cap-badge {
    background: #1a3a2a; color: #9ECE6A; border: 1px solid #2d5a3a;
    border-radius: 20px; padding: 3px 12px; font-size: 12px;
  }

  .endpoint { font-family: 'Fira Code', monospace; padding: 4px 0; }
  .endpoint .method { 
    display: inline-block; width: 50px; text-align: center; font-weight: bold;
    border-radius: 3px; padding: 1px 4px; margin-right: 8px; font-size: 11px;
  }
  .method-GET { background: #1a3a5a; color: #7DCFFF; }
  .method-POST { background: #3a3a1a; color: #E0AF68; }
  .method-PUT { background: #3a2a1a; color: #FF9E64; }
  .method-DELETE { background: #3a1a1a; color: #F7768E; }

  .page-item { padding: 6px 0; }
  .page-item .url { color: #7DCFFF; }
  .page-item .meta { color: #565F89; font-size: 12px; }

  .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #3B4261; color: #565F89; font-size: 12px; text-align: center; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>NICE HACKER — Attack Report</h1>
    <div class="subtitle">Autonomous penetration test generated `+fmt.Sprintf("on %s", time.Now().Format("January 2, 2006 at 15:04"))+`</div>
  </div>
  
  <div class="meta-grid">
    <div class="meta-card">
      <div class="label">Target</div>
      <div class="value" style="font-size:14px">`+html.EscapeString(r.Target)+`</div>
    </div>
    <div class="meta-card">
      <div class="label">Duration</div>
      <div class="value">`+fmt.Sprintf("%.0f", r.Duration.Seconds())+`s</div>
    </div>
    <div class="meta-card">
      <div class="label">Steps</div>
      <div class="value">`+fmt.Sprintf("%d", r.Steps)+`</div>
    </div>
    <div class="meta-card">
      <div class="label">Risk Score</div>
      <div class="value `+riskClass(r.RiskScore)+`">`+fmt.Sprintf("%.1f", r.RiskScore)+` / 10</div>
    </div>
  </div>
`)

	buf.WriteString(`  <section>
    <h2>Impact Summary</h2>
    <p style="color:#9AA5CE">` + html.EscapeString(r.Impact) + `</p>
  </section>
`)

	if len(r.AttackChains) > 0 {
		buf.WriteString(`  <section>
    <h2>Attack Chains Discovered</h2>
`)
		for _, chain := range r.AttackChains {
			buf.WriteString(fmt.Sprintf(
				`    <div class="chain">
      <div class="chain-name">⚡ %s</div>
      <div class="chain-risk risk-%s">Risk: %.0f/10</div>
      <div style="color:#9AA5CE;font-size:13px">→ %s</div>
    </div>
`,
				html.EscapeString(chain.Name),
				riskClass(chain.RiskScore),
				chain.RiskScore,
				html.EscapeString(chain.Impact),
			))
		}
		buf.WriteString("  </section>\n")
	}

	if len(r.Findings) > 0 {
		buf.WriteString(`  <section>
    <h2>Findings</h2>
`)
		for _, f := range r.Findings {
			sev := string(f.Severity)
			buf.WriteString(fmt.Sprintf(
				`    <div class="finding %s">
      <div class="sev %s">%s</div>
      <div class="name">%s</div>
      <div class="desc">%s</div>
      <div class="evid">%s</div>
    </div>
`,
				sev, sevClass(f.Severity),
				sev,
				html.EscapeString(f.Name),
				html.EscapeString(f.Description),
				html.EscapeString(f.Evidence),
			))
		}
		buf.WriteString("  </section>\n")
	}

	if len(r.Capabilities) > 0 {
		buf.WriteString(`  <section>
    <h2>Capabilities Acquired</h2>
    <div class="cap-grid">
`)
		for _, c := range r.Capabilities {
			buf.WriteString(fmt.Sprintf(
				`      <span class="cap-badge">%s</span>
`,
				html.EscapeString(c.Name),
			))
		}
		buf.WriteString("    </div>\n  </section>\n")
	}

	if len(r.Credentials) > 0 {
		buf.WriteString(`  <section>
    <h2>Credentials Obtained</h2>
`)
		for _, c := range r.Credentials {
			valid := "valid"
			if !c.Valid {
				valid = "tested"
			}
			buf.WriteString(fmt.Sprintf(
				`    <div class="finding critical">
      <div class="name">%s:%s (%s)</div>
      <div class="desc">Source: %s</div>
    </div>
`,
				html.EscapeString(c.Username), html.EscapeString(c.Password), valid,
				html.EscapeString(c.Source),
			))
		}
		buf.WriteString("  </section>\n")
	}

	if len(r.Endpoints) > 0 {
		buf.WriteString(`  <section>
    <h2>Endpoints Discovered</h2>
`)
		for _, e := range r.Endpoints {
			buf.WriteString(fmt.Sprintf(
				`    <div class="endpoint"><span class="method method-%s">%s</span> <span style="color:#C0CAF5">%s</span> <span style="color:#565F89">[%d]</span></div>
`,
				e.Method, e.Method,
				html.EscapeString(e.Path), e.Status,
			))
		}
		buf.WriteString("  </section>\n")
	}

	if len(r.Pages) > 0 {
		buf.WriteString(fmt.Sprintf(`  <section>
    <h2>Pages Crawled (%d)</h2>
`, len(r.Pages)))
		for _, p := range r.Pages {
			buf.WriteString(fmt.Sprintf(
				`    <div class="page-item"><span class="url">%s</span> <span class="meta">(%d bytes, %d forms, %d links, %d JS)</span></div>
`,
				html.EscapeString(p.URL), p.BodyLen, p.Forms, len(p.Links), len(p.JSFiles),
			))
		}
		buf.WriteString("  </section>\n")
	}

	buf.WriteString(fmt.Sprintf(`  <div class="footer">
    NICE HACKER — Attack Complete &mdash; %d steps in %.0f seconds
  </div>
</div>
</body>
</html>`, r.Steps, r.Duration.Seconds()))

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
