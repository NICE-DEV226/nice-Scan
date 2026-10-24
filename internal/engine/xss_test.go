package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// Regression for the old keyword matcher: pages carrying <script>, <div>,
// <img>, onerror=… are NOT XSS findings. Only our own canary-tagged probe
// responses are analyzed.
func TestXSSAnalyzerSilentOnForeignPageContent(t *testing.T) {
	a := NewXSSAnalyzer("nsxTESTCANARY")
	resp := &types.Response{
		StatusCode:  200,
		ContentType: "text/html; charset=utf-8",
		Body: []byte(`<html><head><title>t</title><script>alert(1)</script></head>` +
			`<body><div class="col"><img src="/logo.png" onerror=alert(1)>` +
			`<svg><rect/></svg><iframe srcdoc="<b>x"></iframe></body></html>`),
		RequestURL: "http://target.local/",
	}
	if fs := a.Analyze(context.Background(), resp); len(fs) != 0 {
		t.Fatalf("keyword-shaped page must stay silent; got %d findings", len(fs))
	}
}

func TestXSSAnalyzerSilentWhenPayloadReflectedWithoutCanary(t *testing.T) {
	// The pre-P0 probes embedded a static payload; a target echoing it is
	// still not evidence without the scan canary.
	a := NewXSSAnalyzer("nsxTESTCANARY")
	resp := &types.Response{
		StatusCode:  200,
		ContentType: "text/html",
		Body:        []byte(`<p>echo: "><img src=x onerror=alert(1)></p>`),
		RequestURL:  "http://target.local/?q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
	}
	if fs := a.Analyze(context.Background(), resp); len(fs) != 0 {
		t.Fatal("verbatim old-payload reflection without the scan canary must stay silent")
	}
}

func TestXSSAnalyzerExecutableReflection(t *testing.T) {
	a := NewXSSAnalyzer("nsxTESTCANARY")
	resp := &types.Response{
		StatusCode:  200,
		ContentType: "text/html",
		Body: []byte(`<div id="q">'">nsxTESTCANARY><svg onload=alert('nsxTESTCANARY')>` +
			`somestatic<script>alert(1)</script></div>`),
		RequestURL: "http://target.local/?q=%22%27%3EnsxTESTCANARY%3E%3Csvg%20onload%3Dalert(%27nsxTESTCANARY%27)%3E",
	}
	fs := a.Analyze(context.Background(), resp)
	if len(fs) != 1 {
		t.Fatalf("expected exactly one finding, got %d", len(fs))
	}
	f := fs[0]
	if f.Name != "XSS Reflection (executable markup)" {
		t.Fatalf("wrong classification: %q", f.Name)
	}
	if f.Severity != types.SeverityHigh {
		t.Fatalf("executable markup must be high, got %q", f.Severity)
	}
	if f.Metadata["param"] != "q" {
		t.Fatalf("param not extracted from probe URL: %q", f.Metadata["param"])
	}
	if !strings.Contains(f.Evidence, "nsxTESTCANARY") {
		t.Fatalf("evidence must carry the reflection snippet: %q", f.Evidence)
	}
}

func TestXSSAnalyzerEscapedReflection(t *testing.T) {
	a := NewXSSAnalyzer("nsxTESTCANARY")
	resp := &types.Response{
		StatusCode:  200,
		ContentType: "text/html",
		Body:        []byte(`<p>q: &lt;svg onload=alert(&#39;nsxTESTCANARY&#39;)&gt;</p>`),
		RequestURL:  "http://target.local/?q=%3Csvg%20onload%3Dalert(%27nsxTESTCANARY%27)%3E",
	}
	fs := a.Analyze(context.Background(), resp)
	if len(fs) != 1 {
		t.Fatalf("escaped echo is still a reflection worth one finding, got %d", len(fs))
	}
	if fs[0].Name != "XSS Reflection (escaped)" {
		t.Fatalf("wrong classification: %q", fs[0].Name)
	}
	if fs[0].Severity != types.SeverityLow {
		t.Fatalf("escaped reflection must be low, got %q", fs[0].Severity)
	}
}

func TestXSSAnalyzerNonProbeRequestsSilent(t *testing.T) {
	a := NewXSSAnalyzer("nsxTESTCANARY")
	resp := &types.Response{
		StatusCode:  200,
		ContentType: "text/html",
		// content that contains the canary string only outside our probes
		// (a page literally about canaries): no probe has been sent there
		Body:       []byte(`<p>nsxTESTCANARY study group</p>`),
		RequestURL: "http://target.local/docs/canaries",
	}
	if fs := a.Analyze(context.Background(), resp); len(fs) != 0 {
		t.Fatal("non-probe responses must stay silent even if text matches")
	}
}

// Scanner / analyzer canary contract: the probes the scanner builds embed
// exactly the token the analyzer was built with, URL-encoded markup.
func TestScannerXSSCanaryContract(t *testing.T) {
	s := NewScanner(&types.Config{}, transport.NewClient())
	reqs := s.buildProbes("http://target.local")

	xssProbes := 0
	for _, r := range reqs {
		if !strings.Contains(r.URL, s.XSSCanary()) {
			continue
		}
		xssProbes++
		// the markup of the vector must be URL-encoded, not raw: no raw
		// angle bracket may appear in a probe URL
		if strings.Contains(r.URL, "<") {
			t.Fatalf("vector markup must be query-escaped in the probe URL: %q", r.URL)
		}
		if r.Method != "GET" {
			t.Fatalf("XSS probes must be GETs, got %q", r.Method)
		}
	}
	// two shapes × ten parameter names
	if xssProbes < 20 {
		t.Fatalf("expected at least 20 canary probes, got %d", xssProbes)
	}
}
