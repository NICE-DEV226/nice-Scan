package fingerprint

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/nice-scan/nice_scan/internal/types"
)

type Fingerprinter struct {
	signatures []Signature
}

type Signature struct {
	Name       string
	Type       string
	Category   string
	Confidence float64
	Headers    map[string]*regexp.Regexp
	Cookies    map[string]*regexp.Regexp
	HTML       []*regexp.Regexp
	URL        []*regexp.Regexp
	Script     []*regexp.Regexp
	CSP        []*regexp.Regexp
	XHR        []*regexp.Regexp
}

func New() *Fingerprinter {
	f := &Fingerprinter{}
	f.loadSignatures()
	return f
}

func (f *Fingerprinter) Name() string {
	return "fingerprint"
}

func (f *Fingerprinter) Analyze(ctx context.Context, resp *types.Response) []types.Finding {
	if resp == nil {
		return nil
	}

	var findings []types.Finding

	for _, sig := range f.signatures {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		match, evidence := sig.Match(resp)
		if match {
			findings = append(findings, types.Finding{
				Type:        types.FindingTech,
				Name:        sig.Name,
				Severity:    types.SeverityInfo,
				Description: fmt.Sprintf("Detected %s (%s)", sig.Name, sig.Category),
				Evidence:    evidence,
				Confidence:  sig.Confidence,
				Metadata: map[string]string{
					"category": sig.Category,
					"type":     sig.Type,
				},
			})
		}
	}

	return findings
}

func (s *Signature) Match(resp *types.Response) (bool, string) {
	for name, pattern := range s.Headers {
		val := resp.Headers.Get(name)
		if val == "" {
			continue
		}
		if pattern.MatchString(val) {
			return true, fmt.Sprintf("header %s: %s", name, val)
		}
	}

	for name, pattern := range s.Cookies {
		for _, c := range resp.Headers.Values("Set-Cookie") {
			if strings.HasPrefix(strings.TrimSpace(c), name+"=") {
				if pattern.MatchString(c) {
					return true, fmt.Sprintf("cookie %s", name)
				}
			}
		}
	}

	for _, pattern := range s.HTML {
		if pattern.MatchString(string(resp.Body)) {
			return true, fmt.Sprintf("html pattern: %s", pattern.String())
		}
	}

	for _, pattern := range s.URL {
		if pattern.MatchString(resp.FinalURL) {
			return true, fmt.Sprintf("url pattern: %s", pattern.String())
		}
	}

	for _, pattern := range s.CSP {
		csp := resp.Headers.Get("Content-Security-Policy")
		if csp != "" && pattern.MatchString(csp) {
			return true, fmt.Sprintf("csp: %s", pattern.String())
		}
	}

	for _, pattern := range s.Script {
		if pattern.MatchString(string(resp.Body)) {
			return true, fmt.Sprintf("script pattern: %s", pattern.String())
		}
	}

	return false, ""
}

func (f *Fingerprinter) loadSignatures() {
	f.signatures = []Signature{
		// --- Web Servers ---
		{
			Name: "nginx", Type: "web_server", Category: "Server",
			Confidence: 0.95,
			Headers:    map[string]*regexp.Regexp{"Server": regexp.MustCompile(`(?i)nginx`)},
		},
		{
			Name: "Apache", Type: "web_server", Category: "Server",
			Confidence: 0.95,
			Headers:    map[string]*regexp.Regexp{"Server": regexp.MustCompile(`(?i)apache`)},
		},
		{
			Name: "Cloudflare", Type: "cdn", Category: "CDN",
			Confidence: 0.95,
			Headers: map[string]*regexp.Regexp{
				"Server":              regexp.MustCompile(`(?i)cloudflare`),
				"CF-Ray":              regexp.MustCompile(`.+`),
			},
		},
		{
			Name: "Vercel", Type: "hosting", Category: "Hosting",
			Confidence: 0.9,
			Headers: map[string]*regexp.Regexp{
				"Server": regexp.MustCompile(`(?i)vercel`),
				"x-vercel-id": regexp.MustCompile(`.+`),
			},
		},
		{
			Name: "Netlify", Type: "hosting", Category: "Hosting",
			Confidence: 0.9,
			Headers: map[string]*regexp.Regexp{
				"Server": regexp.MustCompile(`(?i)netlify`),
			},
		},
		{
			Name: "GitHub Pages", Type: "hosting", Category: "Hosting",
			Confidence: 0.85,
			Headers: map[string]*regexp.Regexp{
				"Server":              regexp.MustCompile(`(?i)GitHub\.com`),
			},
		},

		// --- WAFs ---
		{
			Name: "Cloudflare WAF", Type: "waf", Category: "WAF",
			Confidence: 0.8,
			Headers: map[string]*regexp.Regexp{
				"CF-Cache-Status": regexp.MustCompile(`.+`),
			},
		},
		{
			Name: "AWS WAF", Type: "waf", Category: "WAF",
			Confidence: 0.7,
			Headers: map[string]*regexp.Regexp{
				"x-amzn-RequestId": regexp.MustCompile(`.+`),
				"x-amzn-WAF":       regexp.MustCompile(`.+`),
			},
		},

		// --- Frameworks ---
		{
			Name: "Next.js", Type: "framework", Category: "React Framework",
			Confidence: 0.85,
			Headers: map[string]*regexp.Regexp{
				"x-nextjs-cache": regexp.MustCompile(`.+`),
			},
			HTML: []*regexp.Regexp{
				regexp.MustCompile(`__NEXT_DATA__`),
				regexp.MustCompile(`/_next/static`),
			},
		},
		{
			Name: "React", Type: "frontend", Category: "UI Library",
			Confidence: 0.75,
			HTML: []*regexp.Regexp{
				regexp.MustCompile(`react\.js`),
				regexp.MustCompile(`__REACT_DEVTOOLS`),
			},
			Script: []*regexp.Regexp{
				regexp.MustCompile(`React\.createElement`),
				regexp.MustCompile(`_react2\b`),
			},
		},
		{
			Name: "Vue.js", Type: "frontend", Category: "UI Library",
			Confidence: 0.8,
			HTML: []*regexp.Regexp{
				regexp.MustCompile(`(?i)vue\.js`),
				regexp.MustCompile(`__VUE__`),
				regexp.MustCompile(`data-v-[a-f0-9]+`),
				regexp.MustCompile(`v-bind|v-if|v-for|v-model`),
			},
		},
		{
			Name: "Angular", Type: "frontend", Category: "UI Library",
			Confidence: 0.8,
			HTML: []*regexp.Regexp{
				regexp.MustCompile(`ng-version`),
				regexp.MustCompile(`ng-app`),
				regexp.MustCompile(`_ngcontent`),
			},
		},
		{
			Name: "Nuxt.js", Type: "framework", Category: "Vue Framework",
			Confidence: 0.8,
			HTML: []*regexp.Regexp{
				regexp.MustCompile(`__NUXT__`),
			},
		},
		{
			Name: "Express", Type: "framework", Category: "Backend",
			Confidence: 0.6,
			Headers: map[string]*regexp.Regexp{
				"X-Powered-By": regexp.MustCompile(`(?i)express`),
			},
		},
		{
			Name: "Django", Type: "framework", Category: "Backend",
			Confidence: 0.8,
			Headers: map[string]*regexp.Regexp{
				"Server": regexp.MustCompile(`(?i)WSGIServer`),
			},
			Cookies: map[string]*regexp.Regexp{
				"csrftoken": regexp.MustCompile(`.+`),
				"sessionid": regexp.MustCompile(`.+`),
			},
		},

		// --- CMS ---
		{
			Name: "WordPress", Type: "cms", Category: "CMS",
			Confidence: 0.9,
			HTML: []*regexp.Regexp{
				regexp.MustCompile(`(?i)wp-content`),
				regexp.MustCompile(`(?i)wp-includes`),
				regexp.MustCompile(`generator" content="WordPress`),
			},
		},
		{
			Name: "Laravel", Type: "framework", Category: "Backend",
			Confidence: 0.75,
			Cookies: map[string]*regexp.Regexp{
				"laravel_session": regexp.MustCompile(`.+`),
				"XSRF-TOKEN":      regexp.MustCompile(`.+`),
			},
		},
		{
			Name: "Ruby on Rails", Type: "framework", Category: "Backend",
			Confidence: 0.8,
			Headers: map[string]*regexp.Regexp{
				"X-Powered-By": regexp.MustCompile(`(?i)Phusion`),
			},
			Cookies: map[string]*regexp.Regexp{
				"_session": regexp.MustCompile(`.+`),
			},
		},

		// --- Cloud ---
		{
			Name: "AWS", Type: "cloud", Category: "Cloud Provider",
			Confidence: 0.7,
			Headers: map[string]*regexp.Regexp{
				"x-amz-request-id": regexp.MustCompile(`.+`),
				"x-amz-id-2":      regexp.MustCompile(`.+`),
			},
		},
		{
			Name: "Google Cloud", Type: "cloud", Category: "Cloud Provider",
			Confidence: 0.6,
			Headers: map[string]*regexp.Regexp{
				"via": regexp.MustCompile(`(?i)google`),
			},
		},
	}
}

func (f *Fingerprinter) LoadCustom(signatures []Signature) {
	f.signatures = append(f.signatures, signatures...)
}

func (f *Fingerprinter) Signatures() int {
	return len(f.signatures)
}
