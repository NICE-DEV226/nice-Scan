package hacker

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/NICE-DEV226/nice-Scan/internal/detect"
	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// XSSAction probes reflected parameters with unique canary-tagged shapes
// and claims results only on classified reflection: executable markup,
// script-block context, or escaped echo. The previous implementation sent
// a 22-payload battery (including remote-fetch payloads toward a
// third-party host) per reflected param and credited a hit when the page
// carried the payload string verbatim — a claim independent of whether the
// payload could ever execute.
type XSSAction struct{}

func (a *XSSAction) Metadata() ActionMetadata {
	return ActionMetadata{
		Name:        "XSS Injector",
		Description: "Canary-tagged reflection probes with context classification",
		Priority:    45,
		// Self-qualifying: the probe itself is a canary randomised per
		// action/param; a verdict requires the canary's OWN reflection on
		// the wire. No capability seed needed — needing a "has_xss" hint
		// seeded by reading the word "XSS" in ANOTHER finding's remote-
		// controlled text was the wiring defect that left this feature dead
		// in orchestrated runs (it only ever fired by accident).
		Requires: []string{},
		Provides: []string{"has_xss_exploit"},
	}
}

func (a *XSSAction) Execute(ctx context.Context, target string, kb *Knowledge, client *transport.Client) ActionResult {
	var findings []Finding
	var spawned []Action

	pages := kb.GetPages()
	if len(pages) == 0 {
		return ActionResult{}
	}

	canary := detect.NewCanary()
	probes := detect.XssProbes(canary)

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
			select {
			case <-ctx.Done():
				return ActionResult{Findings: findings, Actions: spawned}
			default:
			}

			state, rx, vectorName, probeURL := "", detect.XssReflex{}, "", ""
			for _, vp := range probes {
				testURL := appendQueryParam(page.URL, param, vp.Value)
				resp, err := client.Do(ctx, &types.Request{
					Method: "GET",
					URL:    testURL,
				})
				if err != nil {
					continue
				}

				cur, reflected := detect.ClassifyXss(resp.Body, canary)
				if !reflected {
					continue
				}

				level := reflexLevel("echo")
				if cur.Encoded {
					level = reflexLevel("encoded")
				}
				if cur.InScript {
					level = reflexLevel("script")
				}
				if cur.Executable {
					level = reflexLevel("exec")
				}
				if level > reflexLevel(state) {
					state, rx, vectorName, probeURL = levelName(level), cur, vp.Name, testURL
				}
			}

			switch state {
			case "exec":
				findings = append(findings, Finding{
					Type:     "xss_confirmed",
					Name:     fmt.Sprintf("XSS confirmed: %s vector via param %s", vectorName, param),
					Severity: SevHigh,
					Description: fmt.Sprintf(
						"Canary-tagged probe reflected executable markup outside neutralizing containers (param %q, vector %s)", param, vectorName),
					Evidence: fmt.Sprintf("URL: %s\nReflection: %s", probeURL, rx.Snippet),
					Details: map[string]string{
						"param":  param,
						"vector": vectorName,
						"method": "canary-reflection-differential",
					},
				})
				kb.AddCapability(Capability{
					Name:   "has_xss_exploit",
					Origin: OriginVerified,
					Target: target,
					Details: map[string]string{
						"param":  param,
						"vector": vectorName,
						"url":    probeURL,
					},
				})
				spawned = append(spawned, &XSSExploitAction{
					vulnURL:   probeURL,
					param:     param,
					technique: vectorName,
				})
			case "script":
				findings = append(findings, Finding{
					Type:     "xss_script_context",
					Name:     fmt.Sprintf("XSS reflection in script context: param %s", param),
					Severity: SevMedium,
					Description: fmt.Sprintf(
						"Canary landed inside a <script> block via vector %s; exploitation depends on surrounding JS", vectorName),
					Evidence: probeURL + "\n" + rx.Snippet,
				})
			case "encoded":
				findings = append(findings, Finding{
					Type:     "xss_reflected_escaped",
					Name:     fmt.Sprintf("XSS reflection escaped: param %s", param),
					Severity: SevLow,
					Description: fmt.Sprintf(
						"Canary reflected with entity-encoded markup neighbors (%s vector); payload does not execute as reflected", vectorName),
					Evidence: rx.Snippet,
				})
			default:
				// Plain echo — the page-level reflection-points finding
				// already documents the surface; no extra claim.
			}
		}
	}

	return ActionResult{Findings: findings, Actions: spawned}
}

// reflexLevel ranks reflection classes: exec > script > encoded > echo.
func reflexLevel(state string) int {
	switch state {
	case "exec":
		return 4
	case "script":
		return 3
	case "encoded":
		return 2
	default:
		return 1
	}
}

func levelName(level int) string {
	switch level {
	case 4:
		return "exec"
	case 3:
		return "script"
	case 2:
		return "encoded"
	default:
		return "echo"
	}
}

type XSSExploitAction struct {
	vulnURL   string
	param     string
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

// Execute emits a PoC note for confirmed reflections. It is a documented
// deliverable, not an executed attack: nothing here runs against the
// target.
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

// findReflectedParams discovers which parameters echo our input, using the
// same canary discipline: unique random token, no fixed-marker collisions
// across concurrent actions. Existing query parameters are preserved (a
// rebuilt query string dropping state params is what made the boolean
// oracle flip endpoints offline — see setQueryParam in sqli.go).
func findReflectedParams(ctx context.Context, client *transport.Client, pageURL string, kb *Knowledge) []string {
	testPayload := detect.NewCanary()
	probe := url.QueryEscape(testPayload)

	var candidates []string
	if existing := extractURLParams(pageURL); len(existing) > 0 {
		for _, param := range existing {
			testURL := setQueryParam(pageURL, param, probe)
			resp, err := client.Do(ctx, &types.Request{Method: "GET", URL: testURL})
			if err != nil {
				continue
			}
			if strings.Contains(string(resp.Body), testPayload) {
				candidates = append(candidates, param)
			}
		}
	}

	if len(candidates) == 0 {
		commonParams := []string{"q", "s", "search", "query", "id", "page", "p", "name", "user", "message", "text", "comment", "content", "title", "url", "file", "path", "redirect"}
		for _, param := range commonParams {
			testURL := setQueryParam(pageURL, param, probe)
			resp, err := client.Do(ctx, &types.Request{Method: "GET", URL: testURL})
			if err != nil {
				continue
			}
			if strings.Contains(string(resp.Body), testPayload) {
				candidates = append(candidates, param)
			}
		}
	}

	return candidates
}

// appendQueryParam appends param=value with proper URL encoding, keeping
// the raw values out of the query string (the previous builder hand-rolled
// a %20 substitution that left quotes and angle brackets unescaped).
func appendQueryParam(rawURL, param, rawValue string) string {
	sep := "?"
	if strings.Contains(rawURL, "?") {
		sep = "&"
	}
	return rawURL + sep + url.QueryEscape(param) + "=" + url.QueryEscape(rawValue)
}
