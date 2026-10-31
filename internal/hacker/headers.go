package hacker

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// SmartHeadersAction audits the HTTP response headers a target actually
// serves: CSP, HSTS, content-type sniffing, framing protections, referrer
// policy, and cookie attributes (Secure / HttpOnly / SameSite / prefixes).
//
// Every claim is VERIFIED against a fetched response, and the claims are
// about parsed values — not substring presence. That distinction matters:
// `strings.Contains(setCookie, "secure")` passes a cookie merely *named*
// `secure_hint`, and `Contains(acao, "*")` called `https://*.example.com` a
// wildcard. Both are fixed here. A fetch failure becomes an "unable to
// verify" finding, never a fabricated "missing header".
type SmartHeadersAction struct{}

func (a *SmartHeadersAction) Metadata() ActionMetadata {
	return ActionMetadata{
		Name:        "Security Headers",
		Description: "HTTP security headers + cookie attributes on crawled endpoints — parsed values, verified claims only",
		Priority:    30,
		Requires:    nil,
		Provides:    []string{"has_headers"},
	}
}

type smartHeaderTarget struct {
	Label string // sanitized path shown to the operator
	URL   string // absolute URL to fetch
}

func (a *SmartHeadersAction) Execute(ctx context.Context, target string, kb *Knowledge, client *transport.Client) ActionResult {
	probes := []smartHeaderTarget{{Label: types.Sanitize(target), URL: target}}

	// Endpoints with forms carry the session-relevant cookies — their
	// header posture matters most (login/register).
	for _, p := range kb.GetPages() {
		if len(probes) >= 3 {
			break
		}
		if p.Forms > 0 && p.URL != "" && p.Status > 0 {
			probes = append(probes, smartHeaderTarget{Label: types.Sanitize(p.URL), URL: p.URL})
		}
	}

	var findings []Finding
	seen := make(map[string]bool)
	// analyzed tracks responses that actually completed. has_headers is
	// verified evidence only when a response was parsed: a run where every
	// probe failed still emits "unverifiable" findings, and claiming the
	// capability from those would be a fact the run never established.
	analyzed := 0

	for _, probe := range probes {
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		resp, err := client.Do(cctx, &types.Request{
			Method: "GET",
			URL:    probe.URL,
		})
		cancel()
		if err != nil || resp == nil {
			// Never report "missing header" for an unreachable host —
			// say the verification failed instead.
			findings = append(findings, Finding{
				Type:        "headers_unreachable",
				Name:        fmt.Sprintf("Security headers unverifiable: %s", probe.Label),
				Severity:    SevInfo,
				Description: "The request did not complete — header presence is NOT claimed either way",
				Evidence:    types.Sanitize(errString(err)),
			})
			continue
		}

		parsed := analyzeSecurityHeaders(probe.URL, probe.Label, resp.Headers)
		analyzed++
		for _, f := range parsed {
			key := f.Type + "|" + f.Name
			if seen[key] {
				continue
			}
			seen[key] = true
			findings = append(findings, f)
		}
	}

	if analyzed > 0 {
		kb.AddCapability(Capability{
			Name:   "has_headers",
			Origin: OriginVerified,
			Target: target,
			Details: map[string]string{
				"evidence":  fmt.Sprintf("%d header finding(s) from parsed response values", len(findings)),
				"derivedBy": "fetched response headers (executed read, same host)",
			},
		})
	}
	return ActionResult{Findings: findings}
}

// analyzeSecurityHeaders is a pure sink so it is directly testable.
func analyzeSecurityHeaders(rawURL, label string, hdr http.Header) []Finding {
	h := func(name string) string {
		return strings.TrimSpace(hdr.Get(name))
	}
	isHTTPS := strings.HasPrefix(strings.ToLower(rawURL), "https://")

	var findings []Finding

	csp := h("Content-Security-Policy")
	if csp == "" {
		findings = append(findings, Finding{
			Type:        "missing_csp",
			Name:        fmt.Sprintf("Missing Content-Security-Policy: %s", label),
			Severity:    SevMedium,
			Description: "No CSP header observed on this response — XSS payload impact is not reduced by any header-level containment",
			Evidence:    "Content-Security-Policy: <absent>",
		})
	} else {
		findings = append(findings, analyzeCSP(label, csp)...)
	}

	hsts := h("Strict-Transport-Security")
	switch {
	case hsts == "" && isHTTPS:
		findings = append(findings, Finding{
			Type:        "missing_hsts",
			Name:        fmt.Sprintf("Missing HSTS: %s", label),
			Severity:    SevMedium,
			Description: "HTTPS response without Strict-Transport-Security — downgrade/strip attacks stay possible for first-time visitors",
			Evidence:    "Strict-Transport-Security: <absent>",
		})
	case hsts != "":
		findings = append(findings, analyzeHSTS(label, hsts, isHTTPS)...)
	}

	if h("X-Content-Type-Options") == "" {
		findings = append(findings, Finding{
			Type:        "missing_xcto",
			Name:        fmt.Sprintf("Missing X-Content-Type-Options: %s", label),
			Severity:    SevLow,
			Description: "Browser content-type sniffing is not disabled",
			Evidence:    "X-Content-Type-Options: <absent>",
		})
	} else if !strings.EqualFold(h("X-Content-Type-Options"), "nosniff") {
		findings = append(findings, Finding{
			Type:        "xcto_invalid_value",
			Name:        fmt.Sprintf("X-Content-Type-Options has an invalid value: %s", label),
			Severity:    SevLow,
			Description: "Only 'nosniff' is honoured; browsers ignore any other value, so sniffing stays enabled",
			Evidence:    types.Sanitize("X-Content-Type-Options: " + h("X-Content-Type-Options")),
		})
	}

	// Framing protection: XFO header OR CSP frame-ancestors.
	xfo := strings.ToLower(h("X-Frame-Options"))
	frameAncestors := cspHasDirective(csp, "frame-ancestors")
	switch {
	case xfo == "" && !frameAncestors:
		findings = append(findings, Finding{
			Type:        "missing_framing_protection",
			Name:        fmt.Sprintf("No framing protection: %s", label),
			Severity:    SevMedium,
			Description: "Neither X-Frame-Options nor CSP frame-ancestors — clickjacking exposure on this surface",
			Evidence:    "X-Frame-Options: <absent>, CSP frame-ancestors: <absent>",
		})
	case xfo != "" && xfo != "deny" && xfo != "sameorigin" && !frameAncestors:
		findings = append(findings, Finding{
			Type:        "xfo_invalid_value",
			Name:        fmt.Sprintf("X-Frame-Options has an invalid value: %s", label),
			Severity:    SevMedium,
			Description: "Browsers only honour DENY or SAMEORIGIN; an unknown value (or a deprecated ALLOW-FROM) is ignored, so framing stays possible",
			Evidence:    types.Sanitize("X-Frame-Options: " + h("X-Frame-Options")),
		})
	}

	if h("Referrer-Policy") == "" {
		findings = append(findings, Finding{
			Type:        "missing_referrer_policy",
			Name:        fmt.Sprintf("Missing Referrer-Policy: %s", label),
			Severity:    SevInfo,
			Description: "Full referrer URLs may leak to third-party resources",
			Evidence:    "Referrer-Policy: <absent>",
		})
	}

	for _, cookie := range hdr.Values("Set-Cookie") {
		findings = append(findings, analyzeCookie(label, cookie, isHTTPS)...)
	}

	return findings
}

// ---------------------------------------------------------------------------
// CSP
// ---------------------------------------------------------------------------

// parseCSP splits a policy into directive → lowercase values. Repeated
// directives are merged, as browsers do.
func parseCSP(raw string) map[string][]string {
	out := make(map[string][]string)
	for _, part := range strings.Split(raw, ";") {
		fields := strings.Fields(strings.ToLower(strings.TrimSpace(part)))
		if len(fields) == 0 {
			continue
		}
		name := fields[0]
		out[name] = append(out[name], fields[1:]...)
	}
	return out
}

func cspHasDirective(raw, directive string) bool {
	_, ok := parseCSP(raw)[strings.ToLower(directive)]
	return ok
}

// scriptSources returns the directive that governs script inclusion:
// script-src when present, otherwise the default-src fallback.
func scriptSources(policy map[string][]string) (string, []string) {
	if v, ok := policy["script-src"]; ok {
		return "script-src", v
	}
	if v, ok := policy["default-src"]; ok {
		return "default-src", v
	}
	return "", nil
}

func analyzeCSP(label, raw string) []Finding {
	policy := parseCSP(raw)
	name, sources := scriptSources(policy)
	if name == "" {
		// A policy without default-src still constrains the directives it
		// does list; scripts stay unconstrained, which is worth stating.
		return []Finding{{
			Type:        "csp_no_default_src",
			Name:        fmt.Sprintf("CSP has no default-src or script-src: %s", label),
			Severity:    SevInfo,
			Description: "Script loading is not restricted by this policy — every directive it omits falls back to allow-all",
			Evidence:    types.Sanitize(minStr("Content-Security-Policy: "+raw, 200)),
		}}
	}

	var findings []Finding
	hasNonceOrHash := false
	wildcard := false
	unsafeInline := false
	unsafeEval := false
	for _, v := range sources {
		switch {
		case strings.HasPrefix(v, "'nonce-"), strings.HasPrefix(v, "'sha256-"),
			strings.HasPrefix(v, "'sha384-"), strings.HasPrefix(v, "'sha512-"):
			// A nonce/hash makes browsers ignore 'unsafe-inline' in the
			// same directive (CSP3). Reporting it then would be a claim
			// the browser spec contradicts.
			hasNonceOrHash = true
		case v == "*":
			wildcard = true
		case v == "'unsafe-inline'":
			unsafeInline = true
		case v == "'unsafe-eval'":
			unsafeEval = true
		}
	}

	if wildcard {
		findings = append(findings, Finding{
			Type:        "csp_wildcard_source",
			Name:        fmt.Sprintf("CSP allows scripts from any host (%s *): %s", name, label),
			Severity:    SevMedium,
			Description: fmt.Sprintf("%s contains '*', so a script tag pointing at any origin runs — the policy does not constrain script injection to the site's own hosts", name),
			Evidence:    types.Sanitize(minStr("Content-Security-Policy: "+raw, 200)),
		})
	}
	if unsafeInline && !hasNonceOrHash && !wildcard {
		findings = append(findings, Finding{
			Type:        "csp_unsafe_inline",
			Name:        fmt.Sprintf("CSP permits inline scripts (%s 'unsafe-inline'): %s", name, label),
			Severity:    SevMedium,
			Description: "Without a nonce or hash, 'unsafe-inline' lets an injected <script> body execute — the CSP does not stop reflected/stored XSS in markup",
			Evidence:    types.Sanitize(minStr("Content-Security-Policy: "+raw, 200)),
		})
	}
	if unsafeEval {
		findings = append(findings, Finding{
			Type:        "csp_unsafe_eval",
			Name:        fmt.Sprintf("CSP permits eval (%s 'unsafe-eval'): %s", name, label),
			Severity:    SevLow,
			Description: "'unsafe-eval' allows string-to-code execution (eval, new Function, setTimeout with a string), a common gadget for XSS payloads",
			Evidence:    types.Sanitize(minStr("Content-Security-Policy: "+raw, 200)),
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// HSTS
// ---------------------------------------------------------------------------

func analyzeHSTS(label, raw string, isHTTPS bool) []Finding {
	attrs := make(map[string]string)
	for _, part := range strings.Split(raw, ";") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		attrs[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}

	var findings []Finding
	maxAgeRaw, hasMaxAge := attrs["max-age"]
	maxAge, err := strconv.ParseInt(strings.Trim(maxAgeRaw, `"`), 10, 64)
	if !hasMaxAge || err != nil || maxAge <= 0 {
		findings = append(findings, Finding{
			Type:        "hsts_disabled",
			Name:        fmt.Sprintf("HSTS header is present but disabled: %s", label),
			Severity:    SevMedium,
			Description: "Strict-Transport-Security without a positive max-age is ignored by browsers — the header provides no protection at all",
			Evidence:    types.Sanitize("Strict-Transport-Security: " + raw),
		})
		return findings
	}

	// 180 days is the floor most preload lists and config scanners use.
	if maxAge < 15552000 {
		findings = append(findings, Finding{
			Type:        "hsts_short_max_age",
			Name:        fmt.Sprintf("HSTS max-age is short (%ds): %s", maxAge, label),
			Severity:    SevInfo,
			Description: "Browsers forget the HSTS pin after this window; 180 days (15552000s) is the usual floor, one year is recommended",
			Evidence:    types.Sanitize("Strict-Transport-Security: " + raw),
		})
	}
	if _, ok := attrs["includesubdomains"]; !ok {
		findings = append(findings, Finding{
			Type:        "hsts_no_subdomains",
			Name:        fmt.Sprintf("HSTS does not cover subdomains: %s", label),
			Severity:    SevInfo,
			Description: "Without includeSubDomains an attacker can still downgrade a subdomain that serves the same cookies",
			Evidence:    types.Sanitize("Strict-Transport-Security: " + raw),
		})
	}
	_ = isHTTPS
	return findings
}

// ---------------------------------------------------------------------------
// Cookies
// ---------------------------------------------------------------------------

// parseSetCookie splits a Set-Cookie value into its name and a map of
// lowercase attribute → value ("" for valueless flags like Secure). This
// replaces substring matching over the whole header, which treated a cookie
// called `secure_pref` as having the Secure attribute.
func parseSetCookie(raw string) (string, map[string]string) {
	parts := strings.Split(raw, ";")
	name := ""
	if first := strings.TrimSpace(parts[0]); first != "" {
		n, _, _ := strings.Cut(first, "=")
		name = strings.TrimSpace(n)
	}
	attrs := make(map[string]string, len(parts))
	for _, p := range parts[1:] {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		k, v, ok := strings.Cut(p, "=")
		k = strings.ToLower(strings.TrimSpace(k))
		if !ok {
			attrs[k] = ""
			continue
		}
		attrs[k] = strings.TrimSpace(v)
	}
	return name, attrs
}

func analyzeCookie(label, raw string, isHTTPS bool) []Finding {
	name, attrs := parseSetCookie(raw)
	if name == "" {
		return nil
	}
	_, hasSecure := attrs["secure"]
	_, hasHTTPOnly := attrs["httponly"]
	sameSite, hasSameSite := attrs["samesite"]

	lowName := strings.ToLower(name)
	sessionish := nameIsSessionish(name)
	var findings []Finding
	add := func(typ, title string, sev Severity, desc string) {
		findings = append(findings, Finding{
			Type:        typ,
			Name:        fmt.Sprintf("%s: %s", title, label),
			Severity:    sev,
			Description: desc,
			Evidence:    types.Sanitize("Set-Cookie: " + raw),
			Details:     map[string]string{"cookie": name},
		})
	}

	kind := "Cookie"
	baseSev := SevInfo
	if sessionish {
		kind = "Session cookie"
		baseSev = SevMedium
	}

	switch {
	case !hasSecure && isHTTPS:
		add("cookie_missing_secure",
			fmt.Sprintf("%s '%s' without Secure", kind, name),
			baseSev,
			fmt.Sprintf("Cookie '%s' is sent over plaintext HTTP as well, so any downgrade or mixed-content request exposes it. Add Secure.", name))
	case hasSecure && !isHTTPS:
		// Not a weakness in the cookie, but the operator should know the
		// response is plaintext: the cookie will never come back.
		add("cookie_secure_on_http",
			fmt.Sprintf("%s '%s' sets Secure on a plaintext response", kind, name),
			SevInfo,
			fmt.Sprintf("Cookie '%s' carries Secure but this response is HTTP, so browsers will not store or send it.", name))
	}

	if !hasHTTPOnly {
		add("cookie_missing_httponly",
			fmt.Sprintf("%s '%s' without HttpOnly", kind, name),
			baseSev,
			fmt.Sprintf("Cookie '%s' is readable from JavaScript, so any XSS can exfiltrate it. Add HttpOnly for anything session-bearing.", name))
	}

	switch {
	case !hasSameSite:
		add("cookie_missing_samesite",
			fmt.Sprintf("%s '%s' without SameSite", kind, name),
			SevInfo,
			fmt.Sprintf("Cookie '%s' relies on the browser default (Lax in current Chrome/Firefox/Safari); set it explicitly so the behaviour does not depend on the browser.", name))
	case strings.EqualFold(sameSite, "none") && !hasSecure:
		add("cookie_samesite_none_insecure",
			fmt.Sprintf("%s '%s' uses SameSite=None without Secure", kind, name),
			SevMedium,
			fmt.Sprintf("Browsers reject SameSite=None cookies that lack Secure, so '%s' is never stored — the feature relying on it silently breaks, and any fallback is unlabelled.", name))
	}

	// Cookie prefixes carry hard requirements the browser enforces.
	if strings.HasPrefix(lowName, "__host-") {
		var violations []string
		if !hasSecure {
			violations = append(violations, "Secure")
		}
		if attrs["path"] != "/" {
			violations = append(violations, "Path=/")
		}
		if _, ok := attrs["domain"]; ok {
			violations = append(violations, "no Domain")
		}
		if len(violations) > 0 {
			add("cookie_host_prefix_violation",
				fmt.Sprintf("'__Host-' cookie '%s' violates its prefix requirements", name),
				SevMedium,
				fmt.Sprintf("A __Host- cookie must set %s; browsers reject it otherwise, so the protection the prefix promises is not in effect.", strings.Join(violations, ", ")))
		}
	} else if strings.HasPrefix(lowName, "__secure-") && !hasSecure {
		add("cookie_secure_prefix_violation",
			fmt.Sprintf("'__Secure-' cookie '%s' without Secure", name),
			SevMedium,
			"A __Secure- cookie must set Secure; browsers reject it otherwise, so the protection the prefix promises is not in effect.")
	}

	return findings
}

func nameIsSessionish(name string) bool {
	ln := strings.ToLower(name)
	for _, frag := range []string{"session", "sid", "sess", "token", "auth", "jwt", "remember", "login"} {
		if strings.Contains(ln, frag) {
			return true
		}
	}
	return false
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
