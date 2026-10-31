package hacker

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// FormIntegrityAction inspects the markup of crawled forms for
// submission-level weaknesses an attacker can exploit without touching
// the account system: a POST form with no CSRF field, credentials
// submitted through GET, or a password form that posts to a foreign
// origin. Everything is derived from one read-only GET per page — no
// login attempt is made, no account is touched.
//
// The action deliberately does NOT claim a form is vulnerable when the
// page carries a global meta csrf-token: frameworks that attach the
// token via a JS header would otherwise be reported as broken on every
// single page.
type FormIntegrityAction struct{}

func (a *FormIntegrityAction) Metadata() ActionMetadata {
	return ActionMetadata{
		Name:        "Form Integrity",
		Description: "CSRF fields, GET credentials and cross-origin form actions — markup inspection only",
		Priority:    33,
		Requires:    []string{"has_forms"},
		Provides:    []string{"has_form_integrity"},
	}
}

var (
	formAttrRe  = regexp.MustCompile(`(?i)([a-z_:][-a-z0-9_:.]*)\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))`)
	formInputRe = regexp.MustCompile(`(?is)<input\b[^>]*>`)
	metaCSRFRe  = regexp.MustCompile(`(?is)<meta\b[^>]*name\s*=\s*["']?csrf-token["']?`)
)

// csrfFieldFragments are the hidden-input names every mainstream
// framework uses for its anti-CSRF token. Substring matching keeps
// Django's csrfmiddlewaretoken, Rails' authenticity_token and
// ASP.NET's __RequestVerificationToken in one list.
var csrfFieldFragments = []string{
	"csrf", "xsrf", "_token", "authenticity_token",
	"__requestverificationtoken", "antiforgery",
}

// formFacts is one parsed <form> element.
type formFacts struct {
	Action      string
	Method      string
	HasPassword bool
	HasFile     bool
	CSRFField   string
	InputNames  []string
}

func (a *FormIntegrityAction) Execute(ctx context.Context, target string, kb *Knowledge, client *transport.Client) ActionResult {
	var pages []Page
	for _, p := range kb.GetPages() {
		if p.Forms > 0 && p.URL != "" && p.Status > 0 {
			pages = append(pages, p)
		}
		if len(pages) >= 3 {
			break
		}
	}
	if len(pages) == 0 {
		return ActionResult{}
	}

	var findings []Finding
	seen := make(map[string]bool)
	inspected := 0

	for _, page := range pages {
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		resp, err := client.Do(cctx, &types.Request{
			Method: "GET",
			URL:    page.URL,
		})
		cancel()
		if err != nil || resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 400 {
			// Unreachable or error page: no markup, no claim.
			continue
		}
		inspected++

		for _, f := range analyzeFormIntegrity(page.URL, string(resp.Body)) {
			key := f.Type + "|" + f.Name
			if seen[key] {
				continue
			}
			seen[key] = true
			findings = append(findings, f)
		}
	}

	if inspected > 0 {
		kb.AddCapability(Capability{
			Name:   "has_form_integrity",
			Origin: OriginVerified,
			Target: target,
			Details: map[string]string{
				"evidence":  fmt.Sprintf("%d form page(s) inspected in fetched markup", inspected),
				"derivedBy": "read-only GET + markup parse (no credential submitted)",
			},
		})
	}
	return ActionResult{Findings: findings}
}

// analyzeFormIntegrity is a pure sink so the markup rules are testable
// without a live server. Only real <form>…</form> segments are examined;
// prose or scripts that mention "csrf" cannot produce a finding.
func analyzeFormIntegrity(pageURL, body string) []Finding {
	if body == "" {
		return nil
	}
	pageHasMetaCSRF := metaCSRFRe.MatchString(body)
	label := types.Sanitize(minStr(pageURL, 120))

	var findings []Finding
	for _, seg := range formSegmentsOriginal(body) {
		facts := parseFormFacts(seg)
		if facts == nil {
			continue
		}

		action := facts.Action
		if action == "" {
			action = pageURL
		}
		absAction := resolveURL(action, pageURL)

		if facts.HasPassword && facts.Method == "GET" {
			findings = append(findings, Finding{
				Type:        "form_password_in_get",
				Name:        fmt.Sprintf("Credentials submitted via GET: %s", label),
				Severity:    SevHigh,
				Description: "This form carries a password-type input and submits with method=GET — the secret lands in browser history, proxy logs and Referer headers",
				Evidence:    types.Sanitize(minStr(action, 160)),
			})
		}

		if facts.HasPassword && isCrossOrigin(absAction, pageURL) {
			findings = append(findings, Finding{
				Type:        "form_credentials_foreign_origin",
				Name:        fmt.Sprintf("Password form posts to a foreign origin: %s", label),
				Severity:    SevMedium,
				Description: fmt.Sprintf("The form submits credentials to %s — verify this third party is an authorized identity provider", types.Sanitize(minStr(absAction, 120))),
				Evidence:    types.Sanitize(minStr(absAction, 160)),
			})
		}

		// CSRF only applies to state-changing (POST) submissions; a GET
		// form cannot carry a token in the conventional way and is
		// already covered by the password rule above.
		if facts.Method != "POST" {
			continue
		}
		if facts.CSRFField != "" {
			continue
		}
		if pageHasMetaCSRF {
			// The page declares a global token for scripted submissions:
			// the header path may be wired even though this form has no
			// hidden field. Record it as informational, not an accusation.
			findings = append(findings, Finding{
				Type:        "form_csrf_meta_only",
				Name:        fmt.Sprintf("POST form without hidden CSRF field: %s", label),
				Severity:    SevInfo,
				Description: "The page carries a global <meta name=\"csrf-token\">, so a scripted header may protect this submission — confirm before concluding",
				Evidence:    types.Sanitize(facts.describe()),
			})
			continue
		}
		findings = append(findings, Finding{
			Type:        "form_missing_csrf",
			Name:        fmt.Sprintf("POST form without CSRF token: %s", label),
			Severity:    SevMedium,
			Description: "No hidden anti-CSRF field and no global csrf-token meta tag in the fetched markup — cross-site POSTs are not visibly bound to the user's session",
			Evidence:    types.Sanitize(facts.describe()),
		})
	}
	return findings
}

// formSegmentsOriginal returns each real <form>…</form> segment with its
// original casing (case-insensitive search, original slice).
func formSegmentsOriginal(body string) []string {
	low := strings.ToLower(body)
	var segs []string
	i := 0
	for {
		start := strings.Index(low[i:], "<form")
		if start < 0 {
			break
		}
		start += i
		end := strings.Index(low[start:], "</form>")
		if end < 0 {
			segs = append(segs, body[start:])
			break
		}
		segs = append(segs, body[start:start+end])
		i = start + end + len("</form>")
	}
	return segs
}

func parseFormFacts(segment string) *formFacts {
	low := strings.ToLower(segment)

	openEnd := strings.IndexByte(low, '>')
	if openEnd < 0 {
		return nil
	}
	openTag := segment[:openEnd+1]
	attrs := parseAttrs(openTag)

	facts := &formFacts{
		Action: attrs["action"],
		Method: strings.ToUpper(strings.TrimSpace(attrs["method"])),
	}
	if facts.Method == "" {
		facts.Method = "GET"
	}

	for _, input := range formInputRe.FindAllString(segment, -1) {
		ia := parseAttrs(input)
		name := ia["name"]
		typ := strings.ToLower(ia["type"])
		if name != "" {
			facts.InputNames = append(facts.InputNames, name)
			if typ == "hidden" && facts.CSRFField == "" && isCSRFFieldName(name) {
				facts.CSRFField = name
			}
		}
		switch typ {
		case "password":
			facts.HasPassword = true
		case "file":
			facts.HasFile = true
		}
	}
	return facts
}

func parseAttrs(tag string) map[string]string {
	attrs := make(map[string]string, 6)
	for _, m := range formAttrRe.FindAllStringSubmatch(tag, -1) {
		name := strings.ToLower(m[1])
		val := m[3]
		if val == "" {
			val = m[4]
		}
		if val == "" {
			val = m[5]
		}
		attrs[name] = val
	}
	return attrs
}

func isCSRFFieldName(name string) bool {
	low := strings.ToLower(name)
	for _, frag := range csrfFieldFragments {
		if strings.Contains(low, frag) {
			return true
		}
	}
	return false
}

func isCrossOrigin(absAction, pageURL string) bool {
	if absAction == "" {
		return false
	}
	a, err := url.Parse(absAction)
	if err != nil || a.Host == "" {
		return false
	}
	p, err := url.Parse(pageURL)
	if err != nil || p.Host == "" {
		return false
	}
	if strings.EqualFold(a.Hostname(), p.Hostname()) {
		return false
	}
	// Same registrable domain (login.example.com → app.example.com) is
	// an in-family redirect, not a foreign recipient.
	return !strings.HasSuffix(strings.ToLower(a.Hostname()), "."+strings.ToLower(baseDomain(p.Hostname()))) &&
		!strings.HasSuffix(strings.ToLower(p.Hostname()), "."+strings.ToLower(baseDomain(a.Hostname())))
}

// baseDomain is intentionally naive (last two labels): the goal is only
// to keep own-subdomain form actions from being called "foreign".
func baseDomain(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return host
}

func (f *formFacts) describe() string {
	var b strings.Builder
	b.WriteString("method=")
	b.WriteString(f.Method)
	if f.Action != "" {
		b.WriteString(", action=")
		b.WriteString(f.Action)
	}
	if f.HasPassword {
		b.WriteString(", password input")
	}
	if len(f.InputNames) > 0 {
		b.WriteString(", fields=")
		b.WriteString(strings.Join(f.InputNames, ","))
	}
	return b.String()
}
