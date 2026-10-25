package hacker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

type LoginBruteAction struct{}

func (a *LoginBruteAction) Metadata() ActionMetadata {
	return ActionMetadata{
		Name:        "Login Bruteforce",
		Description: "Discover login forms and spray common credentials",
		Priority:    40,
		Requires:    []string{"has_login"},
		Provides:    []string{"has_credentials"},
		// Credentialed spraying: only when a login form was actually
		// observed on a fetched page (verified), never from text hints.
		Sensitive: true,
	}
}

var commonCreds = [][2]string{
	{"admin", "admin"}, {"admin", "password"}, {"admin", "123456"},
	{"admin", "admin123"}, {"admin", "welcome"}, {"admin", "password123"},
	{"admin", "root"}, {"admin", "test"}, {"admin", "letmein"},
	{"user", "user"}, {"user", "password"}, {"user", "123456"},
	{"root", "root"}, {"root", "toor"}, {"root", "admin"},
	{"test", "test"}, {"test", "password"}, {"test", "123456"},
	{"guest", "guest"}, {"admin", "Passw0rd!"},
	{"administrator", "administrator"}, {"administrator", "admin"},
	{"support", "support"}, {"info", "info"},
	{"admin", "admin12345"}, {"admin", "changeme"},
	{"admin", "nimda"}, {"admin", "P@ssw0rd"},
	{"admin", "secret"}, {"tomcat", "tomcat"},
	{"admin", "s3cr3t"}, {"admin", "p@ssw0rd"},
	{"oracle", "oracle"}, {"postgres", "postgres"},
	{"sa", "sa"}, {"sa", "password"},
	{"user", "pass"}, {"admin", "default"},
	{"manager", "manager"}, {"demo", "demo"},
}

func (a *LoginBruteAction) Execute(ctx context.Context, target string, kb *Knowledge, client *transport.Client) ActionResult {
	pages := kb.GetPages()
	var findings []Finding
	var spawned []Action
	totalSprayed := 0

	for _, page := range pages {
		if page.Forms == 0 {
			continue
		}

		resp, err := client.Do(ctx, &types.Request{
			Method: "GET",
			URL:    page.URL,
		})
		if err != nil {
			continue
		}

		body := string(resp.Body)
		formAction, formFields := extractLoginForm(body)
		if len(formFields) < 1 {
			continue
		}

		// Login forms self-reference constantly (action="" or the page's
		// own path). The crawl-grade resolveURL treats that as "nothing
		// new" and returns "", which silently skipped the most common
		// real-world login shape. Resolve for POSTing: a missing or
		// self-resolving action posts to the page itself; the same-host
		// gate still applies to everything.
		var actionURL string
		switch formAction {
		case "", "/":
			actionURL = page.URL
		default:
			actionURL = resolveURL(formAction, page.URL)
			if actionURL == "" {
				actionURL = page.URL
			}
		}
		// A cross-host form action would POST generated credential
		// material to another origin (open redirect / injected form).
		// Only same-host actions participate in the brute force.
		if actionURL == "" || !sameHostStrict(actionURL, target) {
			continue
		}

		// Baseline-differential verification: two junk-credential POSTs
		// shape what a FAILURE looks like on this exact endpoint. Anything
		// the spray cannot distinguish from that baseline is not evidence
		// of a valid credential (fail-closed).
		base, cookiesTrusted := establishLoginBaseline(ctx, client, actionURL, formFields)
		if base == nil {
			findings = append(findings, Finding{
				Type:     "login_baseline_unavailable",
				Severity: SevInfo,
				Name:     "Login spray skipped — baseline failed",
				Description: fmt.Sprintf(
					"Two junk-credential POSTs to %s failed; verdicts would be untrustworthy so the spray was not attempted",
					actionURL,
				),
			})
			continue
		}

		sprayed := 0
		for _, cred := range commonCreds {
			select {
			case <-ctx.Done():
				return ActionResult{Findings: findings, Actions: spawned}
			default:
			}

			loginResp, err := postLoginForm(ctx, client, actionURL, formFields, cred[0], cred[1])
			if err != nil {
				continue
			}
			sprayed++

			if loginVerdict(loginResp, *base, cookiesTrusted) {
				kb.AddCredential(Credential{
					Username: cred[0],
					Password: cred[1],
					Source:   page.URL,
					Valid:    true,
				})

				findings = append(findings, Finding{
					Type:        "login_valid",
					Name:        fmt.Sprintf("Valid credentials: %s:%s", cred[0], cred[1]),
					Severity:    SevCritical,
					Description: fmt.Sprintf("Login successful at %s (differential verdict vs junk-credential baseline)", actionURL),
					Evidence:    fmt.Sprintf("%s:%s → %d richer than baseline", cred[0], cred[1], loginResp.StatusCode),
					Details:     map[string]string{"verification": "baseline-differential"},
				})

				spawned = append(spawned, &PostLoginCrawlAction{
					username:   cred[0],
					password:   cred[1],
					loginURL:   actionURL,
					formFields: formFields,
				})
				break
			}
		}
		totalSprayed += sprayed
	}

	if len(findings) == 0 {
		pagesWithForms := 0
		for _, p := range pages {
			if p.Forms > 0 {
				pagesWithForms++
			}
		}
		findings = append(findings, Finding{
			Type:        "login_brute_complete",
			Name:        fmt.Sprintf("Login bruteforce complete — %d forms tested, no valid creds", pagesWithForms),
			Severity:    SevInfo,
			Description: "Tested " + fmt.Sprintf("%d credentials against %d forms (differential validation)", totalSprayed, pagesWithForms),
		})
	}

	return ActionResult{Findings: findings, Actions: spawned}
}

// ── Form extraction: names AND pre-rendered values ──────────────────────
// The previous extractor kept field names only and posted "=test" for any
// field it did not recognise — including hidden CSRF/anti-forgery tokens,
// which modern frameworks validate. The very common "invalid CSRF token"
// failure shape then made login spray conclusions untrustworthy (or
// silently skipped whole endpoints). Hidden inputs now carry their real
// value into the POST body; token-like names are treated as verbatim
// values even when their type attribute is missing.

// formField is one <input> of a form: name, pre-rendered value (hidden
// fields typically carry the anti-CSRF token), and the declared type.
type formField struct {
	name  string
	value string
	ftype string
}

// tokenNameHints are name substrings that identify anti-forgery inputs
// even without a type="hidden" attribute (framework-side naming: Django,
// Rails, PHP, Struts, SAP, Spring Security...).
var tokenNameHints = []string{
	"csrf", "csrftoken", "_token", "xsrf", "xsrf-token", "nonce",
	"authenticity", "antiforgery", "_wpnonce", "__requestverificationtoken",
	"_csrf_token", "anticsrf", "requesttoken",
}

func isTokenLikeField(name string) bool {
	low := strings.ToLower(name)
	for _, h := range tokenNameHints {
		if strings.Contains(low, h) {
			return true
		}
	}
	return false
}

func fieldIsHidden(inputLow string) bool {
	return strings.Contains(inputLow, `type="hidden"`) ||
		strings.Contains(inputLow, "type=hidden") ||
		strings.Contains(inputLow, `type='hidden'`)
}

func extractLoginForm(body string) (action string, fields []formField) {
	lowBody := strings.ToLower(body)
	for i := 0; i < len(lowBody); {
		idx := strings.Index(lowBody[i:], "<form")
		if idx == -1 {
			break
		}
		formStart := i + idx
		closeTag := strings.IndexByte(body[formStart:], '>')
		if closeTag == -1 {
			break
		}

		formTag := body[formStart : formStart+closeTag+1]
		formLow := strings.ToLower(formTag)

		if strings.Contains(formLow, "password") || strings.Contains(formLow, "login") || strings.Contains(formLow, "signin") {
			action = extractAttribute(formTag, "action")
			fields = extractFormFields(body[formStart+closeTag+1:])
			return action, fields
		}

		formContent := body[formStart+closeTag+1:]
		endForm := strings.Index(strings.ToLower(formContent), "</form>")
		if endForm == -1 {
			break
		}

		if strings.Contains(strings.ToLower(formContent[:endForm]), "password") {
			action = extractAttribute(formTag, "action")
			fields = extractFormFields(formContent[:endForm])
			return action, fields
		}

		i = formStart + len(formTag) + endForm + 7
	}
	return "", nil
}

func extractFormFields(content string) []formField {
	var fields []formField
	lowContent := strings.ToLower(content)
	for i := 0; i < len(lowContent); {
		idx := strings.Index(lowContent[i:], "<input")
		if idx == -1 {
			break
		}
		inputStart := i + idx
		closeTag := strings.IndexByte(content[inputStart:], '>')
		if closeTag == -1 {
			break
		}
		inputTag := content[inputStart : inputStart+closeTag+1]
		inputLow := strings.ToLower(inputTag)

		isSubmit := strings.Contains(inputLow, `type="submit"`) || strings.Contains(inputLow, "type=submit")
		if !isSubmit {
			name := extractAttribute(inputTag, "name")
			if name != "" {
				f := formField{
					name:  name,
					value: extractAttribute(inputTag, "value"),
					ftype: "text",
				}
				switch {
				case fieldIsHidden(inputLow):
					f.ftype = "hidden"
				case strings.Contains(inputLow, `type="password"`), strings.Contains(inputLow, "type=password"):
					f.ftype = "password"
				case isTokenLikeField(name):
					f.ftype = "token"
				}
				fields = append(fields, f)
			}
		}
		i = inputStart + closeTag + 1
	}
	return fields
}

func extractAttribute(tag, attr string) string {
	attrLow := strings.ToLower(attr)
	tagLow := strings.ToLower(tag)
	attrIdx := strings.Index(tagLow, attrLow+"=")
	if attrIdx == -1 {
		return ""
	}
	valStart := attrIdx + len(attrLow) + 1
	if valStart >= len(tag) {
		return ""
	}
	quote := tag[valStart]
	if quote == '"' || quote == '\'' {
		end := strings.IndexByte(tag[valStart+1:], byte(quote))
		if end == -1 {
			return ""
		}
		return tag[valStart+1 : valStart+1+end]
	}
	end := strings.IndexAny(tag[valStart:], " >")
	if end == -1 {
		return tag[valStart:]
	}
	return tag[valStart : valStart+end]
}

// buildFormData assembles the POST body from the form's own fields:
//   - user/password fields get the credential under test;
//   - hidden/token fields keep their pre-rendered value (anti-CSRF tokens,
//     "next" targets, state markers) — sending "=test" for them is what
//     made whole classes of modern login pages untestable;
//   - anything else falls back to the historical filler.
func formValueFor(f formField, username, password string) (string, bool) {
	flow := strings.ToLower(f.name)
	switch {
	case strings.Contains(flow, "user") || strings.Contains(flow, "email") ||
		strings.Contains(flow, "login") || strings.Contains(flow, "name"):
		return strings.ReplaceAll(username, " ", "+"), true
	case strings.Contains(flow, "pass") || strings.Contains(flow, "pwd"):
		return strings.ReplaceAll(password, " ", "+"), true
	case f.ftype == "password":
		return strings.ReplaceAll(password, " ", "+"), true
	case f.ftype == "hidden" || f.ftype == "token" || isTokenLikeField(f.name):
		return f.value, true
	}
	return "test", true
}

func buildFormData(fields []formField, username, password string) string {
	var parts []string
	for _, f := range fields {
		v, _ := formValueFor(f, username, password)
		parts = append(parts, f.name+"="+v)
	}
	return strings.Join(parts, "&")
}

// ── Baseline-differential login verification ─────────────────────────────
// The previous isLoginSuccess() decided from a single response (30x =
// success, magic words on 200). That produced provable false positives on
// two very common real-world shapes:
//   - PRG failure flows (POST → 302 → error page) — a 302 meant "success";
//   - pages carrying static "Welcome/Logout" strings on the error page.
// The verdict is now differential: BEFORE spraying, two junk-credential
// POSTs establish what a failure looks like on this exact endpoint. A
// valid credential may only be claimed on a session/navigation-level delta
// that junk credentials could not reproduce (cookie delta on stable-churn
// endpoints, or a final destination different from the failure one). When
// the baseline is unstable (per-request cookie churn, transport errors),
// signals are downgraded or the spray is skipped — fail-closed.

type loginFingerprint struct {
	status       int
	finalURL     string
	finalPath    string
	finalHost    string
	location     string
	cookieBlob   string // canonicalized "name=value" pairs, sorted
	cookieNames  string // canonicalized cookie names, sorted
	failWords    bool
	successWords bool
}

func fingerprintLogin(r *types.Response) loginFingerprint {
	var f loginFingerprint
	if r == nil {
		return f
	}
	f.status = r.StatusCode
	f.finalURL = r.FinalURL
	if u, err := url.Parse(r.FinalURL); err == nil {
		f.finalPath = u.Path
		f.finalHost = u.Host
	}
	f.location = r.Headers.Get("Location")
	f.cookieBlob, f.cookieNames = canonicalCookies(r.Headers)
	f.failWords, f.successWords = classifyLoginBody(r.Body)
	return f
}

// Word lists are failure markers first. Their only affirmative role is
// documentation in the finding; they can never claim success alone.
var (
	loginSuccessWords = []string{"dashboard", "welcome", "logout", "profile", "my account"}
	loginFailWords    = []string{"invalid", "incorrect", "failed", "error", "wrong"}
)

// classifyLoginBody detects failure markers anywhere in the final body.
// Conservative by design: a legitimate dashboard whose JS bundle contains
// the string "failed" yields a false negative, never a false positive.
func classifyLoginBody(body []byte) (fail, success bool) {
	if len(body) == 0 {
		return false, false
	}
	low := strings.ToLower(string(body))
	for _, w := range loginFailWords {
		if strings.Contains(low, w) {
			fail = true
			break
		}
	}
	for _, w := range loginSuccessWords {
		if strings.Contains(low, w) {
			success = true
			break
		}
	}
	return fail, success
}

// canonicalCookies normalizes Set-Cookie pairs so that a session-name or
// value delta can be compared across responses of the same endpoint.
func canonicalCookies(h http.Header) (blob, names string) {
	var pairs, only []string
	for _, v := range h.Values("Set-Cookie") {
		eq := strings.IndexByte(v, '=')
		if eq <= 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(v[:eq]))
		val := v[eq+1:]
		if semi := strings.IndexByte(val, ';'); semi >= 0 {
			val = val[:semi]
		}
		pairs = append(pairs, name+"="+val)
		only = append(only, name)
	}
	sort.Strings(pairs)
	sort.Strings(only)
	return strings.Join(pairs, "; "), strings.Join(only, ",")
}

func postLoginForm(ctx context.Context, client *transport.Client, actionURL string, formFields []formField, username, password string) (*types.Response, error) {
	return client.Do(ctx, &types.Request{
		Method: "POST",
		URL:    actionURL,
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
		Body: []byte(buildFormData(formFields, username, password)),
	})
}

func randLoginJunk() (string, string) {
	u := make([]byte, 8)
	p := make([]byte, 12)
	if _, err := rand.Read(u); err != nil {
		return "junkuser", "junkpassword"
	}
	if _, err := rand.Read(p); err != nil {
		return "junkuser", "junkpassword"
	}
	return "ns_" + hex.EncodeToString(u), hex.EncodeToString(p)
}

// establishLoginBaseline performs two junk-credential POSTs and returns the
// failure fingerprint plus whether the endpoint's cookie churn is stable
// enough for cookie blobs to act as a success signal.
func establishLoginBaseline(ctx context.Context, client *transport.Client, actionURL string, formFields []formField) (*loginFingerprint, bool) {
	u1, p1 := randLoginJunk()
	r1, err := postLoginForm(ctx, client, actionURL, formFields, u1, p1)
	if err != nil || r1 == nil {
		return nil, false
	}
	u2, p2 := randLoginJunk()
	r2, err := postLoginForm(ctx, client, actionURL, formFields, u2, p2)
	if err != nil || r2 == nil {
		return nil, false
	}
	f1, f2 := fingerprintLogin(r1), fingerprintLogin(r2)
	// Per-request cookie value churn (rotating CSRF/session ids on every
	// response, including failures) makes value deltas meaningless; only
	// name-set changes remain a signal in that case.
	cookiesTrusted := f1.cookieBlob == f2.cookieBlob
	return &f1, cookiesTrusted
}

// loginVerdict decides whether resp PROVES the credentials are valid.
// Strictly differential: the response must differ from the junk baseline on
// a signal junk credentials could not produce:
//   - redirect (non-following mode): a same-host Location the baseline did
//     not target, or a session cookie delta;
//   - 200 (following mode): a cookie delta, or the final destination left
//     the baseline's failure path.
//
// Body words and body size alone can never claim a valid credential — that
// is exactly the false-positive class this rewrite removes.
func loginVerdict(resp *types.Response, base loginFingerprint, cookiesTrusted bool) bool {
	if resp == nil || base.finalHost == "" {
		return false
	}
	cur := fingerprintLogin(resp)
	if cur.failWords {
		return false
	}

	cookieDelta := cur.cookieNames != base.cookieNames ||
		(cookiesTrusted && cur.cookieBlob != base.cookieBlob)

	if cur.status >= 300 && cur.status < 400 {
		// The client returned the redirect itself (followRedirects=false).
		// Compare destinations by PATH: failure flows commonly carry a
		// timestamped or randomized query, which would resurrect the
		// false-positive if compared verbatim.
		loc := cur.location
		if loc == "" || locationPath(loc) == locationPath(base.location) {
			return false
		}
		if !locationSameHost(loc, base.finalURL) {
			return false
		}
		return true
	}

	if cur.status != 200 {
		// 4xx/5xx, rate-limit responses, etc. — no credential claim.
		return false
	}

	return cookieDelta || cur.finalPath != base.finalPath
}

// locationSameHost accepts relative locations unconditionally and absolute
// ones only when they stay on the form's origin — a cross-host redirect is
// never evidence of successful authentication.
func locationSameHost(loc, refererURL string) bool {
	lu, err := url.Parse(loc)
	if err != nil {
		return false
	}
	if lu.Host == "" {
		return true
	}
	if lu.Scheme != "http" && lu.Scheme != "https" {
		return false
	}
	r, err := url.Parse(refererURL)
	if err != nil {
		return false
	}
	return lu.Host == r.Host
}

// locationPath extracts just the path of a Location header, tolerating
// relative references and host-only URLs.
func locationPath(loc string) string {
	u, err := url.Parse(loc)
	if err != nil {
		return loc
	}
	if u.Path == "" {
		return "/"
	}
	return u.Path
}
