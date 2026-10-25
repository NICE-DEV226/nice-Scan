// login.go — the differential login verdict grammar, shared by the hacker
// brain and the --all exploit engine. The review caught the legacy keyword
// verdict surviving in internal/exploit/login.go ("302 without 'login' in
// the Location header, success words, or body > 500 bytes = valid
// credentials"): two verdict formulas in one binary will always drift, so
// the formula lives HERE and every caller consumes it.
package detect

import (
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// LoginShape is the failure fingerprint of a login endpoint: what the
// endpoint does to two WRONG credentials. Only deltas a wrong credential
// cannot produce may claim a valid one.
type LoginShape struct {
	Status       int
	FinalURL     string
	FinalPath    string
	FinalHost    string
	Location     string
	CookieBlob   string // canonicalized "name=value" pairs, sorted
	CookieNames  string // canonicalized cookie names, sorted
	FailWords    bool
	SuccessWords bool
}

// FingerprintLogin captures the wire shape of one login response.
func FingerprintLogin(r *types.Response) LoginShape {
	var f LoginShape
	if r == nil {
		return f
	}
	f.Status = r.StatusCode
	f.FinalURL = r.FinalURL
	if u, err := url.Parse(r.FinalURL); err == nil {
		f.FinalPath = u.Path
		f.FinalHost = u.Host
	}
	f.Location = r.Headers.Get("Location")
	f.CookieBlob, f.CookieNames = canonicalCookies(r.Headers)
	f.FailWords, f.SuccessWords = classifyLoginBody(r.Body)
	return f
}

// CookiesStable reports whether two fingerprints carry identical cookie
// pairs — when true, cookie VALUE deltas act as a success signal; on
// rotating cookie endpoints only name-set deltas remain usable.
func CookiesStable(a, b LoginShape) bool {
	return a.CookieBlob == b.CookieBlob
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

// LoginVerdict decides whether resp PROVES the credentials are valid.
// Strictly differential: the response must differ from the junk baseline on
// a signal junk credentials could not produce:
//   - redirect (non-following mode): a same-host Location the baseline did
//     not target, or a session cookie delta;
//   - 200 (following mode): a cookie delta, or the final destination left
//     the baseline's failure path.
//
// Body words and body size alone can never claim a valid credential — that
// is exactly the false-positive class this rewrite removes.
func LoginVerdict(resp *types.Response, base LoginShape, cookiesTrusted bool) bool {
	if resp == nil || base.FinalHost == "" {
		return false
	}
	cur := FingerprintLogin(resp)
	if cur.FailWords {
		return false
	}

	cookieDelta := cur.CookieNames != base.CookieNames ||
		(cookiesTrusted && cur.CookieBlob != base.CookieBlob)

	if cur.Status >= 300 && cur.Status < 400 {
		// The client returned the redirect itself (followRedirects=false).
		// Compare destinations by PATH: failure flows commonly carry a
		// timestamped or randomized query, which would resurrect the
		// false-positive if compared verbatim.
		loc := cur.Location
		if loc == "" || locationPath(loc) == locationPath(base.Location) {
			return false
		}
		if !locationSameHost(loc, base.FinalURL) {
			return false
		}
		return true
	}

	if cur.Status != 200 {
		// 4xx/5xx, rate-limit responses, etc. — no credential claim.
		return false
	}

	return cookieDelta || cur.FinalPath != base.FinalPath
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
