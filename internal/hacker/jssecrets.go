package hacker

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

const (
	// jsMaxAssets bounds the assets scanned per run; crawl discovers far
	// more scripts on a real SPA than a report can usefully carry.
	jsMaxAssets = 25
	// jsScanCap bounds the bytes matched per asset. Bundles are routinely
	// larger than this; secrets sit anywhere in them, so the window is
	// generous rather than head-only.
	jsScanCap = 4 << 20
	// jsMaxHits bounds findings per asset so one vendored bundle full of
	// public test keys cannot flood the report.
	jsMaxHits = 25
)

// JSSecretsAction refetches first-party JavaScript assets the crawler
// collected and scans their bodies for credential-shaped literals (cloud API
// keys, CI tokens, chat tokens, private keys). Matches are VERIFIED — the
// literal exists in the asset the target actually served; a sanitized
// preview (first glyphs + length) goes in evidence, never the full secret.
//
// Precision comes from three gates, applied in this order: a keyword
// prefilter (no vendor prefix in the body ⇒ no regex run), a shape regex
// per provider, and — for the generic `api_key = "…"` class — a Shannon
// entropy floor plus a placeholder allowlist. Generic regexes without
// entropy are the documented cause of secret-scanner false positives, so
// that class is deliberately the only one that reports below High.
type JSSecretsAction struct{}

func (a *JSSecretsAction) Metadata() ActionMetadata {
	return ActionMetadata{
		Name: "JS Secret Scan",
		// Runs before Source Map Discovery (priority 43) so the map action
		// can reuse the `sourceMappingURL` comments harvested here instead
		// of guessing filenames.
		Description: "Scan first-party served JavaScript for credential-shaped literals — verified matches only",
		Priority:    41,
		Requires:    nil,
		Provides:    []string{"has_js_secrets"},
	}
}

type secretPattern struct {
	Name string
	Re   *regexp.Regexp
	Sev  Severity
	// Keywords is a lowercase prefilter: at least one must appear in the
	// asset before the regex runs. Empty means "always run".
	Keywords []string
	// Group is the submatch that holds the secret when the regex needs
	// context (assignments); 0 uses the whole match.
	Group int
	// MinEntropy rejects low-randomness values for the generic class.
	MinEntropy float64
	// Verify tells the operator how to confirm the credential is live.
	// It is report text: never interpolate remote content into it.
	Verify string
}

const verifyCloud = "Confirm the key is live (provider console or the provider's token-introspection endpoint), then rotate"

var secretPatterns = []secretPattern{
	{
		Name: "AWS access key ID", Re: regexp.MustCompile(`\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b`),
		Sev: SevHigh, Keywords: []string{"akia", "asia", "abia", "acca"}, Verify: verifyCloud,
	},
	{
		Name: "AWS secret access key",
		Re:   regexp.MustCompile(`(?i)aws_?secret_?access_?key["']?\s*[:=]\s*["']([A-Za-z0-9/+=]{40})["']`),
		Sev:  SevHigh, Keywords: []string{"aws_secret", "awssecret", "secret_access_key"}, Group: 1,
		MinEntropy: 3.5, Verify: verifyCloud,
	},
	{
		Name: "Google API key", Re: regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
		Sev: SevHigh, Keywords: []string{"aiza"}, Verify: "Confirm the key is unrestricted and live via the Google APIs console, then rotate",
	},
	{
		Name: "Google OAuth client secret", Re: regexp.MustCompile(`GOCSPX-[A-Za-z0-9_-]{28}`),
		Sev: SevHigh, Keywords: []string{"gocspx"}, Verify: "Confirm the OAuth client secret in the Google Cloud console, then rotate",
	},
	{
		Name: "Stripe live secret key", Re: regexp.MustCompile(`(?:sk|rk)_live_[0-9A-Za-z]{24,}`),
		Sev: SevHigh, Keywords: []string{"_live_"}, Verify: "Test the key with a read-only GET /v1/balance call, then roll it in the Stripe dashboard",
	},
	{
		Name: "OpenAI key", Re: regexp.MustCompile(`sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}`),
		Sev: SevHigh, Keywords: []string{"sk-proj-", "sk-svcacct-", "sk-admin-"}, Verify: "Check the key with a GET /v1/models call, then revoke it",
	},
	{
		Name: "Anthropic key", Re: regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{20,}`),
		Sev: SevHigh, Keywords: []string{"sk-ant-"}, Verify: "Check the key against the Anthropic API, then revoke it",
	},
	{
		Name: "GitHub token", Re: regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,40}|github_pat_[A-Za-z0-9_]{60,}`),
		Sev: SevHigh, Keywords: []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"},
		Verify: "Check the token with GET /user using it as Authorization: Bearer, then revoke it",
	},
	{
		Name: "GitLab token", Re: regexp.MustCompile(`glpat-[A-Za-z0-9_-]{20}`),
		Sev: SevHigh, Keywords: []string{"glpat-"}, Verify: "Check GET /api/v4/user with the token, then revoke it",
	},
	{
		Name: "npm token", Re: regexp.MustCompile(`npm_[A-Za-z0-9]{36}`),
		Sev: SevHigh, Keywords: []string{"npm_"}, Verify: "Check the token with GET /-/whoami, then revoke it",
	},
	{
		Name: "Slack token", Re: regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,60}`),
		Sev: SevMedium, Keywords: []string{"xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-"},
		Verify: "Check the token with auth.test, then revoke it",
	},
	{
		Name: "Slack incoming webhook", Re: regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/[A-Za-z0-9]{20,}`),
		Sev: SevMedium, Keywords: []string{"hooks.slack.com/services"}, Verify: "The URL is the credential: assume any holder can post to the channel until it is revoked",
	},
	{
		Name: "Discord webhook", Re: regexp.MustCompile(`https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{10,}/[A-Za-z0-9_-]{60,}`),
		Sev: SevHigh, Keywords: []string{"discord.com/api/webhooks", "discordapp.com/api/webhooks"},
		Verify: "The URL is the credential: revoke the webhook in channel settings",
	},
	{
		Name: "SendGrid key", Re: regexp.MustCompile(`SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}`),
		Sev: SevHigh, Keywords: []string{"sg."}, Verify: "Check GET /v3/user/profile with the key, then delete it",
	},
	{
		Name: "Mailgun key", Re: regexp.MustCompile(`key-[0-9a-zA-Z]{32}`),
		Sev: SevMedium, Keywords: []string{"key-"}, MinEntropy: 3.2,
		Verify: "Check GET /v3/domains with the key, then rotate it",
	},
	{
		Name: "Twilio API key", Re: regexp.MustCompile(`\bSK[0-9a-fA-F]{32}\b`),
		Sev: SevMedium, Keywords: []string{"twilio"}, MinEntropy: 3.2,
		Verify: "Check the key against the Twilio API, then rotate it",
	},
	{
		Name: "DigitalOcean token", Re: regexp.MustCompile(`dop_v1_[a-f0-9]{64}`),
		Sev: SevHigh, Keywords: []string{"dop_v1_"}, Verify: "Check GET /v2/account with the token, then revoke it",
	},
	{
		Name: "Shopify access token", Re: regexp.MustCompile(`shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}`),
		Sev: SevHigh, Keywords: []string{"shpat_", "shpca_", "shppa_", "shpss_"},
		Verify: "Check the token against the Admin API, then uninstall the app credential",
	},
	{
		Name: "Azure storage account key",
		Re:   regexp.MustCompile(`(?i)AccountKey=([A-Za-z0-9+/=]{40,88})`),
		Sev:  SevHigh, Keywords: []string{"accountkey="}, Group: 1, MinEntropy: 4.0,
		Verify: "Check the key against the storage account, then rotate it in the Azure portal",
	},
	{
		Name: "Firebase/Supabase service role JWT",
		Re:   regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
		Sev:  SevMedium, Keywords: []string{"service_role", "serviceaccount", "service_account"},
		Verify: "Decode the payload: a service_role/service_account claim is a privileged credential",
	},
	{
		Name: "Private key block", Re: regexp.MustCompile(`-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----`),
		Sev: SevHigh, Keywords: []string{"-----begin"}, Verify: "Parse the key and check whether it is accepted by the target's infrastructure, then rotate",
	},
	{
		Name: "Generic hardcoded credential", Re: regexp.MustCompile(`(?i)["']?(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?key|auth[_-]?token|access[_-]?token|client[_-]?secret|private[_-]?key|password|passwd|pwd)["']?\s*[:=]\s*["']([^"'\s]{16,80})["']`),
		// 16 characters and 3.5 bits/char: below that a dictionary word
		// ('administrator' is 3.28) passes a bare entropy check, which is
		// exactly the false positive this gate exists to stop.
		Sev: SevMedium, Group: 1, MinEntropy: 3.5,
		Keywords: []string{"apikey", "api_key", "api-key", "secret", "token", "password", "passwd", "pwd", "credential", "private_key", "privatekey"},
		Verify:   "Entropy match on a credential-named field: confirm the value is used as a credential (not a public identifier) before reporting",
	},
	{
		Name: "Embedded JWT", Re: regexp.MustCompile(`eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}`),
		Sev: SevInfo, Keywords: []string{"eyj"}, Verify: "Decode the payload to see whether it carries a privileged claim; session tokens in JS are expected",
	},
}

// secretHit is one validated literal, already past the keyword, entropy and
// placeholder gates.
type secretHit struct {
	Pattern  string
	Severity Severity
	Literal  string
	Offset   int
	Verify   string
}

// placeholderFragments are values that appear in documentation, SDK samples
// and .env templates. AWS's own documented example key
// (AKIAIOSFODNN7EXAMPLE) matches the access-key regex exactly, so without
// this list every tutorial snippet in a bundle becomes a High finding —
// the single most reported false positive class for JS secret scanners.
var placeholderFragments = []string{
	"example", "sample", "dummy", "placeholder", "changeme", "change_me",
	"your_", "your-", "yourapi", "yourkey", "insert_", "insert-",
	"replace_", "replace-", "redacted", "notreal", "fake", "xxx",
	"****", "abcdefgh", "1234567890", "todo", "fixme", "secret_here",
	"api_key_here", "undefined", "process.env", "os.environ", "${", "{{", "<",
}

// scanSecrets runs every pattern whose keyword prefilter matches and returns
// deduplicated hits. text is JS source (or a concatenation of sourcesContent
// blobs from a source map) — never HTML: a soft-404 page matching a regex is
// not a leaked credential, and callers filter that before calling here.
func scanSecrets(text string) []secretHit {
	if text == "" {
		return nil
	}
	low := strings.ToLower(text)
	var hits []secretHit
	seen := make(map[string]bool)

	for _, p := range secretPatterns {
		if len(p.Keywords) > 0 && !containsAny(low, p.Keywords) {
			continue
		}
		for _, loc := range p.Re.FindAllStringSubmatchIndex(text, jsMaxHits) {
			start, end := loc[0], loc[1]
			if p.Group > 0 {
				if len(loc) <= 2*p.Group+1 || loc[2*p.Group] < 0 {
					continue
				}
				start, end = loc[2*p.Group], loc[2*p.Group+1]
			}
			lit := text[start:end]
			if !looksLikeSecret(lit) {
				continue
			}
			if p.MinEntropy > 0 && shannonEntropy(lit) < p.MinEntropy {
				continue
			}
			if isPlaceholderSecret(lit) || seen[lit] {
				continue
			}
			seen[lit] = true
			hits = append(hits, secretHit{
				Pattern:  p.Name,
				Severity: p.Sev,
				Literal:  lit,
				Offset:   start,
				Verify:   p.Verify,
			})
			if len(hits) >= jsMaxHits {
				return hits
			}
		}
	}
	return hits
}

// looksLikeSecret rejects values no provider would issue: too short, too
// long, or drawn from a tiny alphabet (padding, repetition).
func looksLikeSecret(s string) bool {
	if len(s) < 8 || len(s) > 200 {
		return false
	}
	distinct := make(map[byte]struct{}, 8)
	for i := 0; i < len(s); i++ {
		distinct[s[i]] = struct{}{}
	}
	if len(distinct) < 4 {
		return false
	}
	// A single repeated run ("0000000000000000") passes the distinct check
	// only through one other glyph; require the most common byte to stay
	// under 3/4 of the value.
	counts := make(map[byte]int, len(distinct))
	maxCount := 0
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
		if counts[s[i]] > maxCount {
			maxCount = counts[s[i]]
		}
	}
	return maxCount*4 <= len(s)*3
}

func isPlaceholderSecret(s string) bool {
	low := strings.ToLower(s)
	for _, frag := range placeholderFragments {
		if strings.Contains(low, frag) {
			return true
		}
	}
	return false
}

// shannonEntropy returns bits per character. Random 40-char base64 secrets
// land near 4.5-5.5; dictionary words and padded placeholders near 2-3.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	var e float64
	n := float64(len(s))
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	return e
}

func containsAny(haystack string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(haystack, n) {
			return true
		}
	}
	return false
}

// redactSecret keeps a shape the operator can recognise in the bundle
// without turning the report into a credential dump: first four glyphs and
// the length. Four glyphs identify the provider prefix (AKIA, sk_l…).
func redactSecret(s string) string {
	prefix := s
	if len(prefix) > 4 {
		prefix = prefix[:4]
	}
	return fmt.Sprintf("%s… (%d chars)", types.Sanitize(prefix), len(s))
}

// looksLikeHTMLDocument reports whether a body is an HTML page. SPA servers
// answer 200 with index.html for every unknown path, including /assets/app.js
// — scanning that as JavaScript invents findings from marketing copy.
func looksLikeHTMLDocument(body []byte) bool {
	head := body
	if len(head) > 1024 {
		head = head[:1024]
	}
	trimmed := bytes.TrimLeft(head, " \t\r\n")
	lower := bytes.ToLower(trimmed)
	if bytes.HasPrefix(lower, []byte("<!doctype html")) || bytes.HasPrefix(lower, []byte("<html")) {
		return true
	}
	return bytes.Contains(lower, []byte("<html")) && bytes.Contains(lower, []byte("<head"))
}

// findSourceMappingURL extracts the map reference a bundle declares. The
// last occurrence wins: minifiers append the directive at the end, and dev
// builds sometimes leave stale earlier ones. Empty means "no declared map";
// data: URIs are returned as-is so the caller can decline them explicitly.
func findSourceMappingURL(body []byte) string {
	const marker = "sourceMappingURL="
	idx := bytes.LastIndex(body, []byte(marker))
	if idx < 0 {
		return ""
	}
	rest := body[idx+len(marker):]
	end := 0
	for end < len(rest) {
		switch rest[end] {
		case ' ', '\t', '\r', '\n', '*', '"', '\'', ';', ')':
			goto done
		}
		end++
	}
done:
	return strings.TrimSpace(string(rest[:end]))
}

func (a *JSSecretsAction) Execute(ctx context.Context, target string, kb *Knowledge, client *transport.Client) ActionResult {
	scripts := kb.GetJSScripts()
	if len(scripts) == 0 {
		return ActionResult{}
	}
	if len(scripts) > jsMaxAssets {
		scripts = scripts[:jsMaxAssets]
	}

	var findings []Finding
	// seenLiteral dedupes across assets: the same key re-shipped in five
	// chunks is one credential, not five findings.
	seenLiteral := make(map[string]bool)

	for _, ref := range scripts {
		fetchURL := resolveAgainstTarget(target, ref)
		if fetchURL == "" {
			continue
		}
		asset := shortAsset(ref, target)

		cctx, cancel := context.WithTimeout(ctx, 12*time.Second)
		resp, err := client.Do(cctx, &types.Request{
			Method: "GET",
			URL:    fetchURL,
		})
		cancel()
		if err != nil || resp == nil || resp.StatusCode != 200 || len(resp.Body) == 0 {
			continue
		}
		body := resp.Body
		if looksLikeHTMLDocument(body) {
			// Soft-404/SPA fallback: not JavaScript, nothing to claim.
			continue
		}
		// Hand the declared map reference to Source Map Discovery so it
		// fetches the real map instead of guessing one filename.
		if m := findSourceMappingURL(body); m != "" {
			kb.SetSourceMapRef(ref, m)
		}
		if len(body) > jsScanCap {
			body = body[:jsScanCap]
		}

		for _, hit := range scanSecrets(string(body)) {
			if seenLiteral[hit.Literal] {
				continue
			}
			seenLiteral[hit.Literal] = true

			findings = append(findings, Finding{
				Type:     "js_secret_literal",
				Name:     fmt.Sprintf("%s in served JS: %s", hit.Pattern, types.Sanitize(asset)),
				Severity: hit.Severity,
				Description: fmt.Sprintf("%s matches the %s pattern in the asset body. %s.",
					hit.Pattern, hit.Pattern, hit.Verify),
				Evidence: fmt.Sprintf("%s at byte offset %d in %s", redactSecret(hit.Literal), hit.Offset, types.Sanitize(asset)),
				Details: map[string]string{
					"pattern":        hit.Pattern,
					"asset":          asset,
					"offset":         fmt.Sprintf("%d", hit.Offset),
					"literal_length": fmt.Sprintf("%d", len(hit.Literal)),
					"verify":         hit.Verify,
				},
			})
		}
	}

	if len(findings) > 0 {
		kb.AddCapability(Capability{
			Name:   "has_js_secrets",
			Origin: OriginVerified,
			Target: target,
			Details: map[string]string{
				"evidence":  fmt.Sprintf("%d credential-shaped literal(s) read from first-party assets", len(findings)),
				"derivedBy": "asset body fetched and matched (executed read, same host)",
			},
		})
	}
	return ActionResult{Findings: findings}
}

func shortAsset(ref, target string) string {
	a := strings.TrimPrefix(ref, target)
	a = strings.TrimPrefix(a, "/")
	if a == "" {
		a = ref
	}
	return minStr(a, 120)
}

// resolveAgainstTarget absolutizes a crawler-stored script reference and
// keeps third-party hosts (CDN vendor bundles) out of scope: only the
// target origin is audited. It resolves the script itself — NOT its .map
// counterpart, which is SourceMapAction's job; scanning the map instead
// of the shipped bundle would miss exactly the minified assets where
// secrets live. Empty string means "unresolvable or out of scope".
func resolveAgainstTarget(target, ref string) string {
	base, err := url.Parse(sanitizeTargetForResolve(target))
	if err != nil || base.Host == "" {
		return ""
	}
	abs := resolveURL(strings.TrimSpace(ref), base.String())
	if abs == "" {
		return ""
	}
	if !isDomainScopedURL(abs, strings.ToLower(base.Hostname())) {
		return ""
	}
	return abs
}
