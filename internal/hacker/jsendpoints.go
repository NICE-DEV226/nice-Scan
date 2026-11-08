package hacker

import (
	"regexp"
	"strings"
)

// Endpoint strings harvested from served JavaScript. SPAs declare their
// API surface in bundles, not in HTML — a crawler that only reads markup
// sees the shell and nothing else. These literals are *declared* surface:
// they become Endpoint records other actions can probe, but no finding is
// ever asserted from the string alone.
//
// Conservative by construction: only quoted literals that look like
// same-origin paths (leading '/', sane charset, bounded length). Versioned
// asset paths (/static/js/...) and sourcemap URLs are filtered out — they
// are build artifacts, not API surface.

const jsEndpointMax = 100

var (
	// Quoted string literal: "…" or '…' — JS bundles overwhelmingly use
	// these for route and API paths. Template literals are skipped on
	// purpose: a `…${x}…` path cannot be probed as a concrete URL anyway.
	rxJSString = regexp.MustCompile(`["']([^"']{2,200})["']`)
	// A plausible path: starts with /, no whitespace, URL-safe charset.
	rxJSPath = regexp.MustCompile(`^/[A-Za-z0-9/_.~\-{}%]+$`)
	// Build artifacts that are never API endpoints.
	rxJSAsset = regexp.MustCompile(`(?i)\.(js|css|map|png|jpe?g|svg|woff2?|ttf|ico|webp)(\?|$)`)
)

// extractJSEndpoints pulls same-origin path literals out of a JS bundle.
// Returns deduplicated absolute URLs resolved against target. Third-party
// URLs are dropped — the scope boundary stays with the transport, but
// there is no reason to even record them.
func extractJSEndpoints(body string, target string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, m := range rxJSString.FindAllStringSubmatch(body, -1) {
		lit := m[1]
		if !strings.HasPrefix(lit, "/") || !rxJSPath.MatchString(lit) {
			continue
		}
		if rxJSAsset.MatchString(lit) {
			continue
		}
		// Skip obvious non-routes: single-segment static-looking names
		// are rare enough that the asset filter above suffices; keep it
		// simple rather than guessing at route vs asset by name.
		abs := resolveAgainstTarget(target, lit)
		if abs == "" || seen[abs] {
			continue
		}
		seen[abs] = true
		out = append(out, abs)
		if len(out) >= jsEndpointMax {
			break
		}
	}
	return out
}
