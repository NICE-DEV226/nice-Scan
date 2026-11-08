package detect

import (
	"regexp"
	"strings"
)

// JS path-literal extraction, shared by the hacker pipeline and the
// engine scanner: SPAs declare their API surface in JavaScript bundles,
// not in HTML. One extractor keeps the two callers from drifting — a
// literal the hacker feeds to probes must be the same literal the engine
// would have fed.
//
// Conservative by construction: only quoted literals that look like
// same-origin paths (leading '/', sane charset, bounded length). Build
// artifacts and template literals are filtered — they are not concrete
// URLs a probe could request.

const JSPathMax = 100

var (
	// Quoted string literal: "…" or '…' — JS bundles overwhelmingly use
	// these for route and API paths. Template literals are skipped on
	// purpose: a `…${x}…` path cannot be probed as a concrete URL anyway.
	rxJSString = regexp.MustCompile(`["']([^"']{2,200})["']`)
	// A plausible path: starts with /, no whitespace, URL-safe charset.
	rxJSPath = regexp.MustCompile(`^/[A-Za-z0-9/_.~\-{}%]+$`)
	// Build artifacts that are never API endpoints.
	rxJSAsset = regexp.MustCompile(`(?i)\.(js|css|map|png|jpe?g|svg|woff2?|ttf|ico|webp|json|xml|txt|pdf)(\?|$)`)
)

// ExtractJSPaths returns deduplicated root-relative path literals found
// in a JavaScript body, in order of appearance, capped at JSPathMax.
// Callers resolve them against their own target/origin — this function
// knows nothing about hosts, which keeps it pure and testable.
func ExtractJSPaths(body string) []string {
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
		if seen[lit] {
			continue
		}
		seen[lit] = true
		out = append(out, lit)
		if len(out) >= JSPathMax {
			break
		}
	}
	return out
}
