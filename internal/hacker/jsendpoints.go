package hacker

import (
	"github.com/NICE-DEV226/nice-Scan/internal/detect"
)

// extractJSEndpoints resolves the shared detect.ExtractJSPaths literals
// against the target origin. The literal grammar lives in detect so the
// engine scanner and this pipeline extract the SAME surface from a
// bundle; only the URL resolution is hacker-specific (it already owns
// resolveAgainstTarget and the domain-scope check).
func extractJSEndpoints(body string, target string) []string {
	var out []string
	seen := make(map[string]bool)
	for _, lit := range detect.ExtractJSPaths(body) {
		abs := resolveAgainstTarget(target, lit)
		if abs == "" || seen[abs] {
			continue
		}
		seen[abs] = true
		out = append(out, abs)
	}
	return out
}
