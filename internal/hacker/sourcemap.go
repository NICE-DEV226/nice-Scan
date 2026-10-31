package hacker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// SourceMapAction fetches the source map behind every first-party script the
// crawler collected. A published map hands an attacker the application tree:
// original source paths, function names, and — when `sourcesContent` is
// present — the full original sources, which is where hardcoded credentials
// and hidden endpoints surface.
//
// Three things make the detection real rather than guessed:
//
//  1. The map URL a bundle declares (`//# sourceMappingURL=`) is tried first;
//     hidden-source-map builds and renamed bundles do not follow a filename
//     convention, and guessing alone misses them.
//  2. Both common conventions are tried as fallbacks (app.js → app.js.map,
//     the webpack default; app.js → app.map, the terser default).
//  3. A candidate only counts as a map after it parses as Source Map v3 JSON
//     with a non-empty sources array. A 200 with SPA fallback HTML, an empty
//     object, or a 404 is never reported as exposure.
//
// Severity is graded on what the map actually contains: full original source
// (sourcesContent) is High, paths and names only is Medium.
type SourceMapAction struct{}

func (a *SourceMapAction) Metadata() ActionMetadata {
	return ActionMetadata{
		Name:        "Source Map Discovery",
		Description: "Fetches declared and conventional .map files for crawled scripts — verified Source Map v3 exposure only",
		Priority:    43,
		Requires:    nil,
		Provides:    []string{"has_sourcemaps"},
	}
}

const (
	// sourceMapMaxAssets bounds map fetches per run (up to 3 candidates
	// each, so 15 assets ≈ 45 requests worst case).
	sourceMapMaxAssets = 15
	// sourceMapScanCap bounds sourcesContent bytes scanned for secrets.
	sourceMapScanCap = 4 << 20
)

type sourceMapDoc struct {
	Version        int       `json:"version"`
	File           string    `json:"file"`
	Sources        []string  `json:"sources"`
	SourcesContent []*string `json:"sourcesContent"`
	Names          []string  `json:"names"`
}

// parseSourceMap validates the shape. Callers must already know the body is
// not HTML; a JSON object that does not look like a v3 map (version, a
// non-empty sources array) is refused rather than reported.
func parseSourceMap(body []byte) (*sourceMapDoc, bool) {
	trimmed := strings.TrimSpace(string(body))
	if !strings.HasPrefix(trimmed, "{") {
		return nil, false
	}
	var doc sourceMapDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, false
	}
	if doc.Version != 3 || len(doc.Sources) == 0 {
		return nil, false
	}
	return &doc, true
}

// sourceMapCandidates returns the map URLs worth trying for a script, in
// priority order: the declared reference, then the two filename conventions.
// Every candidate is absolutized against the script URL and re-checked
// against the target's domain scope, because the declared value is
// remote-controlled text.
func sourceMapCandidates(target, scriptRef, declared string) []string {
	scriptAbs := resolveAgainstTarget(target, scriptRef)
	if scriptAbs == "" {
		return nil
	}
	base, err := url.Parse(scriptAbs)
	if err != nil {
		return nil
	}
	scope := strings.ToLower(base.Hostname())

	var out []string
	seen := make(map[string]bool)
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "data:") || strings.HasPrefix(raw, "blob:") {
			return
		}
		abs := resolveURL(raw, scriptAbs)
		if abs == "" || seen[abs] {
			return
		}
		if !isDomainScopedURL(abs, scope) {
			return
		}
		seen[abs] = true
		out = append(out, abs)
	}

	add(declared)

	if strings.HasSuffix(strings.ToLower(base.Path), ".js") {
		// webpack/rollup: bump generates app.js + app.js.map.
		withMap := *base
		withMap.Path = base.Path + ".map"
		add(withMap.String())

		// terser/legacy: app.js + app.map.
		trimmed := *base
		trimmed.Path = strings.TrimSuffix(base.Path, ".js") + ".map"
		add(trimmed.String())
	}
	return out
}

func (a *SourceMapAction) Execute(ctx context.Context, target string, kb *Knowledge, client *transport.Client) ActionResult {
	scripts := kb.GetJSScripts()
	if len(scripts) == 0 {
		return ActionResult{}
	}
	if len(scripts) > sourceMapMaxAssets {
		scripts = scripts[:sourceMapMaxAssets]
	}

	var findings []Finding
	seenLiteral := make(map[string]bool)

	for _, ref := range scripts {
		asset := shortAsset(ref, target)
		for _, mapURL := range sourceMapCandidates(target, ref, kb.GetSourceMapRef(ref)) {
			cctx, cancel := context.WithTimeout(ctx, 12*time.Second)
			resp, err := client.Do(cctx, &types.Request{
				Method: "GET",
				URL:    mapURL,
			})
			cancel()
			if err != nil || resp == nil || resp.StatusCode != 200 || len(resp.Body) == 0 {
				continue // unreachable or absent: no claim either way
			}
			if looksLikeHTMLDocument(resp.Body) {
				continue // SPA fallback answering 200 for every path
			}
			doc, ok := parseSourceMap(resp.Body)
			if !ok {
				continue // JSON that is not a source map
			}

			sourcesWithContent := 0
			for _, c := range doc.SourcesContent {
				if c != nil && strings.TrimSpace(*c) != "" {
					sourcesWithContent++
				}
			}

			sev := SevMedium
			impact := "original paths, file names and identifier names are readable"
			if sourcesWithContent > 0 {
				sev = SevHigh
				impact = fmt.Sprintf("the full original source of %d file(s) is downloadable — logic, internal endpoints and any hardcoded credential are readable", sourcesWithContent)
			}

			details := map[string]string{
				"sources":        fmt.Sprintf("%d", len(doc.Sources)),
				"names":          fmt.Sprintf("%d", len(doc.Names)),
				"sourcesContent": fmt.Sprintf("%d", sourcesWithContent),
				"asset":          asset,
			}
			if internal := countInternalPaths(doc.Sources); internal > 0 {
				// Build-machine paths leak the deployment layout; useful
				// for the operator, not a severity change on its own.
				details["internal_paths"] = fmt.Sprintf("%d", internal)
			}

			findings = append(findings, Finding{
				Type:        "source_map_exposed",
				Name:        fmt.Sprintf("Source map exposed: %s", types.Sanitize(asset)),
				Severity:    sev,
				Description: fmt.Sprintf("The build shipped a valid Source Map v3 (%d entries in sources) reachable at %s — %s", len(doc.Sources), mapURL, impact),
				Evidence:    types.Sanitize(fmt.Sprintf("%s — sources: %s", mapURL, strings.Join(previewSources(doc.Sources, 3), ", "))),
				Details:     details,
			})

			// Hardcoded credentials in the original sources are the payoff
			// of an exposed map. Scan them with the same gates the JS
			// scanner uses (keyword, entropy, placeholder allowlist).
			for i, content := range doc.SourcesContent {
				if content == nil || strings.TrimSpace(*content) == "" {
					continue
				}
				src := *content
				if len(src) > sourceMapScanCap {
					src = src[:sourceMapScanCap]
				}
				name := "sourcesContent"
				if i < len(doc.Sources) && doc.Sources[i] != "" {
					name = doc.Sources[i]
				}
				for _, hit := range scanSecrets(src) {
					if seenLiteral[hit.Literal] {
						continue
					}
					seenLiteral[hit.Literal] = true
					findings = append(findings, Finding{
						Type:     "source_map_secret",
						Name:     fmt.Sprintf("%s hardcoded in published source: %s", hit.Pattern, types.Sanitize(shortAsset(name, target))),
						Severity: hit.Severity,
						Description: fmt.Sprintf("The published source map embeds the original file %s, which contains a %s literal. %s.",
							types.Sanitize(minStr(name, 120)), hit.Pattern, hit.Verify),
						Evidence: fmt.Sprintf("%s at byte offset %d in %s (from %s)", redactSecret(hit.Literal), hit.Offset, types.Sanitize(minStr(name, 120)), types.Sanitize(mapURL)),
						Details: map[string]string{
							"pattern":        hit.Pattern,
							"source_file":    name,
							"map":            mapURL,
							"offset":         fmt.Sprintf("%d", hit.Offset),
							"literal_length": fmt.Sprintf("%d", len(hit.Literal)),
							"verify":         hit.Verify,
						},
					})
				}
			}

			// One working map per script is enough: the other candidates
			// are naming variants of the same exposure.
			break
		}
	}

	if len(findings) > 0 {
		kb.AddCapability(Capability{
			Name:   "has_sourcemaps",
			Origin: OriginVerified,
			Target: target,
			Details: map[string]string{
				"evidence":  fmt.Sprintf("%d exposed source map(s) parsed as Source Map v3", countMaps(findings)),
				"derivedBy": "map body fetched and validated (executed read, same host)",
			},
		})
	}
	return ActionResult{Findings: findings}
}

func countMaps(findings []Finding) int {
	n := 0
	for _, f := range findings {
		if f.Type == "source_map_exposed" {
			n++
		}
	}
	return n
}

func previewSources(sources []string, max int) []string {
	var out []string
	for _, s := range sources {
		if len(out) >= max {
			break
		}
		if s == "" {
			continue
		}
		out = append(out, minStr(types.Sanitize(s), 80))
	}
	if len(out) == 0 {
		return []string{"<none>"}
	}
	return out
}

// countInternalPaths counts sources that reveal a build machine's layout
// (absolute home/root paths, drive letters) rather than app-relative paths.
func countInternalPaths(sources []string) int {
	prefixes := []string{"/home/", "/users/", "/root/", "/var/www", "/srv/", "/builds/", `c:\`, "file://"}
	n := 0
	for _, s := range sources {
		low := strings.ToLower(s)
		for _, p := range prefixes {
			if strings.HasPrefix(low, p) || strings.Contains(low, p) {
				n++
				break
			}
		}
	}
	return n
}

// resolveMapURL turns a (possibly relative) script reference into the
// absolute URL of its conventional source map (`<script>.map`). Empty string
// means "not in scope" (third-party vendor scripts stay outside the
// authorized audit). Kept as the single-candidate helper it always was;
// Execute uses sourceMapCandidates, which also honours the declared map.
func resolveMapURL(target, ref string) string {
	cands := sourceMapCandidates(target, ref, "")
	if len(cands) == 0 {
		return ""
	}
	return cands[0]
}

func sanitizeTargetForResolve(target string) string {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}
	return strings.TrimRight(target, "/")
}

func minStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
