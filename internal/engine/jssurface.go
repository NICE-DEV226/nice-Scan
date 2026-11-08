package engine

import (
	"context"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/detect"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// JS surface discovery for `scan`: a SPA declares its API routes inside
// its bundles, not in its markup. The phase-1 homepage GET already hands
// us the HTML — this pass reads the <script src> tags off THAT response,
// fetches a bounded set of same-origin bundles, and turns the path
// literals inside them into ordinary probes. The literal grammar is
// shared with the hacker pipeline via detect.ExtractJSPaths, so both
// modes see the same surface.
//
// Bounds: at most jsMaxAssets bundles per target, jsAssetTimeout per
// fetch, jsPathMax literals per bundle — a scan stays a scan, not a
// bundle mirror.

const (
	jsMaxAssets     = 5
	jsAssetTimeout  = 10 * time.Second
	jsMaxAssetBytes = 2 << 20 // 2 MiB — larger bundles are truncated anyway
)

var rxScriptSrc = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)

// discoverJSSurface reads each preamble homepage response for script tags,
// fetches the same-origin .js assets, and stores the extracted endpoint
// paths per target. Failures are silent by design: JS discovery is an
// accelerator, never a reason to fail a scan.
func (s *Scanner) discoverJSSurface(ctx context.Context, preamble []*types.Result) {
	if s.opts == nil {
		return
	}
	for _, res := range preamble {
		if res == nil || res.Response == nil || res.Response.StatusCode != 200 {
			continue
		}
		target := res.Target
		body := res.Response.Body
		if !looksLikeHTML(body) {
			continue
		}
		base, err := url.Parse(target)
		if err != nil || base.Host == "" {
			continue
		}

		var paths []string
		seenPath := make(map[string]bool)
		fetched := 0
		for _, m := range rxScriptSrc.FindAllStringSubmatch(string(body), -1) {
			if fetched >= jsMaxAssets {
				break
			}
			src := strings.TrimSpace(m[1])
			if !strings.Contains(strings.ToLower(src), ".js") {
				continue
			}
			abs := resolveSameOrigin(base, src)
			if abs == "" {
				continue
			}
			fetched++
			assetPaths := s.fetchJSEndpoints(ctx, abs)
			for _, p := range assetPaths {
				if !seenPath[p] {
					seenPath[p] = true
					paths = append(paths, p)
				}
			}
		}
		if len(paths) > 0 {
			s.mu.Lock()
			if s.jsPaths == nil {
				s.jsPaths = map[string][]string{}
			}
			s.jsPaths[target] = paths
			s.mu.Unlock()
		}
	}
}

// fetchJSEndpoints GETs one bundle and returns the absolute endpoint URLs
// its literals resolve to. HTML-looking bodies are skipped — that is the
// SPA soft-404 shell, not JavaScript.
func (s *Scanner) fetchJSEndpoints(ctx context.Context, assetURL string) []string {
	cctx, cancel := context.WithTimeout(ctx, jsAssetTimeout)
	defer cancel()
	resp, err := s.client.Do(cctx, &types.Request{
		Method:  "GET",
		URL:     assetURL,
		Timeout: jsAssetTimeout,
		Origin:  types.PathObserved,
	})
	if err != nil || resp == nil || resp.StatusCode != 200 || len(resp.Body) == 0 {
		return nil
	}
	body := resp.Body
	if len(body) > jsMaxAssetBytes {
		body = body[:jsMaxAssetBytes]
	}
	if looksLikeHTML(body) {
		return nil
	}
	text := string(body)

	base, err := url.Parse(assetURL)
	if err != nil {
		return nil
	}
	var out []string
	for _, lit := range detect.ExtractJSPaths(text) {
		if abs := resolveSameOrigin(base, lit); abs != "" {
			out = append(out, abs)
		}
	}
	return out
}

// jsSurfaceRequests turns the paths discoverJSSurface stored for target
// into ordinary GET probes. They flow through the same worker pool,
// analyzers, soft-404 tagging and provenance stamping as every other
// probe — a JS-declared route is surface to test, not a finding.
func (s *Scanner) jsSurfaceRequests(target string) []*types.Request {
	if s.opts == nil {
		return nil
	}
	s.mu.Lock()
	paths := s.jsPaths[target]
	s.mu.Unlock()

	base := strings.TrimRight(target, "/")
	var reqs []*types.Request
	for _, p := range paths {
		// Paths were stored absolute; keep only the path+query and hang
		// it off the scan target so a CDN-hosted literal cannot move the
		// request off-origin.
		if u, err := url.Parse(p); err == nil {
			rel := u.RequestURI()
			if rel != "" && strings.HasPrefix(rel, "/") {
				reqs = append(reqs, &types.Request{
					Method:  "GET",
					URL:     base + rel,
					Timeout: s.opts.Timeout,
					Origin:  types.PathObserved,
				})
			}
		}
	}
	return reqs
}

// resolveSameOrigin absolutizes ref against base and returns "" unless the
// result stays on base's exact host — a bundle must never aim the scanner
// at a third-party origin.
func resolveSameOrigin(base *url.URL, ref string) string {
	u, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	abs := base.ResolveReference(u)
	if abs.Scheme != "http" && abs.Scheme != "https" {
		return ""
	}
	if !strings.EqualFold(abs.Host, base.Host) {
		return ""
	}
	return abs.String()
}
