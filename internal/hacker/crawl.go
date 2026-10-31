package hacker

import (
	"context"
	"net/url"
	"strconv"
	"strings"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

type CrawlAction struct{}

func (a *CrawlAction) Metadata() ActionMetadata {
	return ActionMetadata{
		Name:        "Web Crawler",
		Description: "BFS crawl — discover pages, forms, endpoints, JS files",
		Priority:    10,
		Requires:    nil,
		Provides:    []string{"has_pages", "has_api", "has_login", "has_admin", "has_upload", "has_graphql", "has_forms"},
	}
}

func (a *CrawlAction) Execute(ctx context.Context, target string, kb *Knowledge, client *transport.Client) ActionResult {
	baseURL := strings.TrimRight(target, "/")
	visited := make(map[string]bool)
	var queue []string
	queue = append(queue, baseURL)
	visited[baseURL] = true

	maxPages := 30
	depth := map[string]int{baseURL: 0}
	maxDepth := 2

	var findings []Finding

	for len(queue) > 0 && len(visited) <= maxPages {
		select {
		case <-ctx.Done():
			return ActionResult{Findings: findings}
		default:
		}

		u := queue[0]
		queue = queue[1:]

		if depth[u] >= maxDepth {
			continue
		}

		resp, err := client.Do(ctx, &types.Request{
			Method: "GET",
			URL:    u,
		})
		if err != nil {
			continue
		}

		body := string(resp.Body)
		links := extractLinks(body)
		jsFiles := extractJS(body)
		forms := extractFormCount(body)
		title := extractTitle(body)

		page := Page{
			URL:     u,
			Title:   title,
			Forms:   forms,
			Links:   links,
			JSFiles: jsFiles,
			BodyLen: len(body),
			Status:  resp.StatusCode,
		}
		kb.AddPage(page)

		// has_pages was declared in Metadata.Provides but never recorded, so
		// every action gated on it (the Fuzzer, and through it has_api →
		// LFI/CMD) was silently unreachable: the run stopped after the
		// crawl no matter what the target served. One fetched page is
		// executed evidence that pages exist, so record it verified.
		if resp.StatusCode > 0 {
			kb.AddCapability(Capability{
				Name:   "has_pages",
				Origin: OriginVerified,
				Target: kb.target,
				Details: map[string]string{
					"evidence":  u + " (page fetched, HTTP " + strconv.Itoa(resp.StatusCode) + ")",
					"derivedBy": "crawler executed fetch",
				},
			})
		}

		if forms > 0 {
			// Provenance rules for crawl-derived capabilities (review P0-2):
			// a page the crawler fetched from the target is an EXECUTED
			// fetch, but the capability semantics usually rest on words
			// inside remote-controlled markup. Structural markers (a real
			// password-type input, a real file input) are wire-grounded and
			// verified; word matches ("dashboard", "/api", "graphql") are
			// observed — real page, unproven semantics — and can no longer
			// unlock destructive chains the report sells as executed.
			kb.AddCapability(Capability{
				Name:   "has_forms",
				Origin: OriginVerified,
				Target: kb.target,
				Details: map[string]string{
					"evidence":  u + " (form elements present in fetched markup)",
					"derivedBy": "crawler structural detection (executed fetch, same host)",
				},
			})
			for _, fc := range crawlFormEvidence(body) {
				kb.AddCapability(Capability{
					Name:   fc.name,
					Origin: fc.origin,
					Target: kb.target,
					Details: map[string]string{
						"evidence":  u + ": " + fc.detail,
						"derivedBy": "crawler form detection (" + fc.origin + ")",
					},
				})
				kb.AddFinding(Finding{
					Type:        fc.name,
					Name:        fc.name + " form detected",
					Severity:    SevMedium,
					Description: "Form found on " + u,
					Evidence:    u,
				})
			}
		}

		if len(jsFiles) > 0 {
			findings = append(findings, Finding{
				Type:        "js_discovery",
				Name:        "JavaScript files discovered",
				Severity:    SevInfo,
				Description: "JS files may contain API endpoints, tokens, and secrets",
				Evidence:    strings.Join(jsFiles, ", "),
			})
		}

		if len(links) > 30 {
			findings = append(findings, Finding{
				Type:        "crawl_sitemap",
				Name:        "Large page with many links",
				Severity:    SevInfo,
				Description: "Page may be a sitemap or index with many endpoints",
				Evidence:    u,
			})
		}

		for _, link := range links {
			abs := resolveURL(link, baseURL)
			if abs == "" {
				continue
			}
			if !isSameDomain(abs, baseURL) {
				continue
			}
			if !visited[abs] {
				visited[abs] = true
				depth[abs] = depth[u] + 1
				queue = append(queue, abs)
				kb.SetParentURL(abs, u)
			}
		}
	}

	return ActionResult{Findings: findings}
}

type CrawlResult struct {
	Pages    int
	Findings []Finding
}

func extractLinks(body string) []string {
	var links []string
	seen := make(map[string]bool)

	for i := 0; i < len(body); {
		idx := strings.Index(strings.ToLower(body[i:]), "href=")
		if idx == -1 {
			break
		}
		start := i + idx + 5
		if start >= len(body) {
			break
		}
		var end int
		quote := body[start]
		if quote == '"' || quote == '\'' {
			for end = start + 1; end < len(body); end++ {
				if body[end] == quote {
					break
				}
			}
			link := body[start+1 : end]
			link = strings.TrimSpace(link)
			if link != "" && !strings.HasPrefix(link, "#") && !strings.HasPrefix(link, "javascript:") && !strings.HasPrefix(link, "mailto:") && !strings.HasPrefix(link, "tel:") && !seen[link] {
				links = append(links, link)
				seen[link] = true
			}
			i = end + 1
		} else {
			i = start + 1
		}
	}
	return links
}

func extractJS(body string) []string {
	var jsFiles []string
	seen := make(map[string]bool)
	lowBody := strings.ToLower(body)

	for i := 0; i < len(lowBody); {
		idx := strings.Index(lowBody[i:], "src=")
		if idx == -1 {
			break
		}
		start := i + idx + 4
		if start >= len(lowBody) {
			break
		}
		var end int
		quote := body[start]
		if quote == '"' || quote == '\'' {
			for end = start + 1; end < len(body); end++ {
				if body[end] == quote {
					break
				}
			}
			src := body[start+1 : end]
			if (strings.HasSuffix(strings.ToLower(src), ".js") || strings.Contains(strings.ToLower(src), ".js?")) && !seen[src] {
				jsFiles = append(jsFiles, src)
				seen[src] = true
			}
			i = end + 1
		} else {
			i = start + 1
		}
	}

	_ = strings.Contains(lowBody, "<script")
	return jsFiles
}

func extractFormCount(body string) int {
	count := 0
	lowBody := strings.ToLower(body)
	for i := 0; i < len(lowBody); {
		idx := strings.Index(lowBody[i:], "<form")
		if idx == -1 {
			break
		}
		closing := strings.IndexByte(lowBody[i+idx:], '>')
		if closing == -1 {
			break
		}
		count++
		i = i + idx + closing + 1
	}
	return count
}

func extractTitle(body string) string {
	lowBody := strings.ToLower(body)
	start := strings.Index(lowBody, "<title")
	if start == -1 {
		return ""
	}
	closeTag := strings.IndexByte(body[start:], '>')
	if closeTag == -1 {
		return ""
	}
	contentStart := start + closeTag + 1
	end := strings.Index(lowBody[contentStart:], "</title>")
	if end == -1 {
		return ""
	}
	title := body[contentStart : contentStart+end]
	title = strings.TrimSpace(title)
	if len(title) > 100 {
		title = title[:97] + "..."
	}
	return title
}

// detectFormTypes classifies forms by scanning only the markup between real
// <form> and </form> tags of an already fetched page. Matching keywords
// anywhere in the page body (inside commented-out code, JSON payloads or
// plain prose) used to fabricate "X form detected" findings; restricting the
// scan to actual form segments keeps the classification to what the crawler
// really observed.
// crawlFormCap is one crawl-derived capability with its provenance class
// and the concrete marker that produced it.
type crawlFormCap struct {
	name   string
	origin string
	detail string
}

// crawlFormEvidence classifies fetched form markup. Hygiene split:
//
//   - VERIFIED (structural markers in real markup): a password-type input
//     (a login form exists and takes credentials), a file-type input (an
//     upload surface exists). These are wire-grounded element semantics,
//     not prose.
//   - OBSERVED (remote-controlled words): register/signup/reset, graphql,
//     /api, admin/dashboard, and the word-only login/upload matches. The
//     page is real; the capability is a guess the report must label.
func crawlFormEvidence(body string) []crawlFormCap {
	lowBody := strings.ToLower(body)
	var out []crawlFormCap
	seen := func(name string) bool {
		for _, c := range out {
			if c.name == name {
				return true
			}
		}
		return false
	}
	add := func(name, origin, detail string) {
		if !seen(name) {
			out = append(out, crawlFormCap{name: name, origin: origin, detail: detail})
		}
	}

	segments := formSegments(lowBody)
	for _, seg := range segments {
		hasPasswordInput := strings.Contains(seg, `type="password"`) ||
			strings.Contains(seg, "type=password") ||
			strings.Contains(seg, `type='password'`)
		hasFileInput := strings.Contains(seg, `type="file"`) ||
			strings.Contains(seg, "type=file") ||
			strings.Contains(seg, `type='file'`)

		switch {
		case hasPasswordInput:
			add("has_login", OriginVerified, "password-type input present in fetched form")
		case strings.Contains(seg, "login") || strings.Contains(seg, "signin"):
			add("has_login", OriginObserved, "word 'login/signin' inside form markup")
		}

		switch {
		case hasFileInput:
			add("has_upload", OriginVerified, "file-type input present in fetched form")
		case strings.Contains(seg, "upload") || strings.Contains(seg, "file"):
			add("has_upload", OriginObserved, "word 'upload/file' inside form markup")
		}

		switch {
		case strings.Contains(seg, "register") || strings.Contains(seg, "signup"):
			add("has_register", OriginObserved, "registration marker inside form markup")
		}
		switch {
		case strings.Contains(seg, "reset") || strings.Contains(seg, "forgot"):
			add("has_reset", OriginObserved, "reset-flow marker inside form markup")
		}
		switch {
		case strings.Contains(seg, "graphql"):
			add("has_graphql", OriginObserved, "word 'graphql' inside form markup")
		}
		switch {
		case strings.Contains(seg, "/api") || strings.Contains(seg, "api/"):
			add("has_api", OriginObserved, "api path reference inside form markup")
		}
		switch {
		case strings.Contains(seg, "admin") || strings.Contains(seg, "dashboard"):
			add("has_admin", OriginObserved, "word 'admin/dashboard' inside form markup")
		}
	}
	return out
}

// formSegments slices lowercased markup into <form …>…</form> segments
// (shared by the evidence classifier).
func formSegments(lowBody string) []string {
	var segs []string
	rest := lowBody
	for {
		start := strings.Index(rest, "<form")
		if start < 0 {
			break
		}
		end := strings.Index(rest[start:], "</form>")
		if end >= 0 {
			segs = append(segs, rest[start:start+end])
			rest = rest[start+end+len("</form>"):]
		} else {
			segs = append(segs, rest[start:])
			break
		}
	}
	return segs
}

func detectFormTypes(body string) []string {
	var types []string

	formChecks := []struct {
		keyword string
		ftype   string
	}{
		{"password", "has_login"},
		{"login", "has_login"},
		{"signin", "has_login"},
		{"register", "has_register"},
		{"signup", "has_register"},
		{"reset", "has_reset"},
		{"forgot", "has_reset"},
		{"upload", "has_upload"},
		{"file", "has_upload"},
		{"graphql", "has_graphql"},
		{"/api", "has_api"},
		{"admin", "has_admin"},
		{"dashboard", "has_admin"},
	}

	lowBody := strings.ToLower(body)
	seen := make(map[string]bool)
	rest := lowBody
	for {
		start := strings.Index(rest, "<form")
		if start < 0 {
			break
		}
		end := strings.Index(rest[start:], "</form>")
		segment := rest[start:]
		if end >= 0 {
			segment = rest[start : start+end]
			rest = rest[start+end+len("</form>"):]
		} else {
			rest = ""
		}
		for _, check := range formChecks {
			if strings.Contains(segment, check.keyword) && !seen[check.ftype] {
				types = append(types, check.ftype)
				seen[check.ftype] = true
			}
		}
	}
	return types
}

func resolveURL(href, baseURL string) string {
	if href == "" || href == "/" {
		return ""
	}
	if strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://") {
		return href
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	rel, err := url.Parse(href)
	if err != nil {
		return ""
	}
	resolved := base.ResolveReference(rel)
	result := resolved.String()
	if result == baseURL {
		return ""
	}
	if strings.Contains(result, "#") {
		result = result[:strings.IndexByte(result, '#')]
	}
	result = strings.TrimSuffix(result, "?")
	return result
}

func isSameDomain(u1, u2 string) bool {
	p1, err1 := url.Parse(u1)
	p2, err2 := url.Parse(u2)
	if err1 != nil || err2 != nil {
		return true
	}
	return p1.Host == p2.Host
}

// sameHostStrict is the security-relevant variant used wherever a URL from
// remote data gates a network action: parse errors fail closed (unlike
// isSameDomain, whose fail-open is fine for crawl bookkeeping but not for
// credential routing).
func sameHostStrict(u1, u2 string) bool {
	p1, err1 := url.Parse(u1)
	p2, err2 := url.Parse(u2)
	if err1 != nil || err2 != nil {
		return false
	}
	return strings.EqualFold(p1.Host, p2.Host)
}
