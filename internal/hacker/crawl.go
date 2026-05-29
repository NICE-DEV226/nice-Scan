package hacker

import (
	"context"
	"net/url"
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
		links := extractLinks(body, baseURL)
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

		if forms > 0 {
			formTypes := detectFormTypes(body)
			for _, ft := range formTypes {
				kb.AddFinding(Finding{
					Type:        ft,
					Name:        ft + " form detected",
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
	Pages int
	Findings []Finding
}

func extractLinks(body, baseURL string) []string {
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
				if body[end] == byte(quote) {
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
				if body[end] == byte(quote) {
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

func detectFormTypes(body string) []string {
	var types []string
	lowBody := strings.ToLower(body)

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

	seen := make(map[string]bool)
	for _, check := range formChecks {
		if strings.Contains(lowBody, check.keyword) && !seen[check.ftype] {
			types = append(types, check.ftype)
			seen[check.ftype] = true
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
