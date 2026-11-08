package hacker

import (
	"strings"
	"testing"

	"github.com/NICE-DEV226/nice-Scan/internal/detect"
)

func TestExtractJSEndpoints(t *testing.T) {
	body := `
		const api = {
			users: "/api/v1/users",
			orders: '/api/v1/orders/{id}',
			admin: "/admin/panel",
			static: "/static/js/main.abc123.js",
			map: "/assets/index.js.map",
			img: "/img/logo.png",
			ext: "https://evil.example.com/steal",
			rel: "api/relative/path",
			ws: "/api/with space",
		};
		fetch("/api/v1/users"); axios.get('/api/v1/orders/42');
	`
	got := extractJSEndpoints(body, "https://app.example.com")
	set := map[string]bool{}
	for _, u := range got {
		set[u] = true
	}

	want := []string{
		"https://app.example.com/api/v1/users",
		// {id} is percent-encoded by URL resolution — correct for a probe.
		"https://app.example.com/api/v1/orders/%7Bid%7D",
		"https://app.example.com/admin/panel",
		"https://app.example.com/api/v1/orders/42",
	}
	for _, w := range want {
		if !set[w] {
			t.Errorf("missing endpoint %q (got %v)", w, got)
		}
	}
	for _, u := range got {
		if strings.Contains(u, "evil.example.com") || strings.Contains(u, ".js") ||
			strings.Contains(u, ".map") || strings.Contains(u, ".png") ||
			strings.Contains(u, "relative") || strings.Contains(u, "with space") {
			t.Errorf("non-endpoint leaked: %q", u)
		}
	}
}

func TestExtractJSEndpointsDedupAndCap(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 200; i++ {
		sb.WriteString("'/api/ep" + strings.Repeat("x", i%7) + "'")
	}
	got := extractJSEndpoints(sb.String(), "https://t.example")
	if len(got) > detect.JSPathMax {
		t.Fatalf("cap exceeded: %d > %d", len(got), detect.JSPathMax)
	}
	seen := map[string]bool{}
	for _, u := range got {
		if seen[u] {
			t.Fatalf("duplicate endpoint %q", u)
		}
		seen[u] = true
	}
}
