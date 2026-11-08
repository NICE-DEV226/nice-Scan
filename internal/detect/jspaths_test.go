package detect

import (
	"strings"
	"testing"
)

func TestExtractJSPaths(t *testing.T) {
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
	`
	// Template literals carry ${} — never a concrete URL, must be skipped.
	body += "`/api/items/${id}`"
	got := ExtractJSPaths(body)
	set := map[string]bool{}
	for _, p := range got {
		set[p] = true
	}

	want := []string{"/api/v1/users", "/api/v1/orders/{id}", "/admin/panel"}
	for _, w := range want {
		if !set[w] {
			t.Errorf("missing path %q (got %v)", w, got)
		}
	}
	for _, p := range got {
		if strings.Contains(p, "evil.example.com") || strings.Contains(p, ".js") ||
			strings.Contains(p, ".map") || strings.Contains(p, ".png") ||
			strings.Contains(p, "relative") || strings.Contains(p, " ") ||
			strings.Contains(p, "$") {
			t.Errorf("non-path leaked: %q", p)
		}
	}
}

func TestExtractJSPathsDedupAndCap(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 200; i++ {
		sb.WriteString("'/api/ep" + strings.Repeat("x", i%7) + "'")
	}
	got := ExtractJSPaths(sb.String())
	if len(got) > JSPathMax {
		t.Fatalf("cap exceeded: %d > %d", len(got), JSPathMax)
	}
	seen := map[string]bool{}
	for _, p := range got {
		if seen[p] {
			t.Fatalf("duplicate path %q", p)
		}
		seen[p] = true
	}
}
