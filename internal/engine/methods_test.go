package engine

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// An "Allow:" header only advertises methods; a server can list PUT/TRACE while
// answering 405/501. The analyzer must never assert the method is ENABLED from
// the header alone — the finding is now worded as advertised/unverified.
func TestMethodsHeaderIsAdvertisedNotEnabled(t *testing.T) {
	resp := &types.Response{
		StatusCode: 200,
		Headers:    http.Header{"Allow": []string{"GET, POST, PUT, DELETE, TRACE"}},
		Body:       []byte("ok"),
		FinalURL:   "https://example.com/",
	}

	m := NewHTTPMethodsAnalyzer()
	fs := m.Analyze(context.Background(), resp)
	var found bool
	for _, f := range fs {
		if strings.Contains(f.Name, "Allow Header") {
			found = true
			if strings.Contains(f.Name, "Enabled") {
				t.Errorf("must not claim methods are Enabled from a header: %q", f.Name)
			}
			if !strings.Contains(f.Description, "unverified") && !strings.Contains(f.Description, "NOT proof") {
				t.Errorf("finding must disclose that advertising is not proof of execution: %q", f.Description)
			}
		}
		if f.Name == "Risky HTTP Methods Enabled" {
			t.Errorf("legacy enabled-claim finding resurfaced: %+v", f)
		}
	}
	if !found {
		t.Fatalf("expected the advertised-methods finding, got %+v", fs)
	}
}
