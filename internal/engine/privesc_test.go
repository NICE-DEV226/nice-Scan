package engine

import (
	"context"
	"testing"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// The SQLi/XSS probes request "/?id=1'" etc. — the analyzer used to run its
// URL-shape checks over those probe responses and flag "Potential IDOR — id"
// on the very referent the scanner had synthesized. A real numeric-id hint is
// a complete "?id=123" value; a probe value carrying a payload character must
// not be mistaken for one.

func respWithURL(u string) *types.Response {
	return &types.Response{
		StatusCode: 200,
		Body:       []byte("ok"),
		FinalURL:   u,
		RequestURL: u,
	}
}

func TestPrivescIgnoresScannerProbeIDOR(t *testing.T) {
	a := NewPrivilegeEscalationAnalyzer()

	// Scanner's own SQLi probe value — NOT a real IDOR referent.
	fs := a.Analyze(context.Background(), respWithURL("https://x.example/?id=1'"))
	for _, f := range fs {
		if f.Name == "Potential IDOR — Numeric id" {
			t.Errorf("phantom IDOR from a probe payload: %+v", f)
		}
	}

	// A genuine numeric-id link must still be surfaced.
	fs2 := a.Analyze(context.Background(), respWithURL("https://x.example/account?order_id=9042&ref=us"))
	var found bool
	for _, f := range fs2 {
		if f.Name == "Potential IDOR — Numeric order_id" {
			found = true
		}
	}
	if !found {
		t.Errorf("real numeric-id referent should raise the IDOR hint: %+v", fs2)
	}
}
