package engine

import (
	"context"
	"testing"
)

// role="img" is ARIA accessibility markup, not a leaked privilege; a genuine
// admin/owner/is_admin=true disclosure is. The role indicator must fire only
// on the latter.
func TestAuthRoleIndicatorIgnoresARIARequiresPrivilege(t *testing.T) {
	a := NewAuthAnalyzer()

	fs := a.Analyze(context.Background(), respWithBody(
		`<figure class="session" role="img" aria-label="chart"></figure>`+
			`<span role="presentation">decorative</span>`))
	for _, f := range fs {
		if f.Name == "Privilege/Role Information Exposed" {
			t.Errorf("ARIA role attribute is not a privilege leak: %+v", f)
		}
	}

	fs2 := a.Analyze(context.Background(), respWithBody(
		`{"user":"bob","role":"administrator","is_admin":true}`))
	var found bool
	for _, f := range fs2 {
		if f.Name == "Privilege/Role Information Exposed" {
			found = true
		}
	}
	if !found {
		t.Errorf("a real admin-role binding should raise the privilege finding: %+v", fs2)
	}
}
