package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

func respWithBody(body string) *types.Response {
	return &types.Response{
		StatusCode: 200,
		Body:       []byte(body),
		FinalURL:   "https://example.com/",
		RequestURL: "https://example.com/",
	}
}

// A bare 16-digit run (order id, tracking number) must NOT be a CRITICAL PCI
// finding; only a Luhn-valid number with a real issuer prefix qualifies.
func TestCreditCardRequiresLuhnAndPrefix(t *testing.T) {
	a := NewDataExtractionAnalyzer()

	// Valid test Visa (Luhn-clean, 4-prefix).
	fs := a.Analyze(context.Background(), respWithBody("card on file: 4111111111111111"))
	var cardHit bool
	var ev string
	for _, f := range fs {
		if strings.Contains(f.Name, "Credit Card") {
			cardHit = true
			ev = f.Evidence
		}
	}
	if !cardHit {
		t.Fatal("a Luhn-valid Visa number should surface")
	}
	if strings.Contains(ev, "4111111111111111") {
		t.Errorf("full PAN must be masked in the report, got %q", ev)
	}

	// 16 digits, Luhn-BROKEN and no card prefix → an order id, not a card.
	fs2 := a.Analyze(context.Background(), respWithBody("order 1234567890123456 shipped"))
	for _, f := range fs2 {
		if strings.Contains(f.Name, "Credit Card") {
			t.Errorf("arbitrary digit run must not be flagged as a card: %+v", f)
		}
	}
}

// A structured users collection should raise the reference.
func TestUserDumpRequiresStructuredContext(t *testing.T) {
	a := NewDataExtractionAnalyzer()

	fs := a.Analyze(context.Background(), respWithBody("Thank you to all our valued members and users!"))
	for _, f := range fs {
		if f.Name == "User Data Reference Found" {
			t.Errorf("prose mention of users/members is not a data dump: %+v", f)
		}
	}

	fs2 := a.Analyze(context.Background(), respWithBody(`{"users":[{"email":"a@b.c","ssn":"1"}]}`))
	var found bool
	for _, f := range fs2 {
		if f.Name == "User Data Reference Found" {
			found = true
		}
	}
	if !found {
		t.Errorf("a structured users collection should raise the reference: %+v", fs2)
	}
}

// Template placeholder emails (RFC 2606 domains and stub local-parts like
// "utilisateur@"/"exemple@") flooded the PII finding with non-existent
// contacts. They must be filtered; a real address must still surface.
func TestPlaceholderEmailsFiltered(t *testing.T) {
	a := NewDataExtractionAnalyzer()

	fs := a.Analyze(context.Background(), respWithBody(
		"contact utilisateur@mail.com or exemple@mail.com — ou vous@mail.com"))
	for _, f := range fs {
		if strings.Contains(f.Name, "Email Addresses Found") {
			t.Errorf("placeholder emails must not raise a PII finding: %+v", f)
		}
	}

	fs2 := a.Analyze(context.Background(), respWithBody(
		"reach support at jane.doe@acme-corp.io (utilisateur@mail.com is a sample)"))
	var hit *types.Finding
	for i, f := range fs2 {
		if strings.Contains(f.Name, "Email Addresses Found") {
			hit = &fs2[i]
		}
	}
	if hit == nil {
		t.Fatalf("a real address must still raise the finding despite the placeholder: %+v", fs2)
	}
	if !strings.Contains(hit.Evidence, "jane.doe@acme-corp.io") {
		t.Errorf("evidence should carry the real address, got %q", hit.Evidence)
	}
	if strings.Contains(hit.Evidence, "utilisateur@mail.com") {
		t.Errorf("placeholder address leaked into evidence: %q", hit.Evidence)
	}
}

// const with a real, decodable JWT (header.payload.signature).
const testJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZW1haWwiOiJqb2huQGV4YW1wbGUuY29tIn0.Zsig123"

// The old matcher called ANY {"email":…} JSON a "JWT Claim Data" finding at
// MEDIUM — wrong on two counts: there was no JWT, and a JWT payload is not a
// secret (base64url, not encrypted). It must now (a) only fire when a real
// three-part JWT is present and decoded, and (b) report INFO, not Medium.
func TestJWTIdentityClaimsNotASecretWithoutToken(t *testing.T) {
	a := NewDataExtractionAnalyzer()

	// Plain JSON with a name/email but NO token anywhere.
	fs := a.Analyze(context.Background(), respWithBody(`{"name":"John Doe","email":"john@example.com"}`))
	for _, f := range fs {
		if strings.Contains(f.Name, "JWT") {
			t.Errorf("plain JSON with no JWT must not raise a JWT finding: %+v", f)
		}
	}

	// A real JWT carrying the same identity claims: now it is a genuine, but
	// informational, observation.
	fs2 := a.Analyze(context.Background(), respWithBody("token: "+testJWT))
	var hit *types.Finding
	for i := range fs2 {
		if strings.Contains(fs2[i].Name, "JWT") {
			hit = &fs2[i]
		}
	}
	if hit == nil {
		t.Fatal("a real JWT with identity claims should surface the informational note")
	}
	if hit.Severity != types.SeverityInfo {
		t.Errorf("JWT identity claims are client-visible by design, want Info, got %v", hit.Severity)
	}
	if hit.Type == types.FindingSecret {
		t.Errorf("identity claims are not a secret; Type must not be FindingSecret")
	}
}
