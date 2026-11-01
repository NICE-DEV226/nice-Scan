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

// The user-dump heuristic once fired HIGH on the prose word "members".
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
