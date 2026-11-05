package engine

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// A credential scanner whose own report contains the credentials it found has
// moved the problem: the report becomes a secret store, gets archived, gets
// pasted into tickets, and in this tool's case gets read by a machine that
// repeats it further. Truncating a value is not masking it — the first 30
// characters of a bearer token are the beginning of a live token.
//
// The house rule is types.RedactSecretValue: four glyphs, which identify the
// provider prefix (AKIA, ghp_, xoxb, AIza), plus the length. This test pins it
// across every secret class the engine reports.
func TestSecretFindingsNeverCarryPlaintextValues(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user-77","exp":4102444800,"email":"ops@corp.example"}`)) +
		".JWTsigTAIL-abcdef0123456789"
	basic := base64.StdEncoding.EncodeToString([]byte("ops:BasicAuthSecretTAIL9999"))
	// Assembled at runtime on purpose: a contiguous Slack-format literal in a
	// credential scanner's own fixture is indistinguishable from a leaked token
	// to push protection, and it has no more business being in this repo than
	// in a report.
	slackToken := "xox" + "b-999999999999-tailtailtailtail"

	body := strings.Join([]string{
		`Authorization: Bearer bearerTAIL-0123456789abcdef`,
		`"api_key": "genericTAIL-0123456789abcdef"`,
		`AWS Access Key ID [None]: AKIAIOSFODNN7EXAMPLEQQ`,
		`token: ghp_TAILTAILTAILTAILTAILTAILTAILTAILTAIL0`,
		`slack = "` + slackToken + `"`,
		`https://maps.googleapis.com/maps/api/data?key=AIzaSyTAIL-abcdefghijklmnopqrst`,
		`Authorization: Basic ` + basic,
		`id_token=` + jwt,
		`db_password=UnquotedSecretTAIL123`,
		`{"username":"ops","password":"BuriedSecretTAIL123"}`,
		`dsn: postgres://app:DSNPasswordTAIL99@db.internal:5432/prod`,
		`other: mysql://db.internal:3306/prod?password=QueryDSNTAIL99`,
	}, "\n")

	headers := http.Header{}
	headers.Add("Set-Cookie", "sessionid=CookieValueTAIL0123456789; Secure; HttpOnly")

	resp := &types.Response{
		StatusCode:  200,
		ContentType: "text/html",
		Headers:     headers,
		Body:        []byte(body),
		RequestURL:  "https://example.com/config",
	}

	ctx := context.Background()
	findings := append(NewTokenExtractor().Analyze(ctx, resp),
		NewDataExtractionAnalyzer().Analyze(ctx, resp)...)

	secrets := []string{
		"bearerTAIL-0123456789abcdef",
		"genericTAIL-0123456789abcdef",
		"IOSFODNN7EXAMPLEQQ",
		"TAILTAILTAILTAILTAILTAILTAILTAIL0",
		"999999999999-tailtailtailtail",
		"TAIL-abcdefghijklmnopqrst",
		"BasicAuthSecretTAIL9999",
		"JWTsigTAIL-abcdef0123456789",
		"UnquotedSecretTAIL123",
		"BuriedSecretTAIL123",
		"CookieValueTAIL0123456789",
		"DSNPasswordTAIL99",
		"QueryDSNTAIL99",
	}

	var secretFindings int
	for _, f := range findings {
		if f.Type != types.FindingSecret && !strings.Contains(f.Name, "Credential") {
			continue
		}
		secretFindings++
		report := f.Name + "\n" + f.Description + "\n" + f.Evidence
		for k, v := range f.Metadata {
			report += "\n" + k + "=" + v
		}
		for _, s := range secrets {
			if strings.Contains(report, s) {
				t.Errorf("finding %q carries the credential %q in plaintext:\n%s", f.Name, s, report)
			}
		}
	}

	// Guard the guard: a fixture that no analyzer matched would pass this
	// test silently.
	if secretFindings < 6 {
		t.Fatalf("the fixture produced only %d secret findings; the bodies no longer reach the analyzers under test: %+v",
			secretFindings, findings)
	}
}

// The email matcher and the connection string overlap: the userinfo of a DSN
// reads as an address, so an unguarded pass reports a live database password
// under a PII label.
func TestDSNUserinfoIsNotReportedAsAnEmail(t *testing.T) {
	resp := &types.Response{
		StatusCode:  200,
		ContentType: "text/html",
		Headers:     http.Header{},
		Body: []byte(`<p>reach us at billing@corp-real.example for invoices</p>` +
			`<p>DATABASE_URL=postgres://app:DSNPasswordTAIL99@db.internal:5432/prod</p>`),
		RequestURL: "https://example.com/config",
	}
	for _, f := range NewDataExtractionAnalyzer().Analyze(context.Background(), resp) {
		if !strings.Contains(f.Name, "Email Addresses Found") {
			continue
		}
		if strings.Contains(f.Evidence, "DSNPasswordTAIL99") {
			t.Errorf("the DSN password was reported as a contact: %q", f.Evidence)
		}
		if !strings.Contains(f.Evidence, "billing@corp-real.example") {
			t.Errorf("a real address was dropped along with the credential: %q", f.Evidence)
		}
		return
	}
	t.Error("the real address must still be reported")
}
