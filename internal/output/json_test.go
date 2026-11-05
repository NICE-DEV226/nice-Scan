package output

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NICE-DEV226/nice-Scan/internal/engine"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// The secrets below are dummies, but they are the shape the analyzers actually
// hand the sink: a full Set-Cookie header in metadata.raw, credentials embedded
// in a URL the analyzer is quoting, and an escape sequence arriving in
// target-controlled text.
const (
	fakeSessionValue = "SECRETFULLSESSIONVALUE0123456789"
	fakeURLPassword  = "SuperSecret123"
)

func redactionFixture() *engine.ScanResult {
	return &engine.ScanResult{
		Target: "https://vanstech.space",
		Stats:  engine.ScanStats{Total: 3, Completed: 3, Findings: 3},
		Findings: []types.Finding{
			{
				Type:        types.FindingSecret,
				Name:        "Session Cookie: sessionid\x1b]52;c;aGVsbG8=\x07",
				Severity:    types.SeverityInfo,
				Description: "Session cookie set by application",
				// What the analyzer is allowed to print: a shape, not a value.
				Evidence:   "sessionid=SECR… (36 chars)",
				Confidence: 0.9,
				Metadata: map[string]string{
					"cookie": "sessionid",
					"raw":    "sessionid=" + fakeSessionValue + "; Secure; HttpOnly",
					"count":  "1",
				},
			},
			{
				Type:        types.FindingMisconfig,
				Name:        "Potential IDOR — Numeric id",
				Severity:    types.SeverityMedium,
				Description: "Numeric identifier found in URL parameter 'id'",
				// Credentials embedded in a URL the analyzer is quoting: the URL
				// is the finding, the password inside it is not.
				Evidence: "URL: https://admin:" + fakeURLPassword +
					"@vanstech.space/admin?id=42",
				Confidence: 0.6,
				Metadata: map[string]string{
					"parameter": "id",
					"value":     "42",
					"url":       "https://admin:" + fakeURLPassword + "@vanstech.space/admin",
				},
			},
			{
				Type:        types.FindingExposure,
				Name:        "Exposed .env File",
				Severity:    types.SeverityHigh,
				Description: "Environment file served",
				Evidence:    "https://vanstech.space/.env (212 bytes, status 200; dotenv assignment line)",
				Confidence:  0.9,
				Prov: &types.Provenance{
					RequestURL: "https://admin:" + fakeURLPassword +
						"@vanstech.space/.env",
					PathOrigin:  types.PathSynthesized,
					Methods:     []types.EvidenceMethod{types.MethodBodyPattern},
					BaselineRef: "dotenv assignment line",
					Grade:       types.GradeProven,
				},
			},
		},
	}
}

func renderFixture(t *testing.T) (string, JSONOutput) {
	t.Helper()
	var buf bytes.Buffer
	if err := NewJSON().Render(&buf, redactionFixture()); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()
	var parsed JSONOutput
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("the JSON sink must emit bytes a machine can read: %v\n%s", err, out)
	}
	return out, parsed
}

// TestJSONSinkNeverLeaksCredentials is the point of slice D: this is the sink a
// model or a script reads without a human reviewing the bytes first, so it
// cannot be the one path that recopies Evidence and Metadata verbatim.
func TestJSONSinkNeverLeaksCredentials(t *testing.T) {
	out, _ := renderFixture(t)

	for _, leak := range []string{
		fakeSessionValue, // the full Set-Cookie header, from metadata.raw
		fakeURLPassword,  // credentials embedded in a probed URL
		"\x1b",           // raw terminal escape
		"\x07",           // raw BEL
	} {
		if strings.Contains(out, leak) {
			t.Errorf("the JSON sink leaked %q to a machine consumer\n%s", leak, out)
		}
	}

	// Defused, not silently deleted: what remains is inert text an operator
	// can still read.
	if !strings.Contains(out, `\x1B`) {
		t.Error("a terminal escape must be shown as escaped text, not dropped")
	}
}

func TestJSONSinkCarriesTheGrade(t *testing.T) {
	_, parsed := renderFixture(t)

	byName := map[string]JSONFinding{}
	for _, f := range parsed.Findings {
		// The sanitized cookie name carries an escaped tail; key on the part
		// that survives.
		byName[strings.SplitN(f.Name, `\`, 2)[0]] = f
	}

	proven := byName["Exposed .env File"]
	if proven.Grade != string(types.GradeProven) {
		t.Errorf("grade = %q, want proven", proven.Grade)
	}
	if proven.Prov == nil {
		t.Fatal("a finding with provenance must not lose it on the way to the sink")
	}
	if proven.Prov.PathOrigin != types.PathSynthesized {
		t.Errorf("path origin = %q, want synthesized: this path was the scanner's guess", proven.Prov.PathOrigin)
	}
	if len(proven.Prov.Methods) != 1 || proven.Prov.Methods[0] != types.MethodBodyPattern {
		t.Errorf("methods = %v, want the differential that earned the grade", proven.Prov.Methods)
	}
	if !strings.Contains(proven.Prov.RequestURL, "<redacted-credentials>@vanstech.space/.env") {
		t.Errorf("provenance.url = %q, want the credentials stripped and the host kept", proven.Prov.RequestURL)
	}

	// An unmigrated finding is still read: the grade falls back to the
	// documented Confidence ladder instead of disappearing.
	legacy := byName["Potential IDOR — Numeric id"]
	if legacy.Grade != string(types.GradeIndicated) {
		t.Errorf("legacy grade = %q, want indicated from confidence 0.6", legacy.Grade)
	}
	if legacy.Prov != nil {
		t.Error("a finding without provenance must not grow one in the sink")
	}
	if legacy.Metadata["value"] != "42" {
		t.Errorf("metadata.value = %q, want 42: an IDOR object reference is the actionable part, not a secret", legacy.Metadata["value"])
	}
	if !strings.Contains(legacy.Evidence, "<redacted-credentials>@vanstech.space/admin?id=42") {
		t.Errorf("evidence = %q, want the URL still quotable without its password", legacy.Evidence)
	}
	if !strings.Contains(legacy.Metadata["url"], "<redacted-credentials>@") {
		t.Errorf("metadata.url = %q, want its credentials stripped", legacy.Metadata["url"])
	}

	cookie := byName["Session Cookie: sessionid"]
	if !strings.HasPrefix(cookie.Metadata["raw"], "<masked len=") {
		t.Errorf("metadata.raw = %q, want the full Set-Cookie header masked", cookie.Metadata["raw"])
	}
	if cookie.Metadata["cookie"] != "sessionid" {
		t.Errorf("metadata.cookie = %q, want the cookie NAME kept: a name is not its secret", cookie.Metadata["cookie"])
	}
	if cookie.Grade != string(types.GradeIndicated) {
		t.Errorf("cookie grade = %q, want indicated", cookie.Grade)
	}
}

// TestJSONSinkIsTestableWithoutStdout pins the seam: Render takes a writer, so
// the masking above tests the sink instead of a captured stdout.
func TestJSONSinkIsTestableWithoutStdout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer srv.Close()

	var buf bytes.Buffer
	res := &engine.ScanResult{
		Target:   srv.URL,
		Findings: []types.Finding{{Name: "Only a name"}},
		Results: []*types.Result{{
			Target: srv.URL + "/?token=abc",
			Error:  errors.New(`Get "https://user:pass@target/admin": context deadline exceeded`),
		}},
	}
	if err := NewJSON().Render(&buf, res); err != nil {
		t.Fatalf("Render: %v", err)
	}

	var parsed JSONOutput
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("Render output is not valid JSON: %v", err)
	}
	if parsed.Target != srv.URL {
		t.Errorf("target = %q, want %q", parsed.Target, srv.URL)
	}
	if len(parsed.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(parsed.Results))
	}
	if strings.Contains(parsed.Results[0].Error, "user:pass") {
		t.Errorf("error = %q, want the URL credentials in a transport failure stripped", parsed.Results[0].Error)
	}
	if !strings.Contains(parsed.Results[0].Error, "context deadline exceeded") {
		t.Errorf("error = %q, want the real failure still readable", parsed.Results[0].Error)
	}
}
