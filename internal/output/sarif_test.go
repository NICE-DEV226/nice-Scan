package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

func renderSARIFFixture(t *testing.T) (string, sarifReport) {
	t.Helper()
	var buf bytes.Buffer
	if err := NewSARIF("test").Render(&buf, redactionFixture()); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()
	var parsed sarifReport
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("SARIF must emit bytes a machine can read: %v\n%s", err, out)
	}
	return out, parsed
}

func TestSARIFStructure(t *testing.T) {
	out, parsed := renderSARIFFixture(t)

	if parsed.Version != "2.1.0" {
		t.Fatalf("version = %q, want 2.1.0", parsed.Version)
	}
	if len(parsed.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(parsed.Runs))
	}
	run := parsed.Runs[0]
	if run.Tool.Driver.Name != "nice_scan" {
		t.Fatalf("driver name = %q", run.Tool.Driver.Name)
	}
	if run.Tool.Driver.Version != "test" {
		t.Fatalf("driver version = %q", run.Tool.Driver.Version)
	}
	if len(run.Results) != 3 {
		t.Fatalf("results = %d, want 3", len(run.Results))
	}
	if !run.Invocations[0].ExecutionSuccessful {
		t.Error("executionSuccessful must be true for a clean scan")
	}
	if len(run.Tool.Driver.Rules) == 0 {
		t.Error("rules catalog must not be empty")
	}

	// SARIF consumed by Code Scanning expects $schema present in raw bytes.
	if !strings.Contains(out, `"$schema"`) {
		t.Error("missing $schema declaration")
	}
}

// The SARIF document is archived by pipelines and replayed by dashboards —
// it inherits the JSON sink's masking obligation.
func TestSARIFSinkNeverLeaksCredentials(t *testing.T) {
	out, _ := renderSARIFFixture(t)

	for _, leak := range []string{
		fakeSessionValue,
		fakeURLPassword,
		"\x1b",
		"\x07",
	} {
		if strings.Contains(out, leak) {
			t.Errorf("the SARIF sink leaked %q\n%s", leak, out)
		}
	}
}

func TestSARIFLevelsAndLocations(t *testing.T) {
	_, parsed := renderSARIFFixture(t)

	levels := map[string]string{}
	for _, res := range parsed.Runs[0].Results {
		levels[res.RuleID] = res.Level
		if res.RuleID == string(types.FindingExposure) {
			if len(res.Locations) != 1 {
				t.Fatalf("provenance-bearing finding must carry a location, got %d", len(res.Locations))
			}
			uri := res.Locations[0].PhysicalLocation.ArtifactLocation.URI
			if strings.Contains(uri, fakeURLPassword) {
				t.Errorf("location URI leaked credentials: %q", uri)
			}
			if res.Properties["grade"] != string(types.GradeProven) {
				t.Errorf("grade property = %v, want proven", res.Properties["grade"])
			}
		}
	}

	want := map[string]string{
		string(types.FindingSecret):    "note",    // info severity
		string(types.FindingMisconfig): "warning", // medium
		string(types.FindingExposure):  "error",   // high
	}
	for rule, level := range want {
		if levels[rule] != level {
			t.Errorf("%s level = %q, want %q", rule, levels[rule], level)
		}
	}
}

func TestSARIFFingerprintsAreStable(t *testing.T) {
	fixture := redactionFixture()

	var a, b bytes.Buffer
	if err := NewSARIF("test").Render(&a, fixture); err != nil {
		t.Fatal(err)
	}
	if err := NewSARIF("test").Render(&b, fixture); err != nil {
		t.Fatal(err)
	}
	if a.String() != b.String() {
		t.Error("identical scans must produce identical SARIF (rule order + fingerprints stable)")
	}
}

func TestSeverityAtOrAbove(t *testing.T) {
	findings := []types.Finding{
		{Severity: types.SeverityInfo},
		{Severity: types.SeverityLow},
		{Severity: types.SeverityMedium},
		{Severity: types.SeverityHigh},
		{Severity: types.SeverityCritical},
	}

	cases := []struct {
		min   types.Severity
		count int
	}{
		{types.SeverityInfo, 5},
		{types.SeverityLow, 4},
		{types.SeverityMedium, 3},
		{types.SeverityHigh, 2},
		{types.SeverityCritical, 1},
	}
	for _, c := range cases {
		if n, _ := SeverityAtOrAbove(findings, c.min); n != c.count {
			t.Errorf("min=%s: count = %d, want %d", c.min, n, c.count)
		}
	}
	if n, _ := SeverityAtOrAbove(nil, types.SeverityInfo); n != 0 {
		t.Errorf("empty findings must not gate, got %d", n)
	}
}

func TestValidSeverity(t *testing.T) {
	for _, ok := range []string{"info", "LOW", "Medium", "high", "CRITICAL"} {
		if !ValidSeverity(ok) {
			t.Errorf("%q must be a valid severity", ok)
		}
	}
	for _, bad := range []string{"", "severe", "warn", "0"} {
		if ValidSeverity(bad) {
			t.Errorf("%q must not be a valid severity", bad)
		}
	}
}
