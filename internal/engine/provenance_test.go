package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

func TestStampProvenanceReportsTheExchange(t *testing.T) {
	req := &types.Request{
		Method: "GET",
		URL:    "http://target/.env",
		Origin: types.PathSynthesized,
	}
	resp := &types.Response{RequestURL: req.URL, StatusCode: 200}
	findings := []types.Finding{{Name: "Exposed .env File"}}

	stampProvenance(req, resp, findings, "")

	p := findings[0].Prov
	if p == nil {
		t.Fatal("the engine must give every analyzer finding a provenance record")
	}
	if p.RequestURL != req.URL || p.RequestMethod != "GET" {
		t.Errorf("exchange = %s %q, want GET %q", p.RequestMethod, p.RequestURL, req.URL)
	}
	if p.PathOrigin != types.PathSynthesized {
		t.Errorf("path origin = %q, want synthesized: this path was the scanner's guess", p.PathOrigin)
	}
	// No baseline was available for this path, so no comparison ran and no
	// grade is asserted. Recording one here would invent evidence.
	if len(p.Methods) != 0 || p.Grade != "" {
		t.Errorf("methods = %v with grade %q, want neither: nothing was compared", p.Methods, p.Grade)
	}
}

// TestStampProvenanceRecordsTheDifferentialThatRan covers the half of the
// soft-404 comparison that used to be discarded: a response MEASURABLY DIFFERENT
// from the target's own shell means the server did route that path.
func TestStampProvenanceRecordsTheDifferentialThatRan(t *testing.T) {
	req := &types.Request{Method: "GET", URL: "http://target/login", Origin: types.PathSynthesized}
	resp := &types.Response{RequestURL: req.URL, StatusCode: 200}
	findings := []types.Finding{{Name: "Login Form Detected", Confidence: 0.8}}

	stampProvenance(req, resp, findings, "SIG_SHELL")

	p := findings[0].Prov
	if !hasMethod(p.Methods, types.MethodBaselineDifferential) {
		t.Errorf("methods = %v, want the baseline comparison this response passed", p.Methods)
	}
	if p.BaselineRef != "SIG_SHELL" {
		t.Errorf("baseline ref = %q, want the shell signature it differed from", p.BaselineRef)
	}
	if p.Grade != types.GradeIndicated {
		t.Errorf("grade = %q, want indicated: a distinct page is a signal, not a proof", p.Grade)
	}
}

func TestStampProvenanceSoft404RecordsTheComparisonAndDemotes(t *testing.T) {
	req := &types.Request{Method: "GET", URL: "http://target/admin", Origin: types.PathSynthesized}
	resp := &types.Response{RequestURL: req.URL, StatusCode: 200, Soft404: true}
	findings := []types.Finding{
		{Name: "Admin Surface Detected", Confidence: 0.6},
		{Name: "Exposed .env File", Prov: &types.Provenance{
			Methods: []types.EvidenceMethod{types.MethodMagicPrefix},
			Grade:   types.GradeProven,
		}},
	}

	stampProvenance(req, resp, findings, "SIG_SHELL")

	soft := findings[0].Prov
	if soft.BaselineRef != "SIG_SHELL" {
		t.Errorf("baseline ref = %q, want the shell signature this response matched", soft.BaselineRef)
	}
	if !hasMethod(soft.Methods, types.MethodSoft404Baseline) {
		t.Errorf("methods = %v, want the byte-identity comparison recorded", soft.Methods)
	}
	if soft.Grade != types.GradeUnverified {
		t.Errorf("grade = %q: a response identical to the shared shell proved nothing about this path", soft.Grade)
	}

	// An analyzer that recognized the artifact itself keeps its grade: the
	// shell could not have carried it, so the two facts are not in conflict.
	proved := findings[1].Prov
	if proved.Grade != types.GradeProven {
		t.Errorf("grade = %q, want proven kept for artifact-level evidence", proved.Grade)
	}
	if !hasMethod(proved.Methods, types.MethodMagicPrefix) {
		t.Errorf("methods = %v, want the analyzer's own differential preserved", proved.Methods)
	}
}

func TestStampProvenanceLeavesAnalyzerClaimsAlone(t *testing.T) {
	req := &types.Request{Method: "GET", URL: "http://target/", Origin: types.PathObserved}
	resp := &types.Response{RequestURL: "http://target/?id=1%27", StatusCode: 200}
	canary := "nsxdeadbeef"
	findings := []types.Finding{{
		Name: "XSS Reflection (plain echo)",
		Prov: &types.Provenance{
			RequestURL:  resp.RequestURL,
			BaselineRef: canary,
			Methods:     []types.EvidenceMethod{types.MethodCanaryReflection},
			Grade:       types.GradeProven,
		},
	}}

	stampProvenance(req, resp, findings, "")

	p := findings[0].Prov
	if p.RequestURL != resp.RequestURL {
		t.Errorf("request = %q, want the analyzer's own probe URL preserved", p.RequestURL)
	}
	if p.BaselineRef != canary {
		t.Errorf("baseline ref = %q, want the canary, not a shell signature", p.BaselineRef)
	}
	if p.Grade != types.GradeProven {
		t.Errorf("grade = %q, want proven", p.Grade)
	}
	if p.PathOrigin != types.PathObserved {
		t.Errorf("path origin = %q, want observed: the query was guessed, the path was the operator's", p.PathOrigin)
	}
}

func TestMergeFindingProvenanceSurvivesADuplicate(t *testing.T) {
	// Two probes, one finding name: the second is a soft-404 shell reply.
	// Merging by name must not let it erase where the proof came from.
	weak := types.Finding{
		Name:     "Exposed .env File",
		Evidence: "shell at /backup/.env",
		Prov: &types.Provenance{
			RequestURL:  "http://target/backup/.env",
			PathOrigin:  types.PathSynthesized,
			Methods:     []types.EvidenceMethod{types.MethodSoft404Baseline},
			BaselineRef: "SIG_SHELL",
			Grade:       types.GradeUnverified,
		},
	}
	strong := types.Finding{
		Name:       "Exposed .env File",
		Evidence:   "dotenv assignments at /.env",
		Confidence: 0.9,
		Prov: &types.Provenance{
			RequestURL: "http://target/.env",
			PathOrigin: types.PathSynthesized,
			Methods:    []types.EvidenceMethod{types.MethodBodyPattern},
			Grade:      types.GradeProven,
		},
	}

	merged := mergeFinding(weak, strong)

	if merged.Evidence != "shell at /backup/.env | dotenv assignments at /.env" {
		t.Errorf("evidence = %q, want both probes' evidence kept", merged.Evidence)
	}
	if merged.Prov.Grade != types.GradeProven {
		t.Errorf("grade = %q, want proven: the merge must take the stronger evidence", merged.Prov.Grade)
	}
	if merged.Prov.RequestURL != "http://target/.env" {
		t.Errorf("request = %q, want the URL that carried the proof", merged.Prov.RequestURL)
	}
	if !hasMethod(merged.Prov.Methods, types.MethodSoft404Baseline) ||
		!hasMethod(merged.Prov.Methods, types.MethodBodyPattern) {
		t.Errorf("methods = %v, want the union: two differentials ran", merged.Prov.Methods)
	}
	// The inputs must not be mutated: the event stream hands the same
	// findings to the TUI while the map holds the merged record.
	if weak.Prov.Grade != types.GradeUnverified || len(weak.Prov.Methods) != 1 {
		t.Errorf("the loser's record was mutated: %+v", weak.Prov)
	}
}

// stubAnalyzer reports one finding per response, named after the URL it came
// from so no two findings merge. That keeps an end-to-end scan showing what the
// engine stamps, without depending on any real analyzer's heuristics.
type stubAnalyzer struct{}

func (a stubAnalyzer) Name() string { return "stub" }

func (a stubAnalyzer) Analyze(_ context.Context, resp *types.Response) []types.Finding {
	return []types.Finding{{
		Type:     types.FindingMisconfig,
		Name:     "Stub " + resp.RequestURL,
		Severity: types.SeverityInfo,
		Evidence: resp.RequestURL,
	}}
}

// TestScanGradesSelfSynthesizedProbes is the point of the primitive: a wordlist
// path answered by the target's own catch-all shell must come back as a lead
// that says it is a lead, naming the comparison that graded it - while the
// operator's own homepage request stays identifiable as an observed path.
func TestScanGradesSelfSynthesizedProbes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(catchAllShell))
	}))
	defer srv.Close()

	client := transport.NewClient(transport.WithRetries(0), transport.WithTimeout(5*time.Second))
	defer func() { _ = client.Close() }()

	scanner := NewScanner(&types.Config{Workers: 4, Timeout: 5 * time.Second, FollowRedirects: true}, client)
	scanner.RegisterAnalyzer(stubAnalyzer{})
	res := scanner.Scan(context.Background(), []string{srv.URL})

	byURL := map[string]*types.Provenance{}
	for _, f := range res.Findings {
		if !strings.HasPrefix(f.Name, "Stub ") {
			continue
		}
		if f.Prov == nil {
			t.Fatalf("finding %q carries no provenance", f.Name)
		}
		byURL[f.Prov.RequestURL] = f.Prov
	}

	probe, ok := byURL[srv.URL+"/admin"]
	if !ok {
		t.Fatalf("the /admin probe was never reported: %v", byURL)
	}
	if probe.PathOrigin != types.PathSynthesized {
		t.Errorf("path origin = %q, want synthesized: /admin is the scanner's guess, not the target's", probe.PathOrigin)
	}
	if probe.Grade != types.GradeUnverified {
		t.Errorf("grade = %q, want unverified: the reply was byte-identical to the shared shell", probe.Grade)
	}
	if !hasMethod(probe.Methods, types.MethodSoft404Baseline) {
		t.Errorf("methods = %v, want the comparison that produced this verdict", probe.Methods)
	}
	if probe.BaselineRef == "" {
		t.Error("baseline ref must name the shell signature the response was matched against")
	}
	if probe.RequestMethod != "GET" {
		t.Errorf("method = %q, want GET", probe.RequestMethod)
	}

	home, ok := byURL[srv.URL]
	if !ok {
		t.Fatalf("the homepage GET was never analyzed: %v", byURL)
	}
	if home.PathOrigin != types.PathObserved {
		t.Errorf("path origin = %q, want observed: the operator named this path", home.PathOrigin)
	}
	if home.Grade == types.GradeProven {
		t.Error("nothing was recognized on the homepage, so nothing may be graded proven")
	}
	// The shell is never graded against itself: it IS the baseline.
	if home.Grade != "" || len(home.Methods) != 0 {
		t.Errorf("homepage provenance = %+v, want no comparison recorded", home)
	}

	// A scan whose every path probe bounced off the same shell must not be
	// able to report any proven finding at all.
	for url, p := range byURL {
		if p.Grade == types.GradeProven {
			t.Errorf("%s was graded proven on a catch-all target", url)
		}
	}
}

func hasMethod(methods []types.EvidenceMethod, want types.EvidenceMethod) bool {
	for _, m := range methods {
		if m == want {
			return true
		}
	}
	return false
}
