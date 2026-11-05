package types

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDeriveGradeRanksMethods(t *testing.T) {
	cases := []struct {
		name    string
		methods []EvidenceMethod
		want    Grade
	}{
		{"nothing carried no evidence", nil, GradeUnverified},
		{"a soft-404 comparison alone proves the path was never routed",
			[]EvidenceMethod{MethodSoft404Baseline}, GradeIndicated},
		{"a header is one real signal, not proof",
			[]EvidenceMethod{MethodHeaderDerived}, GradeIndicated},
		{"differing from the target's own shell is a signal, not an artifact",
			[]EvidenceMethod{MethodBaselineDifferential}, GradeIndicated},
		{"two families agreeing is corroboration",
			[]EvidenceMethod{MethodCrossSourceCorroboration}, GradeCorroborated},
		{"corroboration outranks an accompanying baseline",
			[]EvidenceMethod{MethodSoft404Baseline, MethodCrossSourceCorroboration}, GradeCorroborated},
		{"a file-format signature recognizes the artifact",
			[]EvidenceMethod{MethodMagicPrefix}, GradeProven},
		{"the strongest method decides, whatever the order",
			[]EvidenceMethod{MethodSoft404Baseline, MethodCrossSourceCorroboration, MethodMagicPrefix}, GradeProven},
		{"an echo of our own probe value is proof",
			[]EvidenceMethod{MethodExactEcho}, GradeProven},
		{"a reaction to a value we injected is proof",
			[]EvidenceMethod{MethodOwnProbeAttribution}, GradeProven},
		{"an answer that changes with the presenting principal is caused by that principal",
			[]EvidenceMethod{MethodPrincipalDifferential}, GradeProven},
		{"a principal differential is not demoted by riding along with a shell comparison",
			[]EvidenceMethod{MethodSoft404Baseline, MethodPrincipalDifferential}, GradeProven},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := DeriveGrade(c.methods); got != c.want {
				t.Errorf("DeriveGrade(%v) = %q, want %q", c.methods, got, c.want)
			}
		})
	}
}

// TestGradeOfNeverPromotesConfidence is the whole point of the ceiling: a
// hand-written Confidence of 1.0 is an analyzer rating its own work, which is
// exactly the number the differential doctrine refuses to trust.
func TestGradeOfNeverPromotesConfidence(t *testing.T) {
	cases := []struct {
		confidence float64
		want       Grade
	}{
		{1.0, GradeIndicated},
		{0.9, GradeIndicated},
		{0.6, GradeIndicated},
		{0.59, GradeUnverified},
		{0.0, GradeUnverified},
	}
	for _, c := range cases {
		f := Finding{Confidence: c.confidence}
		if got := GradeOf(f); got != c.want {
			t.Errorf("GradeOf(confidence=%v, no prov) = %q, want %q", c.confidence, got, c.want)
		}
	}
}

func TestGradeOfPrefersStampedGradeThenMethods(t *testing.T) {
	stamped := Finding{Confidence: 0.2, Prov: &Provenance{Grade: GradeProven}}
	if got := GradeOf(stamped); got != GradeProven {
		t.Errorf("an explicit grade must not be overridden by a low confidence, got %q", got)
	}

	derived := Finding{Prov: &Provenance{Methods: []EvidenceMethod{MethodCanaryReflection}}}
	if got := GradeOf(derived); got != GradeProven {
		t.Errorf("an unset grade falls back to the methods, got %q", got)
	}

	// A provenance that records only the exchange says where the finding came
	// from, not that nothing was shown: the reading falls back to Confidence,
	// which still cannot reach proven.
	exchangeOnly := Finding{Confidence: 1.0, Prov: &Provenance{RequestURL: "http://x/"}}
	if got := GradeOf(exchangeOnly); got != GradeIndicated {
		t.Errorf("GradeOf(provenance with no differential) = %q, want the confidence ladder's ceiling", got)
	}

	dropped := Finding{Confidence: 0.2, Prov: &Provenance{RequestURL: "http://x/"}}
	if got := GradeOf(dropped); got != GradeUnverified {
		t.Errorf("GradeOf(low confidence, no differential) = %q, want unverified", got)
	}
}

func TestMergeProvenanceKeepsTheProof(t *testing.T) {
	weak := &Provenance{
		RequestURL:  "http://target/.env",
		PathOrigin:  PathSynthesized,
		Methods:     []EvidenceMethod{MethodSoft404Baseline},
		BaselineRef: "SIG_SHELL",
		Grade:       GradeUnverified,
	}
	strong := &Provenance{
		RequestURL: "http://target/config/.env",
		PathOrigin: PathObserved,
		Methods:    []EvidenceMethod{MethodBodyPattern, MethodNoHTMLShape},
		Grade:      GradeProven,
	}

	// Either order must produce the same record: the probe that proved the
	// finding carries its identity, not whichever duplicate arrived second.
	for i, merged := range []*Provenance{MergeProvenance(weak, strong), MergeProvenance(strong, weak)} {
		if merged.Grade != GradeProven {
			t.Errorf("[%d] grade = %q, want proven", i, merged.Grade)
		}
		if merged.RequestURL != "http://target/config/.env" {
			t.Errorf("[%d] request = %q, want the proving probe", i, merged.RequestURL)
		}
		if merged.PathOrigin != PathObserved {
			t.Errorf("[%d] path origin = %q, want observed (the winner's)", i, merged.PathOrigin)
		}
		if len(merged.Methods) != 3 {
			t.Errorf("[%d] methods = %v, want the union of both records", i, merged.Methods)
		}
	}
}

func TestMergeProvenanceNilSidesAndBaselineBackfill(t *testing.T) {
	if got := MergeProvenance(nil, nil); got != nil {
		t.Errorf("merging nothing must stay nil, got %+v", got)
	}
	rec := &Provenance{Grade: GradeProven}
	if got := MergeProvenance(nil, rec); got != rec {
		t.Errorf("a nil side must yield the other, got %+v", got)
	}
	if got := MergeProvenance(rec, nil); got != rec {
		t.Errorf("a nil side must yield the other, got %+v", got)
	}

	// The winner recorded no comparison; the duplicate did. Keeping that
	// reference costs nothing and loses a fact otherwise.
	a := &Provenance{Grade: GradeProven, Methods: []EvidenceMethod{MethodMagicPrefix}}
	b := &Provenance{Grade: GradeIndicated, BaselineRef: "SIG_SHELL"}
	if got := MergeProvenance(a, b); got.BaselineRef != "SIG_SHELL" {
		t.Errorf("baseline ref = %q, want the duplicate's SIG_SHELL", got.BaselineRef)
	}
}

func TestAddMethodIsIdempotent(t *testing.T) {
	p := &Provenance{}
	p.AddMethod(MethodCanaryReflection)
	p.AddMethod(MethodCanaryReflection)
	p.AddMethod(MethodSoft404Baseline)
	if len(p.Methods) != 2 {
		t.Fatalf("methods = %v, want two distinct entries", p.Methods)
	}
}

// TestProvenanceIsAdditiveOnTheWire guards the migration path: an analyzer
// that never sets Prov must serialize exactly as it did before this field
// existed, so adopting grading cannot change a report nobody agreed to.
func TestProvenanceIsAdditiveOnTheWire(t *testing.T) {
	legacy, err := json.Marshal(Finding{Name: "Legacy", Confidence: 0.9})
	if err != nil {
		t.Fatalf("marshal legacy: %v", err)
	}
	if strings.Contains(string(legacy), "prov") {
		t.Errorf("a finding with no provenance must not carry the key: %s", legacy)
	}

	stamped, err := json.Marshal(Finding{
		Name: "Graded",
		Prov: &Provenance{Methods: []EvidenceMethod{MethodMagicPrefix}, Grade: GradeProven},
	})
	if err != nil {
		t.Fatalf("marshal stamped: %v", err)
	}
	s := string(stamped)
	if !strings.Contains(s, `"grade":"proven"`) {
		t.Errorf("the grade must be readable by a machine: %s", s)
	}
	// Unset facts stay absent: an empty request URL is not a fact of "no URL".
	if strings.Contains(s, `"request_url"`) || strings.Contains(s, `"baseline_ref"`) {
		t.Errorf("unset provenance fields must stay absent: %s", s)
	}
}
