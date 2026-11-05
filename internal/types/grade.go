package types

// Grading is the answer to "how do you know?", and until now the tool could
// only answer it in prose. Every analyzer carries a Confidence float, but a
// 0.9 set by hand next to a regex says nothing about WHY: a magic-number
// match on a file header, an exact echo of a value this scan invented, and a
// keyword that happened to be in the body all get to carry the same number.
// The differential signals are already in the code — this makes them
// structured, so a consumer that is not a human reading a terminal (a model,
// a script, a report diff) can rank evidence rather than trust a decimal.
//
// Nothing here replaces Severity or Confidence: severity is what a finding
// costs, confidence is what the analyzer felt, grade is what was PROVEN. They
// are orthogonal, and a finding with no Provenance keeps reporting exactly as
// it did before.

// EvidenceMethod names the differential that produced a finding. The values
// are the tool's existing proof mechanisms, not a new theory.
type EvidenceMethod string

const (
	// MethodMagicPrefix: the body starts with a file-format signature
	// (ZIP's PK\x03\x04). An error page cannot satisfy it.
	MethodMagicPrefix EvidenceMethod = "magic-prefix"
	// MethodBodyPattern: content only the named artifact type can carry
	// (a dotenv assignment line, [core] + repositoryformatversion).
	MethodBodyPattern EvidenceMethod = "magic-body-pattern"
	// MethodNoHTMLShape: the body is not an HTML document, so it is not a
	// catch-all page answering the probe.
	MethodNoHTMLShape EvidenceMethod = "no-html-shape"
	// MethodSoft404Baseline: the response was compared byte-for-byte
	// (status + content-type + body digest) with the target's own homepage.
	MethodSoft404Baseline EvidenceMethod = "soft404-baseline"
	// MethodCanaryReflection: a token THIS scan invented came back through
	// the wire, so the page reacted to the input rather than to chance.
	MethodCanaryReflection EvidenceMethod = "canary-reflection"
	// MethodExactEcho: the server echoed exactly the probe value the
	// scanner supplied (a CORS answer to our own Origin).
	MethodExactEcho EvidenceMethod = "exact-echo"
	// MethodOwnProbeAttribution: the response reacted to a value this scan
	// injected, so the signal is attributable to the input rather than
	// already sitting on the page (a DB error surfacing only on the
	// quote-break probe).
	MethodOwnProbeAttribution EvidenceMethod = "own-probe-attribution"
	// MethodCrossSourceCorroboration: two independent sources agree, and a
	// wildcard catch-all was excluded (subdomain CT log + DNS answer).
	MethodCrossSourceCorroboration EvidenceMethod = "cross-source-corroboration"
	// MethodBaselineDifferential: the response differs from a known-bad
	// baseline the tool learned first (a login attempt against junk-POST
	// responses).
	MethodBaselineDifferential EvidenceMethod = "baseline-differential"
	// MethodPrincipalDifferential: the SAME request, replayed under two
	// identities, produced two different answers. Unlike
	// MethodBaselineDifferential — where a distinct page only proves it is
	// not the catch-all shell — a difference that appears and disappears
	// with the presenting principal is caused by that principal.
	MethodPrincipalDifferential EvidenceMethod = "principal-differential"
	// MethodHeaderDerived: the claim comes from response headers, which a
	// soft-404 shell cannot fake — a real, single-source signal.
	MethodHeaderDerived EvidenceMethod = "header-derived"
)

// PathOrigin records who came up with the probed path. The scanner's own
// wordlist is a hypothesis; a path the target advertised is a fact about it.
// A URL-shaped conclusion on a path the scanner invented is the weakest class
// of finding this tool produces, and it is exactly the one that used to be
// indistinguishable from a proven one.
type PathOrigin string

const (
	// PathObserved: requested by the operator, or taken from the target's
	// own content.
	PathObserved PathOrigin = "observed"
	// PathSynthesized: built from the scanner's built-in probe list.
	PathSynthesized PathOrigin = "synthesized"
)

// Grade is the ladder a consumer ranks on.
type Grade string

const (
	// GradeProven: the artifact itself was recognised — a file format, a
	// content signature the error page cannot match, a value this scan
	// injected and got back.
	GradeProven Grade = "proven"
	// GradeCorroborated: independent sources agree, with the catch-all case
	// excluded. No single artifact, but no single source either.
	GradeCorroborated Grade = "corroborated"
	// GradeIndicated: one real signal, not proof. A header, a distinct page
	// that says what it appears to be.
	GradeIndicated Grade = "indicated"
	// GradeUnverified: the shape of the response carried no information —
	// a self-synthesized path answered by the shared shell, a keyword in
	// prose. Reported because it is a lead, never because it was shown.
	GradeUnverified Grade = "unverified"
)

// Provenance is the record of one finding's evidence: which exchange produced
// it, whether the scanner or the target named the path, which differentials
// graded it, and what they were compared against.
type Provenance struct {
	RequestURL    string           `json:"request_url,omitempty"`
	RequestMethod string           `json:"request_method,omitempty"`
	PathOrigin    PathOrigin       `json:"path_origin,omitempty"`
	Methods       []EvidenceMethod `json:"methods,omitempty"`
	// BaselineRef is the concrete thing the comparison was made against:
	// the response signature of the homepage shell, the canary, the probe
	// Origin, the wildcard address that was excluded.
	BaselineRef string `json:"baseline_ref,omitempty"`
	Grade       Grade  `json:"grade,omitempty"`
}

// AddMethod records a differential that ran, once. Re-stating a method the
// finding already carried is not new evidence.
func (p *Provenance) AddMethod(m EvidenceMethod) {
	for _, have := range p.Methods {
		if have == m {
			return
		}
	}
	p.Methods = append(p.Methods, m)
}

// proofMethods are the mechanisms whose signal cannot come from chance or
// from a shared catch-all page: the artifact itself recognised, a value this
// scan injected and got back, or a difference that only appears when a
// principal presents itself.
var proofMethods = map[EvidenceMethod]bool{
	MethodMagicPrefix:           true,
	MethodBodyPattern:           true,
	MethodExactEcho:             true,
	MethodCanaryReflection:      true,
	MethodOwnProbeAttribution:   true,
	MethodPrincipalDifferential: true,
}

// DeriveGrade is the single ranking rule: proof first, then corroboration,
// then any real signal, then nothing was shown. Methods accumulate; the
// strongest one decides.
func DeriveGrade(methods []EvidenceMethod) Grade {
	var corroborated bool
	for _, m := range methods {
		if proofMethods[m] {
			return GradeProven
		}
		if m == MethodCrossSourceCorroboration {
			corroborated = true
		}
	}
	switch {
	case corroborated:
		return GradeCorroborated
	case len(methods) > 0:
		return GradeIndicated
	default:
		return GradeUnverified
	}
}

var gradeRank = map[Grade]int{
	GradeUnverified:   0,
	GradeIndicated:    1,
	GradeCorroborated: 2,
	GradeProven:       3,
}

// rank orders grades for merges. An empty grade ranks below every named one,
// so a stamped finding always beats an unset one.
func (g Grade) rank() int { return gradeRank[g] }

// GradeOf is the reading every consumer should use. A finding whose
// provenance records a differential is graded by what was actually compared.
// A finding without one —
// every analyzer not yet migrated — is graded from its Confidence, and the
// ceiling for that is GradeIndicated: a hand-written 1.0 is an analyzer's
// self-assessment, never a proof, and promoting it to proven would be the
// same mistake as trusting a 200 status.
//
// The distinction matters now that the engine stamps every finding: a
// provenance carrying no method records WHERE the finding came from, not that
// nothing was shown, and reading that as unverified would silently demote
// every analyzer that has not been migrated yet.
func GradeOf(f Finding) Grade {
	if f.Prov != nil && (f.Prov.Grade != "" || len(f.Prov.Methods) > 0) {
		if f.Prov.Grade != "" {
			return f.Prov.Grade
		}
		return DeriveGrade(f.Prov.Methods)
	}
	if f.Confidence >= 0.6 {
		return GradeIndicated
	}
	return GradeUnverified
}

// MergeProvenance combines two records for findings reported under the same
// name (the engine merges by Name across probes). The stronger evidence wins
// its slot and carries the request that produced it, so "Exposed .env File"
// merged from ten probes still says which probe proved it; methods are unioned
// because two different proofs on one finding are two facts, not one.
func MergeProvenance(a, b *Provenance) *Provenance {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	if b.Grade.rank() > a.Grade.rank() {
		a, b = b, a
	}
	out := *a
	out.Methods = nil
	for _, m := range a.Methods {
		out.AddMethod(m)
	}
	for _, m := range b.Methods {
		out.AddMethod(m)
	}
	if out.BaselineRef == "" {
		out.BaselineRef = b.BaselineRef
	}
	// Only derive when a differential exists: an empty method list is the
	// engine's "I know where this came from, nothing more", and inventing a
	// grade for it would overwrite the reading GradeOf is meant to give.
	if out.Grade == "" && len(out.Methods) > 0 {
		out.Grade = DeriveGrade(out.Methods)
	}
	return &out
}
