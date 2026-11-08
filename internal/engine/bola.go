package engine

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// Cross-session object-access differential (BOLA/IDOR).
//
// The check is deliberately narrow because the failure mode of every
// multi-session scanner is the same false positive: "user B also got a
// 200". A 200 proves nothing — the object may be public, the page may be
// a shared directory, or the server may have ignored the session entirely.
//
// What DOES prove broken object-level authorization: session B requests a
// URL whose response under session A carries identity A's private marker,
// and the SAME URL under session B returns identity A's marker while NOT
// carrying identity B's. B received an object that belongs to A.
//
// Operators must therefore point --identity-* at PRIVATE identifiers
// (account email, internal user id) — never a public username, or every
// profile page becomes a false BOLA.

const bolaMaxCandidates = 25

var (
	// An "object" URL carries a numeric id or a UUID-ish token in path or
	// query. Anything weaker (slugs, names) cannot be replayed
	// meaningfully across two identities.
	rxNumericObject = regexp.MustCompile(`(?:^|[/?&=._~-])\d{1,12}(?:[/?&=._~-]|$)`)
	rxUUIDObject    = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
)

// bolaArmed reports whether the operator supplied the full two-identity
// configuration. All four pieces are required: without identities there is
// no marker to prove ownership with, and without sessions there is no
// differential to run.
func (s *Scanner) bolaArmed() bool {
	return s.opts != nil &&
		s.opts.IdentityA != "" && s.opts.IdentityB != "" &&
		len(s.opts.SessionA) > 0 && len(s.opts.SessionB) > 0
}

// bolaCandidates collects replayable object URLs from the completed scan:
// GET probes that answered 200 with real content (not a soft-404 shell)
// and whose URL embeds a numeric id or UUID.
func bolaCandidates(results []*types.Result) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range results {
		if len(out) >= bolaMaxCandidates {
			break
		}
		if r == nil || r.Request == nil || r.Response == nil {
			continue
		}
		if r.Request.Method != "" && r.Request.Method != "GET" {
			continue
		}
		if r.Response.StatusCode != 200 || r.Response.Soft404 {
			continue
		}
		u := r.Request.URL
		if !rxNumericObject.MatchString(u) && !rxUUIDObject.MatchString(u) {
			continue
		}
		// Only replay URLs on the scanned origin: the scope boundary would
		// refuse the rest anyway, and replaying them wastes the budget.
		if parsed, err := url.Parse(u); err == nil && parsed.Host != "" {
			if seen[u] {
				continue
			}
			seen[u] = true
			out = append(out, u)
		}
	}
	return out
}

func bolaHeaders(sess map[string]string) map[string]string {
	h := make(map[string]string, len(sess))
	for k, v := range sess {
		h[k] = v
	}
	return h
}

// runBOLADiff replays each candidate URL under both sessions and reports
// the one outcome that is real evidence: session B received a body marked
// with identity A while carrying none of identity B.
func (s *Scanner) runBOLADiff(ctx context.Context, result *ScanResult) {
	if !s.bolaArmed() {
		return
	}
	idA := []byte(s.opts.IdentityA)
	idB := []byte(s.opts.IdentityB)

	for _, u := range bolaCandidates(result.Results) {
		if ctx.Err() != nil {
			return
		}

		respA, errA := s.client.Do(ctx, &types.Request{
			Method: "GET", URL: u, Timeout: s.opts.Timeout,
			Origin: types.PathObserved, Headers: bolaHeaders(s.opts.SessionA),
		})
		if errA != nil || respA == nil || respA.StatusCode != 200 {
			continue // not an A-visible object at 200 — nothing to prove against
		}
		bodyA := respA.Body
		if !bytes.Contains(bodyA, idA) {
			continue // the object is not marked with A's identity; skip
		}

		respB, errB := s.client.Do(ctx, &types.Request{
			Method: "GET", URL: u, Timeout: s.opts.Timeout,
			Origin: types.PathObserved, Headers: bolaHeaders(s.opts.SessionB),
		})
		if errB != nil || respB == nil || respB.StatusCode != 200 {
			continue // B was refused or errored — access control held
		}
		bodyB := respB.Body
		if !bytes.Contains(bodyB, idA) || bytes.Contains(bodyB, idB) {
			continue // B did not receive A's marker, or the page carries both
			// identities (a shared directory view — ambiguous, not proof)
		}

		result.Findings = append(result.Findings, types.Finding{
			Type:        types.FindingMisconfig,
			Name:        "Cross-session object access (BOLA/IDOR)",
			Severity:    types.SeverityHigh,
			Description: "Session B retrieved an object whose response is marked with identity A's private identifier and carries none of identity B's — object-level authorization did not hold",
			Evidence: fmt.Sprintf(
				"GET %s → 200 under both sessions; body served to session B contains identity A marker %q and no identity B marker",
				u, s.opts.IdentityA),
			Confidence: 0.9,
			Prov: &types.Provenance{
				RequestURL:    u,
				RequestMethod: "GET",
				PathOrigin:    types.PathObserved,
				Methods:       []types.EvidenceMethod{types.MethodExactEcho, types.MethodCrossSourceCorroboration},
				Grade:         types.GradeProven,
			},
		})
		result.Stats.Findings++
	}
}

// bolaSummaryLine renders a one-line note for operators who configured a
// single session only — the feature exists but stayed silent, and silence
// should be explainable.
func bolaSummaryLine(opts *types.Config) string {
	if opts == nil {
		return ""
	}
	missing := []string{}
	if opts.IdentityA == "" || opts.IdentityB == "" {
		missing = append(missing, "--identity-a/--identity-b")
	}
	if len(opts.SessionA) == 0 || len(opts.SessionB) == 0 {
		missing = append(missing, "--session-a/--session-b")
	}
	if len(missing) == 0 {
		return ""
	}
	return "BOLA differential armed only with two identities — missing " + strings.Join(missing, " and ")
}
