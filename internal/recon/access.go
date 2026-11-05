package recon

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/NICE-DEV226/nice-Scan/internal/exploit"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// ErrNoSession is returned when an access check is asked to run with nothing to
// present. It is an error and not an anonymous run because the comparison needs
// two rounds to mean anything: without a session the tool has one observation
// per path, and one observation per path is a scan, not an access result.
var ErrNoSession = errors.New("recon: an access check needs an identity — a session cookie or a credential")

// Session says how the caller proves who it is. Exactly one field is used; a
// Cookie wins when both are set, because the caller already holds the session
// it wants tested and a login would silently test a different identity.
type Session struct {
	// Cookie is a complete Cookie header value the operator already holds.
	Cookie string
	// Credential logs in through a form the target itself publishes.
	Credential *exploit.Credential
}

// AccessPath is one endpoint read twice — anonymously, then with the session —
// and the verdict is the difference, never either status code alone.
type AccessPath struct {
	Path            string `json:"path"`
	AnonymousStatus int    `json:"anonymous_status"`
	SessionStatus   int    `json:"session_status"`
	BodySize        int    `json:"body_size"`
	Lifted          bool   `json:"lifted"`
	Evidence        string `json:"evidence"`
}

// AccessReport is a capability read: what one identity was shown where another
// was refused. It is deliberately not an authorization verdict — a session
// reaching the surface it owns is expected behaviour. What the report is worth
// is the map: the paths that answered differently are where a caller aims the
// next, sharper comparison (a second, lower-privileged identity).
type AccessReport struct {
	Target   string          `json:"target"`
	Identity string          `json:"identity"`
	Session  string          `json:"session"`
	Paths    []AccessPath    `json:"paths"`
	Findings []types.Finding `json:"findings"`
}

// VerifyAccess replays paths under two identities through the same scoped
// client the scan uses, and returns the difference as graded findings.
//
// With no paths it uses the tool's admin wordlist; passing them is how a
// caller that learned /api/admin from the target's own sitemap aims the
// differential at something it knows rather than at a guess. Read-only
// throughout: only GETs reach the wire.
func (s *Service) VerifyAccess(ctx context.Context, target string, sess Session, paths ...string) (*AccessReport, error) {
	if sess.Cookie == "" && sess.Credential == nil {
		return nil, ErrNoSession
	}

	exp := exploit.New(s.client, exploit.Options{Target: target, Verbose: s.verbose})

	if sess.Cookie != "" {
		exp.AttachHarvestedSession(sess.Cookie, "operator-supplied cookie")
	} else {
		attempt := exp.TryLogin(ctx, target, *sess.Credential)
		if !exp.HasAuthCookie() {
			why := "no login form on the target answered"
			if attempt != nil && attempt.Evidence != "" {
				why = types.RedactText(attempt.Evidence)
			}
			return nil, fmt.Errorf("recon: login as %q yielded no session: %s", sess.Credential.User, why)
		}
	}

	cookie, identity := exp.AuthCookie()
	if identity == "" {
		identity = "recorded session"
	}
	report := &AccessReport{
		Target:   target,
		Identity: identity,
		// The NAME of a session cookie is provenance; the value is the
		// credential. Nothing in this report ever carries the value.
		Session: exploit.ShortCookie(cookie),
	}

	observed := len(paths) > 0
	if !observed {
		paths = exploit.CommonAdminPaths
	}

	for _, res := range exp.VerifiedAccessOn(ctx, target, paths) {
		row := AccessPath{
			Path:            res.Path,
			AnonymousStatus: res.Anonymous,
			SessionStatus:   res.WithSess,
			BodySize:        res.BodySize,
			Lifted:          res.Success,
			Evidence:        types.RedactText(res.Evidence),
		}
		report.Paths = append(report.Paths, row)
		if !row.Lifted {
			continue
		}
		report.Findings = append(report.Findings, accessFinding(target, row, observed))
	}

	return report, nil
}

// accessFinding grades a lift by the mechanism that established it: the same
// URL, two identities, two answers. That is the strongest differential this
// tool has — the control and the experiment differ by exactly one thing, and
// that thing is the presenting principal.
func accessFinding(target string, row AccessPath, observed bool) types.Finding {
	origin := types.PathSynthesized
	if observed {
		origin = types.PathObserved
	}

	return types.Finding{
		Type:        types.FindingAccess,
		Name:        fmt.Sprintf("Session reaches %s", row.Path),
		Severity:    types.SeverityInfo,
		Description: "the same URL answered the anonymous round and the session round differently; whether this identity should be able to reach it is a second question this read cannot answer",
		Evidence:    row.Evidence,
		Confidence:  1.0, // the two rounds are the evidence; nothing is inferred
		Metadata: map[string]string{
			"path":             row.Path,
			"anonymous_status": strconv.Itoa(row.AnonymousStatus),
			"session_status":   strconv.Itoa(row.SessionStatus),
		},
		Prov: &types.Provenance{
			RequestURL:    target + row.Path,
			RequestMethod: "GET",
			PathOrigin:    origin,
			Methods:       []types.EvidenceMethod{types.MethodPrincipalDifferential},
			BaselineRef:   "anonymous:" + strconv.Itoa(row.AnonymousStatus),
			Grade:         types.GradeProven,
		},
	}
}
