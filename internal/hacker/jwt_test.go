package hacker

import (
	"strings"
	"testing"
)

func hs256Token(t *testing.T, secret string, payload map[string]any) string {
	t.Helper()
	tok := signJWT(payload, secret)
	if !hmacSecretMatches(tok, secret) {
		t.Fatalf("test fixture: HMAC of %q does not verify against %q", tok, secret)
	}
	return tok
}

// The crack loop must VERIFY (constant-time HMAC compare), not enumerate:
// the old code emitted one "candidate" finding per dictionary word because
// it compared signJWT's output against the empty string.
func TestJWTForgeVerifiesRealSecretOnly(t *testing.T) {
	_, kb := kbForTest("example.com")

	tok := hs256Token(t, "secret", map[string]any{"sub": "42", "role": "user"})
	kb.AddJWT(JWTToken{Raw: tok, Algorithm: "HS256", Valid: false})

	res := (&JWTForgeAction{}).Execute(testCtx(), "example.com", kb, nil)

	var verified, candidates int
	for _, f := range res.Findings {
		switch f.Type {
		case "jwt_secret_verified":
			verified++
			if !strings.Contains(f.Name, "'secret'") {
				t.Errorf("verified finding must name the matched secret, got %q", f.Name)
			}
		case "jwt_cracked_candidate":
			candidates++
		}
	}
	if verified != 1 {
		t.Fatalf("matching secret must produce exactly one verified finding, got %d", verified)
	}
	if candidates != 0 {
		t.Errorf("unverified candidates are fabrication: got %d", candidates)
	}
}

func TestJWTForgeMissIsHonest(t *testing.T) {
	_, kb := kbForTest("example.com")

	tok := hs256Token(t, "not-in-any-wordlist-x7q", map[string]any{"sub": "1"})
	kb.AddJWT(JWTToken{Raw: tok, Algorithm: "HS256", Valid: false})

	res := (&JWTForgeAction{}).Execute(testCtx(), "example.com", kb, nil)

	for _, f := range res.Findings {
		if f.Type == "jwt_secret_verified" || f.Type == "jwt_cracked_candidate" {
			t.Errorf("non-matching secret must not produce %q", f.Type)
		}
	}
}

// An alg=none HEADER is wire evidence; server ACCEPTANCE is not probed.
// SevCritical "trivial forge" claimed the unprobed half.
func TestAlgNoneUnprobedIsNotCritical(t *testing.T) {
	_, kb := kbForTest("example.com")

	kb.AddJWT(JWTToken{
		Raw:       "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0.",
		Algorithm: "none",
		Valid:     false,
	})

	res := (&JWTForgeAction{}).Execute(testCtx(), "example.com", kb, nil)
	found := false
	for _, f := range res.Findings {
		if f.Type == "jwt_none" {
			found = true
			if f.Severity == SevCritical {
				t.Errorf("unprobed alg=none must not be critical, got %q", f.Severity)
			}
		}
	}
	if !found {
		t.Error("alg=none observation must still surface as a finding")
	}
}

// The forge itself runs locally: minting variants must not become the run's
// attached identity and the finding must state acceptance is unprobed.
func TestForgedTokensNeverAttachToSession(t *testing.T) {
	_, kb := kbForTest("example.com")

	header := map[string]any{"alg": "none", "typ": "JWT"}
	payload := map[string]any{"sub": "1", "role": "admin"}
	res := (&JWTForgeNoneAction{original: "x.y.", header: header, payload: payload}).
		Execute(testCtx(), "example.com", kb, nil)

	if kb.Session.GetActiveJWT() != "" {
		t.Error("forged token attached as active session identity")
	}
	if kb.Session.HasSession() {
		t.Error("forged token entered the session store")
	}
	for _, f := range res.Findings {
		if f.Severity == SevCritical {
			t.Errorf("unaccepted forgery must not claim critical, got %q (%s)", f.Severity, f.Name)
		}
	}
	for _, j := range kb.GetJWTs() {
		if j.Valid {
			t.Error("local forging can never mark a token Valid")
		}
	}
}

func TestAddJWTAttachesOnlyValidTokens(t *testing.T) {
	_, kb := kbForTest("example.com")

	kb.AddJWT(JWTToken{Raw: "harvested.unvalidated.sig", Algorithm: "HS256", Valid: false})
	if kb.Session.HasSession() {
		t.Error("harvested-but-unvalidated token must not become an attached session")
	}

	kb.AddJWT(JWTToken{Raw: "accepted.token.sig", Algorithm: "HS256", Valid: true})
	if !kb.Session.HasSession() {
		t.Error("server-accepted token must attach")
	}
}
