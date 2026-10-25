package hacker

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
)

// Phase 1 — "the report tells the truth": regression tests locking the
// provenance rules for capabilities and risk scoring.

func kbForTest(target string) (*Brain, *Knowledge) {
	kb := NewKnowledge(target)
	b := &Brain{kb: kb, chainer: NewChainer()}
	return b, kb
}

func TestDeriveCapabilitiesAreHints(t *testing.T) {
	_, kb := kbForTest("example.com")

	// A remotely-controlled finding text mentioning keywords may only
	// produce hint-origin capabilities.
	kb.AddFinding(Finding{
		Type:        "introspection",
		Name:        "GraphQL introspection enabled",
		Description: "The response mentions jwt and admin dashboards",
		Evidence:    "contains secret strings",
	})

	for _, name := range []string{"has_graphql", "has_jwt", "has_admin", "has_secret"} {
		cap := kb.capability(name)
		if cap == nil {
			t.Fatalf("capability %s was not derived", name)
		}
		if cap.Origin != OriginHint {
			t.Errorf("capability %s origin = %q, want %q (hint must not pass as verified)", name, cap.Origin, OriginHint)
		}
	}

	if kb.HasVerifiedCapability("has_jwt") {
		t.Error("has_jwt must not be verified from remote text")
	}
}

// The deliberate change from the review: a silent default must never
// fabricate verified evidence. Every caller states its provenance
// explicitly; forgetting the field fails closed to observed.
func TestAddCapabilityDefaultsToObserved(t *testing.T) {
	_, kb := kbForTest("example.com")

	kb.AddCapability(Capability{Name: "has_sqli", Target: "example.com"})
	cap := kb.capability("has_sqli")
	if cap == nil || cap.Origin != OriginObserved {
		t.Fatalf("silent default must be observed (fail-closed), got %+v", cap)
	}
}

func TestAddScannerStateIsNotSecret(t *testing.T) {
	_, kb := kbForTest("example.com")

	kb.AddScannerState("OOB callback URL: http://127.0.0.1:9999/callback?token={target_id}")
	kb.AddScannerState("CORS+XSS PoC generated — manual deployment required")

	if len(kb.GetSecrets()) != 0 {
		t.Errorf("scanner state leaked into secrets: %v", kb.GetSecrets())
	}
	if kb.capability("has_secret") != nil {
		t.Error("scanner bookkeeping must not flip has_secret")
	}
}

func TestAddSecretFlipsVerifiedHasSecret(t *testing.T) {
	_, kb := kbForTest("example.com")

	kb.AddSecret("etc_shadow: 1024 bytes read via LFI")
	secrets := kb.GetSecrets()
	if len(secrets) != 1 {
		t.Fatalf("AddSecret must record the captured secret, got %v", secrets)
	}
	cap := kb.capability("has_secret")
	if cap == nil || cap.Origin != OriginVerified {
		t.Fatalf("captured secret must yield verified has_secret, got %+v", cap)
	}
}

func TestPlannerBlocksSensitiveActionOnHints(t *testing.T) {
	actions := []Action{&SQLiAction{}, &LoginBruteAction{}}
	p := NewPlanner(actions...)
	_, kb := kbForTest("example.com")

	// Only remote-text mentions of login: Login Bruteforce is sensitive and
	// must never run off hints; SQLi (non-sensitive same-target probes) may.
	kb.AddFinding(Finding{Type: "login_page", Name: "login form password page", Evidence: "x"})
	kb.AddFinding(Finding{Type: "sqli_evidence", Name: "sqli error returned", Evidence: "x"})

	got := make(map[string]bool)
	for {
		a := p.NextAction(kb)
		if a == nil {
			break
		}
		got[a.Metadata().Name] = true
	}

	if got["Login Bruteforce"] {
		t.Error("Login Bruteforce ran on hint-origin capabilities — credential attack unlocked by remote text")
	}
}

func TestPlannerRunsSensitiveActionOnVerified(t *testing.T) {
	p := NewPlanner(&LoginBruteAction{})
	_, kb := kbForTest("example.com")

	kb.AddCapability(Capability{Name: "has_login", Origin: OriginVerified})
	a := p.NextAction(kb)
	if a == nil || a.Metadata().Name != "Login Bruteforce" {
		t.Fatalf("verified has_login must unlock Login Bruteforce, got %+v", a)
	}
}

func TestChainsRequireVerifiedCapabilities(t *testing.T) {
	b, kb := kbForTest("example.com")

	// Feed remote-text hints for has_cors and has_xss: the CORS→XSS chain
	// (risk 9.0) must NOT appear in DetectChains.
	kb.AddFinding(Finding{Type: "cors_hint", Name: "cors mentioned in response text"})
	kb.AddFinding(Finding{Type: "xss_hint", Name: "xss keyword present in html"})

	chains := b.chainer.DetectChains(kb)
	if len(chains) != 0 {
		t.Fatalf("hint-only knowledge must produce zero attack chains, got %+v", chains)
	}

	report := b.buildReport(1)
	if report.RiskScore != 0 {
		t.Errorf("hint-only report risk = %.1f, want 0", report.RiskScore)
	}
	if report.Impact != "No significant vulnerabilities discovered" {
		t.Errorf("hint-only impact = %q", report.Impact)
	}
}

func TestChainsFireOnVerifiedCapabilities(t *testing.T) {
	b, kb := kbForTest("example.com")

	kb.AddCapability(Capability{Name: "has_cors", Origin: OriginVerified})
	kb.AddCapability(Capability{Name: "has_xss", Origin: OriginVerified})

	chains := b.chainer.DetectChains(kb)
	if len(chains) == 0 {
		t.Fatal("verified evidences must surface the attack chain")
	}
}

func TestBuildReportInvalidCredsDoNotGrantRisk9(t *testing.T) {
	b, kb := kbForTest("example.com")

	kb.AddCredential(Credential{Username: "admin", Password: "wrong", Valid: false})
	report := b.buildReport(1)
	if report.RiskScore >= 9.0 {
		t.Errorf("rejected credentials must not confirm account compromise, risk = %.1f", report.RiskScore)
	}
}

func TestBuildReportValidCredsGrantRisk9(t *testing.T) {
	b, kb := kbForTest("example.com")

	kb.AddCredential(Credential{Username: "admin", Password: "ok", Valid: true})
	report := b.buildReport(1)
	if report.RiskScore < 9.0 {
		t.Errorf("accepted credentials must report ≥9.0, got %.1f", report.RiskScore)
	}
}

func TestBuildReportForgedJWTNotValidDoesNotClaimTakeover(t *testing.T) {
	b, kb := kbForTest("example.com")

	// JWTForgeNoneAction stores computed tokens with Valid=false; a token
	// computed but never accepted must not produce "account takeover".
	kb.AddJWT(JWTToken{Algorithm: "none", Raw: "e30.e30.", Valid: false})
	report := b.buildReport(1)
	if report.RiskScore == 10.0 {
		t.Error("forged-but-unverified alg=none token must not claim takeover")
	}
}

func TestBuildReportCapturedSecretGrantsRisk10(t *testing.T) {
	b, kb := kbForTest("example.com")

	kb.AddSecret("env: 320 bytes read via LFI")
	report := b.buildReport(1)
	if report.RiskScore != 10.0 {
		t.Errorf("real secret capture must report 10.0, got %.1f", report.RiskScore)
	}
}

func TestDetectFormTypesRequiresFormSegment(t *testing.T) {
	// Keywords outside any <form> must not classify.
	body := `<html><body><p>Our platform has a login page and an admin dashboard.</p></body></html>`
	if got := detectFormTypes(body); len(got) != 0 {
		t.Errorf("text-only mentions must not become forms, got %v", got)
	}

	// A real form containing a password field classifies as has_login.
	withForm := `<form action="/login"><input type="password" name="pwd"></form>`
	got := detectFormTypes(withForm)
	if len(got) != 1 || got[0] != "has_login" {
		t.Fatalf("real login form must classify as has_login, got %v", got)
	}

	// A form segment must not leak keywords from after </form>.
	mixed := `<form action="/search"></form><input type="password" id="x"></input>`
	if got := detectFormTypes(mixed); len(got) != 0 {
		t.Errorf("keyword after </form> must not classify, got %v", got)
	}
}

func TestOOBServerBindsLoopback(t *testing.T) {
	a := NewOOBAction()
	srv := a.server
	kb := NewKnowledge("example.com")
	client := transport.NewClient()
	defer func() { _ = client.Close() }()

	res := a.Execute(testCtx(), "", kb, client)
	_ = res

	addr := srv.listener.Addr().String()
	if !isLoopbackAddr(addr) {
		t.Fatalf("OOB server must bind loopback, bound to %s", addr)
	}
	srv.Stop()

	if len(kb.GetSecrets()) != 0 {
		t.Errorf("OOB URL recorded as secret: %v", kb.GetSecrets())
	}
	if kb.capability("has_secret") != nil {
		t.Error("OOB URL must not flip has_secret")
	}
	if len(kb.GetScannerState()) == 0 {
		t.Error("OOB callback URL must be recorded as scanner state")
	}
}

// ── Wave C: origins tell the truth; risk counts executed findings ────────

// Crawl keyword matches must land at observed tier: a page whose markup
// mentions "/api" or "dashboard" cannot unlock sensitive actions nor
// headline critical chains anymore — only structural markers (real
// password-type input) keep verified provenance.
func TestCrawlKeywordCapsAreObservedNotVerified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// NO password input anywhere: has_login must not be verified either.
		// The admin/api/register markers ride INSIDE a real form segment —
		// exactly the class the review showed minting verified evidence.
		_, _ = w.Write([]byte(`<html><body>
			<form action="/api/register" method="post"><input name="user"><input name="dashboard_url"><button>Join admin panel</button></form>
			<script src="/app.js"></script></body></html>`))
	}))
	defer srv.Close()

	_, kb := kbForTest(srv.URL)
	client := transport.NewClient(transport.WithRetries(0), transport.WithTimeout(10*time.Second))
	defer func() { _ = client.Close() }()

	a := &CrawlAction{}
	a.Execute(testCtx(), srv.URL, kb, client)

	for _, name := range []string{"has_api", "has_register", "has_admin"} {
		cap := kb.capability(name)
		if cap == nil {
			t.Fatalf("crawl forgot %s entirely", name)
		}
		if cap.Origin != OriginObserved {
			t.Errorf("crawl keyword cap %s origin = %q, want %q (page words must not mint verified evidence)", name, cap.Origin, OriginObserved)
		}
	}
	if kb.capability("has_login") != nil {
		t.Errorf("has_login minted without any password input")
	}
}

// A real password-type input IS wire-grounded: that one stays verified —
// this is what keeps the login-bruteforce feature alive on real targets.
func TestCrawlPasswordInputStaysVerified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body><form action="/login" method="post">
			<input name="user"><input type="password" name="pass"><button>Login</button></form></body></html>`))
	}))
	defer srv.Close()

	_, kb := kbForTest(srv.URL)
	client := transport.NewClient(transport.WithRetries(0), transport.WithTimeout(10*time.Second))
	defer func() { _ = client.Close() }()
	a := &CrawlAction{}
	a.Execute(testCtx(), srv.URL, kb, client)

	cap := kb.capability("has_login")
	if cap == nil || cap.Origin != OriginVerified {
		t.Fatalf("structural password input must keep verified origin, got %+v", cap)
	}
	p := NewPlanner(&LoginBruteAction{})
	if act := p.NextAction(kb); act == nil || act.Metadata().Name != "Login Bruteforce" {
		t.Error("verified structural has_login must still unlock the login brute force")
	}
}

// The second half of the double lie: with a wire-confirmed finding and no
// chain, the report must not claim risk 0 anymore.
func TestBuildReportCountsExecutedFindings(t *testing.T) {
	b, kb := kbForTest("example.com")

	kb.AddFinding(Finding{
		Type:     "xss_confirmed",
		Name:     "XSS: executable markup reflection at /search?q",
		Severity: SevHigh,
	})
	rep := b.buildReport(1)
	if rep.RiskScore < 7.5 {
		t.Fatalf("confirmed high finding must lift the risk floor, got %.1f (the old score ignored findings entirely)", rep.RiskScore)
	}
	if !strings.Contains(rep.Impact, "XSS") {
		t.Errorf("impact must name the finding that drove it, got %q", rep.Impact)
	}
}

// Chain patterns the scheduler runs are hypotheses: the scanner contacts
// nothing. SevCritical "Risk 10/10" claims over them were the headline lie
// of the old report.
func TestGenericChainFindingIsAHypothesis(t *testing.T) {
	_, kb := kbForTest("example.com")
	client := transport.NewClient()
	defer func() { _ = client.Close() }()
	a := &GenericChainAction{pattern: ChainPattern{
		Name:     "Upload → RCE",
		Requires: []string{"has_upload", "has_admin"},
		Impact:   "Upload shell to admin area",
		Risk:     10.0,
	}}
	res := a.Execute(testCtx(), "example.com", kb, client)

	f := res.Findings[0]
	if f.Severity != SevInfo {
		t.Errorf("chain finding severity = %q, want SevInfo (a hypothesis is not a breach)", f.Severity)
	}
	if !strings.Contains(f.Name, "hypothesis") {
		t.Errorf("finding must be labelled a hypothesis, got %q", f.Name)
	}
}
