package engine

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// certResp builds a passive-response fixture around a synthesised leaf
// certificate so analyzeCertificate can be exercised against a controlled
// clock and controlled validity windows — no live handshake, no calendar waits.
func certResp(notBefore, notAfter time.Time, sigAlgo x509.SignatureAlgorithm, dnsNames []string) *types.Response {
	cert := &x509.Certificate{
		SerialNumber:       big.NewInt(1337),
		Subject:            pkix.Name{CommonName: "shop.example.com"},
		Issuer:             pkix.Name{CommonName: "R3 Example Authority"},
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		SignatureAlgorithm: sigAlgo,
		DNSNames:           dnsNames,
	}
	return &types.Response{
		TLS: &tls.ConnectionState{
			Version:          tls.VersionTLS13,
			CipherSuite:      tls.TLS_AES_128_GCM_SHA256,
			PeerCertificates: []*x509.Certificate{cert},
		},
	}
}

func findFinding(fs []types.Finding, substr string) *types.Finding {
	for i := range fs {
		if strings.Contains(fs[i].Name, substr) {
			return &fs[i]
		}
	}
	return nil
}

// The dogfood symptom this guards: `tls <target>` printed exactly one line —
// "TLS Version: TLS 1.3" — because the passive analyzer read none of the
// certificate facts sitting in resp.TLS. A healthy cert must now yield the
// certificate-facts finding with issuer, expiry and SAN coverage.
func TestTLSHealthyCertReportsCertificateFacts(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	resp := certResp(now.Add(-30*24*time.Hour), now.Add(60*24*time.Hour),
		x509.SHA256WithRSA, []string{"shop.example.com", "www.shop.example.com"})

	fs := analyzeCertificate(resp, now)
	facts := findFinding(fs, "TLS Certificate:")
	if facts == nil {
		t.Fatalf("healthy cert must produce a certificate-facts finding; got %+v", namesOf(fs))
	}
	if facts.Severity != types.SeverityInfo {
		t.Fatalf("certificate facts are informational, got %s", facts.Severity)
	}
	if !strings.Contains(facts.Description, "R3 Example Authority") ||
		!strings.Contains(facts.Description, now.Add(60*24*time.Hour).UTC().Format("2006-01-02")) {
		t.Fatalf("facts description must carry issuer and expiry, got %q", facts.Description)
	}
	if !strings.Contains(facts.Evidence, "shop.example.com") {
		t.Fatalf("facts evidence must carry the SAN list, got %q", facts.Evidence)
	}
	if facts.Metadata["issuer"] != "R3 Example Authority" || facts.Metadata["tls_version"] != "TLS 1.3" {
		t.Fatalf("structured metadata missing issuer/version: %+v", facts.Metadata)
	}

	// And no false alarm on a healthy certificate.
	for _, want := range []string{"Expired", "Expires in", "Not Yet Valid", "SHA-1", "Without SubjectAltName"} {
		if findFinding(fs, want) != nil {
			t.Fatalf("healthy cert must NOT raise %q; full set: %+v", want, namesOf(fs))
		}
	}
}

func TestTLSCertificateExpired(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	resp := certResp(now.Add(-400*24*time.Hour), now.Add(-1*time.Hour),
		x509.SHA256WithRSA, []string{"shop.example.com"})
	f := findFinding(analyzeCertificate(resp, now), "Expired")
	if f == nil || f.Severity != types.SeverityHigh {
		t.Fatalf("expired cert must raise a HIGH finding, got %+v", f)
	}
}

func TestTLSCertificateExpiringSoon(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	resp := certResp(now.Add(-80*24*time.Hour), now.Add(10*24*time.Hour),
		x509.SHA256WithRSA, []string{"shop.example.com"})
	f := findFinding(analyzeCertificate(resp, now), "Expires in")
	if f == nil || f.Severity != types.SeverityMedium {
		t.Fatalf("cert inside the 14-day window must raise a MEDIUM renewal finding, got %+v", f)
	}
	if !strings.Contains(f.Name, "10") {
		t.Fatalf("renewal finding should name the remaining days, got %q", f.Name)
	}
}

func TestTLSCertificateNotYetValid(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	resp := certResp(now.Add(2*24*time.Hour), now.Add(90*24*time.Hour),
		x509.SHA256WithRSA, []string{"shop.example.com"})
	f := findFinding(analyzeCertificate(resp, now), "Not Yet Valid")
	if f == nil || f.Severity != types.SeverityMedium {
		t.Fatalf("a not-yet-valid cert must raise a MEDIUM finding, got %+v", f)
	}
}

func TestTLSCertificateSHA1Signature(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	resp := certResp(now.Add(-1*24*time.Hour), now.Add(300*24*time.Hour),
		x509.SHA1WithRSA, []string{"shop.example.com"})
	f := findFinding(analyzeCertificate(resp, now), "SHA-1")
	if f == nil || f.Severity != types.SeverityMedium {
		t.Fatalf("SHA-1 signature must raise a MEDIUM finding, got %+v", f)
	}
}

func TestTLSCertificateNoSAN(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	// CN present, no SANs: legacy-only cert. The old code only flagged a cert
	// missing BOTH; a no-SAN cert is what actually breaks modern clients.
	resp := certResp(now.Add(-1*24*time.Hour), now.Add(300*24*time.Hour),
		x509.SHA256WithRSA, nil)
	f := findFinding(analyzeCertificate(resp, now), "Without SubjectAltName")
	if f == nil || f.Severity != types.SeverityLow {
		t.Fatalf("a certificate with no SAN must raise a LOW validation finding, got %+v", f)
	}
}

func TestTLSCertificateNoPeerCerts(t *testing.T) {
	resp := &types.Response{TLS: &tls.ConnectionState{Version: tls.VersionTLS13}}
	if fs := analyzeCertificate(resp, time.Now()); len(fs) != 0 {
		t.Fatalf("no peer certificate must produce no cert findings, got %+v", namesOf(fs))
	}
}

func namesOf(fs []types.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Name)
	}
	return out
}
