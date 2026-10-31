package hacker

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func testLeaf(now time.Time) *x509.Certificate {
	return &x509.Certificate{
		Subject:            pkix.Name{CommonName: "app.example.com"},
		Issuer:             pkix.Name{CommonName: "Test CA"},
		DNSNames:           []string{"app.example.com", "www.example.com"},
		NotBefore:          now.Add(-30 * 24 * time.Hour),
		NotAfter:           now.Add(60 * 24 * time.Hour),
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
}

func TestCertificateSANsAreReported(t *testing.T) {
	now := time.Now()
	state := &tls.ConnectionState{
		Version:          tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{testLeaf(now)},
	}

	got := findingsByType(analyzeTLSFindings("app.example.com", state, nil, now))
	f, ok := got["tls_certificate_names"]
	if !ok {
		t.Fatalf("certificate SANs must be reported: %+v", got)
	}
	if !strings.Contains(f.Evidence, "www.example.com") {
		t.Errorf("evidence must list the SANs, got %q", f.Evidence)
	}
	if f.Details["issuer"] != "Test CA" {
		t.Errorf("issuer detail = %q, want Test CA", f.Details["issuer"])
	}
}

func TestExpiredCertificateIsHigh(t *testing.T) {
	now := time.Now()
	leaf := testLeaf(now)
	leaf.NotAfter = now.Add(-24 * time.Hour)
	state := &tls.ConnectionState{
		Version:          tls.VersionTLS12,
		PeerCertificates: []*x509.Certificate{leaf},
	}

	got := findingsByType(analyzeTLSFindings("app.example.com", state, nil, now))
	f, ok := got["tls_certificate_expired"]
	if !ok {
		t.Fatalf("expired certificate must be reported: %+v", got)
	}
	if f.Severity != SevHigh {
		t.Errorf("severity = %v, want High", f.Severity)
	}
}

func TestExpiringCertificateIsMedium(t *testing.T) {
	now := time.Now()
	leaf := testLeaf(now)
	leaf.NotAfter = now.Add(5 * 24 * time.Hour)
	state := &tls.ConnectionState{
		Version:          tls.VersionTLS12,
		PeerCertificates: []*x509.Certificate{leaf},
	}

	got := findingsByType(analyzeTLSFindings("app.example.com", state, nil, now))
	if _, ok := got["tls_certificate_expiring"]; !ok {
		t.Fatalf("certificate expiring within 14 days must be reported: %+v", got)
	}
}

func TestLegacyTLSVersionIsMedium(t *testing.T) {
	now := time.Now()
	for _, version := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
		state := &tls.ConnectionState{
			Version:          version,
			PeerCertificates: []*x509.Certificate{testLeaf(now)},
		}
		got := findingsByType(analyzeTLSFindings("app.example.com", state, nil, now))
		if _, ok := got["tls_legacy_version"]; !ok {
			t.Errorf("%s must be reported as legacy: %+v", tlsVersionName(version), got)
		}
	}

	state := &tls.ConnectionState{
		Version:          tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{testLeaf(now)},
	}
	got := findingsByType(analyzeTLSFindings("app.example.com", state, nil, now))
	if _, ok := got["tls_legacy_version"]; ok {
		t.Error("TLS 1.3 must not be flagged as legacy")
	}
}

func TestHostnameMismatchIsHigh(t *testing.T) {
	now := time.Now()
	state := &tls.ConnectionState{
		Version:          tls.VersionTLS12,
		PeerCertificates: []*x509.Certificate{testLeaf(now)},
	}
	verifyErr := x509.HostnameError{Certificate: testLeaf(now), Host: "other.example.net"}

	got := findingsByType(analyzeTLSFindings("other.example.net", state, verifyErr, now))
	f, ok := got["tls_certificate_untrusted"]
	if !ok {
		t.Fatalf("hostname mismatch must be reported: %+v", got)
	}
	if f.Severity != SevHigh {
		t.Errorf("severity = %v, want High", f.Severity)
	}
}

func TestUnknownAuthorityIsMedium(t *testing.T) {
	now := time.Now()
	state := &tls.ConnectionState{
		Version:          tls.VersionTLS12,
		PeerCertificates: []*x509.Certificate{testLeaf(now)},
	}
	verifyErr := x509.UnknownAuthorityError{Cert: testLeaf(now)}

	got := findingsByType(analyzeTLSFindings("app.example.com", state, verifyErr, now))
	f, ok := got["tls_certificate_untrusted"]
	if !ok {
		t.Fatalf("untrusted chain must be reported: %+v", got)
	}
	if f.Severity != SevMedium {
		t.Errorf("severity = %v, want Medium", f.Severity)
	}
}

func TestNoSANIsLow(t *testing.T) {
	now := time.Now()
	leaf := testLeaf(now)
	leaf.DNSNames = nil
	leaf.IPAddresses = []net.IP{}

	state := &tls.ConnectionState{
		Version:          tls.VersionTLS12,
		PeerCertificates: []*x509.Certificate{leaf},
	}
	got := findingsByType(analyzeTLSFindings("app.example.com", state, nil, now))
	if _, ok := got["tls_no_san"]; !ok {
		t.Fatalf("certificate without SANs must be reported: %+v", got)
	}
}

// errors.As must be able to unwrap wrapped verification errors — the
// tls package wraps them in a *tls.CertificateVerificationError.
func TestWrappedVerifyErrorKeepsSeverity(t *testing.T) {
	now := time.Now()
	inner := x509.HostnameError{Certificate: testLeaf(now), Host: "other.example.net"}
	wrapped := &tls.CertificateVerificationError{Err: inner}

	state := &tls.ConnectionState{
		Version:          tls.VersionTLS12,
		PeerCertificates: []*x509.Certificate{testLeaf(now)},
	}
	got := findingsByType(analyzeTLSFindings("other.example.net", state, wrapped, now))
	if got["tls_certificate_untrusted"].Severity != SevHigh {
		t.Errorf("wrapped hostname error lost its severity: %+v", got)
	}

	if !errors.As(wrapped, &inner) {
		t.Error("test premise broken: wrapped error should unwrap")
	}
}
