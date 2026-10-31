package hacker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// TLSInspectorAction reads the certificate the target actually serves:
// subject alternative names, issuer, expiry, signature algorithm and the
// negotiated protocol version. These are the TLS facts an operator needs
// in a report — not a pass/fail badge.
//
// The handshake is read-only (no HTTP body is requested). When the
// certificate fails verification the action retries once without
// verification solely to collect the metadata, and reports the failure
// as a finding: a target with an expired or untrusted certificate is
// exactly the kind of fact that must not disappear into a silent error.
type TLSInspectorAction struct{}

func (a *TLSInspectorAction) Metadata() ActionMetadata {
	return ActionMetadata{
		Name:        "TLS Inspector",
		Description: "Served certificate: SANs, issuer, expiry, signature and negotiated protocol",
		Priority:    32,
		Requires:    nil,
		Provides:    []string{"has_tls"},
	}
}

func (a *TLSInspectorAction) Execute(ctx context.Context, target string, kb *Knowledge, client *transport.Client) ActionResult {
	host, port := tlsEndpoint(target)
	if host == "" {
		return ActionResult{Findings: []Finding{{
			Type:        "tls_skipped",
			Name:        "TLS inspection skipped: no hostname in target",
			Severity:    SevInfo,
			Description: "The target could not be parsed into a hostname — TLS posture is NOT verified",
		}}}
	}

	dialCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()

	state, verifyErr := dialTLSInspect(dialCtx, host, port)
	if state == nil {
		reason := "handshake failed"
		if verifyErr != nil {
			reason = types.Sanitize(verifyErr.Error())
		}
		return ActionResult{Findings: []Finding{{
			Type:        "tls_unavailable",
			Name:        fmt.Sprintf("TLS inspection unavailable: %s:%s", host, port),
			Severity:    SevInfo,
			Description: "No TLS session could be established — certificate and protocol posture are NOT verified",
			Evidence:    reason,
		}}}
	}

	findings := analyzeTLSFindings(host, state, verifyErr, time.Now())
	kb.AddCapability(Capability{
		Name:   "has_tls",
		Origin: OriginVerified,
		Target: target,
		Details: map[string]string{
			"evidence":  fmt.Sprintf("handshake completed with %s:%s (%s)", host, port, tlsVersionName(state.Version)),
			"derivedBy": "direct TLS handshake (read-only, no HTTP body requested)",
		},
	})
	return ActionResult{Findings: findings}
}

// dialTLSInspect performs the verified handshake and, when verification
// fails, one unverified retry so the certificate metadata is still
// collectable. A protocol-version rejection is retried at the TLS 1.0
// floor to expose servers that still only speak legacy TLS.
func dialTLSInspect(ctx context.Context, host, port string) (*tls.ConnectionState, error) {
	state, err := tlsHandshake(ctx, host, port, false, 0)
	if err == nil {
		return state, nil
	}

	if isProtocolVersionError(err) {
		if legacyState, legacyErr := tlsHandshake(ctx, host, port, false, tls.VersionTLS10); legacyErr == nil {
			return legacyState, nil
		}
	}

	// Unverified retry: collect cert facts, keep the original
	// verification error for the findings.
	unverifiedState, unverifiedErr := tlsHandshake(ctx, host, port, true, 0)
	if unverifiedErr != nil {
		return nil, err
	}
	return unverifiedState, err
}

func tlsHandshake(ctx context.Context, host, port string, insecure bool, minVersion uint16) (*tls.ConnectionState, error) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 8 * time.Second},
		Config: &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: insecure,
			MinVersion:         minVersion,
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("unexpected connection type %T", conn)
	}
	state := tlsConn.ConnectionState()
	return &state, nil
}

func isProtocolVersionError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "protocol version")
}

func tlsEndpoint(target string) (host, port string) {
	raw := target
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return "", ""
	}
	port = u.Port()
	if port == "" {
		port = "443"
	}
	return u.Hostname(), port
}

// analyzeTLSFindings is a pure sink: tests feed it a certificate and a
// synthetic clock without touching the network.
func analyzeTLSFindings(host string, state *tls.ConnectionState, verifyErr error, now time.Time) []Finding {
	var findings []Finding

	if verifyErr != nil {
		findings = append(findings, Finding{
			Type:        "tls_certificate_untrusted",
			Name:        fmt.Sprintf("TLS certificate verification failed: %s", host),
			Severity:    tlsVerifySeverity(verifyErr),
			Description: "A default-trust client rejects this certificate; the exact cause is in the evidence",
			Evidence:    types.Sanitize(minStr(verifyErr.Error(), 240)),
		})
	}

	if len(state.PeerCertificates) == 0 {
		return findings
	}
	leaf := state.PeerCertificates[0]

	if now.After(leaf.NotAfter) {
		findings = append(findings, Finding{
			Type:        "tls_certificate_expired",
			Name:        fmt.Sprintf("TLS certificate expired: %s", host),
			Severity:    SevHigh,
			Description: fmt.Sprintf("The leaf certificate stopped being valid on %s", leaf.NotAfter.UTC().Format("2006-01-02")),
			Evidence:    fmt.Sprintf("NotAfter=%s", leaf.NotAfter.UTC().Format(time.RFC3339)),
		})
	} else if days := int(leaf.NotAfter.Sub(now).Hours() / 24); days < 14 {
		findings = append(findings, Finding{
			Type:        "tls_certificate_expiring",
			Name:        fmt.Sprintf("TLS certificate expires in %d in day(s): %s", days, host),
			Severity:    SevMedium,
			Description: "Renewal window: an expired certificate turns every client into a block screen",
			Evidence:    fmt.Sprintf("NotAfter=%s", leaf.NotAfter.UTC().Format(time.RFC3339)),
		})
	}

	switch leaf.SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		findings = append(findings, Finding{
			Type:        "tls_weak_signature",
			Name:        fmt.Sprintf("TLS certificate uses SHA-1 signature: %s", host),
			Severity:    SevMedium,
			Description: "SHA-1 certificate signatures are deprecated and rejected by current browser policies",
			Evidence:    fmt.Sprintf("SignatureAlgorithm=%s", leaf.SignatureAlgorithm.String()),
		})
	}

	names := make([]string, 0, len(leaf.DNSNames)+len(leaf.IPAddresses))
	names = append(names, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		names = append(names, ip.String())
	}
	if len(names) == 0 {
		findings = append(findings, Finding{
			Type:        "tls_no_san",
			Name:        fmt.Sprintf("TLS certificate has no subjectAltName: %s", host),
			Severity:    SevLow,
			Description: "Modern clients ignore the legacy CN field; a certificate without SANs fails validation",
			Evidence:    "subjectAltName=<absent>",
		})
	} else {
		shown := names
		truncated := false
		if len(shown) > 40 {
			shown = shown[:40]
			truncated = true
		}
		details := make([]string, 0, len(shown))
		for _, n := range shown {
			details = append(details, types.Sanitize(n))
		}
		evidence := strings.Join(details, ", ")
		if truncated {
			evidence += fmt.Sprintf(" … (+%d more)", len(names)-len(shown))
		}
		findings = append(findings, Finding{
			Type:     "tls_certificate_names",
			Name:     fmt.Sprintf("TLS certificate covers %d hostname(s): %s", len(names), host),
			Severity: SevInfo,
			Description: fmt.Sprintf("Issuer: %s · expires %s · signature %s",
				types.Sanitize(leaf.Issuer.CommonName),
				leaf.NotAfter.UTC().Format("2006-01-02"),
				leaf.SignatureAlgorithm.String()),
			Evidence: evidence,
			Details: map[string]string{
				"sans":        strings.Join(details, ","),
				"issuer":      types.Sanitize(leaf.Issuer.CommonName),
				"not_after":   leaf.NotAfter.UTC().Format(time.RFC3339),
				"tls_version": tlsVersionName(state.Version),
			},
		})
	}

	if state.Version != 0 && state.Version < tls.VersionTLS12 {
		findings = append(findings, Finding{
			Type:        "tls_legacy_version",
			Name:        fmt.Sprintf("Legacy TLS version negotiated: %s", tlsVersionName(state.Version)),
			Severity:    SevMedium,
			Description: "TLS 1.0/1.1 are deprecated (RFC 8996) and blocked by current browsers",
			Evidence:    fmt.Sprintf("negotiated=%s", tlsVersionName(state.Version)),
		})
	}

	return findings
}

func tlsVerifySeverity(err error) Severity {
	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return SevHigh
	}
	var invalidErr x509.CertificateInvalidError
	if errors.As(err, &invalidErr) && invalidErr.Reason == x509.Expired {
		return SevHigh
	}
	var unknownErr x509.UnknownAuthorityError
	if errors.As(err, &unknownErr) {
		return SevMedium
	}
	return SevMedium
}

func tlsVersionName(v uint16) string {
	if v == 0 {
		return "unknown"
	}
	if name := tls.VersionName(v); name != "" {
		return name
	}
	return fmt.Sprintf("0x%04x", v)
}
