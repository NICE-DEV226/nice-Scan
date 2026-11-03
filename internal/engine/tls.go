package engine

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// ProbeLegacyTLS actively attempts a TLS 1.0 / 1.1 handshake against an HTTPS
// target and reports the versions it ACCEPTS.
//
// Why this exists: Go's default client refuses to negotiate anything below
// TLS 1.2, so resp.TLS.Version — the passive signal — can never be 1.0 or 1.1.
// The old passive "TLS 1.0 deprecated" check was therefore unreachable dead
// code: it looked like it tested for legacy TLS and never did. Detecting a
// server that still ENABLES TLS 1.0/1.1 requires explicitly opting the dial
// down to that version; if the handshake succeeds the server really does
// speak it. This is the only place that dials on purpose (and only at the
// operator's HTTPS target, one connection per version).
func ProbeLegacyTLS(ctx context.Context, target string) []types.Finding {
	u, err := url.Parse(target)
	if err != nil || !strings.EqualFold(u.Scheme, "https") {
		return nil
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(host, port)

	legacy := []struct {
		version uint16
		name    string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
	}

	var findings []types.Finding
	for _, lv := range legacy {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		d := &net.Dialer{Timeout: 8 * time.Second}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			continue
		}
		// InsecureSkipVerify is deliberate and safe HERE: the check is whether
		// the server completes a handshake at a legacy VERSION, not whether its
		// certificate is trusted — cert trust is judged by the passive pass.
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         host,
			MinVersion:         lv.version,
			MaxVersion:         lv.version,
			InsecureSkipVerify: true,
		})
		_ = tlsConn.SetDeadline(time.Now().Add(8 * time.Second))
		hsErr := tlsConn.HandshakeContext(ctx)
		version := tlsConn.ConnectionState().Version
		_ = tlsConn.Close()

		if hsErr == nil && version == lv.version {
			findings = append(findings, types.Finding{
				Type:        types.FindingTLS,
				Name:        fmt.Sprintf("Legacy TLS Enabled: %s", lv.name),
				Severity:    types.SeverityHigh,
				Description: fmt.Sprintf("Server completed a %s handshake — deprecated protocol still enabled and negotiable (BEAST/SWEET32 class exposure); disable it and restrict to TLS 1.2+", lv.name),
				Evidence:    fmt.Sprintf("Handshake negotiated %s with %s", lv.name, addr),
				Confidence:  1.0,
				Metadata:    map[string]string{"tls_version": lv.name, "enabled": "true"},
			})
		}
	}
	return findings
}

type TLSAnalyzer struct{}

func NewTLSAnalyzer() *TLSAnalyzer {
	return &TLSAnalyzer{}
}

func (a *TLSAnalyzer) Name() string {
	return "tls"
}

func (a *TLSAnalyzer) Analyze(ctx context.Context, resp *types.Response) []types.Finding {
	if resp == nil || resp.TLS == nil {
		return nil
	}

	var findings []types.Finding

	findings = append(findings, a.checkVersion(resp)...)
	findings = append(findings, a.checkCipher(resp)...)
	findings = append(findings, a.checkCertificate(resp)...)

	return findings
}

func (a *TLSAnalyzer) checkVersion(resp *types.Response) []types.Finding {
	var findings []types.Finding

	versionChecks := []struct {
		version  uint16
		name     string
		severity types.Severity
		message  string
	}{
		// Only 1.2/1.3 can appear here: a Go client that refused to
		// negotiate below 1.2 produced resp.TLS in the first place, so a
		// legacy version never reaches this table. Legacy TLS ENABLEMENT is
		// detected actively by ProbeLegacyTLS, not passively.
		{tls.VersionTLS12, "TLS 1.2", types.SeverityInfo, "TLS 1.2 negotiated (acceptable); TLS 1.3 is recommended where clients support it"},
		{tls.VersionTLS13, "TLS 1.3", types.SeverityInfo, "TLS 1.3 is the latest secure version"},
	}

	for _, vc := range versionChecks {
		if resp.TLS.Version == vc.version {
			findings = append(findings, types.Finding{
				Type:        types.FindingTLS,
				Name:        fmt.Sprintf("TLS Version: %s", vc.name),
				Severity:    vc.severity,
				Description: vc.message,
				Evidence:    fmt.Sprintf("Negotiated: %s", vc.name),
				Confidence:  1.0,
				Metadata: map[string]string{
					"tls_version": vc.name,
				},
			})
			break
		}
	}

	return findings
}

func (a *TLSAnalyzer) checkCipher(resp *types.Response) []types.Finding {
	var findings []types.Finding

	cipherName := tls.CipherSuiteName(resp.TLS.CipherSuite)

	if strings.Contains(cipherName, "RC4") || strings.Contains(cipherName, "CBC") || strings.Contains(cipherName, "3DES") || strings.Contains(cipherName, "EXPORT") {
		findings = append(findings, types.Finding{
			Type:        types.FindingTLS,
			Name:        "Weak TLS Cipher Suite",
			Severity:    types.SeverityHigh,
			Description: fmt.Sprintf("Weak cipher suite negotiated: %s", cipherName),
			Evidence:    fmt.Sprintf("Cipher: %s", cipherName),
			Confidence:  1.0,
		})
	}

	return findings
}

func (a *TLSAnalyzer) checkCertificate(resp *types.Response) []types.Finding {
	return analyzeCertificate(resp, time.Now())
}

// analyzeCertificate is a pure sink: it reads the certificate the target
// actually served out of resp.TLS (a *tls.ConnectionState the client already
// holds) and reports the facts an operator needs — subject/SAN coverage,
// issuer, validity window, signature algorithm — plus the negative findings
// (expired, expiring, not-yet-valid, SHA-1, no-SAN). Tests feed it a synthetic
// clock so the expiry windows are checked without waiting for a real calendar.
//
// Severity thresholds mirror hacker.analyzeTLSFindings deliberately: a single
// `tls` run and an autonomous `hack` must not disagree about what an expired
// certificate is worth. Keep the two in step when either changes.
func analyzeCertificate(resp *types.Response, now time.Time) []types.Finding {
	var findings []types.Finding

	if len(resp.TLS.PeerCertificates) == 0 {
		return findings
	}
	cert := resp.TLS.PeerCertificates[0]

	// Validity window, evaluated against the injected clock.
	switch {
	case now.After(cert.NotAfter):
		findings = append(findings, types.Finding{
			Type:        types.FindingTLS,
			Name:        "TLS Certificate Expired",
			Severity:    types.SeverityHigh,
			Description: fmt.Sprintf("The leaf certificate stopped being valid on %s; every client turns into a block screen", cert.NotAfter.UTC().Format("2006-01-02")),
			Evidence:    fmt.Sprintf("NotAfter=%s", cert.NotAfter.UTC().Format(time.RFC3339)),
			Confidence:  1.0,
		})
	case now.Before(cert.NotBefore):
		findings = append(findings, types.Finding{
			Type:        types.FindingTLS,
			Name:        "TLS Certificate Not Yet Valid",
			Severity:    types.SeverityMedium,
			Description: fmt.Sprintf("The certificate's validity window starts on %s — before then clients reject it", cert.NotBefore.UTC().Format("2006-01-02")),
			Evidence:    fmt.Sprintf("NotBefore=%s", cert.NotBefore.UTC().Format(time.RFC3339)),
			Confidence:  1.0,
		})
	default:
		if days := int(cert.NotAfter.Sub(now).Hours() / 24); days < 14 {
			findings = append(findings, types.Finding{
				Type:        types.FindingTLS,
				Name:        fmt.Sprintf("TLS Certificate Expires in %d Day(s)", days),
				Severity:    types.SeverityMedium,
				Description: "Renewal window is short; an expired certificate breaks every client at once",
				Evidence:    fmt.Sprintf("NotAfter=%s", cert.NotAfter.UTC().Format(time.RFC3339)),
				Confidence:  1.0,
			})
		}
	}

	switch cert.SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		findings = append(findings, types.Finding{
			Type:        types.FindingTLS,
			Name:        "TLS Certificate Uses SHA-1 Signature",
			Severity:    types.SeverityMedium,
			Description: "SHA-1 certificate signatures are deprecated and rejected by current browser policies",
			Evidence:    fmt.Sprintf("SignatureAlgorithm=%s", cert.SignatureAlgorithm.String()),
			Confidence:  1.0,
		})
	}

	// Subject coverage: modern clients validate against subjectAltName and
	// ignore the legacy CN, so a certificate with no SAN fails validation even
	// when its CN looks right.
	names := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses))
	names = append(names, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		names = append(names, ip.String())
	}
	if len(names) == 0 {
		findings = append(findings, types.Finding{
			Type:        types.FindingTLS,
			Name:        "Certificate Without SubjectAltName",
			Severity:    types.SeverityLow,
			Description: "No subjectAltName entries; modern clients ignore the CN and will reject this certificate",
			Evidence:    fmt.Sprintf("CN=%s · Issuer=%s", types.Sanitize(cert.Subject.CommonName), types.Sanitize(cert.Issuer.CommonName)),
			Confidence:  0.9,
		})
	}

	// The certificate-facts finding is the reason this command exists: the
	// issuer, expiry, coverage and negotiated parameters an operator reads off
	// a `tls` run. It is INFO (no vulnerability implied) but carries the whole
	// picture in Metadata so JSON/report consumers get structured values.
	shown := names
	truncated := false
	if len(shown) > 40 {
		shown = shown[:40]
		truncated = true
	}
	cleanNames := make([]string, 0, len(shown))
	for _, n := range shown {
		cleanNames = append(cleanNames, types.Sanitize(n))
	}
	sanEvidence := strings.Join(cleanNames, ", ")
	if truncated {
		sanEvidence += fmt.Sprintf(" … (+%d more)", len(names)-len(shown))
	} else if len(cleanNames) == 0 {
		sanEvidence = "<none>"
	}
	findings = append(findings, types.Finding{
		Type:        types.FindingTLS,
		Name:        fmt.Sprintf("TLS Certificate: %s", typeOfFirst(cleanNames, types.Sanitize(cert.Subject.CommonName))),
		Severity:    types.SeverityInfo,
		Description: fmt.Sprintf("Issuer: %s · expires %s · signature %s", types.Sanitize(cert.Issuer.CommonName), cert.NotAfter.UTC().Format("2006-01-02"), cert.SignatureAlgorithm.String()),
		Evidence:    sanEvidence,
		Confidence:  1.0,
		Metadata: map[string]string{
			"subject":        types.Sanitize(cert.Subject.CommonName),
			"issuer":         types.Sanitize(cert.Issuer.CommonName),
			"not_before":     cert.NotBefore.UTC().Format(time.RFC3339),
			"not_after":      cert.NotAfter.UTC().Format(time.RFC3339),
			"signature":      cert.SignatureAlgorithm.String(),
			"sans":           strings.Join(cleanNames, ","),
			"tls_version":    tlsVersionOr(resp.TLS.Version),
			"cipher":         tls.CipherSuiteName(resp.TLS.CipherSuite),
			"serial":         cert.SerialNumber.String(),
			"is_self_signed": fmt.Sprint(cert.Issuer.String() == cert.Subject.String()),
		},
	})

	return findings
}

func typeOfFirst(primary []string, fallback string) string {
	if len(primary) > 0 {
		return primary[0]
	}
	if fallback != "" {
		return fallback
	}
	return "(no name)"
}

func tlsVersionOr(v uint16) string {
	if name := tls.VersionName(v); name != "" {
		return name
	}
	return fmt.Sprintf("0x%04x", v)
}
