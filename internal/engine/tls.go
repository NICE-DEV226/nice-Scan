package engine

import (
	"context"
	"crypto/tls"
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
	var findings []types.Finding

	if len(resp.TLS.PeerCertificates) == 0 {
		return findings
	}

	cert := resp.TLS.PeerCertificates[0]

	if len(cert.DNSNames) == 0 && len(cert.Subject.CommonName) == 0 {
		findings = append(findings, types.Finding{
			Type:        types.FindingTLS,
			Name:        "Certificate Without SAN/CN",
			Severity:    types.SeverityMedium,
			Description: "Certificate has no Subject Alternative Names or Common Name",
			Evidence:    fmt.Sprintf("Issuer: %s", cert.Issuer),
			Confidence:  0.9,
		})
	}

	return findings
}
