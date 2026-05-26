package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"

	"nice_scan/internal/types"
)

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
		version   uint16
		name      string
		severity  types.Severity
		message   string
		deprecated bool
	}{
		{tls.VersionTLS10, "TLS 1.0", types.SeverityHigh, "TLS 1.0 is deprecated and insecure", true},
		{tls.VersionTLS11, "TLS 1.1", types.SeverityHigh, "TLS 1.1 is deprecated and insecure", true},
		{tls.VersionTLS12, "TLS 1.2", types.SeverityInfo, "TLS 1.2 is acceptable but TLS 1.3 is recommended", false},
		{tls.VersionTLS13, "TLS 1.3", types.SeverityInfo, "TLS 1.3 is the latest secure version", false},
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
