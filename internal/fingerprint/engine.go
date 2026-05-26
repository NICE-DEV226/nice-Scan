package fingerprint

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/nice-scan/nice_scan/internal/types"
)

var rxNumbers = regexp.MustCompile(`[\d]+\.[\d]+[\w.-]*`)

type Fingerprinter struct {
	signatures []Signature
}

type Signature struct {
	Name       string
	Type       string
	Category   string
	Confidence float64
	CWE        string
	Remediation string

	Headers map[string]*regexp.Regexp
	Cookies map[string]*regexp.Regexp
	HTML    []*regexp.Regexp
	URL     []*regexp.Regexp
	Script  []*regexp.Regexp
	CSP     []*regexp.Regexp
	Meta    []*regexp.Regexp
	Favicon string

	VersionHeaders map[string]*regexp.Regexp
	VersionCookies map[string]*regexp.Regexp
	VersionHTML    []*regexp.Regexp
}

func New() *Fingerprinter {
	f := &Fingerprinter{}
	f.loadSignatures()
	return f
}

func (f *Fingerprinter) Name() string {
	return "fingerprint"
}

func (f *Fingerprinter) Analyze(ctx context.Context, resp *types.Response) []types.Finding {
	if resp == nil {
		return nil
	}

	var findings []types.Finding

	for _, sig := range f.signatures {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		match, evidence, version := sig.Match(resp)
		if !match {
			continue
		}

		meta := map[string]string{
			"category": sig.Category,
			"type":     sig.Type,
		}
		desc := fmt.Sprintf("Detected %s (%s)", sig.Name, sig.Category)
		if version != "" {
			meta["version"] = version
			desc = fmt.Sprintf("Detected %s %s (%s)", sig.Name, version, sig.Category)
		}
		if sig.CWE != "" {
			meta["cwe"] = sig.CWE
		}

		findings = append(findings, types.Finding{
			Type:        types.FindingTech,
			Name:        sig.Name,
			Severity:    types.SeverityInfo,
			Description: desc,
			Evidence:    evidence,
			Confidence:  sig.Confidence,
			Metadata:    meta,
		})
	}

	return findings
}

func (s *Signature) Match(resp *types.Response) (bool, string, string) {
	matched := false
	evidence := ""
	version := ""

	for name, pattern := range s.Headers {
		val := resp.Headers.Get(name)
		if val == "" {
			continue
		}
		if pattern.MatchString(val) {
			matched = true
			evidence = fmt.Sprintf("header %s: %s", name, val)
			if v, ok := s.extractVersionHeader(name, val); ok {
				version = v
			}
			break
		}
	}

	for name, pattern := range s.Cookies {
		if matched {
			break
		}
		for _, c := range resp.Headers.Values("Set-Cookie") {
			if strings.HasPrefix(strings.TrimSpace(c), name+"=") {
				if pattern.MatchString(c) {
					matched = true
					evidence = fmt.Sprintf("cookie %s", name)
					if v, ok := s.extractVersionCookie(name, c); ok {
						version = v
					}
					break
				}
			}
		}
	}

	for _, pattern := range s.HTML {
		if matched {
			break
		}
		if pattern.MatchString(string(resp.Body)) {
			matched = true
			evidence = fmt.Sprintf("html: %s", pattern.String())
			if v, ok := s.extractVersionHTML(string(resp.Body), pattern); ok {
				version = v
			}
			break
		}
	}

	for _, pattern := range s.URL {
		if matched {
			break
		}
		if pattern.MatchString(resp.FinalURL) {
			matched = true
			evidence = fmt.Sprintf("url: %s", pattern.String())
			break
		}
	}

	for _, pattern := range s.CSP {
		if matched {
			break
		}
		csp := resp.Headers.Get("Content-Security-Policy")
		if csp != "" && pattern.MatchString(csp) {
			matched = true
			evidence = fmt.Sprintf("csp: %s", pattern.String())
			break
		}
	}

	for _, pattern := range s.Script {
		if matched {
			break
		}
		if pattern.MatchString(string(resp.Body)) {
			matched = true
			evidence = fmt.Sprintf("script: %s", pattern.String())
			break
		}
	}

	for _, pattern := range s.Meta {
		if matched {
			break
		}
		if pattern.MatchString(string(resp.Body)) {
			matched = true
			evidence = fmt.Sprintf("meta: %s", pattern.String())
			if v, ok := s.extractVersionHTML(string(resp.Body), pattern); ok {
				version = v
			}
			break
		}
	}

	if !matched && s.Favicon != "" {
		if hasFavicon(resp, s.Favicon) {
			matched = true
			evidence = "favicon hash match"
		}
	}

	return matched, evidence, version
}

func (s *Signature) extractVersionHeader(name, val string) (string, bool) {
	pat, ok := s.VersionHeaders[name]
	if !ok {
		v := rxNumbers.FindString(val)
		return v, v != ""
	}
	m := pat.FindStringSubmatch(val)
	if len(m) > 1 && m[1] != "" {
		return m[1], true
	}
	return "", false
}

func (s *Signature) extractVersionCookie(name, val string) (string, bool) {
	pat, ok := s.VersionCookies[name]
	if !ok {
		return "", false
	}
	m := pat.FindStringSubmatch(val)
	if len(m) > 1 && m[1] != "" {
		return m[1], true
	}
	return "", false
}

func (s *Signature) extractVersionHTML(body string, pattern *regexp.Regexp) (string, bool) {
	for _, pat := range s.VersionHTML {
		m := pat.FindStringSubmatch(body)
		if len(m) > 1 && m[1] != "" {
			return m[1], true
		}
	}
	return "", false
}

func hasFavicon(resp *types.Response, expectedHash string) bool {
	return false
}

func (f *Fingerprinter) LoadCustom(signatures []Signature) {
	f.signatures = append(f.signatures, signatures...)
}

func (f *Fingerprinter) Signatures() int {
	return len(f.signatures)
}
