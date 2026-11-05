package types

import (
	"fmt"
	"regexp"
	"strings"
)

// Sanitize is the terminal-safety filter for any remote-influenced text
// rendered to the operator (finding names, evidence, URLs extracted from
// responses). Without it a crafted response could escape highlight rendering
// and emit raw escape/OSC sequences — e.g. clipboard writes (OSC 52), screen
// mirroring (OSC 50+), or bidi masking of report text.
func Sanitize(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n':
			b.WriteByte('\n')
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7F || (r >= 0x80 && r <= 0xA0):
			v := byte(r) & 0xFF
			b.WriteString(`\x`)
			b.WriteByte(hex[v>>4])
			b.WriteByte(hex[v&0x0F])
		case r == 0x202E || r == 0x202D || r == 0x202A || r == 0x202B || r == 0x202C ||
			(r >= 0x2066 && r <= 0x2069):
			// Directional formatting: drop entirely.
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// MaskSecret destroys a credential's value while keeping its length (useful to
// class it) so a discovered or verified password is never written to the
// terminal, JSON, or HTML report in plaintext. Only the username is safe to
// display; pair it with MaskSecret for the value.
func MaskSecret(v string) string {
	n := len(strings.TrimSpace(v))
	if n == 0 {
		return "<empty>"
	}
	return fmt.Sprintf("<masked len=%d>", n)
}

// credentialKeyNames are the Metadata keys that hold a value worth stealing,
// as opposed to a fact worth reporting. It is deliberately narrow: "value" and
// "id" carry a numeric object reference in an IDOR finding, and masking those
// would destroy the only actionable part of the report while protecting
// nothing. A key that NAMES a credential is the signal.
var credentialKeyNames = []string{
	"password", "passwd", "pwd", "pass",
	"token", "secret", "authorization", "credential",
	"cookie", "session", "raw",
	"api_key", "apikey", "access_key", "private_key", "key_material",
}

// labelKeys name a thing instead of holding its value. Masking them destroys
// the actionable half of a report while protecting nothing: a username is safe
// to display by this file's own rule, a cookie's NAME is not its secret, and an
// IDOR's object reference is the whole finding.
var labelKeys = map[string]bool{
	"cookie": true, "cookie_name": true, "token_name": true,
	"parameter": true, "param": true, "name": true, "type": true,
	"user": true, "username": true, "auth_user": true, "account": true,
	"endpoint": true, "path": true,
}

// isCredentialKey reports whether a metadata key names a stored credential.
func isCredentialKey(k string) bool {
	lower := strings.ToLower(strings.TrimSpace(k))
	if labelKeys[lower] {
		return false
	}
	for _, name := range credentialKeyNames {
		if lower == name || strings.HasSuffix(lower, "_"+name) || strings.Contains(lower, name+"_") {
			return true
		}
	}
	return false
}

// RedactURL strips the userinfo from a URL. A scanner writes down the exact
// URLs it exchanged, and an operator who authenticated by URL
// (https://user:pass@host) would otherwise have those credentials copied into
// every report field that echoes it. The presence of credentials is kept —
// that is a finding — the values are not.
func RedactURL(raw string) string {
	if raw == "" || !strings.Contains(raw, "://") {
		return raw
	}
	i := strings.Index(raw, "://")
	rest := raw[i+3:]
	j := strings.IndexAny(rest, "/?#")
	hostPart := rest
	if j >= 0 {
		hostPart = rest[:j]
	}
	at := strings.LastIndex(hostPart, "@")
	if at < 0 {
		return raw
	}
	return raw[:i+3] + "<redacted-credentials>@" + rest[at+1:]
}

// rxInlineURLCredentials matches credentials embedded in a URL inside free
// text, which is how they reach Evidence and Description: an analyzer quoting
// "URL: https://admin:s3cret@host/admin" is reporting a fact and leaking a
// password in the same breath.
var rxInlineURLCredentials = regexp.MustCompile(`(?i)([a-z][a-z0-9.+-]*://)[^\s/"'<>?#@]+:[^\s/"'<>?#@]+@`)

// rxSecretParam matches a credential-shaped key bound to a literal value
// anywhere inside a block of report text. A DSN is quoted as one URL, and the
// password is either the userinfo or a query parameter, so masking only the
// userinfo would leave the second form standing.
var rxSecretParam = regexp.MustCompile(`(?i)([?&;]?\b(password|passwd|pwd|secret|token|access_token|apikey|api_key)[='"])([^&\s'"\\]{6,})`)

// redactInlineText applies RedactURL's rule to every URL inside a block of
// report text, and masks literal values bound to a credential-shaped key.
func redactInlineText(s string) string {
	out := s
	if strings.Contains(out, "://") {
		out = rxInlineURLCredentials.ReplaceAllString(out, "${1}<redacted-credentials>@")
	}
	return rxSecretParam.ReplaceAllStringFunc(out, func(m string) string {
		groups := rxSecretParam.FindStringSubmatch(m)
		return groups[1] + MaskSecret(groups[3])
	})
}

// RedactSecretValue keeps the shape an operator can recognise without turning
// the report into a credential dump: the first four glyphs, which identify the
// provider prefix (AKIA, sk_l…), plus the length that classes it.
//
// Truncating a value is not masking it. A prefix of a session token is still
// the beginning of a live credential, and "…(30 chars)" of an API key tells a
// reader everything they needs to know about the leak.
func RedactSecretValue(s string) string {
	prefix := s
	if len(prefix) > 4 {
		prefix = prefix[:4]
	}
	return fmt.Sprintf("%s… (%d chars)", Sanitize(prefix), len(s))
}

// RedactFinding is the single source of truth for putting a finding where a
// machine — or a model — will read it without a human reviewing the bytes
// first. Every renderer prints a report a person looks at; the JSON sink is
// consumed by things that do not look, so it cannot be the one path that
// recopies Evidence and Metadata verbatim.
//
// It returns a copy: a redacted finding must never be the object the scan
// still holds in memory or renders on screen.
func RedactFinding(f Finding) Finding {
	out := f
	out.Name = redactText(f.Name)
	out.Description = redactText(f.Description)
	out.Evidence = redactText(f.Evidence)

	if f.Metadata != nil {
		m := make(map[string]string, len(f.Metadata))
		for k, v := range f.Metadata {
			if isCredentialKey(k) {
				m[k] = MaskSecret(v)
				continue
			}
			m[k] = redactText(v)
		}
		out.Metadata = m
	}

	if f.Prov != nil {
		p := *f.Prov
		p.RequestURL = redactText(p.RequestURL)
		p.BaselineRef = redactText(p.BaselineRef)
		out.Prov = &p
	}

	return out
}

// redactText is the pair every report string must pass through: kill the
// terminal-control characters, then the credentials quoted inside the text.
func redactText(s string) string {
	if s == "" {
		return s
	}
	return redactInlineText(Sanitize(s))
}

// RedactText exposes the report-string filter to renderers that build their own
// strings (a transport error, a URL from a redirect chain) and must not
// reimplement the rule.
func RedactText(s string) string { return redactText(s) }
