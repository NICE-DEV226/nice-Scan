package detect

import (
	"encoding/base64"
	"regexp"
	"strings"
)

// Login-pair extraction, shared by the exploit module and the autonomous hacker
// so a credential the TARGET itself leaked is aimed at its own form through ONE
// formula (the login verdict grammar moved here for the same reason: two
// extractors in one binary drift). Where a response discards BOTH halves of a
// login pair — a decodable Basic-Auth blob, or a user+pass sitting together in
// JSON or a form/query string — the pair is actionable. A lone secret is not:
// we only ever return a user AND a pass from the same body, never a spray.
//
// The caller attempts a returned pair; nothing here executes it. Passwords are
// returned in plaintext only so the caller can attempt them — every display and
// report site must mask them with types.MaskSecret.
type CredPair struct {
	User string
	Pass string
}

const (
	credUserKeys = `username|user_name|user|login|email|e-?mail|account|user_id|uid|usr`
	credPassKeys = `password|passwd|pwd|pass`

	// bounded: a couple of real leads, never a wordlist.
	maxCredPairs = 8
)

var (
	rxBasicPair = regexp.MustCompile(`(?i)Basic\s+([A-Za-z0-9+/=]{8,})`)

	// "user":"…" ... "password":"…" and the reverse order, within one object.
	rxJSONUserPass = regexp.MustCompile(`(?is)"(?:` + credUserKeys + `)"\s*:\s*"([^"]{2,64})"\s*,\s*"(?:` + credPassKeys + `)"\s*:\s*"([^"]{3,80})"`)
	rxJSONPassUser = regexp.MustCompile(`(?is)"(?:` + credPassKeys + `)"\s*:\s*"([^"]{3,80})"\s*,\s*"(?:` + credUserKeys + `)"\s*:\s*"([^"]{2,64})"`)

	// form-encoded / query pairs, both orders, other params interleaved.
	rxFormUserPass = regexp.MustCompile(`(?i)(?:^|[?&/])(?:` + credUserKeys + `)=([^&\s"'<>]{2,64})[\s\S]{0,120}?(?:^|[&])(?:` + credPassKeys + `)=([^&\s"'<>]{3,80})`)
	rxFormPassUser = regexp.MustCompile(`(?i)(?:^|[?&/])(?:` + credPassKeys + `)=([^&\s"'<>]{3,80})[\s\S]{0,120}?(?:^|[&])(?:` + credUserKeys + `)=([^&\s"'<>]{2,64})`)
)

// LooksRealCred rejects template/placeholder/echo values so a `user=<%= x %>`
// or `password=changeme` is never mistaken for a lead. Exported so the exploit
// wrapper applies the identical bar as this package's extractor.
func LooksRealCred(v string) bool {
	v = strings.TrimSpace(v)
	if len(v) < 3 {
		return false
	}
	switch strings.ToLower(v) {
	case "changeme", "changeit", "password", "passwd", "secret", "todo", "tbd",
		"example", "placeholder", "null", "none", "undefined", "yourpassword", "xxx":
		return false
	}
	if strings.ContainsAny(v, "<>{}%$") || strings.HasPrefix(v, "${") {
		return false
	}
	return true
}

func decodeBasicPair(b64 string) (user, pass string, ok bool) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		if raw, err = base64.URLEncoding.DecodeString(b64); err != nil {
			return "", "", false
		}
	}
	u, p, found := strings.Cut(string(raw), ":")
	if !found {
		return "", "", false
	}
	return u, p, true
}

// ExtractCredentialPairs pulls login pairs out of a single response body. It
// dedupes and caps the result; an empty slice is an honest "no discovered
// credential pair here", not an error.
func ExtractCredentialPairs(body string) []CredPair {
	var out []CredPair
	seen := map[string]bool{}
	add := func(user, pass string) {
		user, pass = strings.TrimSpace(user), strings.TrimSpace(pass)
		if !LooksRealCred(user) || !LooksRealCred(pass) {
			return
		}
		key := user + "\x00" + pass
		if seen[key] || len(out) >= maxCredPairs {
			return
		}
		seen[key] = true
		out = append(out, CredPair{User: user, Pass: pass})
	}

	for _, m := range rxBasicPair.FindAllStringSubmatch(body, -1) {
		if u, p, ok := decodeBasicPair(m[1]); ok {
			add(u, p)
		}
	}
	// user-then-pass first, then the reverse; a pair matching both orders is
	// deduped by the seen set.
	for _, rx := range []*regexp.Regexp{rxJSONUserPass, rxJSONPassUser, rxFormUserPass, rxFormPassUser} {
		for _, m := range rx.FindAllStringSubmatch(body, -1) {
			if len(m) < 3 {
				continue
			}
			u, p := m[1], m[2]
			if rx == rxJSONPassUser || rx == rxFormPassUser {
				u, p = p, u
			}
			add(u, p)
		}
	}
	return out
}
