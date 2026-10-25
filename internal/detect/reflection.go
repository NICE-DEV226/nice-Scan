// Package detect holds the small, shared evidence primitives used by both
// the engine analyzers and the hacker actions: unique canaries that prove
// reflection, and classified reflection verdicts built from real response
// bytes. Nothing here claims a vulnerability on word matching alone — a
// finding requires our own random canary to come back through the wire.
package detect

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"
)

const canaryPrefix = "nsx"

// NewCanary returns a unique alphanumeric token, prefix + random hex. The
// token cannot pre-exist in the target's content: a response containing it
// is necessarily a reflection of our input.
func NewCanary() string {
	b := make([]byte, 5)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing means the system is broken; keep a
		// time-derived value so two scans still carry distinct tokens.
		return canaryPrefix + hex.EncodeToString([]byte(time.Now().Format("060102150405.999999999")))
	}
	return canaryPrefix + hex.EncodeToString(b)
}

// XssVector is one probe shape. Two shapes, canary inlined: tag-break tries
// to leave every quote/tag context and land raw markup with an event
// handler; script-break targets unpacked JS string contexts.
type XssVector struct {
	Name  string
	Value string
}

func XssProbes(canary string) []XssVector {
	return []XssVector{
		{
			Name:  "tag-break",
			Value: `"'>` + canary + `><svg onload=alert('` + canary + `')>`,
		},
		{
			Name:  "script-break",
			Value: `";` + canary + `//`,
		},
	}
}

// XssReflex classifies how a canary came back in a response body.
type XssReflex struct {
	Occurrences int
	// Encoded: the canary's markup neighbors came back HTML-entity
	// encoded (&lt;nsx…). The payload cannot execute as-is.
	Encoded bool
	// Executable: the probe markup (<svg onload=alert('…')>) landed raw,
	// outside markup-neutralizing containers. This is the only state
	// that claims exploitability.
	Executable bool
	// Neutralized: markup arrived raw but inside a comment, textarea,
	// title or noscript — browsers do not parse markup there.
	Neutralized bool
	// InScript: a raw canary occurrence sits inside a <script> block —
	// JS string context; exploitation depends on the surrounding code.
	InScript bool
	Snippet  string
	Offset   int
}

// ClassifyXss inspects body for the canary and, when found, classifies the
// reflection. Second return is false when the canary is absent: no canary,
// no XSS opinion — the rule that removes the old keyword-based noise.
func ClassifyXss(body []byte, canary string) (XssReflex, bool) {
	var rx XssReflex
	if len(body) == 0 || canary == "" {
		return rx, false
	}
	s := string(body)

	offsets := offsetsGlobal(s, canary)
	rx.Occurrences = len(offsets)

	// Encoded state: the OUR-canary probe came back entity-encoded — the
	// payload cannot execute as markup. The marker requires the canary
	// inside: a page that happens to carry an unrelated pre-encoded
	// '<svg onload=alert(' string (tutorials, sanitizer demos, docs)
	// previously produced "escaped reflection" verdicts with no canary on
	// the page at all — an opinion without evidence. The quote between
	// alert( and the canary may itself be encoded (htmlspecialchars default)
	// or left raw (frameworks escaping only markup).
	encodedCore := false
	for _, enc := range []string{"&lt;svg onload=alert(", "&#x3c;svg onload=alert(", "&#60;svg onload=alert("} {
		for _, q := range []string{"&#39;", "&#039;", "&#x27;", "&apos;", "'"} {
			if strings.Contains(s, enc+q+canary) {
				encodedCore = true
			}
		}
	}

	if rx.Occurrences == 0 && !encodedCore {
		return rx, false
	}

	// Executable markup: the full probe core landed raw.
	core := "<svg onload=alert('" + canary + "')>"
	coreOff := strings.Index(s, core)
	switch {
	case coreOff >= 0:
		if insideComment(s, coreOff) || insideMarkupBlackHole(s, coreOff) {
			rx.Neutralized = true
		} else {
			rx.Executable = true
		}
	case encodedCore:
		rx.Encoded = true
	}

	if len(offsets) > 0 {
		rx.Offset = offsets[0]
	}
	for _, off := range offsets {
		if insideComment(s, off) {
			rx.Neutralized = true
		} else if insideScriptBlock(s, off) {
			rx.InScript = true
		}
	}

	if rx.Executable {
		rx.Encoded = false
	}
	center := coreOff
	if center < 0 && len(offsets) > 0 {
		center = offsets[0]
	}
	rx.Snippet = snippetWindow(s, center)

	return rx, true
}

func offsetsGlobal(s, token string) []int {
	var out []int
	for i := 0; ; {
		j := strings.Index(s[i:], token)
		if j == -1 {
			break
		}
		out = append(out, i+j)
		i += j + 1
	}
	return out
}

func snippetWindow(s string, center int) string {
	if center < 0 {
		return ""
	}
	start := center - 40
	if start < 0 {
		start = 0
	}
	end := center + 90
	if end > len(s) {
		end = len(s)
	}
	return strings.ReplaceAll(s[start:end], "\n", " ")
}

// lowerByte ASCII-lowercases one byte (context scans must not materialize
// lowercased copies of whole page prefixes).
func lowerByte(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// eqTailLower reports whether s[end-len(lit):end] case-insensitively equals
// lit, without copying.
func eqTailLower(s string, end int, lit string) bool {
	start := end - len(lit)
	if start < 0 {
		return false
	}
	for i := 0; i < len(lit); i++ {
		if lowerByte(s[start+i]) != lit[i] {
			return false
		}
	}
	return true
}

// lastTailOf finds the last case-insensitive occurrence of lit starting
// strictly before off. Returns the start index or -1.
func lastTailOf(s string, off int, lit string) int {
	for end := off; end >= len(lit); end-- {
		if eqTailLower(s, end, lit) {
			return end - len(lit)
		}
	}
	return -1
}

// containsCaseInsensASCII is a no-copy case-insensitive Contains.
func containsCaseInsensASCII(hay, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	first := lowerByte(needle[0])
	for i := 0; i+len(needle) <= len(hay); i++ {
		if lowerByte(hay[i]) != first {
			continue
		}
		ok := true
		for j := 1; j < len(needle); j++ {
			if lowerByte(hay[i+j]) != needle[j] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// tagDelimiterOK verifies the character following `<tag` makes it a real
// tag opening (`<scripter` is not a script tag).
func tagDelimiterOK(s string, afterOpen int) bool {
	if afterOpen >= len(s) {
		return false
	}
	switch s[afterOpen] {
	case '>', ' ', '\t', '\n', '\r', '/':
		return true
	}
	return false
}

// insideComment reports whether off sits between `<!--` and its terminator.
// Backward case-insensitive tail scan — no lowercased prefix copy.
func insideComment(s string, off int) bool {
	open := lastTailOf(s, off, "<!--")
	if open == -1 {
		return false
	}
	closer := lastTailOf(s, off, "-->")
	return closer <= open
}

// insideMarkupBlackHole reports whether off sits inside an unclosed
// <textarea>, <title> or <noscript>. Browsers do not parse inner markup of
// those containers, so raw reflected markup cannot execute there.
func insideMarkupBlackHole(s string, off int) bool {
	for _, tag := range []string{"textarea", "title", "noscript"} {
		openTag := "<" + tag
		open := lastTailOf(s, off, openTag)
		if open == -1 || !tagDelimiterOK(s, open+len(openTag)) {
			continue
		}
		if closer := lastTailOf(s, off, "</"+tag); closer > open {
			continue
		}
		return true
	}
	return false
}

// insideScriptBlock reports whether off sits between <script …> opening and
// its `</script>` terminator; src-attribute tags carry no JS body.
func insideScriptBlock(s string, off int) bool {
	open := lastTailOf(s, off, "<script")
	if open == -1 || !tagDelimiterOK(s, open+len("<script")) {
		return false
	}
	tagEnd := strings.Index(s[open:], ">")
	if tagEnd == -1 {
		return false
	}
	if containsCaseInsensASCII(s[open:open+tagEnd+1], "src=") {
		return false
	}
	return lastTailOf(s, off, "</script") <= open
}
