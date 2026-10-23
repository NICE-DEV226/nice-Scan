package types

import "strings"

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
