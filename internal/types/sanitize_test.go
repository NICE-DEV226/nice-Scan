package types

import (
	"strings"
	"testing"
)

func TestSanitizeStripsEscapeSequences(t *testing.T) {
	in := "\x1b]52;c;YWJj\x07evil\x1b[2J" + "keep\nlines" + "\x1b]8;;http://x\x07link\x1b]8;;\x07"
	got := Sanitize(in)

	if len(got) == len(in) {
		t.Fatal("sanitizer did not remove any control bytes")
	}
	for _, b := range []byte(got) {
		if b < 0x20 && b != '\n' && b != '\t' {
			t.Errorf("control byte 0x%02X survived sanitization", b)
		}
	}
	if !containsStrSimple(got, "keep\nlines") {
		t.Errorf("legit content lost: %q", got)
	}
}

func TestSanitizeDropsBidi(t *testing.T) {
	in := "user" + string([]rune{0x202E}) + "adminoverride"
	got := Sanitize(in)
	if containsStrSimple(got, string(rune(0x202E))) {
		t.Errorf("bidi override survived")
	}
}

func containsStrSimple(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestRedactTextMasksCredentialsQuotedInText(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		mustNot string
	}{
		{
			name:    "URL userinfo keeps host and path",
			in:      `URL: https://admin:Sup3rSecret@vanstech.space/admin?id=42`,
			want:    "<redacted-credentials>@vanstech.space/admin",
			mustNot: "Sup3rSecret",
		},
		{
			name:    "DSN query password",
			in:      `mongodb://db.internal:27017/prod?authSource=admin&password=Sup3rSecret`,
			want:    "password=<masked len=",
			mustNot: "Sup3rSecret",
		},
		{
			name:    "bearer literal",
			in:      `header: token=abcdefgh12345`,
			want:    "token=<masked len=",
			mustNot: "abcdefgh12345",
		},
	}
	for _, c := range cases {
		got := RedactText(c.in)
		if strings.Contains(got, c.mustNot) {
			t.Errorf("%s: RedactText leaked %q in %q", c.name, c.mustNot, got)
		}
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: RedactText(%q) = %q, want it to contain %q", c.name, c.in, got, c.want)
		}
	}
}

// A report that launders prose is a report that hides the finding. Only a
// credential-shaped key bound to a literal value may be masked.
func TestRedactTextLeavesOrdinaryReportTextAlone(t *testing.T) {
	for _, s := range []string{
		"Fields: password, username/email",
		"A secret-bearing key is bound to a literal value",
		"Emails: ops@corp.example",
		"parameter: id | value: 42",
		`login?next=/dashboard`,
	} {
		if got := RedactText(s); got != s {
			t.Errorf("RedactText rewrote non-credential report text:\n in: %q\nout: %q", s, got)
		}
	}
}
