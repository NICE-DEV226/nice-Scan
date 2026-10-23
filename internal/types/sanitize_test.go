package types

import "testing"

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
