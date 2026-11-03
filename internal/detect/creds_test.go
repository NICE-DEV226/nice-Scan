package detect

import "testing"

// The shared extractor is the single formula the exploit module and the
// autonomous hacker both read a leaked pair through. Lock its contract:
// recover a pair from each leak shape, never emit a lone half, and reject
// placeholder/template noise.
func TestExtractCredentialPairs(t *testing.T) {
	cases := []struct{ name, body, wantUser, wantPass string }{
		{"json user,pass", `{"username":"admin","password":"S3cr3t-Pass"}`, "admin", "S3cr3t-Pass"},
		{"json pass,user", `{"password":"S3cr3t-Pass","user":"root"}`, "root", "S3cr3t-Pass"},
		{"form query", `?email=ops@corp.io&pwd=hunter2key&next=/x`, "ops@corp.io", "hunter2key"},
		{"basic", "Authorization: Basic YWRtaW46UzNjcjN0UEBzcw==", "admin", "S3cr3tP@ss"},
	}
	for _, c := range cases {
		got := ExtractCredentialPairs(c.body)
		if len(got) == 0 {
			t.Errorf("%s: expected a pair, got none", c.name)
			continue
		}
		if got[0].User != c.wantUser || got[0].Pass != c.wantPass {
			t.Errorf("%s: got %q/%q want %q/%q", c.name, got[0].User, got[0].Pass, c.wantUser, c.wantPass)
		}
	}

	// A lone half is never a credential, and templates/placeholders are rejected.
	for _, noise := range []string{
		`{"username":"admin"}`,       // user only
		`{"password":"S3cr3t-Pass"}`, // pass only
		`{"username":"admin","password":"changeme"}`,
		`{"username":"${DB_USER}","password":"${DB_PASS}"}`,
	} {
		if got := ExtractCredentialPairs(noise); len(got) != 0 {
			t.Errorf("noise must not yield a pair (%q): %+v", noise, got)
		}
	}
}

// Both halves must come from the SAME body, and the result is capped so a
// bundle stuffed with pairs never becomes a wordlist.
func TestExtractCredentialPairsCapped(t *testing.T) {
	body := ""
	for i := 0; i < 50; i++ {
		body += `{"username":"u` + string(rune('a'+i%26)) + `","password":"Passw0rd` + string(rune('0'+i%10)) + `"}`
	}
	if got := ExtractCredentialPairs(body); len(got) > maxCredPairs {
		t.Fatalf("extraction must cap leads at %d, got %d", maxCredPairs, len(got))
	}
}
