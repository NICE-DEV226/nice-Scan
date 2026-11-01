package fingerprint

import (
	"net/http"
	"testing"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

func stackResp(headers map[string]string, body string) *types.Response {
	h := http.Header{}
	for k, v := range headers {
		h.Add(k, v)
	}
	return &types.Response{
		StatusCode: 200,
		Headers:    h,
		Body:       []byte(body),
	}
}

func TestClassifyHeaderSignals(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
		wantFam []string
	}{
		{"php powered", map[string]string{"X-Powered-By": "PHP/7.4"}, []string{FamPHP}},
		{"java session", map[string]string{"Set-Cookie": "JSESSIONID=abc; Path=/"}, []string{FamJava}},
		{"asp.net", map[string]string{"X-AspNet-Version": "4.0"}, []string{FamASPNet}},
		{"python simplehttp", map[string]string{"Server": "SimpleHTTP/0.6 Python/3.12"}, []string{FamPython}},
		{"node express", map[string]string{"X-Powered-By": "Express"}, []string{FamNode}},
		{"laravel cookie", map[string]string{"Set-Cookie": "laravel_session=xyz; Path=/"}, []string{FamLaravel, FamPHP}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st := Classify(stackResp(c.headers, "<html></html>"))
			if !st.Known() {
				t.Fatalf("expected Known() for %v", c.headers)
			}
			for _, fam := range c.wantFam {
				if !st.Has(fam) {
					t.Fatalf("want family %s, got %+v", fam, st)
				}
			}
		})
	}
}

func TestClassifyWordPressBody(t *testing.T) {
	st := Classify(stackResp(map[string]string{"Server": "nginx"},
		`<html><link rel="stylesheet" href="/wp-content/themes/x/style.css"></html>`))
	if !st.Has(FamWP) || !st.Has(FamPHP) {
		t.Fatalf("wp-content marker must map to WordPress+PHP: %+v", st)
	}
	if st.Allows(FamJava) {
		t.Fatal("java-family probe must be skipped on a WordPress target")
	}
	if !st.Allows(FamWP) {
		t.Fatal("wordpress-family probe must run on a WordPress target")
	}
}

func TestUnknownStackKeepsEverything(t *testing.T) {
	// A bare response with no stack signal must NOT justify skipping:
	// absence of evidence is not evidence of another stack.
	st := Classify(stackResp(map[string]string{}, "<html>hello</html>"))
	if st.Known() {
		t.Fatal("no signal may not mark the stack known")
	}
	for _, fam := range []string{FamPHP, FamWP, FamJava, FamASPNet} {
		if !st.Allows(fam) {
			t.Fatalf("unknown stack must keep the full probe set, rejected %s", fam)
		}
	}
	if st.String() == "" {
		t.Fatal("String must render the honest unknown fallback")
	}
}

func TestApacheAloneIsNotConditioning(t *testing.T) {
	// "Server: Apache" says nothing about PHP being installed: the label
	// shows in Techs but does not gate java or asp probes.
	st := Classify(stackResp(map[string]string{"Server": "Apache/2.4.41"}, "<html></html>"))
	if st.Known() {
		t.Fatalf("Apache product label alone must not condition probes: %+v", st)
	}
	if !st.Allows(FamJava) {
		t.Fatal("unknown scripting family must keep foreign probes")
	}
}
