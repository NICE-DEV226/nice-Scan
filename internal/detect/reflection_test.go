package detect

import "testing"

const can = "nsxab12cd34"

func TestClassifyXssExecutableShapes(t *testing.T) {
	// canonical executable echo: whole tag-break vector reflected raw
	body := []byte(`<html><div>hello</div>` + `"'>` + can + `><svg onload=alert('` + can + `')></html>`)
	rx, ok := ClassifyXss(body, can)
	if !ok {
		t.Fatal("canary reflected raw must classify")
	}
	if !rx.Executable {
		t.Fatalf("raw markup core must be executable, got %+v", rx)
	}
	if rx.Encoded || rx.Neutralized || rx.InScript {
		t.Fatalf("mutually exclusive states leaked: %+v", rx)
	}
	if rx.Occurrences != 2 {
		t.Fatalf("tag-break vector carries the canary twice, got %d", rx.Occurrences)
	}
	if rx.Snippet == "" {
		t.Fatal("evidence snippet required")
	}
}

func TestClassifyXssSilentWithoutCanary(t *testing.T) {
	// The OLD analyzer flagged every page containing <script>/<div>/<img>.
	// The classifier must stay silent unless OUR token round-trips.
	body := []byte(`<html><head><script>alert(1)</script></head>` +
		`<body><div id=x class="col"><img src="/logo.png" onerror=alert(1)>` +
		`<svg><rect/></svg><iframe srcdoc="<b>"></body></html>`)
	if _, ok := ClassifyXss(body, can); ok {
		t.Fatal("pages without the canary must produce no XSS opinion")
	}
	if _, ok := ClassifyXss(nil, can); ok {
		t.Fatal("empty body must produce no opinion")
	}
	if _, ok := ClassifyXss([]byte("noise"), ""); ok {
		t.Fatal("empty canary must produce no opinion")
	}
}

func TestClassifyXssEncodedEcho(t *testing.T) {
	// htmlspecialchars-style reflection: markup neighbors escaped (and the
	// quote encoded with it, which is htmlspecialchars' default).
	body := []byte(`<p>search: &lt;svg onload=alert(&#39;` + can + `&#39;)></p>`)
	rx, ok := ClassifyXss(body, can)
	if !ok {
		t.Fatal("escaped echo must classify (it is a reflection)")
	}
	if rx.Executable {
		t.Fatal("entity-encoded markup must never claim executability")
	}
	if !rx.Encoded {
		t.Fatalf("escaped markup core must mark Encoded, got %+v", rx)
	}
}

// The exact false positive the canary-anchoring removes: sanitizers,
// tutorials and docs pages carry a PRE-encoded '<svg onload=alert(...)'
// string they were never sent. With the canary absent there is no
// reflection — and no XSS opinion at all.
func TestClassifyXssPreEncodedMarkerWithoutCanaryIsSilent(t *testing.T) {
	body := []byte(`<p>The sanitizer converts <code>&lt;svg onload=alert(&#39;xss&#39;)&gt;</code> into harmless text.</p>`)
	if _, ok := ClassifyXss(body, can); ok {
		t.Fatal("a pre-encoded marker without OUR canary must produce no opinion")
	}
}

func TestClassifyXssNeutralizedContainers(t *testing.T) {
	textarea := []byte(`<textarea>` + `"'>` + can + `><svg onload=alert('` + can + `')></textarea>`)
	rx, _ := ClassifyXss(textarea, can)
	if rx.Executable {
		t.Fatal("markup inside <textarea> cannot execute")
	}
	if !rx.Neutralized {
		t.Fatalf("textarea reflection must be neutralized, got %+v", rx)
	}

	commented := []byte(`<div><!-- ` + can + ` <svg onload=alert('` + can + `')> --></div>`)
	if rx, _ := ClassifyXss(commented, can); rx.Executable {
		t.Fatal("markup inside an HTML comment cannot execute")
	}

	titled := []byte(`<title>` + can + `<svg onload=alert('` + can + `')></title>`)
	if rx, _ := ClassifyXss(titled, can); rx.Executable {
		t.Fatal("markup inside <title> cannot execute")
	}
}

func TestClassifyXssScriptBlockContext(t *testing.T) {
	body := []byte(`<script>var q = ";` + can + `//";</script>`)
	rx, ok := ClassifyXss(body, can)
	if !ok {
		t.Fatal("script-block reflection must classify")
	}
	if rx.Executable {
		t.Fatal("script-break vector inside a script block is not executable markup")
	}
	if !rx.InScript {
		t.Fatalf("must report JS string context, got %+v", rx)
	}
}

func TestClassifyXssExternalScriptSrcNotABody(t *testing.T) {
	// <script src=…> has no JS body; content following it is text again.
	body := []byte(`<script src="/app.js"></script>` + `";` + can + `//`)
	rx, ok := ClassifyXss(body, can)
	if !ok {
		t.Fatal("reflection must classify")
	}
	if rx.InScript {
		t.Fatalf("content after a src-only script tag is not script body, got %+v", rx)
	}
}

func TestXssProbesShape(t *testing.T) {
	probes := XssProbes("nsxTEST")
	if len(probes) != 2 {
		t.Fatalf("two probe shapes expected, got %d", len(probes))
	}
	for _, p := range probes {
		if !containsN(p.Value, "nsxTEST") {
			t.Fatalf("probe %q missing canary", p.Name)
		}
	}
	if !containsN(probes[0].Value, "<svg onload=alert('nsxTEST')") {
		t.Fatalf("tag-break probe lost its executable core: %q", probes[0].Value)
	}
}

func containsN(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestNewCanaryUniqueness(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		c := NewCanary()
		if len(c) < len(canaryPrefix)+10 {
			t.Fatalf("canary %q too short", c)
		}
		if seen[c] {
			t.Fatalf("duplicate canary %q across %d iterations", c, i+1)
		}
		seen[c] = true
	}
}
