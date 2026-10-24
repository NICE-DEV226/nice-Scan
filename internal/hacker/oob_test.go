package hacker

import (
	"net"
	"strings"
	"testing"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
)

// Remote target + default loopback sink: the honest state is an explicit
// "unreachable" finding — NOT a "ready" claim whose sink no remote target
// could ever hit. No listener is kept alive behind the disclosure.
func TestOOBRemoteTargetWithLoopbackSinkDiscloses(t *testing.T) {
	t.Setenv(oobBindEnv, "")
	a := NewOOBAction()
	defer a.server.Stop()

	kb := NewKnowledge("http://example.com")
	client := transport.NewClient()
	defer func() { _ = client.Close() }()

	res := a.Execute(testCtx(), "http://example.com", kb, client)

	if len(res.Findings) != 1 {
		t.Fatalf("expected the single unreachable disclosure, got %d findings", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Type != "oob_unreachable" {
		t.Fatalf("expected oob_unreachable, got %q", f.Type)
	}
	if !strings.Contains(f.Description, "NICESCAN_OOB_BIND") {
		t.Fatal("disclosure must point at the override mechanism")
	}
	if a.server.IsRunning() {
		t.Fatal("no ghost listener may stay up behind an unreachable disclosure")
	}
	if got := kb.GetScannerState(); len(got) != 0 {
		t.Fatalf("unreachable sink must not seed scanner state, got %v", got)
	}
}

// Local (loopback) target: loopback sink IS reachable — the ready path
// stays, binds loopback, and keeps the no-secret guarantee.
func TestOOBLocalTargetReadyPath(t *testing.T) {
	t.Setenv(oobBindEnv, "")
	a := NewOOBAction()
	defer a.server.Stop()

	kb := NewKnowledge("127.0.0.1")
	client := transport.NewClient()
	defer func() { _ = client.Close() }()

	res := a.Execute(testCtx(), "http://127.0.0.1:8080/", kb, client)

	if len(res.Findings) != 1 || res.Findings[0].Type != "oob_ready" {
		t.Fatalf("local target must reach the ready path, got %q", findingsOf(res))
	}
	addr := a.server.listener.Addr().String()
	if !isLoopbackAddr(addr) {
		t.Fatalf("default bind must stay loopback, got %s", addr)
	}
	if len(kb.GetSecrets()) != 0 {
		t.Errorf("OOB URL recorded as secret: %v", kb.GetSecrets())
	}
	if kb.capability("has_secret") != nil {
		t.Error("OOB URL must not flip has_secret")
	}
	if len(kb.GetScannerState()) == 0 {
		t.Error(" scanner state must carry the callback URL on the ready path")
	}
}

// Wildcard bind advertises the machine's primary non-loopback IPv4, and a
// remote target classifies as reachable with that host advertised.
func TestOOBWildcardBindAdvertisesPrimaryIPv4(t *testing.T) {
	primary, err := primaryLocalIPv4()
	if err != nil || primary == "" {
		t.Skip("no non-loopback IPv4 on this machine")
	}
	if primary == "0.0.0.0" {
		t.Skip("machine has no routable interface; wildcard advertise undefined")
	}

	t.Setenv(oobBindEnv, "0.0.0.0")
	a := NewOOBAction()
	defer a.server.Stop()

	kb := NewKnowledge("http://example.com")
	client := transport.NewClient()
	defer func() { _ = client.Close() }()

	res := a.Execute(testCtx(), "http://example.com", kb, client)

	if len(res.Findings) != 1 || res.Findings[0].Type != "oob_ready" {
		t.Fatalf("wildcard bind must keep the ready path for remote targets, got %q", findingsOf(res))
	}
	ev := res.Findings[0].Evidence
	if !strings.Contains(ev, primary) {
		t.Fatalf("advertised URL must carry the primary IPv4 %s: %q", primary, ev)
	}
	listenAddr := a.server.listener.Addr().String()
	host, _, err := net.SplitHostPort(listenAddr)
	if err != nil {
		t.Fatalf("listener addr unparseable: %v", err)
	}
	if host != "0.0.0.0" && host != "::" {
		t.Fatalf("wildcard bind must listen on 0.0.0.0, got %s", listenAddr)
	}
}

func TestOOBTargetReachabilityClassifier(t *testing.T) {
	cases := []struct {
		target, sink string
		want         bool
	}{
		{"http://example.com", "127.0.0.1", false},
		{"http://10.0.0.5/target/", "127.0.0.1", false},
		{"", "127.0.0.1", true},
		{"http://localhost:8080", "127.0.0.1", true},
		{"http://127.0.0.1:8080", "127.0.0.1", true},
		{"http://example.com", "10.0.0.7", true},
		{"http://example.com", "0.0.0.0", true},
		{"::: nosuchurl", "127.0.0.1", true},
	}
	for _, c := range cases {
		if got := oobTargetCanReach(c.target, c.sink); got != c.want {
			t.Fatalf("oobTargetCanReach(%q, %q) = %v, want %v", c.target, c.sink, got, c.want)
		}
	}
}
