package subdomain

import (
	"context"
	"errors"
	"testing"
)

// fakeResolver answers from a fixed table so corroboration is deterministic and
// touches no network. An absent host yields (nil, nil) — an NXDOMAIN-like
// negative, distinct from a genuine resolver failure.
type fakeResolver struct {
	table map[string][]string
	err   error // when non-nil, every lookup fails with it
}

func (f fakeResolver) Resolve(_ context.Context, host string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	addrs, ok := f.table[host]
	if !ok {
		return nil, nil
	}
	return addrs, nil
}

// fakeCT returns a fixed hostname list for any domain.
type fakeCT struct {
	hosts []string
	err   error
}

func (f fakeCT) Hosts(_ context.Context, _ string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.hosts, nil
}

func names(recs []Record) map[string]bool {
	m := map[string]bool{}
	for _, r := range recs {
		m[r.Host] = true
	}
	return m
}

// A name is CONFIRMED only when BOTH families support it. One family alone —
// a stale CT entry that no longer resolves, or a live name the logs never saw —
// must land in Unconfirmed.
func TestDiscoverRequiresBothSources(t *testing.T) {
	res := fakeResolver{table: map[string][]string{
		"www.example.com": {"93.184.216.34"}, // CT + DNS -> confirmed
		"api.example.com": nil,               // CT only, stale -> unconfirmed
		"db.example.com":  {"10.0.0.5"},      // DNS only, never in CT -> unconfirmed
	}}
	ct := fakeCT{hosts: []string{"www.example.com", "api.example.com"}}

	got, err := Discover(context.Background(), "example.com", Options{
		Resolver:       res,
		CT:             ct,
		Labels:         []string{"db", "ghost"}, // ghost: no DNS, no CT -> dropped entirely
		WildcardProbes: -1,                      // disable; resolver has no catch-all to exclude
	})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(got.Confirmed) != 1 || got.Confirmed[0].Host != "www.example.com" {
		t.Fatalf("confirmed = %v, want only www.example.com", got.Confirmed)
	}
	if !got.Confirmed[0].Confirmed {
		t.Error("confirmed record must carry Confirmed=true")
	}
	unc := names(got.Unconfirmed)
	if !unc["api.example.com"] || !unc["db.example.com"] {
		t.Errorf("unconfirmed = %v, want api (stale CT) and db (DNS-only)", got.Unconfirmed)
	}
	// A zero-source wordlist guess is noise: it must appear in neither list.
	if unc["ghost.example.com"] {
		t.Error("ghost.example.com (no source) must be dropped, not kept as unconfirmed")
	}
	if names(got.Confirmed)["ghost.example.com"] {
		t.Error("ghost.example.com must never be confirmed")
	}
}

// On a wildcard namespace the resolver answers EVERY name with the catch-all
// address. A candidate whose only address IS that catch-all gets no DNS credit
// and so never clears the two-family bar, even when CT lists it.
func TestDiscoverWildcardCatchAllNotCredited(t *testing.T) {
	res := fakeResolver{table: map[string][]string{
		"nicescan-fixed.example.com": {"1.2.3.4"}, // wildcard probe -> catch-all
		"real.example.com":           {"5.6.7.8"}, // distinct live IP -> DNS credit
		"fake.example.com":           {"1.2.3.4"}, // == catch-all -> no DNS credit
	}}
	ct := fakeCT{hosts: []string{"real.example.com", "fake.example.com"}}

	got, err := Discover(context.Background(), "example.com", Options{
		Resolver:       res,
		CT:             ct,
		Labels:         []string{"real", "fake"},
		WildcardProbes: 3,
		RandomLabel:    func() string { return "fixed" },
	})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if !got.Wildcard {
		t.Fatal("wildcard must be detected from the catch-all probe")
	}
	if len(got.Confirmed) != 1 || got.Confirmed[0].Host != "real.example.com" {
		t.Fatalf("confirmed = %v, want only real.example.com", got.Confirmed)
	}
	if !names(got.Unconfirmed)["fake.example.com"] {
		t.Error("wildcard-only fake.example.com must be unconfirmed")
	}
}

// A cancelled context must abort the run with ctx.Err(), not a silent empty ok.
func TestDiscoverHonoursContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res := fakeResolver{table: map[string][]string{"a.example.com": {"1.1.1.1"}}}
	got, err := Discover(ctx, "example.com", Options{
		Resolver:       res,
		CT:             fakeCT{hosts: []string{"a.example.com"}},
		WildcardProbes: -1,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if got == nil {
		t.Fatal("result must still be returned alongside the cancellation error")
	}
}

// A hard resolver failure during wildcard detection (not an NXDOMAIN) must be
// surfaced rather than mistaken for "no wildcard, nothing found".
func TestDiscoverSurfacesResolverFailure(t *testing.T) {
	boom := errors.New("dns: connection refused")
	res := fakeResolver{err: boom}
	_, err := Discover(context.Background(), "example.com", Options{
		Resolver:       res,
		CT:             fakeCT{},
		WildcardProbes: 3,
		RandomLabel:    func() string { return "p" },
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the resolver failure %v", err, boom)
	}
}

func TestDiscoverValidatesInputs(t *testing.T) {
	if _, err := Discover(context.Background(), "", Options{Resolver: fakeResolver{}, CT: fakeCT{}}); !errors.Is(err, ErrEmptyDomain) {
		t.Errorf("empty domain err = %v, want ErrEmptyDomain", err)
	}
	if _, err := Discover(context.Background(), "example.com", Options{}); !errors.Is(err, ErrMissingDependency) {
		t.Errorf("missing deps err = %v, want ErrMissingDependency", err)
	}
}

// A CT failure is not fatal: the brute side is still reported, just degraded
// (nothing can be confirmed without the CT family).
func TestDiscoverDegradesOnCTFailure(t *testing.T) {
	res := fakeResolver{table: map[string][]string{"www.example.com": {"93.184.216.34"}}}
	ct := fakeCT{err: errors.New("ct: 503")}

	got, err := Discover(context.Background(), "example.com", Options{
		Resolver:       res,
		CT:             ct,
		Labels:         []string{"www"},
		WildcardProbes: -1,
	})
	if err != nil {
		t.Fatalf("Discover must not fail on a CT error: %v", err)
	}
	if len(got.Confirmed) != 0 {
		t.Errorf("confirmed = %v, want none without the CT family", got.Confirmed)
	}
	if !names(got.Unconfirmed)["www.example.com"] {
		t.Error("DNS-live www.example.com should still appear (unconfirmed) despite CT failure")
	}
}

func TestNormalizeDomain(t *testing.T) {
	cases := map[string]string{
		"https://WWW.Example.com:443/path": "example.com",
		"example.com.":                     "example.com",
		"www.example.com":                  "example.com",
		"user@sub.example.com":             "sub.example.com",
		"examp&le.com":                     "example.com", // '&' smuggler dropped
		"":                                 "",
	}
	for in, want := range cases {
		if got := normalizeDomain(in); got != want {
			t.Errorf("normalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSanitizeLabel(t *testing.T) {
	if got := sanitizeLabel("www"); got != "www" {
		t.Errorf("sanitizeLabel(www) = %q", got)
	}
	if got := sanitizeLabel("sub.domain"); got != "" {
		t.Errorf("dotted label must be rejected, got %q", got)
	}
	if got := sanitizeLabel("bad&"); got != "bad" {
		t.Errorf("sanitizeLabel(bad&) = %q, want bad", got)
	}
}

func TestAllAddrsIn(t *testing.T) {
	if !allAddrsIn([]string{"1.2.3.4"}, []string{"1.2.3.4", "5.6.7.8"}) {
		t.Error("single addr inside set should be true")
	}
	if allAddrsIn([]string{"9.9.9.9"}, []string{"1.2.3.4"}) {
		t.Error("addr outside set should be false")
	}
	if allAddrsIn(nil, []string{"1.2.3.4"}) {
		t.Error("empty input is not inside anything")
	}
	if allAddrsIn([]string{"1.2.3.4"}, nil) {
		t.Error("empty set cannot contain anything")
	}
}
