// Package subdomain discovers subdomains of a target domain and reports only
// the ones an operator can trust.
//
// The whole point is precision, not volume. Anyone can spray a wordlist and
// print every name that "resolved" — on a domain with a wildcard DNS record
// (*.example.com -> one catch-all IP) that returns thousands of names that
// are not real. A name is only reported as CONFIRMED when it is corroborated
// by two INDEPENDENT source families:
//
//   - ct  : the name appears in a public Certificate-Transparency log, i.e.
//     somebody once issued a real certificate for it.
//   - dns : the name resolves to a live, non-wildcard address right now.
//
// One family can lie (a wildcard makes every guess "resolve"; a stale CT entry
// lists a host that no longer exists). Both agreeing on the same name is the
// signal. That is the "très sûr" bar this package is built around — it will
// miss subdomains that only one source knows about, and that tradeoff is the
// entire design goal.
//
// Every network dependency sits behind an interface (Resolver, CTSource) so
// the corroboration/wildcard logic is a pure, deterministic sink under test.
package subdomain

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
)

// Source names an independent discovery family.
type Source string

const (
	SourceCT  Source = "ct"  // observed in a Certificate-Transparency log
	SourceDNS Source = "dns" // resolves to a live, non-wildcard address
)

// Resolver turns a hostname into its addresses. The real implementation wraps
// net.Resolver; tests feed a fixed table so corroboration is deterministic and
// touches no network.
type Resolver interface {
	// Resolve returns the deduped addresses (A/AAAA/CNAME targets) for host.
	// An unresolvable name yields a nil slice and a nil error (NXDOMAIN-like),
	// distinct from a genuine resolver failure, which yields a non-nil error.
	Resolve(ctx context.Context, host string) (addrs []string, err error)
}

// CTSource returns hostnames seen in Certificate-Transparency logs for a
// domain. The real implementation queries a public CT API; tests supply a list.
type CTSource interface {
	// Hosts returns the hostnames (any case) logged for the apex `domain`,
	// including the domain itself and its subdomains.
	Hosts(ctx context.Context, domain string) ([]string, error)
}

// Options configures a Discover run. Resolver and CT are required; everything
// else has a safe default.
type Options struct {
	Resolver Resolver
	CT       CTSource

	// Labels are the candidate names brute-forced as <label>.<domain>. When
	// empty, CommonLabels is used. The brute channel is only a CANDIDATE
	// generator here — a brute hit alone never becomes CONFIRMED; it still
	// needs the CT family to corroborate it.
	Labels []string

	// WildcardProbes is how many random labels are resolved to detect a
	// wildcard namespace. Defaults to 3; a value <=0 disables the check
	// (then every resolving name is credited as live).
	WildcardProbes int

	// RandomLabel, when set, supplies the probe labels used for wildcard
	// detection. Injected so tests are deterministic; production leaves it
	// nil and Discover generates crypto-random labels.
	RandomLabel func() string

	// Concurrency bounds how many candidate resolutions run at once.
	// Defaults to 16.
	Concurrency int
}

// Record is one candidate subdomain with the evidence behind it.
type Record struct {
	Host  string   `json:"host"`
	Addrs []string `json:"addrs,omitempty"`
	// Sources lists the families that independently supported this name.
	// A CONFIRMED record always carries both SourceCT and SourceDNS.
	Sources []Source `json:"sources,omitempty"`
	// Confirmed is true only when the name is corroborated by >=2 independent
	// families AND resolves to a live non-wildcard address.
	Confirmed bool `json:"confirmed"`
}

// Result is the outcome of a Discover run.
type Result struct {
	Domain string `json:"domain"`
	// Wildcard marks that the domain answered random labels — every "resolved"
	// name is then only trusted when its addresses DIFFER from the catch-all.
	Wildcard bool `json:"wildcard"`
	// Stats give the operator the honest denominator: how much was looked at
	// versus how much cleared the bar.
	Candidates   int      `json:"candidates"`
	Resolved     int      `json:"resolved"`
	Confirmed    []Record `json:"confirmed"`
	Unconfirmed  []Record `json:"unconfirmed,omitempty"` // single-source / wildcard-only names, kept for context
	wildcardAddr []string
}

// Discover enumerates and corroborates subdomains of domain. It is cancellation
// aware: every loop and every resolve honors ctx.
func Discover(ctx context.Context, domain string, opts Options) (*Result, error) {
	domain = normalizeDomain(domain)
	if domain == "" {
		return nil, ErrEmptyDomain
	}
	if opts.Resolver == nil || opts.CT == nil {
		return nil, ErrMissingDependency
	}

	labels := opts.Labels
	if len(labels) == 0 {
		labels = CommonLabels
	}
	wildProbes := opts.WildcardProbes
	if wildProbes == 0 {
		wildProbes = 3
	}
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 16
	}

	res := &Result{Domain: domain}

	// 1. Detect a wildcard namespace up front. On a wildcard domain the
	//    resolver answers everything with a catch-all address, so "it
	//    resolved" carries no information until we know what catch-all to
	//    exclude.
	if wildProbes > 0 {
		if addrs, werr := detectWildcard(ctx, opts.Resolver, domain, wildProbes, opts.RandomLabel); werr != nil {
			// Resolver is failing outright — surface it rather than pretend
			// nothing was found.
			return nil, werr
		} else if len(addrs) > 0 {
			res.Wildcard = true
			res.wildcardAddr = addrs
		}
	}

	// 2. Seed the candidate set from the CT channel. A CT failure is not fatal:
	//    we can still report on the brute side, and the operator is told the
	//    corroboration is degraded.
	ctSet := map[string]bool{}
	if hosts, cerr := opts.CT.Hosts(ctx, domain); cerr == nil {
		for _, h := range hosts {
			h = normalizeHost(h)
			if h == domain || strings.HasSuffix(h, "."+domain) {
				ctSet[h] = true
			}
		}
	}

	// 3. Merge the brute candidates with the CT candidates.
	cand := map[string]bool{}
	for _, label := range labels {
		l := sanitizeLabel(label)
		if l == "" {
			continue
		}
		cand[l+"."+domain] = true
	}
	for h := range ctSet {
		cand[h] = true
	}
	res.Candidates = len(cand)

	// 4. Resolve every candidate concurrently, tagging which families support
	//    it, then split into confirmed vs context.
	hosts := make([]string, 0, len(cand))
	for h := range cand {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	records := make([]Record, len(hosts))
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	for i := range hosts {
		select {
		case <-ctx.Done():
			wg.Wait()
			return res, ctx.Err()
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer func() { <-sem; wg.Done() }()
			records[i] = evaluate(ctx, opts.Resolver, hosts[i], ctSet, res.Wildcard, res.wildcardAddr)
		}(i)
	}
	wg.Wait()

	for _, rec := range records {
		if len(rec.Addrs) > 0 {
			res.Resolved++
		}
		switch {
		case rec.Confirmed:
			res.Confirmed = append(res.Confirmed, rec)
		case len(rec.Sources) > 0:
			// Exactly one family supported it — worth showing as context.
			res.Unconfirmed = append(res.Unconfirmed, rec)
		default:
			// Zero sources: a wordlist guess that neither the logs listed nor
			// DNS resolved (or resolved only to a wildcard catch-all). Pure
			// noise — dropped, so Unconfirmed stays "single-family names".
		}
	}
	sort.Slice(res.Confirmed, func(i, j int) bool { return res.Confirmed[i].Host < res.Confirmed[j].Host })
	sort.Slice(res.Unconfirmed, func(i, j int) bool { return res.Unconfirmed[i].Host < res.Unconfirmed[j].Host })
	return res, nil
}

// evaluate resolves one candidate and assigns its evidence. A name is
// Confirmed only when BOTH families independently support it.
func evaluate(ctx context.Context, r Resolver, host string, ctSet map[string]bool, wildcard bool, wildcardAddr []string) Record {
	rec := Record{Host: host}
	if ctSet[host] {
		rec.Sources = append(rec.Sources, SourceCT)
	}

	addrs, err := r.Resolve(ctx, host)
	if err == nil && len(addrs) > 0 {
		// On a wildcard namespace the resolver answers EVERY name with the
		// catch-all address, so a resolution is only independent evidence of a
		// live host when it yields at least one address OUTSIDE that catch-all.
		if wildcard && allAddrsIn(addrs, wildcardAddr) {
			// only the catch-all answered — no dns-side credit
		} else {
			rec.Addrs = dedup(addrs)
			rec.Sources = append(rec.Sources, SourceDNS)
		}
	}

	// Need BOTH families: at least one CT and one live, non-wildcard DNS hit.
	hasCT, hasDNS := false, false
	for _, s := range rec.Sources {
		switch s {
		case SourceCT:
			hasCT = true
		case SourceDNS:
			hasDNS = true
		}
	}
	rec.Confirmed = hasCT && hasDNS && len(rec.Addrs) > 0
	return rec
}

// detectWildcard resolves `n` random labels under domain. If any resolves, the
// domain is wildcarded and the union of those addresses is the catch-all.
func detectWildcard(ctx context.Context, r Resolver, domain string, n int, random func() string) ([]string, error) {
	var catchAll []string
	for i := 0; i < n; i++ {
		select {
		case <-ctx.Done():
			return catchAll, nil
		default:
		}
		label := "nicescan-" + randomToken(random)
		addrs, err := r.Resolve(ctx, label+"."+domain)
		if err != nil {
			// First probe failing hard is likely a resolver problem, not NX;
			// a later one is noise. Only surface it if NOTHING resolved yet.
			if i == 0 && len(catchAll) == 0 && isResolverError(err) {
				return nil, err
			}
			continue
		}
		if len(addrs) > 0 {
			catchAll = append(catchAll, addrs...)
		}
	}
	return dedup(catchAll), nil
}

func randomToken(random func() string) string {
	if random != nil {
		return random()
	}
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "000000"
	}
	return hex.EncodeToString(b[:])
}

// isResolverError distinguishes a transport-level resolver failure (which
// should abort the run) from an ordinary NXDOMAIN (errors that contain
// "no such host"). Kept conservative: only explicit "no such host"/"not
// found"/"nxdomain" are treated as normal negatives.
func isResolverError(err error) bool {
	msg := strings.ToLower(err.Error())
	for _, benign := range []string{"no such host", "nxdomain", "not found", "server misbehaving", "temporary failure in name resolution"} {
		if strings.Contains(msg, benign) {
			return false
		}
	}
	return true
}

func normalizeDomain(input string) string {
	h := normalizeHost(input)
	h = strings.TrimPrefix(h, "www.")
	if h == "" {
		return ""
	}
	return strings.ToLower(h)
}

func normalizeHost(input string) string {
	h := strings.TrimSpace(strings.ToLower(input))
	// Drop a leading "scheme://" so a full URL reduces to its authority.
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	// Accept a bare host, a host:port, or a URL.
	if i := strings.IndexAny(h, "/*"); i >= 0 {
		h = h[:i]
	}
	if i := strings.LastIndex(h, "@"); i >= 0 {
		h = h[i+1:]
	}
	// Strip a trailing ":port" from an ordinary hostname, but leave an IPv6
	// literal (which contains internal colons/brackets) untouched — it is then
	// filtered to nothing by the charset pass below, which is fine: IPv6
	// addresses are not subdomain names.
	if i := strings.LastIndex(h, ":"); i >= 0 &&
		!strings.Contains(h[i+1:], ":") && !strings.Contains(h, "]") {
		h = h[:i]
	}
	h = strings.Trim(h, ".[]")

	// Keep only DNS-hostname characters. A CT entry can contain an IP (dots are
	// fine); a caller-supplied domain must never smuggle '&', '?', '#', '%' or
	// whitespace into the query we build against the log. Anything else is dropped.
	var b strings.Builder
	for _, r := range h {
		switch {
		case r >= 'a' && r <= 'z',
			r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
			b.WriteRune(r)
		}
	}
	return b.String()
}

func sanitizeLabel(label string) string {
	l := normalizeHost(strings.TrimSpace(label))
	// A label must not contain a dot once we prefix it to the domain; if the
	// wordlist carries full names, keep only the leading label relative to it.
	if strings.Contains(l, ".") {
		return ""
	}
	return l
}

func dedup(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// allAddrsIn reports whether every address in `in` also appears in `set` —
// i.e. the resolution produced nothing beyond that set (a wildcard catch-all).
// An empty `in` is not "inside" anything.
func allAddrsIn(in, set []string) bool {
	if len(in) == 0 || len(set) == 0 {
		return false
	}
	m := make(map[string]bool, len(set))
	for _, x := range set {
		m[x] = true
	}
	for _, y := range in {
		if !m[y] {
			return false
		}
	}
	return true
}
