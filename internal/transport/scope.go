package transport

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// This file is the request boundary, not the credential boundary.
//
// credScope (client.go) answers "may the operator's cookie ride on this
// request?" and deliberately fails open when no scope was configured,
// because interactive sessions construct a client before a target is known.
// That is the correct rule for credentials and a catastrophic one for
// destinations: a caller that is not a human reading the command line — a
// model, a script, anything driving this tool — must not be able to aim the
// scanner wherever it wants. Here the default is refusal.

// extraBlocked are the ranges net.IP's predicates do not cover and that must
// never be dialled: CGNAT (carrier-side, routinely proxied to internal
// infrastructure), the "this host" class and the benchmarking range.
// Loopback, RFC1918, link-local (which is where 169.254.169.254 lives),
// unique-local and v4-in-6 forms are handled by the predicates directly.
var extraBlocked = mustCIDRs([]string{
	"100.64.0.0/10",
	"0.0.0.0/8",
	"198.18.0.0/15",
})

func mustCIDRs(nets []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(nets))
	for _, n := range nets {
		_, block, err := net.ParseCIDR(n)
		if err != nil {
			slog.Error("internal error: bad blocked CIDR, ignored", "cidr", n, "error", err)
			continue
		}
		out = append(out, block)
	}
	return out
}

// ipBlocked reports whether an address is not a globally routable destination.
func ipBlocked(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	for _, block := range extraBlocked {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// WithTargetScope installs the hard allow-list of destinations and turns
// scope enforcement on: every request must be to one of these hosts (or a
// subdomain of one), and a redirect that leaves them aborts the exchange
// instead of merely shedding credentials.
//
// It is also what fills credScope when nothing else did, so the two lists
// cannot drift apart into "requests may go here but secrets go everywhere".
// An empty list is deliberately inert: enforcement is "a scope was
// configured", which keeps the pre-target constructors (interactive shell,
// unit callers) working exactly as before.
func WithTargetScope(hosts ...string) ClientOption {
	return func(o *clientOptions) {
		scope := normalizeScope(hosts)
		o.targetScope = scope
		o.enforceScope = len(scope) > 0
		if len(o.credScope) == 0 {
			o.credScope = append([]string(nil), scope...)
		}
	}
}

// WithPrivateNetworkAllowed controls the dial-time guard. Default is allowed
// (true), which is today's behavior: a scanner legitimately targets its own
// dev server, so refusing loopback has to be opted into. A machine-facing
// caller should opt in.
//
// With it off, the guard resolves the name itself and dials the resolved
// literal, so the address that was checked is the address that was
// contacted: a second lookup by the stdlib would be a DNS-rebinding window.
func WithPrivateNetworkAllowed(b bool) ClientOption {
	return func(o *clientOptions) { o.allowPrivate = b }
}

// withResolver lets the dial guard be tested against a fixed address table
// without any network. Unexported on purpose: production code never swaps
// the resolver.
func withResolver(r *net.Resolver) ClientOption {
	return func(o *clientOptions) { o.resolver = r }
}

func (c *Client) scopeEnforced() bool {
	c.opts.mu.Lock()
	defer c.opts.mu.Unlock()
	return c.opts.enforceScope
}

// scopeAllows is the pure host rule for the allow-list. A scope entry
// covers the host itself and its subdomains, and the subdomain test requires
// the dot boundary, so "example.com" never admits "evilexample.com".
// An unparseable URL is refused: the boundary fails closed.
func (c *Client) scopeAllows(rawURL string) bool {
	c.opts.mu.Lock()
	scope := c.opts.targetScope
	c.opts.mu.Unlock()

	host := HostDomain(rawURL)
	if host == "" {
		return false
	}
	for _, s := range scope {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

// admit is the single gate every outbound request passes through. Do calls
// it, and DoBatch's workers call Do, so one check covers both entry points
// whatever the caller asks for.
func (c *Client) admit(rawURL string) error {
	if !c.scopeEnforced() {
		return nil
	}
	if c.scopeAllows(rawURL) {
		return nil
	}
	return fmt.Errorf("%w: %s", types.ErrOutOfScope, HostDomain(rawURL))
}

// envProxyActive reports whether HTTP_PROXY / HTTPS_PROXY (or their
// lowercase forms) would route traffic at all. The question is asked of the
// stdlib's own rule rather than a private re-read of the environment, so the
// guard and the transport cannot disagree about who is dialling. A NO_PROXY
// match for some hosts makes this answer conservative in one direction only:
// it can report a proxy where the real request would go direct, which turns
// off a guard with a warning rather than leaving one that lies.
func envProxyActive() bool {
	probe := &http.Request{URL: &url.URL{Scheme: "https", Host: "example.com"}}
	proxyURL, err := http.ProxyFromEnvironment(probe)
	return err == nil && proxyURL != nil
}

// routeAddresses turns what a name resolved to into the literals that may be
// dialled. Vetting the answers and then dialling exactly those answers is
// what closes the gap between "the hostname looked public" and "the
// connection went internal"; re-resolving afterwards would reopen it.
func routeAddresses(host, port string, ips []net.IPAddr) ([]string, error) {
	dialable := make([]string, 0, len(ips))
	blocked := make([]string, 0, len(ips))
	for _, ia := range ips {
		if ipBlocked(ia.IP) {
			blocked = append(blocked, ia.IP.String())
			continue
		}
		dialable = append(dialable, net.JoinHostPort(ia.IP.String(), port))
	}
	switch {
	case len(dialable) > 0:
		return dialable, nil
	case len(blocked) > 0:
		return nil, fmt.Errorf("%w: %s resolves to %s", types.ErrInternalTarget, host, strings.Join(blocked, ", "))
	default:
		return nil, fmt.Errorf("guard: no address for %s", host)
	}
}

// guardedDialer resolves then dials, refusing any answer that is not a
// globally routable destination.
func guardedDialer(res *net.Resolver, d *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("guard: bad address %q: %w", addr, err)
		}

		// An IP literal short-circuits inside net: no lookup is performed.
		ips, err := res.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("guard: resolve %s: %w", host, err)
		}

		addrs, err := routeAddresses(host, port, ips)
		if err != nil {
			return nil, err
		}

		var lastErr error
		for _, a := range addrs {
			conn, err := d.DialContext(ctx, network, a)
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
}
