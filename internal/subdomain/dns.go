package subdomain

import (
	"context"
	"net"
)

// DNSResolver is the production Resolver: it asks the system resolver for a
// name's addresses. LookupHost follows CNAMEs, so an alias to a real host still
// counts as "live". A lookup that returns nothing — NXDOMAIN or an empty answer —
// is reported as a nil slice, which the corroboration logic treats as "no
// independent DNS evidence"; a hard resolver failure returns a non-nil error so
// wildcard detection can tell the difference and abort rather than trust noise.
type DNSResolver struct {
	R *net.Resolver
}

// NewDNSResolver builds a Resolver over the default system resolver.
func NewDNSResolver() *DNSResolver { return &DNSResolver{R: net.DefaultResolver} }

// Resolve implements Resolver.
func (d *DNSResolver) Resolve(ctx context.Context, host string) ([]string, error) {
	r := d.R
	if r == nil {
		r = net.DefaultResolver
	}
	addrs, err := r.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	return addrs, nil
}
