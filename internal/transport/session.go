package transport

import (
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// cookieStore captures session cookies that the TARGET itself set, and
// re-attaches them for authenticated workflows (post-login crawl). The
// store is:
//   - domain-strict: a cookie captured on host H is replayed only to host H
//     (never to sibling hosts, never cross-origin through redirects);
//   - scope-aware: attaching is gated by the same credsAllowedFor() rule
//     as the operator's cookie;
//   - off by default: passive crawls stay unauthenticated. Workflows that
//     have proven a valid credential enable it explicitly
//     (Client.SetSessionCookies) for their own requests.
//
// It deliberately is NOT a browser-grade jar: no expiry pruning beyond the
// process lifetime, no sharing across targets, no Secure/HttpOnly policy
// enforcement at attach time (send-back to the 1P origin only).
type cookieStore struct {
	mu     sync.Mutex
	byHost map[string][]cookieRecord
}

type cookieRecord struct {
	name  string
	value string
	setAt time.Time
}

func newCookieStore() *cookieStore {
	return &cookieStore{byHost: make(map[string][]cookieRecord)}
}

// hostKey normalizes a host for the domain-strict map. Cookies are stored
// per exact hostname (no wildcard domains): replaying a captured session
// cookie to a parent domain would leak it to anything that domain points
// to.
func hostKey(host string) string {
	return strings.ToLower(HostDomain(host))
}

// capture records the cookies a response set. Session clearing (an
// empty-value Set-Cookie with the same name) is honored: it removes the
// stored record instead of capturing an empty value.
func (cs *cookieStore) capture(host string, cookies []*http.Cookie) {
	if cs == nil {
		return
	}
	key := hostKey(host)
	if key == "" || len(cookies) == 0 {
		return
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	for _, c := range cookies {
		if c == nil || c.Name == "" {
			continue
		}
		recs := cs.byHost[key]
		if c.Value == "" {
			// RFC: Set-Cookie with empty value deletes the cookie.
			out := recs[:0]
			for _, r := range recs {
				if r.name != c.Name {
					out = append(out, r)
				}
			}
			cs.byHost[key] = out
			continue
		}
		replaced := false
		for i := range recs {
			if recs[i].name == c.Name {
				recs[i].value = c.Value
				recs[i].setAt = time.Now()
				replaced = true
				break
			}
		}
		if !replaced {
			recs = append(recs, cookieRecord{name: c.Name, value: c.Value, setAt: time.Now()})
		}
		cs.byHost[key] = recs
	}
}

// cookieHeader renders the stored cookies of one host as a Cookie header
// value ("n1=v1; n2=v2"), deterministically ordered by name. The host may
// be a bare host or a full URL.
func (cs *cookieStore) cookieHeader(host string) string {
	if cs == nil {
		return ""
	}
	key := hostKey(host)
	if key == "" {
		return ""
	}
	cs.mu.Lock()
	recs := cs.byHost[key]
	cs.mu.Unlock()
	if len(recs) == 0 {
		return ""
	}
	names := make([]cookieRecord, len(recs))
	copy(names, recs)
	sort.Slice(names, func(i, j int) bool { return names[i].name < names[j].name })
	var parts []string
	for _, r := range names {
		parts = append(parts, r.name+"="+r.value)
	}
	return strings.Join(parts, "; ")
}
