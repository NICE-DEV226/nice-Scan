package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

const (
	DefaultMaxBodySize = 10 * 1024 * 1024
	DefaultTimeout     = 15 * time.Second
	DefaultRetries     = 2
	DefaultConcurrency = 64
)

type ClientOption func(*clientOptions)

type clientOptions struct {
	// mu guards fields set at runtime after construction (credScope).
	mu              sync.Mutex
	timeout         time.Duration
	maxBodySize     int64
	retries         int
	retryWaitMin    time.Duration
	retryWaitMax    time.Duration
	followRedirects bool
	maxRedirects    int
	proxy           string
	headers         map[string]string
	cookie          string
	// credScope restricts where operator credentials (cookie + configured
	// headers) are attached. When set, requests to hosts outside the scope
	// never carry them. Empty means "no scoping requested" (attach
	// everywhere) — commands that know their target must always configure
	// it.
	credScope      []string
	// sessionCookies enables capture/attach of target-issued cookies for
	// authenticated workflows (off by default; runtime toggle only).
	sessionCookies bool
	rateLimit      int
	verbose         bool
	dialTimeout     time.Duration
	tlsTimeout      time.Duration
	keepAlive       time.Duration
	maxIdleConns    int
	maxIdlePerHost  int
	idleConnTimeout time.Duration
}

func defaultOptions() *clientOptions {
	return &clientOptions{
		timeout:         DefaultTimeout,
		maxBodySize:     DefaultMaxBodySize,
		retries:         DefaultRetries,
		retryWaitMin:    500 * time.Millisecond,
		retryWaitMax:    5 * time.Second,
		followRedirects: true,
		maxRedirects:    5,
		rateLimit:       0,
		dialTimeout:     10 * time.Second,
		tlsTimeout:      10 * time.Second,
		keepAlive:       30 * time.Second,
		maxIdleConns:    200,
		maxIdlePerHost:  20,
		idleConnTimeout: 90 * time.Second,
	}
}

func WithTimeout(d time.Duration) ClientOption {
	return func(o *clientOptions) { o.timeout = d }
}

func WithRetries(n int) ClientOption {
	return func(o *clientOptions) { o.retries = n }
}

func WithRetryWait(min, max time.Duration) ClientOption {
	return func(o *clientOptions) { o.retryWaitMin = min; o.retryWaitMax = max }
}

func WithFollowRedirects(b bool) ClientOption {
	return func(o *clientOptions) { o.followRedirects = b }
}

func WithMaxRedirects(n int) ClientOption {
	return func(o *clientOptions) { o.maxRedirects = n }
}

func WithProxy(p string) ClientOption {
	return func(o *clientOptions) { o.proxy = p }
}

func WithHeaders(h map[string]string) ClientOption {
	return func(o *clientOptions) { o.headers = h }
}

// SetCredScope constrains request hosts allowed to receive the operator's
// credentials at runtime (used by interactive sessions whose targets are
// typed per command). Thread-safe.
func (c *Client) SetCredScope(domains ...string) {
	c.opts.mu.Lock()
	defer c.opts.mu.Unlock()
	c.opts.credScope = normalizeScope(domains)
}

// credsAllowedFor reports whether a request URL may carry the operator's
// cookie/header credentials. With no scope configured credentials attach as
// before (legacy behaviour for interactive sessions built before a target is
// known); with a scope, out-of-scope hosts never receive them. Per-request
// headers set by scanner actions (Content-Type etc.) are unaffected.
func (c *Client) credsAllowedFor(rawURL string) bool {
	c.opts.mu.Lock()
	cookie := c.opts.cookie
	headersCount := len(c.opts.headers)
	c.opts.mu.Unlock()

	hasCreds := cookie != "" || headersCount > 0
	if !hasCreds {
		return false
	}
	return c.hostInScope(rawURL)
}

// hostInScope is the pure scope rule, without the "operator has
// credentials at all" clause: target-issued session cookies use it with
// that clause removed (they exist even on clients with no operator
// credentials configured).
func (c *Client) hostInScope(rawURL string) bool {
	c.opts.mu.Lock()
	scope := c.opts.credScope
	c.opts.mu.Unlock()
	if len(scope) == 0 {
		return true
	}
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

func WithCookie(c string) ClientOption {
	return func(o *clientOptions) { o.cookie = c }
}

// WithCredScope constrains the request hosts that may receive the operator's
// credentials (cookie + configured headers). Domains are registrable hosts:
// the scope matches the host itself and any of its subdomains.
func WithCredScope(domains []string) ClientOption {
	return func(o *clientOptions) { o.credScope = normalizeScope(domains) }
}

func normalizeScope(domains []string) []string {
	out := make([]string, 0, len(domains))
	for _, d := range domains {
		d = strings.ToLower(HostDomain(d))
		if d != "" {
			out = append(out, d)
		}
	}
	return out
}

// HostDomain extracts a bare, lowercase host (port stripped) from either a
// full URL or a bare host string. It is the matching unit for credential
// scoping.
func HostDomain(u string) string {
	if u == "" {
		return ""
	}
	if !strings.Contains(u, "://") {
		u = "http://" + u
	}
	parsed, err := url.Parse(u)
	if err != nil {
		return ""
	}
	host := parsed.Hostname()
	if h, _, err2 := net.SplitHostPort(host); err2 == nil {
		host = h
	}
	return strings.ToLower(host)
}

// isSameOriginURL compares scheme+host+port exactly — the strict origin
// identity net/http's redirect policy is supposed to enforce. This toolchain
// keeps Cookie headers across redirects sharing only a hostname, so the
// client enforces the strict rule itself.
func isSameOriginURL(a, b *url.URL) bool {
	return a.Scheme == b.Scheme && a.Host == b.Host
}

// hopsCtxKey carries the per-request redirect-hop buffer.
type hopsCtxKey struct{}

func WithRateLimit(r int) ClientOption {
	return func(o *clientOptions) { o.rateLimit = r }
}

func WithVerbose(b bool) ClientOption {
	return func(o *clientOptions) { o.verbose = b }
}

type Client struct {
	opts    *clientOptions
	http    *http.Client
	rl      *RateLimiter
	sess    *cookieStore
	stats   RequestStats
	statsMu sync.Mutex
}

type RequestStats struct {
	Total       int64
	Success     int64
	Failed      int64
	Retried     int64
	RateLimited int64
	TotalBytes  int64
	TotalTime   time.Duration
}

// SetSessionCookies enables (or disables) capture and re-attach of cookies
// the target itself issues. Only workflows whose credential was verified
// (e.g. a login confirmed by a differential verdict) enable it, for their
// own requests; passive scanning stays unauthenticated so Set-Cookie
// banners cannot silently grow a scanner session.
func (c *Client) SetSessionCookies(enabled bool) {
	c.opts.mu.Lock()
	c.opts.sessionCookies = enabled
	c.opts.mu.Unlock()
}

func (c *Client) sessionCookiesEnabled() bool {
	c.opts.mu.Lock()
	v := c.opts.sessionCookies
	c.opts.mu.Unlock()
	return v
}

// captureStoreFromResponse records Set-Cookie values of one response into
// the session store, bounded to the session mode. hi = the URL the response
// belongs to (the host that issued the cookies).
func (c *Client) captureStoreFromResponse(u *url.URL, resp *http.Response) {
	if resp == nil || u == nil || !c.sessionCookiesEnabled() {
		return
	}
	c.sess.capture(u.Host, resp.Cookies())
}

func NewClient(opts ...ClientOption) *Client {
	o := defaultOptions()
	for _, opt := range opts {
		opt(o)
	}

	// The Client exists before the http.Client: the redirect callback
	// captures per-hop Set-Cookie values from redirect responses
	// (req.Response), which stdlib never surfaces to the caller.
	c := &Client{
		opts: o,
		sess: newCookieStore(),
	}

	tr := newTransport(o)

	httpClient := &http.Client{
		Transport: tr,
		Timeout:   0, // We manage timeouts per-request via context
	}

	if !o.followRedirects {
		httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else {
		// The stdlib's redirect header stripping is a thin guarantee (and on
		// this toolchain it keeps Cookie headers across redirects that match
		// the hostname ignoring ports). OPSEC-enforce it here: any Cookie
		// header riding the request — the operator's credentials or target-
		// issued session cookies — survives a redirect hop only when the
		// destination is covered by the same allow rules as the initial
		// request; every other hop is stripped down. Redirect responses are
		// also the only place interim Set-Cookie hops can be captured for
		// the session store.
		httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= o.maxRedirects {
				return fmt.Errorf("max redirects exceeded (%d)", o.maxRedirects)
			}

			// Interim hop capture: this request was built from a 3xx
			// response stdlib handled internally. Its Set-Cookie values get
			// attached to the same store as the final hop's, and the
			// redirect chain is recorded for verdicts that need it.
			if req.Response != nil && req.Response.Request != nil {
				c.captureStoreFromResponse(req.Response.Request.URL, req.Response)
				if buf, ok := req.Context().Value(hopsCtxKey{}).(*[]types.RedirectHop); ok && buf != nil {
					*buf = append(*buf, types.RedirectHop{
						Status:   req.Response.StatusCode,
						URL:      req.Response.Request.URL.String(),
						Location: req.Response.Header.Get("Location"),
					})
				}
			}

			if len(via) == 0 {
				return nil
			}

			origin := via[0].URL.String()
			dest := req.URL.String()
			if HostDomain(origin) == "" || HostDomain(dest) == "" {
				return fmt.Errorf("unresolvable redirect host")
			}

			o.mu.Lock()
			scope := append([]string(nil), o.credScope...)
			o.mu.Unlock()

			allowed := false
			if len(scope) > 0 {
				hostname := HostDomain(dest)
				for _, s := range scope {
					if hostname == s || strings.HasSuffix(hostname, "."+s) {
						allowed = true
						break
					}
				}
			} else {
				// No scope configured: cookies stay on the exact origin
				// (scheme+host+port) they were issued for — mirroring the
				// stdlib's domain-sensitive redirect rule, which this
				// toolchain does not honor for cookies.
				allowed = isSameOriginURL(via[0].URL, req.URL)
			}

			// Belt and suspenders: whatever cookie reached this hop, wrong
			// destination means no cookie. This now also covers the session
			// store: an authenticated redirect bounce (login open redirect)
			// must not replay the captured session out of the target origin.
			if !allowed && req.Header.Get("Cookie") != "" {
				req.Header.Del("Cookie")
			}

			// Operator credentials: assert exactly what is allowed.
			if o.cookie != "" {
				if allowed {
					req.Header.Set("Cookie", o.cookie)
				} else {
					req.Header.Del("Authorization")
					for k := range o.headers {
						req.Header.Del(k)
					}
				}
			}
			if allowed {
				for k, v := range o.headers {
					req.Header.Set(k, v)
				}
			}
			return nil
		}
	}
	c.http = httpClient

	if o.rateLimit > 0 {
		c.rl = NewRateLimiter(o.rateLimit)
	}

	return c
}

func newTransport(o *clientOptions) *http.Transport {
	dialer := &net.Dialer{
		Timeout:   o.dialTimeout,
		KeepAlive: o.keepAlive,
	}

	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          o.maxIdleConns,
		MaxIdleConnsPerHost:   o.maxIdlePerHost,
		MaxConnsPerHost:       0,
		IdleConnTimeout:       o.idleConnTimeout,
		TLSHandshakeTimeout:   o.tlsTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		ReadBufferSize:        32 * 1024,
		WriteBufferSize:       32 * 1024,
		DisableCompression:    false,
	}

	if o.proxy != "" {
		if proxyURL, err := url.Parse(o.proxy); err == nil {
			tr.Proxy = http.ProxyURL(proxyURL)
		} else {
			slog.Warn("invalid proxy URL, ignoring", "proxy", o.proxy, "error", err)
		}
	}

	return tr
}

func (c *Client) Do(ctx context.Context, req *types.Request) (*types.Response, error) {
	if c.rl != nil {
		// Count only requests the limiter actually delayed, not every
		// request sent while the limiter exists.
		if c.rl.Wait(ctx) {
			c.statsMu.Lock()
			c.stats.RateLimited++
			c.statsMu.Unlock()
		}
	}

	start := time.Now()
	resp, err := doWithRetries(ctx, c, req)
	duration := time.Since(start)

	c.statsMu.Lock()
	c.stats.Total++
	c.stats.TotalTime += duration
	if err != nil {
		c.stats.Failed++
	} else {
		c.stats.Success++
	}
	c.statsMu.Unlock()

	if err != nil {
		return nil, err
	}

	// resp.Duration is the wire-attempt time set inside execute(); keep it
	// (time oracles gate on it). duration here additionally covers rate-
	// limiter waits and only fills in when nothing else could measure.
	if resp != nil && resp.Duration == 0 {
		resp.Duration = duration
	}

	return resp, nil
}

// idempotentMethod reports whether repeating a request can never cause a
// second state change at the target: the retry loop must never resend a
// POST Spray of credentials or a state-changing request on a 500/429 or a
// timeout — the first attempt may have been processed, and a resend
// double-submits the payload (account lockouts, double registrations).
func idempotentMethod(method string) bool {
	switch strings.ToUpper(method) {
	case "GET", "HEAD", "OPTIONS", "TRACE":
		return true
	}
	return false
}

func doWithRetries(ctx context.Context, c *Client, req *types.Request) (*types.Response, error) {
	var lastErr error
	var lastResp *types.Response

	for attempt := 0; attempt <= c.opts.retries; attempt++ {
		if attempt > 0 {
			c.statsMu.Lock()
			c.stats.Retried++
			c.statsMu.Unlock()

			wait := backoffDuration(attempt, c.opts.retryWaitMin, c.opts.retryWaitMax)
			select {
			case <-ctx.Done():
				return lastResp, ctx.Err()
			case <-time.After(wait):
			}
		}

		resp, err := c.execute(ctx, req)
		lastErr = err
		lastResp = resp

		// Non-idempotent requests get exactly one attempt, whatever the
		// outcome: a timeout on a POST means the server may already have
		// processed it, and a 500/429 does not undo that. Resending would
		// double-submit credentials, registrations, uploads.
		if !idempotentMethod(req.Method) {
			if err != nil {
				return nil, err
			}
			return resp, nil
		}

		// Idempotent: retry real retryable conditions only.
		if err == nil && !isRetryable(nil, resp) {
			return resp, nil
		}
		if err != nil && !isRetryable(err, resp) {
			return resp, err
		}
		// else: retryable — loop (backoff happens at iteration start).
	}

	if lastErr != nil {
		return nil, fmt.Errorf("%w after %d attempts: %w", types.ErrMaxRetries, c.opts.retries+1, lastErr)
	}
	return lastResp, nil
}

func (c *Client) execute(ctx context.Context, req *types.Request) (*types.Response, error) {
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	// Per-request redirect-hop buffer: seeded into the request context so
	// the CheckRedirect callback (which sees every interim 3xx the stdlib
	// handles) can record the chain the caller otherwise never receives.
	var hops []types.RedirectHop
	httpReq = httpReq.WithContext(context.WithValue(httpReq.Context(), hopsCtxKey{}, &hops))

	if len(req.Body) > 0 {
		httpReq.Body = io.NopCloser(bytes.NewReader(req.Body))
		httpReq.ContentLength = int64(len(req.Body))
	}

	// Operator credentials ride only hosts covered by credScope (cookie #
	// custom headers — both carry secrets the operator entered for a known
	// target; legacy behaviour attaches everywhere when no scope is set).
	// Target-issued session cookies ride only when session mode is enabled.
	cookieAllowed := c.credsAllowedFor(req.URL)
	if cookieAllowed {
		if c.opts.cookie != "" {
			httpReq.Header.Set("Cookie", c.opts.cookie)
		}
		for k, v := range c.opts.headers {
			httpReq.Header.Set(k, v)
		}
	}
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}
	if c.sessionCookiesEnabled() && c.hostInScope(req.URL) {
		if sessionHdr := c.sess.cookieHeader(req.URL); sessionHdr != "" {
			existing := httpReq.Header.Get("Cookie")
			if existing == "" {
				httpReq.Header.Set("Cookie", sessionHdr)
			} else {
				// Target-issued cookies come last: servers keep the last
				// duplicate, so a refreshed session wins over a stale
				// operator-supplied one for the same name.
				httpReq.Header.Set("Cookie", existing+"; "+sessionHdr)
			}
		}
	}

	httpReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
	httpReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	httpReq.Header.Set("Accept-Language", "en-US,en;q=0.5")
	// Note: Accept-Encoding is deliberately NOT set. When the caller sets
	// it manually, net/http stops transparently decompressing the response
	// and delivers raw gzip/deflate/br bytes — which silently blinded every
	// body-based detection (canaries, error signatures, keyword classes)
	// on any server that compresses. With no manual header and
	// DisableCompression=false, the transport adds gzip itself and hands
	// back plain bytes.

	wireStart := time.Now()
	httpResp, err := c.http.Do(httpReq)
	if err != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		return nil, fmt.Errorf("%w: %w", types.ErrRequestFailed, err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	resp := &types.Response{
		StatusCode:    httpResp.StatusCode,
		Status:        httpResp.Status,
		Headers:       httpResp.Header.Clone(),
		RequestURL:    req.URL,
		FinalURL:      httpResp.Request.URL.String(),
		Proto:         httpResp.Proto,
		ContentType:   httpResp.Header.Get("Content-Type"),
		ContentLength: httpResp.ContentLength,
		RedirectHops:  append([]types.RedirectHop(nil), hops...),
	}

	if httpResp.TLS != nil {
		resp.TLS = httpResp.TLS
		resp.TLSVersion = tlsVersionString(httpResp.TLS.Version)
		resp.TLSCipher = tls.CipherSuiteName(httpResp.TLS.CipherSuite)
	}

	body, err := io.ReadAll(io.LimitReader(httpResp.Body, c.opts.maxBodySize))
	// The response duration measures the wire attempt only (request sent →
	// body fully read): time-based oracles gate on this value, so rate-
	// limiter waits and retry backoff that previously inflated it must not
	// contribute.
	resp.Duration = time.Since(wireStart)
	if err != nil {
		return resp, fmt.Errorf("read body: %w", err)
	}
	c.captureStoreFromResponse(httpResp.Request.URL, httpResp)

	resp.Body = body
	resp.BodySize = int64(len(body))

	return resp, nil
}

func (c *Client) Get(ctx context.Context, url string, headers map[string]string) (*types.Response, error) {
	return c.Do(ctx, &types.Request{
		Method:  "GET",
		URL:     url,
		Headers: headers,
	})
}

func (c *Client) DoBatch(ctx context.Context, reqs []*types.Request, results chan<- *types.Result, workers int) {
	if workers <= 0 {
		workers = DefaultConcurrency
	}

	jobs := make(chan *types.Request, len(reqs))
	var wg sync.WaitGroup

	for i := range reqs {
		jobs <- reqs[i]
	}
	close(jobs)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go c.worker(ctx, &wg, jobs, results)
	}

	wg.Wait()
	close(results)
}

func (c *Client) worker(ctx context.Context, wg *sync.WaitGroup, jobs <-chan *types.Request, results chan<- *types.Result) {
	defer wg.Done()

	for req := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
		}

		start := time.Now()
		resp, err := c.Do(ctx, req)
		duration := time.Since(start)

		result := &types.Result{
			Target:   req.URL,
			Request:  req,
			Response: resp,
			Error:    err,
			Duration: duration,
		}

		results <- result
	}
}

func (c *Client) Stats() RequestStats {
	c.statsMu.Lock()
	defer c.statsMu.Unlock()
	return c.stats
}

func (c *Client) Close() error {
	c.http.CloseIdleConnections()
	return nil
}

func isRetryable(err error, resp *types.Response) bool {
	// Server-side hiccups are retry conditions regardless of err==nil: the
	// response completed, the status itself signals a transient failure.
	if resp != nil {
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			return true
		}
		return false
	}
	if err == nil {
		return false
	}
	if errors.Is(err, types.ErrRateLimited) {
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	return false
}

func backoffDuration(attempt int, minWait, maxWait time.Duration) time.Duration {
	if attempt <= 0 {
		return 0
	}
	backoff := float64(minWait) * math.Pow(2, float64(attempt-1))
	jitter := rand.Float64() * float64(minWait)
	d := time.Duration(backoff + jitter)
	if d > maxWait {
		d = maxWait
	}
	return d
}

func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04X)", version)
	}
}
