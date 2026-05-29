package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
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
	rateLimit       int
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

func WithCookie(c string) ClientOption {
	return func(o *clientOptions) { o.cookie = c }
}

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
	stats   RequestStats
	statsMu sync.Mutex
}

type RequestStats struct {
	Total      int64
	Success    int64
	Failed     int64
	Retried    int64
	RateLimited int64
	TotalBytes int64
	TotalTime  time.Duration
}

func NewClient(opts ...ClientOption) *Client {
	o := defaultOptions()
	for _, opt := range opts {
		opt(o)
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
		httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= o.maxRedirects {
				return fmt.Errorf("max redirects exceeded (%d)", o.maxRedirects)
			}
			if len(via) > 0 {
				for i := range via {
					req.Header.Set("Cookie", via[i].Header.Get("Cookie"))
				}
			}
			return nil
		}
	}

	c := &Client{
		opts: o,
		http: httpClient,
	}

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
		c.rl.Wait(ctx)
		c.statsMu.Lock()
		c.stats.RateLimited++
		c.statsMu.Unlock()
	}

	start := time.Now()
	resp, err := c.doWithRetries(ctx, req)
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

	if resp != nil {
		resp.Duration = duration
	}

	return resp, nil
}

func (c *Client) doWithRetries(ctx context.Context, req *types.Request) (*types.Response, error) {
	var lastErr error

	for attempt := 0; attempt <= c.opts.retries; attempt++ {
		if attempt > 0 {
			c.statsMu.Lock()
			c.stats.Retried++
			c.statsMu.Unlock()

			wait := backoffDuration(attempt, c.opts.retryWaitMin, c.opts.retryWaitMax)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
		}

		resp, err := c.execute(ctx, req)
		if err == nil {
			return resp, nil
		}

		lastErr = err

		if !isRetryable(err, resp) {
			return resp, err
		}
	}

	return nil, fmt.Errorf("%w after %d attempts: %w", types.ErrMaxRetries, c.opts.retries+1, lastErr)
}

func (c *Client) execute(ctx context.Context, req *types.Request) (*types.Response, error) {
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	if len(req.Body) > 0 {
		httpReq.Body = io.NopCloser(bytes.NewReader(req.Body))
		httpReq.ContentLength = int64(len(req.Body))
	}

	for k, v := range c.opts.headers {
		httpReq.Header.Set(k, v)
	}
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}
	if c.opts.cookie != "" {
		httpReq.Header.Set("Cookie", c.opts.cookie)
	}

	httpReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
	httpReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	httpReq.Header.Set("Accept-Language", "en-US,en;q=0.5")
	httpReq.Header.Set("Accept-Encoding", "gzip, deflate, br")

	httpResp, err := c.http.Do(httpReq)
	if err != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		return nil, fmt.Errorf("%w: %w", types.ErrRequestFailed, err)
	}
	defer httpResp.Body.Close()

	resp := &types.Response{
		StatusCode:    httpResp.StatusCode,
		Status:        httpResp.Status,
		Headers:       httpResp.Header.Clone(),
		RequestURL:    req.URL,
		FinalURL:      httpResp.Request.URL.String(),
		Proto:         httpResp.Proto,
		ContentType:   httpResp.Header.Get("Content-Type"),
		ContentLength: httpResp.ContentLength,
	}

	if httpResp.TLS != nil {
		resp.TLS = httpResp.TLS
		resp.TLSVersion = tlsVersionString(httpResp.TLS.Version)
		resp.TLSCipher = tls.CipherSuiteName(httpResp.TLS.CipherSuite)
	}

	body, err := io.ReadAll(io.LimitReader(httpResp.Body, c.opts.maxBodySize))
	if err != nil {
		return resp, fmt.Errorf("read body: %w", err)
	}
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
	if err == nil {
		return false
	}
	if errorsIs(err, types.ErrRateLimited) {
		return true
	}
	if errorsIs(err, context.DeadlineExceeded) {
		return true
	}
	if resp != nil && resp.StatusCode == http.StatusTooManyRequests {
		return true
	}
	if resp != nil && resp.StatusCode >= 500 {
		return true
	}
	return false
}

func errorsIs(err, target error) bool {
	for err != nil {
		if err == target {
			return true
		}
		if ue, ok := err.(interface{ Unwrap() error }); ok {
			err = ue.Unwrap()
			continue
		}
		if ue, ok := err.(interface{ Unwrap() []error }); ok {
			for _, e := range ue.Unwrap() {
				if errorsIs(e, target) {
					return true
				}
			}
			return false
		}
		return false
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


