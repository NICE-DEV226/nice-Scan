package hacker

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
)

// oobBindEnv lets an operator expose the callback sink on an interface the
// TARGET can reach. The default remains loopback; see oobBindDoc.
const oobBindEnv = "NICESCAN_OOB_BIND"

// oobBindDoc documents the OOB reachability premise: a blind probe only
// turns into evidence when the target can route bytes back to the sink.
const oobBindDoc = "loopback by default — a remote target cannot route to 127.0.0.1; set NICESCAN_OOB_BIND to an interface IP the target can reach"

type OOBAction struct {
	server *OOBServer
}

type OOBServer struct {
	mu        sync.Mutex
	callbacks []OOBRequest
	listener  net.Listener
	port      int
	running   bool
}

type OOBRequest struct {
	ID         string
	RemoteAddr string
	Path       string
	Query      string
	Headers    map[string]string
	Body       string
	Timestamp  time.Time
}

func NewOOBAction() *OOBAction {
	return &OOBAction{
		server: &OOBServer{
			port: 9999,
		},
	}
}

func (a *OOBAction) Metadata() ActionMetadata {
	return ActionMetadata{
		Name:        "OOB Server",
		Description: "HTTP callback server for blind SSRF/SSTI/XSS detection",
		Priority:    80,
		Requires:    []string{},
		Provides:    []string{"has_oob"},
	}
}

func (a *OOBAction) Execute(ctx context.Context, target string, kb *Knowledge, client *transport.Client) ActionResult {
	if a.server.IsRunning() {
		return ActionResult{}
	}

	bind := strings.TrimSpace(os.Getenv(oobBindEnv))
	if bind == "" {
		bind = "127.0.0.1"
	}

	advertisedHost, advertiseErr := oobAdvertisedHost(bind)
	if advertiseErr != nil {
		return ActionResult{Findings: []Finding{
			{
				Type:        "oob_error",
				Name:        "OOB sink cannot be advertised",
				Severity:    SevInfo,
				Description: fmt.Sprintf("Interface lookup failed for bind %q: %s", bind, advertiseErr),
			},
		}}
	}

	// Reachability verdict BEFORE binding: a remote target pointing at a
	// loopback sink is the documented idle limitation — declaring "ready"
	// would be misinformation, every blind payload causes zero evidence.
	if !oobTargetCanReach(target, advertisedHost) {
		return ActionResult{Findings: []Finding{
			{
				Type:     "oob_unreachable",
				Severity: SevInfo,
				Name:     "OOB sink unreachable from the target — no blind verdicts",
				Description: fmt.Sprintf(
					"The callback sink listens on %s (advertised as %s) while the target %s is not on this host: blind SSRF/SSTI/XSS payloads aimed at this sink can never return evidence. Set %s to an interface IP the target can reach, or run an intercept domain, before re-running blind probes.",
					bind, advertisedHost, nicename(target), oobBindEnv),
			},
		}}
	}

	err := a.server.Start(ctx, bind)
	if err != nil {
		return ActionResult{
			Findings: []Finding{
				{
					Type:        "oob_error",
					Name:        "OOB server failed to start",
					Severity:    SevLow,
					Description: fmt.Sprintf("Error: %s", err),
				},
			},
		}
	}

	oobURL := fmt.Sprintf("http://%s:%d/callback", advertisedHost, a.server.port)

	go func() {
		<-ctx.Done()
		a.server.Stop()
	}()

	// The callback URL is scanner infrastructure, not a secret captured on
	// the target: it must not flip has_secret or drive risk scoring.
	kb.AddScannerState(fmt.Sprintf("OOB callback URL: %s?token={target_id}", oobURL))

	return ActionResult{
		Findings: []Finding{
			{
				Type:        "oob_ready",
				Name:        "OOB callback server ready",
				Severity:    SevInfo,
				Description: fmt.Sprintf("Listening on %s:%d — use for blind SSRF/SSTI/XSS (%s)", advertisedHost, a.server.port, oobBindDoc),
				Evidence:    oobURL,
			},
		},
	}
}

// oobTargetCanReach reports whether the target could plausibly route
// bytes back to the advertised sink host. Empty/undetermined targets are
// treated as scanner-local (lab default). A non-loopback advertised host
// is assumed routable — interface IPs the operator controls.
func oobTargetCanReach(target, advertisedHost string) bool {
	if !isLoopbackHost(advertisedHost) {
		return true
	}
	u, err := url.Parse(target)
	if err != nil {
		return true
	}
	host := u.Hostname()
	if host == "" {
		return true
	}
	return isLoopbackHost(host)
}

// oobAdvertisedHost resolves what to put in payload URLs for the given
// bind. Wildcard binds advertise the machine's primary IPv4 — the sink is
// server-side, single-homed per interface; listing every interface is a
// multi-homed setups are a documented future concern; the finding text
// states this.
func oobAdvertisedHost(bind string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(bind)) {
	case "", "0.0.0.0", "::", "*":
		return primaryLocalIPv4()
	}
	return bind, nil
}

// primaryLocalIPv4 returns the first non-loopback IPv4 of the machine —
// best-effort basis for "which interface would a remote target hit".
func primaryLocalIPv4() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.To4() == nil || ipnet.IP.IsLoopback() {
			continue
		}
		return ipnet.IP.String(), nil
	}
	return "0.0.0.0", nil
}

// isLoopbackHost classifies hostnames and IPs that can only be reached
// from the scanner host itself.
func isLoopbackHost(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1":
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// nicename renders an empty target safely in finding text.
func nicename(target string) string {
	if strings.TrimSpace(target) == "" {
		return "(unspecified)"
	}
	return target
}

const (
	// oobMaxBodySize caps the memory a single callback body can consume.
	oobMaxBodySize = 4 << 20 // 4 MiB
	// oobMaxCallbacks bounds stored callbacks; the FIFO evicts oldest so the
	// server cannot grow unbounded across a long session.
	oobMaxCallbacks = 1000
)

func (s *OOBServer) Start(ctx context.Context, bind string) error {
	// Default binding is loopback: the callback host is scanner-local and
	// 127.0.0.1 is the honest default. Wildcard binds via oobBindEnv are
	// operator decisions and expose an open HTTP sink to the network —
	// the Execute() path documents that premise in every finding before
	// the sink goes live.
	if bind == "" {
		bind = "127.0.0.1"
	}
	var err error
	s.listener, err = net.Listen("tcp", net.JoinHostPort(bind, fmt.Sprintf("%d", s.port)))
	if err != nil {
		return err
	}
	s.setRunning(true)

	go func() {
		_ = http.Serve(s.listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Enforce a hard cap on body size regardless of client behaviour.
			body, _ := io.ReadAll(io.LimitReader(r.Body, oobMaxBodySize))
			_ = r.Body.Close() // request body fully consumed

			req := OOBRequest{
				ID:         fmt.Sprintf("oob-%d", time.Now().UnixNano()),
				RemoteAddr: r.RemoteAddr,
				Path:       r.URL.Path,
				Query:      r.URL.RawQuery,
				Timestamp:  time.Now(),
			}
			for k, v := range r.Header {
				if req.Headers == nil {
					req.Headers = make(map[string]string)
				}
				req.Headers[k] = v[0]
			}
			if len(body) > 0 {
				req.Body = string(body)
			}

			s.mu.Lock()
			s.callbacks = append(s.callbacks, req)
			// FIFO eviction: keep memory bounded, oldest callbacks drop.
			if len(s.callbacks) > oobMaxCallbacks {
				s.callbacks = s.callbacks[1:]
			}
			s.mu.Unlock()

			w.WriteHeader(200)
			_, _ = w.Write([]byte("OK"))
		}))
	}()

	time.Sleep(100 * time.Millisecond)
	return nil
}

func (s *OOBServer) setRunning(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running = v
}

func (s *OOBServer) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

func (s *OOBServer) Stop() {
	if s.listener != nil {
		_ = s.listener.Close() // cleanup; Stop is called on shutdown paths only
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running = false
	// Clear stored callbacks along with the listener so a restart starts
	// without stale records.
	s.callbacks = nil
}

func (s *OOBServer) GetCallbacks() []OOBRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]OOBRequest, len(s.callbacks))
	copy(out, s.callbacks)
	return out
}
