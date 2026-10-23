package hacker

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
)

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

	err := a.server.Start(ctx)
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

	oobURL := fmt.Sprintf("http://127.0.0.1:%d/callback", a.server.port)

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
				Description: fmt.Sprintf("Listening on port %d — use for blind SSRF/SSTI/XSS", a.server.port),
				Evidence:    oobURL,
			},
		},
	}
}

const (
	// oobMaxBodySize caps the memory a single callback body can consume.
	oobMaxBodySize = 4 << 20 // 4 MiB
	// oobMaxCallbacks bounds stored callbacks; the FIFO evicts oldest so the
	// server cannot grow unbounded across a long session.
	oobMaxCallbacks = 1000
)

func (s *OOBServer) Start(ctx context.Context) error {
	// Bind loopback only: the callback host is scanner-local. A wildcard
	// bind would expose an open HTTP sink to the network (anyone able to
	// reach the workstation could relay bodies through it).
	var err error
	s.listener, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", s.port))
	if err != nil {
		return err
	}
	s.setRunning(true)

	go func() {
		_ = http.Serve(s.listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Enforce a hard cap on body size regardless of client behaviour.
			body, _ := io.ReadAll(io.LimitReader(r.Body, oobMaxBodySize))
			r.Body.Close()

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
		s.listener.Close()
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
