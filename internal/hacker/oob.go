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
	mu       sync.Mutex
	callbacks []OOBRequest
	listener net.Listener
	port     int
	running  bool
}

type OOBRequest struct {
	ID        string
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
	if a.server.running {
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

	oobURL := fmt.Sprintf("http://localhost:%d/callback", a.server.port)

	go func() {
		<-ctx.Done()
		a.server.Stop()
	}()

	kb.AddSecret(fmt.Sprintf("OOB callback URL: %s?token={target_id}", oobURL))

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

func (s *OOBServer) Start(ctx context.Context) error {
	var err error
	s.listener, err = net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return err
	}
	s.running = true

	go func() {
		http.Serve(s.listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
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
			s.mu.Unlock()

			w.WriteHeader(200)
			w.Write([]byte("OK"))
		}))
	}()

	time.Sleep(100 * time.Millisecond)
	return nil
}

func (s *OOBServer) Stop() {
	if s.listener != nil {
		s.listener.Close()
	}
	s.running = false
}

func (s *OOBServer) GetCallbacks() []OOBRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]OOBRequest, len(s.callbacks))
	copy(out, s.callbacks)
	return out
}
