// Package hacker is the autonomous side of the engine: a planner picks the
// next action from the evidence it has, and the actions report findings.
//
// This file is the boundary the hack command used to carry alone. Two
// decisions make an autonomous run safe, and both lived in cmd/nice_scan:
// where a request may be aimed (a scoped transport) and whether the target may
// be modified at all (--destructive consent). A caller that is not a human
// reading the command line — a script, a model, the shell — could not inherit
// either without copying the command's code, and a copy drifts. NewService
// owns both and fails closed: no scope means no service, and the brain's
// dispatch gate withholds every destructive action unless the same Config says
// otherwise.
package hacker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// ErrNoScope is returned when a service is asked to exist without a target
// allow-list. The caller that is not a human reading the output must state
// where it is allowed to go.
var ErrNoScope = errors.New("hacker: a non-empty target scope is required")

// ServiceOptions configures a Brain that owns its transport. Operator policy
// (timeout, retries, proxy, headers, whether the scope is a hard boundary,
// whether internal addresses are dialable, whether state-changing actions are
// consented to) comes from Config; the scope is the service's contract with
// its caller and is explicit here, the same split recon and exploit use.
type ServiceOptions struct {
	// Config is the operator's policy. Nil means types.DefaultConfig().
	Config *types.Config
	// Scope lists the hosts requests may be aimed at: the target host and,
	// for a multi-host run, each of them. Entries match as registrable hosts,
	// so a host and its subdomains are in scope.
	Scope []string
	// Target is the base URL the actions aim at. It must be inside Scope.
	Target string
}

// Service is a brain bound to a client whose destination boundary and consent
// decision were fixed at construction.
type Service struct {
	brain  *Brain
	client *transport.Client
}

// NewService builds a scoped client and a Brain bound to it. Passing no
// actions registers the read-only default roster; a caller that wants the
// state-changing modules must register them explicitly, and the dispatch gate
// still withholds them without consent.
//
// The brain writes to io.Discard: a machine caller gets a report, not terminal
// decoration. The CLI opts back into stdout through SetOutput.
func NewService(o ServiceOptions, actions ...Action) (*Service, error) {
	scope := transport.NormalizeScope(o.Scope)
	if len(scope) == 0 {
		return nil, fmt.Errorf("%w: got %v", ErrNoScope, o.Scope)
	}

	target := strings.TrimSpace(o.Target)
	if target == "" {
		return nil, errors.New("hacker: no target")
	}
	host := transport.HostDomain(target)
	if host == "" {
		return nil, fmt.Errorf("hacker: unusable target %q", o.Target)
	}
	if !hostInScope(host, scope) {
		// A target outside the list would make the first action's request
		// refuse and read as "target unreachable" instead of "wrong target".
		return nil, fmt.Errorf("hacker: target %q is outside the scope %v", host, scope)
	}

	cfg := o.Config
	if cfg == nil {
		cfg = types.DefaultConfig()
	}

	opts := transport.OptionsFromConfig(cfg)
	opts = append(opts, transport.WithCredScope(scope))
	if cfg.EnforceScope {
		opts = append(opts, transport.WithTargetScope(scope...))
	}
	if cfg.BlockInternal {
		opts = append(opts, transport.WithPrivateNetworkAllowed(false))
	}

	client := transport.NewClient(opts...)
	if len(actions) == 0 {
		actions = DefaultActions(cfg)
	}
	brain := NewBrain(target, client, actions...)
	// Consent is one decision, not two: the flag the CLI exposes is the
	// same field the API reads.
	brain.SetDestructive(cfg.Destructive)
	brain.SetOutput(io.Discard)

	return &Service{brain: brain, client: client}, nil
}

// Brain hands out the configured brain for callers that need to append
// actions or select an output writer before Run.
func (s *Service) Brain() *Brain { return s.brain }

// Run executes the plan and returns the report. Nothing is rendered.
func (s *Service) Run(ctx context.Context) *Report { return s.brain.Run(ctx) }

// RenderReport writes the human-readable report to w. Passing nil discards it.
func (s *Service) RenderReport(r *Report, w io.Writer) {
	s.brain.SetOutput(w)
	s.brain.RenderReport(r)
}

// Client hands out the scoped transport for callers that need its stats; the
// actions already use it.
func (s *Service) Client() *transport.Client { return s.client }

// Close releases the transport's idle connections.
func (s *Service) Close() error { return s.client.Close() }

// hostInScope mirrors the transport's allow-list rule: an entry covers the
// host itself and its subdomains, on the dot boundary.
func hostInScope(host string, scope []string) bool {
	host = strings.ToLower(host)
	for _, s := range scope {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}
