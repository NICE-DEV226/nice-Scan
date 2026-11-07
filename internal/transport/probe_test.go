package transport

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// ProbeHost is the boundary for dials the HTTP client does not make (a port
// scan, a TLS handshake): the destination allow-list and the private-network
// guard must hold there too.

func TestProbeHostRefusesOutOfScope(t *testing.T) {
	c := NewClient(WithTargetScope("example.com"))

	_, err := c.ProbeHost(context.Background(), "127.0.0.1")
	if !errors.Is(err, types.ErrOutOfScope) {
		t.Fatalf("want ErrOutOfScope, got %v", err)
	}
}

func TestProbeHostBlocksInternalWhenGuardIsOn(t *testing.T) {
	c := NewClient(
		WithTargetScope("127.0.0.1"),
		WithPrivateNetworkAllowed(false),
	)

	_, err := c.ProbeHost(context.Background(), "127.0.0.1")
	if !errors.Is(err, types.ErrInternalTarget) {
		t.Fatalf("want ErrInternalTarget, got %v", err)
	}
}

func TestProbeHostReturnsVettedLiteral(t *testing.T) {
	c := NewClient(
		WithTargetScope("127.0.0.1"),
		WithPrivateNetworkAllowed(true),
	)

	ips, err := c.ProbeHost(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("ProbeHost: %v", err)
	}
	if len(ips) == 0 || !ips[0].IsLoopback() {
		t.Fatalf("want the loopback literal, got %v", ips)
	}
}

func TestDialContextRefusesInternalWhenGuardIsOn(t *testing.T) {
	c := NewClient(
		WithTargetScope("127.0.0.1"),
		WithPrivateNetworkAllowed(false),
	)

	_, err := c.DialContext(context.Background(), "tcp", "127.0.0.1:80")
	if !errors.Is(err, types.ErrInternalTarget) {
		t.Fatalf("want ErrInternalTarget, got %v", err)
	}
}

func TestDialContextConnectsToVettedAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	c := NewClient(
		WithTargetScope("127.0.0.1"),
		WithPrivateNetworkAllowed(true),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := c.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	_ = conn.Close()
}
