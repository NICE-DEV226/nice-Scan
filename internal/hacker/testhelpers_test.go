package hacker

import (
	"context"
	"net"
	"testing"
)

// testCtx returns a context for actions that spawn background servers. The
// caller is responsible for stopping servers explicitly (Stop()).
func testCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	_ = cancel // retained for symmetry; processes exit at test teardown
	return ctx
}

func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

func TestIsLoopbackAddr(t *testing.T) {
	if !isLoopbackAddr("127.0.0.1:9999") {
		t.Error("127.0.0.1:9999 must be loopback")
	}
	if isLoopbackAddr("0.0.0.0:9999") {
		t.Error("0.0.0.0:9999 must not be loopback (wildcard bind)")
	}
}
