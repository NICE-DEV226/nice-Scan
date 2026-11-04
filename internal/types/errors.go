package types

import "errors"

var (
	ErrNoTargets     = errors.New("no targets specified")
	ErrRequestFailed = errors.New("request failed")
	ErrTimeout       = errors.New("request timeout")
	ErrRateLimited   = errors.New("rate limited")
	ErrMaxRetries    = errors.New("max retries exceeded")
	ErrInvalidURL    = errors.New("invalid URL")
	ErrTLSFailure    = errors.New("TLS handshake failed")
	ErrBodyTooLarge  = errors.New("response body too large")
	ErrNoResponse    = errors.New("no response received")
	// ErrOutOfScope is the hard scope boundary: the request host is not the
	// configured target. Unlike credential scoping (which only decides
	// whether an operator secret rides along), this refuses the request.
	ErrOutOfScope = errors.New("host outside target scope")
	// ErrInternalTarget is the dial-time refusal of a non-globally-routable
	// address, so a caller cannot aim the scanner at loopback, private space
	// or cloud metadata by way of a hostname.
	ErrInternalTarget = errors.New("internal or non-routable address")
)
