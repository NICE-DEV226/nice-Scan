package types

import "errors"

var (
	ErrNoTargets        = errors.New("no targets specified")
	ErrRequestFailed    = errors.New("request failed")
	ErrTimeout          = errors.New("request timeout")
	ErrRateLimited      = errors.New("rate limited")
	ErrMaxRetries       = errors.New("max retries exceeded")
	ErrInvalidURL       = errors.New("invalid URL")
	ErrTLSFailure       = errors.New("TLS handshake failed")
	ErrBodyTooLarge     = errors.New("response body too large")
	ErrNoResponse       = errors.New("no response received")
)
