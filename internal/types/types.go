package types

import (
	"crypto/tls"
	"net/http"
	"time"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type FindingType string

const (
	FindingTech       FindingType = "technology"
	FindingExposure   FindingType = "exposure"
	FindingMisconfig  FindingType = "misconfiguration"
	FindingTLS        FindingType = "tls"
	FindingHeader     FindingType = "header"
	FindingWAF        FindingType = "waf"
	FindingSecret     FindingType = "secret"
)

type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte
	Timeout time.Duration

	Metadata map[string]any
}

// RedirectHop records one hop of an internally-followed redirect chain:
// the 3xx the server answered (its own URL) and the Location it advertised
// toward the next request. stdlib hides these responses from the caller —
// verdicts that reason about login flows need them (the Location a login
// POST redirect advertises is only visible here).
type RedirectHop struct {
	Status   int
	URL      string
	Location string
}

type Response struct {
	StatusCode  int
	Status      string
	Headers     http.Header
	Body        []byte
	BodySize    int64
	Duration    time.Duration
	ContentType string
	ContentLength int64

	TLSVersion    string
	TLSCipher     string
	TLS           *tls.ConnectionState
	RequestURL    string
	FinalURL      string
	RedirectCount int
	Proto         string
	// RedirectHops is scanner-internal observation, not report content.
	RedirectHops []RedirectHop `json:"-"`
}

type Result struct {
	Target    string
	Request   *Request
	Response  *Response
	Findings  []Finding
	Error     error
	Duration  time.Duration
}

type Finding struct {
	Type        FindingType `json:"type"`
	Name        string      `json:"name"`
	Severity    Severity    `json:"severity"`
	Description string      `json:"description"`
	Evidence    string      `json:"evidence,omitempty"`
	Confidence  float64     `json:"confidence"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

type Config struct {
	Targets  []string
	Workers  int
	Timeout  time.Duration
	Retries  int
	RateLimit int
	Proxy    string
	OutputFormat string
	OutputFile   string
	Verbose  bool
	FollowRedirects bool
	MaxRedirects   int
	Headers  map[string]string
	HTTP2    bool
	Cookie   string
}
