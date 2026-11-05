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
	FindingTech      FindingType = "technology"
	FindingExposure  FindingType = "exposure"
	FindingMisconfig FindingType = "misconfiguration"
	FindingTLS       FindingType = "tls"
	FindingHeader    FindingType = "header"
	FindingWAF       FindingType = "waf"
	FindingSecret    FindingType = "secret"
	FindingSubdomain FindingType = "subdomain"
	// FindingAccess is a capability read: what one identity was shown where
	// another was refused. It is not an authorization verdict — reaching an
	// admin surface with a valid admin session is expected behaviour, and the
	// claim worth reporting is only the difference itself.
	FindingAccess FindingType = "access"
)

type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte
	Timeout time.Duration

	// Origin records who came up with this URL. The engine stamps it, and a
	// finding's Provenance carries it through, so "the target links to this"
	// and "our wordlist named this" stay distinguishable all the way to the
	// report instead of collapsing into one 200-okay conclusion.
	Origin PathOrigin
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
	StatusCode    int
	Status        string
	Headers       http.Header
	Body          []byte
	BodySize      int64
	Duration      time.Duration
	ContentType   string
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
	// Soft404 is scanner-internal: set by the engine when this probe's
	// response is byte-identical (status + content-type + body) to the
	// target's homepage. A client-side-routing SPA serves the SAME shell for
	// every unknown path, so the requested path was never treated
	// specially by the server — any conclusion drawn from the path or the
	// shared shell body is false evidence. Path/body analyzers honor this
	// flag; header/TLS analyzers ignore it (their signal is real).
	Soft404 bool `json:"-"`
}

type Result struct {
	Target   string
	Request  *Request
	Response *Response
	Findings []Finding
	Error    error
	Duration time.Duration
}

type Finding struct {
	Type        FindingType       `json:"type"`
	Name        string            `json:"name"`
	Severity    Severity          `json:"severity"`
	Description string            `json:"description"`
	Evidence    string            `json:"evidence,omitempty"`
	Confidence  float64           `json:"confidence"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	// Prov is how the finding was earned: which exchange, which differential,
	// compared against what. A pointer with omitempty so an analyzer that has
	// not been migrated yet is unchanged on the wire — and so adopting it in
	// one analyzer cannot silently promote a hand-written Confidence into a
	// proof claimed for all the others.
	Prov *Provenance `json:"prov,omitempty"`
}

type Config struct {
	Targets         []string
	Workers         int
	Timeout         time.Duration
	Retries         int
	RateLimit       int
	Proxy           string
	OutputFormat    string
	OutputFile      string
	Verbose         bool
	FollowRedirects bool
	MaxRedirects    int
	Headers         map[string]string
	HTTP2           bool
	Cookie          string
	// Destructive: explicit operator consent for state-modifying actions
	// (command/shell uploads, account registration). Anything that writes
	// or spawns state on the target is gated on this — a default-on scan
	// must never create or alter assets the operator did not opt into.
	Destructive bool
	// EnforceScope makes the target's host a hard boundary: requests to any
	// other host, and redirects that leave it, are refused outright instead
	// of merely shedding credentials. On by default for target-bound
	// commands, because a caller that is not a human reading the output —
	// a model or a script driving the tool — must not be able to aim it
	// elsewhere. --allow-out-of-scope turns it off.
	EnforceScope bool
	// BlockInternal refuses to dial addresses that are not globally
	// routable (loopback, RFC1918, link-local including the cloud metadata
	// address, CGNAT). Off by default: scanning one's own dev server is a
	// legitimate use of this tool, so the operator opts in.
	BlockInternal bool
}
