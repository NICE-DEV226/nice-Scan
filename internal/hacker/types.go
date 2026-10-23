package hacker

import (
	"context"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
)

type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

// Capability origin values. A capability is "verified" only when it is backed
// by executed evidence (credential login succeeded, secret content actually
// captured, token actually obtained). Capabilities derived by substring
// matching over remote-controlled text are always "hint" origin.
const (
	OriginVerified = "verified"
	OriginHint     = "hint"
)

type Capability struct {
	Name string
	// Origin records how this capability was established. The planner, chainer
	// and risk scoring treat "hint" capabilities as unproven.
	Origin  string
	Target  string
	Details map[string]string
}

type Finding struct {
	Type        string
	Name        string
	Severity    Severity
	Description string
	Evidence    string
	Details     map[string]string
}

type Credential struct {
	Username string
	Password string
	Source   string
	Valid    bool
}

type Page struct {
	URL     string
	Title   string
	Forms   int
	Links   []string
	JSFiles []string
	BodyLen int
	Status  int
}

type Endpoint struct {
	Path        string
	Method      string
	Status      int
	BodyLen     int
	ContentType string
}

type SessionToken struct {
	Token  string
	Type   string
	Source string
	Valid  bool
}

type ChainStep struct {
	Action    string
	Input     string
	Output    string
	Success   bool
	Impact    string
	Timestamp time.Time
}

type AttackChain struct {
	Name      string
	Steps     []ChainStep
	Impact    string
	RiskScore float64
	Target    string
}

type ActionMetadata struct {
	Name        string
	Description string
	Priority    int
	Requires    []string
	Provides    []string
	// Sensitive marks actions that attack with credentials or modify target
	// state (credential brute force, file upload, session takeover). A
	// sensitive action only runs when every Requires capability is verified
	// (Origin == OriginVerified), never from remote-text hints.
	Sensitive bool
}

type ActionResult struct {
	Findings []Finding
	Actions  []Action
}

type Action interface {
	Metadata() ActionMetadata
	Execute(ctx context.Context, target string, kb *Knowledge, client *transport.Client) ActionResult
}

type JWTToken struct {
	Raw       string
	Header    map[string]any
	Payload   map[string]any
	Algorithm string
	Valid     bool
	Role      string
	Subject   string
}

type Report struct {
	Target       string
	Duration     time.Duration
	Steps        int
	Impact       string
	RiskScore    float64
	AttackChains []AttackChain
	Findings     []Finding
	Capabilities []Capability
	Credentials  []Credential
	Endpoints    []Endpoint
	Pages        []Page
}
