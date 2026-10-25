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

// Capability origin values. Three provenance tiers:
//
//   - verified: the scanner EXECUTED an interaction and observed an effect
//     attributable to its own probe (a login that answered differently
//     with and without the credential, a canary that came back classified,
//     a traversal that returned file content). The planner unlocks
//     sensitive actions and the chainer builds attack chains only from
//     these.
//   - observed: the scanner fetched data directly from the target over the
//     wire, and the capability rests on shape or keywords read inside
//     remote-controlled content (a form whose markup says "upload", a
//     page whose body contains "/api"). Real observation, unproven
//     capability: it cannot unlock sensitive actions and it must not be
//     the only basis of a critical report headline.
//   - hint: derived by substring matching over remote-controlled text
//     (finding descriptions, third-party feeds). Unproven; may guide
//     read-only probing of the same target only.
const (
	OriginVerified = "verified"
	OriginObserved = "observed"
	OriginHint     = "hint"
)

type Capability struct {
	Name string
	// Origin records how this capability was established. The planner, chainer
	// and risk scoring treat anything below verified as unproven. Leaving
	// Origin empty is refused by design: AddCapability records a silent
	// empty origin as observed (the lowest tier a direct fetch can support),
	// so a sloppy call can never fabricate verified evidence.
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
