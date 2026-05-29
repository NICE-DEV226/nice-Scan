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

type Capability struct {
	Name    string
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
