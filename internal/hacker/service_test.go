package hacker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// recordingAction is a planner entry that claims nothing and touches nothing;
// it exists to observe whether the gate dispatched it.
type recordingAction struct {
	name        string
	destructive bool
	ran         bool
}

func (a *recordingAction) Metadata() ActionMetadata {
	return ActionMetadata{Name: a.name, Destructive: a.destructive}
}

func (a *recordingAction) Execute(context.Context, string, *Knowledge, *transport.Client) ActionResult {
	a.ran = true
	return ActionResult{}
}

func serviceFor(t *testing.T, cfg *types.Config, actions ...Action) *Service {
	t.Helper()
	svc, err := NewService(ServiceOptions{
		Config: cfg,
		Scope:  []string{"example.com"},
		Target: "https://example.com",
	}, actions...)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	return svc
}

func TestNewServiceRefusesEmptyScope(t *testing.T) {
	_, err := NewService(ServiceOptions{Target: "https://example.com"})
	if !errors.Is(err, ErrNoScope) {
		t.Fatalf("empty scope must be ErrNoScope, got %v", err)
	}
}

func TestNewServiceRefusesTargetOutsideScope(t *testing.T) {
	_, err := NewService(ServiceOptions{
		Scope:  []string{"example.com"},
		Target: "https://not-example.test",
	})
	if err == nil {
		t.Fatal("a target outside the scope must be refused at construction")
	}
	if errors.Is(err, ErrNoScope) {
		t.Fatalf("the scope was present; want a wrong-target error, got %v", err)
	}
}

// The consent decision is Config.Destructive, and the package enforces it at
// dispatch even for a caller that never reads the CLI. Without consent the
// action does not run and is named in the report.
func TestServiceWithholdsDestructiveActionWithoutConsent(t *testing.T) {
	act := &recordingAction{name: "state writer", destructive: true}
	svc := serviceFor(t, types.DefaultConfig(), act)

	report := svc.Run(context.Background())

	if act.ran {
		t.Fatal("destructive action ran without consent")
	}
	found := false
	for _, name := range report.PendingDestructive {
		if name == "state writer" {
			found = true
		}
	}
	if !found {
		t.Fatalf("withheld action must be named in the report, got %v", report.PendingDestructive)
	}
}

func TestServiceRunsDestructiveActionWithConfigConsent(t *testing.T) {
	cfg := types.DefaultConfig()
	cfg.Destructive = true
	act := &recordingAction{name: "state writer", destructive: true}
	svc := serviceFor(t, cfg, act)

	report := svc.Run(context.Background())

	if !act.ran {
		t.Fatal("consent in Config must reach the dispatch gate")
	}
	if len(report.PendingDestructive) != 0 {
		t.Fatalf("consent granted: nothing may remain withheld, got %v", report.PendingDestructive)
	}
}

// A machine caller gets silence: the brain's writer is io.Discard unless the
// caller opts into stdout.
func TestServiceOutputIsOptIn(t *testing.T) {
	svc := serviceFor(t, types.DefaultConfig(), &recordingAction{name: "read-only"})
	if svc.Brain().out != io.Discard {
		t.Fatal("NewService must route the brain to io.Discard")
	}

	var buf bytes.Buffer
	svc.Brain().SetOutput(&buf)
	svc.Run(context.Background())
	if buf.Len() == 0 {
		t.Fatal("SetOutput must restore human-readable output")
	}
	if !strings.Contains(buf.String(), "Decision Engine") {
		t.Fatalf("output does not carry the run header: %q", buf.String())
	}
}

// A port scan dials hosts the boundary approved, not names it resolved. Out of
// scope and internal targets produce a refusal finding, never a silent clean
// scan.
func TestPortScanRefusesHostOutsideScope(t *testing.T) {
	client := transport.NewClient(transport.WithTargetScope("example.com"))
	res := (&PortScanAction{}).Execute(context.Background(), "127.0.0.1", NewKnowledge("127.0.0.1"), client)

	if len(res.Findings) != 1 || res.Findings[0].Type != "probe_refused" {
		t.Fatalf("want one probe_refused finding, got %+v", res.Findings)
	}
}

func TestPortScanRefusesInternalAddressWhenGuardIsOn(t *testing.T) {
	client := transport.NewClient(
		transport.WithTargetScope("127.0.0.1"),
		transport.WithPrivateNetworkAllowed(false),
	)
	res := (&PortScanAction{}).Execute(context.Background(), "127.0.0.1", NewKnowledge("127.0.0.1"), client)

	if len(res.Findings) != 1 || res.Findings[0].Type != "probe_refused" {
		t.Fatalf("want one probe_refused finding, got %+v", res.Findings)
	}
	if !strings.Contains(res.Findings[0].Evidence, "internal") {
		t.Fatalf("refusal must name the private-network rule, got %q", res.Findings[0].Evidence)
	}
}

// Credential-shaped text that arrives from the target never reaches a render
// sink in the clear — terminal or HTML.
func TestReportsRedactCredentialText(t *testing.T) {
	const secret = "hunter2-unique"
	f := Finding{
		Type:     "sqli",
		Name:     "leak https://admin:" + secret + "@example.com/",
		Severity: SevHigh,
		Evidence: "password=" + secret,
	}

	b := NewBrain("example.com", nil)
	var term bytes.Buffer
	b.SetOutput(&term)
	b.renderFinding(f)
	if strings.Contains(term.String(), secret) {
		t.Fatalf("terminal render leaked the secret: %q", term.String())
	}

	page := RenderHTMLReport(&Report{Target: "example.com", Findings: []Finding{f}})
	if strings.Contains(page, secret) {
		t.Fatal("HTML render leaked the secret")
	}
}

func TestRenderJSONReportMasksCredentialsAndIsValidJSON(t *testing.T) {
	const secret = "hunter2-json"
	r := &Report{
		Target:   "example.com",
		Findings: []Finding{{Type: "sqli", Name: "x", Evidence: "password=" + secret}},
		Credentials: []Credential{
			{Username: "admin", Password: secret, Source: "login", Valid: true},
		},
	}

	data, err := RenderJSONReport(r)
	if err != nil {
		t.Fatalf("RenderJSONReport: %v", err)
	}
	if strings.Contains(string(data), secret) {
		t.Fatal("JSON report leaked the password")
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("JSON report is not valid JSON: %v", err)
	}
}

// A chain action the consent gate skipped is named in the report instead of
// being dropped without a trace.
func TestWithheldChainIsReported(t *testing.T) {
	b := NewBrain("example.com", nil)
	b.SetOutput(io.Discard)
	b.noteWithheldChain("Upload And Execute")

	pending := b.pendingWithheld()
	found := false
	for _, name := range pending {
		if name == "Upload And Execute" {
			found = true
		}
	}
	if !found {
		t.Fatalf("withheld chain missing from the report: %v", pending)
	}
}
