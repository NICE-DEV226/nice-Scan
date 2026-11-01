package hacker

import (
	"context"
	"fmt"
	"strings"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
)

type ChainPattern struct {
	Name     string
	Requires []string
	Impact   string
	Risk     float64
}

type Chainer struct {
	patterns []ChainPattern
	executed map[string]bool
}

func NewChainer() *Chainer {
	return &Chainer{
		executed: make(map[string]bool),
		// Every Requires name below is a capability an action records at
		// OriginVerified (executed evidence only). Chains built on names
		// the origin-graded model NEVER verifies were the previous
		// failure: has_cors / has_idor / has_register / has_forged_jwt
		// and the has_xss / has_admin spellings exist only as
		// remote-text hints, so those patterns could never fire and the
		// chaining subsystem was decorative. A chain is still only a
		// HYPOTHESIS assembled from verified primitives (the scanner
		// contacts nothing here) and is reported as SevInfo.
		patterns: []ChainPattern{
			{
				Name:     "RCE → Full Compromise",
				Requires: []string{"has_rce"},
				Impact:   "A command was executed on the target — remote code execution, full host compromise",
				Risk:     10.0,
			},
			{
				Name:     "SQLi → Data Exfiltration",
				Requires: []string{"has_sqli_exploit"},
				Impact:   "Differential-confirmed SQL injection can read other users' rows and dump the database",
				Risk:     9.0,
			},
			{
				Name:     "XSS → Session Hijack",
				Requires: []string{"has_xss_exploit", "has_token"},
				Impact:   "Confirmed executable XSS reflection against a live session token can steal cookies / bearer tokens",
				Risk:     8.5,
			},
			{
				Name:     "Login → Verified Admin Session",
				Requires: []string{"has_login", "has_admin_session"},
				Impact:   "A real login form plus a differential-confirmed authenticated surface means credentialed access was exercised",
				Risk:     8.5,
			},
			{
				Name:     "Secrets → Cloud Compromise",
				Requires: []string{"has_secret"},
				Impact:   "Exposed secrets (AWS keys, tokens) captured by an executed read allow cloud account compromise",
				Risk:     10.0,
			},
			{
				Name:     "Upload → RCE",
				Requires: []string{"has_upload"},
				Impact:   "A real file-upload input is the entry point for webshell / remote code execution (execution not demonstrated by this chain)",
				Risk:     9.0,
			},
			{
				Name:     "Token Reuse → Authenticated Surface",
				Requires: []string{"has_token", "has_login"},
				Impact:   "A captured session token replayed against the login-protected surface may grant access without credentials",
				Risk:     7.0,
			},
		},
	}
}

func (c *Chainer) DetectAndExecute(ctx context.Context, target string, kb *Knowledge, client *transport.Client) []Action {
	caps := kb.GetCapabilities()
	capMap := make(map[string]bool)
	verifiedCapMap := make(map[string]bool)
	for _, cp := range caps {
		capMap[cp.Name] = true
		if cp.Origin == OriginVerified {
			verifiedCapMap[cp.Name] = true
		}
	}

	var spawned []Action

	for _, p := range c.patterns {
		if c.executed[p.Name] {
			continue
		}

		// Chains describe compound compromise; they may only execute (and
		// only then be reported / scored) when every required capability is
		// backed by executed evidence, not by remote-controlled text.
		allMet := true
		for _, req := range p.Requires {
			if !verifiedCapMap[req] {
				allMet = false
				break
			}
		}
		if !allMet {
			continue
		}

		c.executed[p.Name] = true

		spawned = append(spawned, &GenericChainAction{pattern: p})
	}
	return spawned
}

func (c *Chainer) DetectChains(kb *Knowledge) []AttackChain {
	caps := kb.GetCapabilities()
	capMap := make(map[string]bool)
	for _, cp := range caps {
		if cp.Origin == OriginVerified {
			capMap[cp.Name] = true
		}
	}

	var chains []AttackChain
	for _, p := range c.patterns {
		allMet := true
		for _, req := range p.Requires {
			if !capMap[req] {
				allMet = false
				break
			}
		}
		if allMet {
			chains = append(chains, AttackChain{
				Name:      p.Name,
				Impact:    p.Impact,
				RiskScore: p.Risk,
				Target:    kb.Target(),
			})
		}
	}
	return chains
}

type GenericChainAction struct {
	pattern ChainPattern
}

func (a *GenericChainAction) Metadata() ActionMetadata {
	return ActionMetadata{
		Name:        "Chain: " + a.pattern.Name,
		Description: a.pattern.Impact,
		Priority:    1,
		Requires:    a.pattern.Requires,
		Provides:    []string{},
	}
}

func (a *GenericChainAction) Execute(ctx context.Context, target string, kb *Knowledge, client *transport.Client) ActionResult {
	// A chain pattern match is a HYPOTHESIS built from verified-input
	// capabilities: the scanner contacted nothing here. The previous
	// "SevCritical + Risk 10/10" headline was the exact report lie the
	// review called out (keyword-derived caps minting critical risk with
	// zero contacts — and with origins fixed, verified caps are executed
	// evidence; the chain still is not executed until the operator runs
	// it).
	findings := []Finding{
		{
			Type:        "chain",
			Name:        "Chain hypothesis (not executed): " + a.pattern.Name,
			Severity:    SevInfo,
			Description: a.pattern.Impact,
			Evidence:    fmt.Sprintf("Potential risk %.0f/10 if executed — capabilities met, no contact made", a.pattern.Risk),
			Details: map[string]string{
				"status":      "hypothesis",
				"requires":    strings.Join(a.pattern.Requires, ", "),
				"risk_if_run": fmt.Sprintf("%.0f", a.pattern.Risk),
			},
		},
	}
	return ActionResult{Findings: findings}
}
