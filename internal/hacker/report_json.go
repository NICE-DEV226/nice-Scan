package hacker

import (
	"encoding/json"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// RenderJSONReport is the machine sink for a hack run. It is the counterpart
// of RenderHTMLReport: findings go through the same redaction rule, and every
// credential is masked (username filtered, password replaced by its length).
// A report that leaves the process cannot carry a live secret.
func RenderJSONReport(r *Report) ([]byte, error) {
	safe := *r
	safe.Findings = make([]Finding, len(r.Findings))
	for i, f := range r.Findings {
		safe.Findings[i] = redactFinding(f)
	}
	safe.Credentials = make([]Credential, len(r.Credentials))
	for i, c := range r.Credentials {
		c.Username = types.RedactText(c.Username)
		c.Password = types.MaskSecret(c.Password)
		safe.Credentials[i] = c
	}

	return json.MarshalIndent(safe, "", "  ")
}
