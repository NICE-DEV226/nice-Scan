package output

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/NICE-DEV226/nice-Scan/internal/engine"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// SARIF 2.1.0 output — the interchange format GitHub Code Scanning, GitLab
// vulnerability reports and Azure DevOps consume natively. A finding here is
// the same redacted finding the JSON sink emits: SARIF is a file a pipeline
// archives and a dashboard replays, so it obeys the same masking rule.
//
// Level mapping follows the Code Scanning convention: error/warning/note.
// Provenance survives in properties — the grade ladder (proven /
// corroborated / indicated) is what makes this scanner's output different
// from a template runner's, and a CI consumer can gate on it.

type SARIFRenderer struct {
	version string
}

func NewSARIF(version string) *SARIFRenderer {
	return &SARIFRenderer{version: version}
}

type sarifReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool     `json:"tool"`
	Invocations []sarifInvoke `json:"invocations"`
	Results     []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	Name             string       `json:"name"`
	ShortDescription sarifMessage `json:"shortDescription"`
	HelpURI          string       `json:"helpUri,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifInvoke struct {
	ExecutionSuccessful bool `json:"executionSuccessful"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

// sarifLevel maps scanner severity onto the SARIF level vocabulary. Info and
// low stay "note" — Code Scanning renders them without failing checks.
func sarifLevel(s types.Severity) string {
	switch s {
	case types.SeverityCritical, types.SeverityHigh:
		return "error"
	case types.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// severityRank orders severities for --fail-on-severity. Unknown values rank
// below info so a typo'd flag can never gate on everything.
func severityRank(s types.Severity) int {
	switch s {
	case types.SeverityCritical:
		return 4
	case types.SeverityHigh:
		return 3
	case types.SeverityMedium:
		return 2
	case types.SeverityLow:
		return 1
	default:
		return 0
	}
}

// SeverityAtOrAbove reports whether the scan produced a finding at or above
// the named severity — the CI gate --fail-on-severity implements.
func SeverityAtOrAbove(findings []types.Finding, min types.Severity) (int, types.Severity) {
	threshold := severityRank(min)
	count := 0
	worst := types.SeverityInfo
	for _, f := range findings {
		if severityRank(f.Severity) >= threshold {
			count++
			if severityRank(f.Severity) > severityRank(worst) {
				worst = f.Severity
			}
		}
	}
	return count, worst
}

func (r *SARIFRenderer) Render(w io.Writer, res *engine.ScanResult) error {
	report := sarifReport{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "nice_scan",
				Version:        r.version,
				InformationURI: "https://github.com/NICE-DEV226/nice-Scan",
			}},
			Invocations: []sarifInvoke{{ExecutionSuccessful: res.Error == nil}},
			Results:     make([]sarifResult, 0, len(res.Findings)),
		}},
	}

	// Rules are keyed by finding type: one ruleId per analyzer family keeps
	// Code Scanning's rule list readable instead of one rule per finding.
	rules := map[string]sarifRule{}
	for _, f := range res.Findings {
		fd := types.RedactFinding(f)
		ruleID := string(fd.Type)
		if _, ok := rules[ruleID]; !ok {
			rules[ruleID] = sarifRule{
				ID:   ruleID,
				Name: ruleID,
				ShortDescription: sarifMessage{
					Text: fmt.Sprintf("NICE_SCAN %s finding", ruleID),
				},
			}
		}

		msg := fd.Name
		if fd.Description != "" {
			msg += "\n\n" + fd.Description
		}
		if fd.Evidence != "" {
			msg += "\n\nEvidence: " + fd.Evidence
		}

		result := sarifResult{
			RuleID:  ruleID,
			Level:   sarifLevel(fd.Severity),
			Message: sarifMessage{Text: msg},
			PartialFingerprints: map[string]string{
				// Stable across runs so Code Scanning dedups instead of
				// re-opening the same alert every pipeline execution.
				"nice_scan/v1": fingerprintOf(fd),
			},
			Properties: map[string]any{
				"severity":   string(fd.Severity),
				"confidence": fd.Confidence,
				"grade":      string(types.GradeOf(f)),
			},
		}
		if fd.Prov != nil {
			if fd.Prov.RequestURL != "" {
				result.Locations = []sarifLocation{{
					PhysicalLocation: sarifPhysical{
						ArtifactLocation: sarifArtifact{URI: types.RedactText(fd.Prov.RequestURL)},
					},
				}}
			}
			if len(fd.Prov.Methods) > 0 {
				methods := make([]string, len(fd.Prov.Methods))
				for i, m := range fd.Prov.Methods {
					methods[i] = string(m)
				}
				result.Properties["evidence_methods"] = methods
			}
			if fd.Prov.PathOrigin != "" {
				result.Properties["path_origin"] = string(fd.Prov.PathOrigin)
			}
			if fd.Prov.BaselineRef != "" {
				result.Properties["baseline_ref"] = types.RedactText(fd.Prov.BaselineRef)
			}
		}
		report.Runs[0].Results = append(report.Runs[0].Results, result)
	}

	// Deterministic rule order: map iteration would reshuffle the rules
	// array between runs and defeat SARIF diffing.
	ruleList := make([]sarifRule, 0, len(rules))
	for _, rule := range rules {
		ruleList = append(ruleList, rule)
	}
	sort.Slice(ruleList, func(i, j int) bool { return ruleList[i].ID < ruleList[j].ID })
	report.Runs[0].Tool.Driver.Rules = ruleList

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}

// fingerprintOf hashes the identity of a finding — type, name, evidence and
// the URL it was observed on — into a stable dedup key. Redacted fields are
// hashed, never stored: the fingerprint cannot leak what the report masks.
func fingerprintOf(f types.Finding) string {
	requestURL := ""
	if f.Prov != nil {
		requestURL = f.Prov.RequestURL
	}
	h := sha256.New()
	for _, part := range []string{
		string(f.Type), f.Name, f.Evidence, f.Description, requestURL,
	} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func (r *SARIFRenderer) RenderResult(res *engine.ScanResult) {
	if err := r.Render(os.Stdout, res); err != nil {
		fmt.Fprintf(os.Stderr, "SARIF render error: %v\n", err)
	}
}

// WriteSARIFFile is the file sink for --sarif: same 0600 discipline as the
// HTML reports, since the document embeds scan evidence.
func WriteSARIFFile(path string, res *engine.ScanResult, version string) error {
	var w io.Writer
	var f *os.File
	if path == "-" {
		w = os.Stdout
	} else {
		var err error
		f, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		w = f
	}
	return NewSARIF(version).Render(w, res)
}

// ValidSeverity reports whether s names a real severity — used to reject a
// typo'd --fail-on-severity before the scan burns time.
func ValidSeverity(s string) bool {
	switch types.Severity(strings.ToLower(s)) {
	case types.SeverityInfo, types.SeverityLow, types.SeverityMedium,
		types.SeverityHigh, types.SeverityCritical:
		return true
	}
	return false
}
