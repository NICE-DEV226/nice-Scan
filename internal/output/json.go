package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/NICE-DEV226/nice-Scan/internal/engine"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

type JSONRenderer struct {
	indent bool
}

func NewJSON() *JSONRenderer {
	return &JSONRenderer{indent: true}
}

type JSONOutput struct {
	Version  string        `json:"version"`
	Target   string        `json:"target"`
	Stats    JSONStats     `json:"stats"`
	Findings []JSONFinding `json:"findings"`
	Results  []JSONResult  `json:"results,omitempty"`
}

type JSONStats struct {
	Total     int `json:"total"`
	Completed int `json:"completed"`
	Failed    int `json:"failed"`
	// Refused is how many requests the scope boundary rejected. A consumer
	// that sees Failed alone cannot tell "target unreachable" from "scan
	// never went anywhere", and would read an empty findings list as clean.
	Refused  int    `json:"refused"`
	Findings int    `json:"findings"`
	Duration string `json:"duration"`
}

type JSONFinding struct {
	Type        string            `json:"type"`
	Name        string            `json:"name"`
	Severity    string            `json:"severity"`
	Description string            `json:"description"`
	Evidence    string            `json:"evidence,omitempty"`
	Confidence  float64           `json:"confidence"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	// Prov is how the finding was earned, and Grade is the ladder a consumer
	// ranks on. This sink is the one a script or a model reads without a human
	// reviewing the bytes first, so it is where provenance pays for itself —
	// a terminal reader can weigh "0.9 confidence" against the evidence in
	// front of them; an automated consumer has only these fields.
	Prov  *types.Provenance `json:"prov,omitempty"`
	Grade string            `json:"grade"`
}

type JSONResult struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Duration   string `json:"duration"`
	Error      string `json:"error,omitempty"`
}

// Render writes the machine-readable report to w. RenderResult is the
// os.Stdout convenience around it: a sink that hard-codes its writer cannot be
// tested against a buffer, and a sink that cannot be tested is a sink whose
// masking is assumed.
func (r *JSONRenderer) Render(w io.Writer, res *engine.ScanResult) error {
	output := JSONOutput{
		Version: "0.1.0",
		Target:  types.RedactText(res.Target),
		Stats: JSONStats{
			Total:     res.Stats.Total,
			Completed: res.Stats.Completed,
			Failed:    res.Stats.Failed,
			Refused:   res.Stats.Refused,
			Findings:  res.Stats.Findings,
			Duration:  res.Stats.Duration.String(),
		},
		Findings: make([]JSONFinding, 0, len(res.Findings)),
		Results:  make([]JSONResult, 0, len(res.Results)),
	}

	for _, f := range res.Findings {
		// RedactFinding, not the raw finding: every other sink in this tool
		// prints a report someone is looking at. This one recopies Evidence
		// and Metadata verbatim unless it is told not to.
		fd := types.RedactFinding(f)
		output.Findings = append(output.Findings, JSONFinding{
			Type:        string(fd.Type),
			Name:        fd.Name,
			Severity:    string(fd.Severity),
			Description: fd.Description,
			Evidence:    fd.Evidence,
			Confidence:  fd.Confidence,
			Metadata:    fd.Metadata,
			Prov:        fd.Prov,
			Grade:       string(types.GradeOf(f)),
		})
	}

	for _, r := range res.Results {
		jr := JSONResult{
			URL:      types.RedactText(r.Target),
			Duration: r.Duration.String(),
		}
		if r.Response != nil {
			jr.StatusCode = r.Response.StatusCode
		}
		if r.Error != nil {
			// A transport error quotes the URL it failed on, and that URL is
			// whatever the operator or the target wrote.
			jr.Error = types.RedactText(r.Error.Error())
		}
		output.Results = append(output.Results, jr)
	}

	var (
		data []byte
		err  error
	)

	if r.indent {
		data, err = json.MarshalIndent(output, "", "  ")
	} else {
		data, err = json.Marshal(output)
	}

	if err != nil {
		return err
	}

	_, err = fmt.Fprintln(w, string(data))
	return err
}

func (r *JSONRenderer) RenderResult(res *engine.ScanResult) {
	if err := r.Render(os.Stdout, res); err != nil {
		fmt.Fprintf(os.Stderr, "JSON render error: %v\n", err)
	}
}
