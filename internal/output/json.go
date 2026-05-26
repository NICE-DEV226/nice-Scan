package output

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/nice-scan/nice_scan/internal/engine"
)

type JSONRenderer struct {
	indent bool
}

func NewJSON() *JSONRenderer {
	return &JSONRenderer{indent: true}
}

type JSONOutput struct {
	Version  string            `json:"version"`
	Target   string            `json:"target"`
	Stats    JSONStats         `json:"stats"`
	Findings []JSONFinding     `json:"findings"`
	Results  []JSONResult      `json:"results,omitempty"`
}

type JSONStats struct {
	Total     int    `json:"total"`
	Completed int    `json:"completed"`
	Failed    int    `json:"failed"`
	Findings  int    `json:"findings"`
	Duration  string `json:"duration"`
}

type JSONFinding struct {
	Type        string            `json:"type"`
	Name        string            `json:"name"`
	Severity    string            `json:"severity"`
	Description string            `json:"description"`
	Evidence    string            `json:"evidence,omitempty"`
	Confidence  float64           `json:"confidence"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

type JSONResult struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Duration   string `json:"duration"`
	Error      string `json:"error,omitempty"`
}

func (r *JSONRenderer) RenderResult(res *engine.ScanResult) {
	output := JSONOutput{
		Version: "0.1.0",
		Target:  res.Target,
		Stats: JSONStats{
			Total:     res.Stats.Total,
			Completed: res.Stats.Completed,
			Failed:    res.Stats.Failed,
			Findings:  res.Stats.Findings,
			Duration:  res.Stats.Duration.String(),
		},
		Findings: make([]JSONFinding, 0, len(res.Findings)),
		Results:  make([]JSONResult, 0, len(res.Results)),
	}

	for _, f := range res.Findings {
		output.Findings = append(output.Findings, JSONFinding{
			Type:        string(f.Type),
			Name:        f.Name,
			Severity:    string(f.Severity),
			Description: f.Description,
			Evidence:    f.Evidence,
			Confidence:  f.Confidence,
			Metadata:    f.Metadata,
		})
	}

	for _, r := range res.Results {
		jr := JSONResult{
			URL:        r.Target,
			Duration:   r.Duration.String(),
		}
		if r.Response != nil {
			jr.StatusCode = r.Response.StatusCode
		}
		if r.Error != nil {
			jr.Error = r.Error.Error()
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
		fmt.Fprintf(os.Stderr, "JSON marshal error: %v\n", err)
		return
	}

	fmt.Fprintln(os.Stdout, string(data))
}
