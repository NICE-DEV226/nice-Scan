package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/engine"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// The TUI renders remote-controlled strings (finding names/descriptions,
// replayed request targets) on the operator's terminal. Like the other
// render sinks (output/terminal, hacker/brain, main.go), it must never emit
// raw escape sequences — these tests pin the sanitization at the sink.
func containsStr(s, sub string) bool { return strings.Contains(s, sub) }

func assertSanitized(t *testing.T, out string) {
	t.Helper()
	for _, bad := range []string{
		"\x1b",             // ESC (CSI/OSC intros)
		"\x9b",             // C1 CSI
		"\x8e",             // C1 SS2
		"\u202e",           // bidi RLO
		"\u0000", "\u0007", // C0
	} {
		if containsStr(out, bad) {
			t.Fatalf("render sink leaked control sequence %q;\noutput:\n%q", bad, out)
		}
	}
}

func maliciousFinding() types.Finding {
	return types.Finding{
		Type:        "xss",
		Name:        "\x1b]0;EVIL\x07XSS\u202e" + "name" + "\x9b31m",
		Severity:    "high",
		Description: "\x1b[2;1Hdesc\u9b40x" + "\u202e" + "desc",
		Metadata:    map[string]string{"k": "\x1b[5Dmeta"},
	}
}

func TestRenderFindingsSummaryStripsInjection(t *testing.T) {
	m := NewModel(nil, []string{"example.com"})
	m.state = stateDone
	m.Update(scanEventMsg(engine.ScanEvent{
		Findings: []types.Finding{maliciousFinding()},
		Stats:    engine.ScanStats{Completed: 1, Total: 1},
	}))

	out := m.renderFindingsSummary()
	if !containsStr(out, "name") || !containsStr(out, "desc") {
		t.Fatalf("sanitized content missing from findings summary:\n%q", out)
	}
	assertSanitized(t, out)
}

func TestSummaryRendersNothingForEmptyFindings(t *testing.T) {
	m := NewModel(nil, []string{"example.com"})
	m.state = stateDone
	if out := m.renderFindingsSummary(); !containsStr(out, "No findings") {
		t.Fatalf("empty findings should render the muted placeholder, got %q", out)
	}
}

func TestRequestLogEntriesAreSanitized(t *testing.T) {
	m := NewModel(nil, []string{"example.com"})
	m.Update(scanEventMsg(engine.ScanEvent{
		Result: &types.Result{
			Target:   "\x1b[30;1Htarget" + "\u202e" + "/redirect",
			Response: &types.Response{StatusCode: 302},
			Duration: 5 * 1e6, // 5ms
		},
		Stats: engine.ScanStats{Completed: 1, Total: 1},
	}))

	out := m.renderEventLog()
	if !containsStr(out, "302") {
		t.Fatalf("status code missing from event log:\n%q", out)
	}
	m.state = stateRunning
	assertSanitized(t, out)
	assertSanitized(t, m.View()) // running-state full render (header+stats+log+progress)
}

func TestRequestLogCapsAtFifty(t *testing.T) {
	m := NewModel(nil, []string{"example.com"})
	for i := 0; i < 55; i++ {
		m.Update(scanEventMsg(engine.ScanEvent{
			Result: &types.Result{
				Target:   "example.com",
				Response: &types.Response{StatusCode: 200},
			},
			Stats: engine.ScanStats{Completed: i + 1, Total: 60},
		}))
	}
	if len(m.requestLog) != 50 {
		t.Fatalf("request log cap = %d, want 50", len(m.requestLog))
	}
	// Newest entries survive the rotation.
	if last := m.requestLog[len(m.requestLog)-1]; !containsStr(last, "example.com (200)") {
		t.Fatalf("newest entry lost after rotation: %q", last)
	}
}

func TestProgressClampsAboveOneHundred(t *testing.T) {
	m := NewModel(nil, []string{"example.com"})
	m.Update(scanEventMsg(engine.ScanEvent{
		Stats: engine.ScanStats{Completed: 42, Total: 40}, // over-completed stats must not panic the bar
	}))
	out := m.renderProgress()
	assertSanitized(t, out)
}

// -i scans quit on completion (or instant, fully-failed failure) and the
// alt screen is torn down; PostRunSummary is the only durable outcome the
// operator sees. These tests pin its three explanations.
func TestPostRunSummaryExplainsAllFailed(t *testing.T) {
	m := NewModel(nil, []string{"example.com"})
	m.stats = engine.ScanStats{Total: 42, Failed: 42, Duration: 3 * time.Second}
	out := m.PostRunSummary()

	if !containsStr(out, "Requests 0/42 completed") || !containsStr(out, "42 failed") {
		t.Fatalf("stats line missing/incorrect:\n%q", out)
	}
	if !containsStr(out, "Every request failed") {
		t.Fatalf("fully-failed scan must get an explicit unreachable verdict:\n%q", out)
	}
	assertSanitized(t, out)
}

func TestPostRunSummaryReportsError(t *testing.T) {
	m := NewModel(nil, []string{"example.com"})
	m.err = fmt.Errorf("proxy refused connection")
	out := m.PostRunSummary()

	if !containsStr(out, "Scan error: proxy refused connection") {
		t.Fatalf("error verdict missing:\n%q", out)
	}
	assertSanitized(t, out)
}

func TestPostRunSummaryMarksOperatorCancel(t *testing.T) {
	m := NewModel(nil, []string{"example.com"})
	m.quitting = true
	out := m.PostRunSummary()

	if !containsStr(out, "canceled by operator") {
		t.Fatalf("operator-cancel verdict missing:\n%q", out)
	}
}

func TestPostRunSummaryCarriesFindingsCounts(t *testing.T) {
	m := NewModel(nil, []string{"example.com"})
	m.stats = engine.ScanStats{Total: 8, Completed: 8}
	m.findings = []types.Finding{{Name: "Sqli"}, {Name: "Cors"}}
	out := m.PostRunSummary()

	if !containsStr(out, "2 findings") {
		t.Fatalf("finding count missing:\n%q", out)
	}
	if !containsStr(out, "Requests 8/8 completed") {
		t.Fatalf("completed stats missing:\n%q", out)
	}
}

// A transport-level failure carries a nil Result.Response; dereferencing
// StatusCode panicked the bubbletea event loop — the whole dashboard was
// torn down mid-scan ("program was killed: program experienced a panic").
// Any unreachable/dead target hit this on its first failed request.
func TestUpdateFailedRequestEventSurvives(t *testing.T) {
	m := NewModel(nil, []string{"example.com"})
	m.state = stateRunning

	failed := engine.ScanEvent{
		Result: &types.Result{Target: "http://127.0.0.1:1", Duration: 3 * time.Millisecond},
		Stats:  engine.ScanStats{Total: 2, Failed: 1},
	}
	if _, _ = m.Update(scanEventMsg(failed)); len(m.requestLog) != 1 {
		t.Fatalf("failed request must still be logged, log=%q", m.requestLog)
	}
	if !containsStr(m.requestLog[0], "failed") || !containsStr(m.requestLog[0], "127.0.0.1:1") {
		t.Fatalf("failed-request entry lacks target/verdict: %q", m.requestLog[0])
	}

	success := engine.ScanEvent{
		Result: &types.Result{Target: "http://127.0.0.1:1", Duration: time.Millisecond,
			Response: &types.Response{StatusCode: 404}},
		Stats: engine.ScanStats{Total: 2, Completed: 1},
	}
	if _, _ = m.Update(scanEventMsg(success)); !containsStr(m.requestLog[1], "404") {
		t.Fatalf("successful-request entry lacks status code: %q", m.requestLog[1])
	}
	assertSanitized(t, m.View())
}
