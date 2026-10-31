package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// Phase 6 — exposure analyzer proof gate.
//
// The audit found that a status code plus a size was treated as proof, so a
// catch-all SPA answering 200 with a few KB of HTML produced "Exposed Backup
// File — High" and "Exposed .gitignore — Medium" on ordinary sites. These
// tests pin the new rule: a finding needs file-format or content proof, and
// an HTML error page is never proof.

func exposureResp(rawURL string, body string) *types.Response {
	return &types.Response{
		StatusCode: 200,
		RequestURL: rawURL,
		Body:       []byte(body),
		BodySize:   int64(len(body)),
	}
}

func b64pad(s string, n int) string {
	return s + strings.Repeat("A", n)
}

// soft404Body mimics what a modern SPA/all-in-one handler returns for any
// unknown path — including the words a naive pattern would match on.
func soft404Body(path string) string {
	return `<!DOCTYPE html><html lang="en"><head><title>App</title>` +
		`<meta charset="utf-8"></head><body><div id="root"></div>` +
		`<script src="/static/js/main.js"></script>` +
		`<p>Requested ` + path + ` was not found — PASSWORD=see-below API_KEY=placeholder</p>` +
		`</body></html>` + b64pad("", 2000)
}

func TestExposureSoft404IsNeverAHighBackupFinding(t *testing.T) {
	a := NewExposureAnalyzer()
	fs := a.Analyze(context.Background(), exposureResp("https://app.example.com/backup.zip", soft404Body("/backup.zip")))
	if len(fs) != 0 {
		t.Fatalf("a 200 HTML catch-all page is not a backup file: %+v", fs)
	}
}

func TestExposureRealZipIsReportedWithItsProof(t *testing.T) {
	a := NewExposureAnalyzer()
	body := append([]byte{'P', 'K', 0x03, 0x04}, []byte(b64pad("zipcontent", 2000))...)
	fs := a.Analyze(context.Background(), exposureResp("https://app.example.com/backup.zip", string(body)))

	if len(fs) != 1 {
		t.Fatalf("expected the real archive to be reported, got %+v", fs)
	}
	if fs[0].Name != "Exposed Backup File" || fs[0].Severity != types.SeverityHigh {
		t.Fatalf("unexpected finding: %+v", fs[0])
	}
	if !strings.Contains(fs[0].Evidence, "PK") {
		t.Errorf("evidence must carry the format proof, got %q", fs[0].Evidence)
	}
}

func TestExposureSoft404IsNeverAnEnvOrGitFinding(t *testing.T) {
	a := NewExposureAnalyzer()
	for _, path := range []string{"/.env", "/.git/config", "/.gitignore", "/static/js/main.js.map"} {
		fs := a.Analyze(context.Background(), exposureResp("https://app.example.com"+path, soft404Body(path)))
		if len(fs) != 0 {
			t.Errorf("%s: catch-all HTML page produced %+v", path, fs)
		}
	}
}

func TestExposureRealEnvIsReported(t *testing.T) {
	a := NewExposureAnalyzer()
	body := "APP_ENV=production\nDB_PASSWORD=hunter2\nAPI_KEY=abc123\n# comment\n"
	fs := a.Analyze(context.Background(), exposureResp("https://app.example.com/.env", body))

	if len(fs) != 1 || fs[0].Name != "Exposed .env File" || fs[0].Severity != types.SeverityCritical {
		t.Fatalf("a dotenv file with credential keys must be Critical, got %+v", fs)
	}
}

func TestExposureEnvWithSecretWordsButNoAssignmentIsQuiet(t *testing.T) {
	a := NewExposureAnalyzer()
	// Words match the secret bimap, but nothing is assigned: this is prose,
	// not a dotenv file.
	fs := a.Analyze(context.Background(), exposureResp("https://app.example.com/.env",
		"Set API_KEY and DB_PASSWORD in your environment before running the app.\n"))
	if len(fs) != 0 {
		t.Fatalf("prose mentioning secret keys is not an exposed .env: %+v", fs)
	}
}

func TestExposureRealGitConfigIsReported(t *testing.T) {
	a := NewExposureAnalyzer()
	body := "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
	fs := a.Analyze(context.Background(), exposureResp("https://app.example.com/.git/config", body))
	if len(fs) != 1 || fs[0].Name != "Exposed .git Directory" {
		t.Fatalf("a real .git/config must be reported, got %+v", fs)
	}
}

func TestExposureQueryStringDoesNotHideThePath(t *testing.T) {
	a := NewExposureAnalyzer()
	body := "DB_PASSWORD=hunter2\n"
	fs := a.Analyze(context.Background(), exposureResp("https://app.example.com/.env?v=2", body))
	if len(fs) != 1 {
		t.Fatalf("a query string must not defeat path matching, got %+v", fs)
	}
}

func TestDirectoryListingIsStillProvenByContent(t *testing.T) {
	a := NewExposureAnalyzer()
	body := `<html><head><title>Index of /files</title></head><body><h1>Index of /files</h1><a href="../">Parent Directory</a></body></html>`
	fs := a.Analyze(context.Background(), exposureResp("https://app.example.com/files/", body))
	if len(fs) != 1 || fs[0].Name != "Directory Listing Enabled" {
		t.Fatalf("a real directory index must be reported, got %+v", fs)
	}
}

func TestExposureUnrelatedPathIsIgnored(t *testing.T) {
	a := NewExposureAnalyzer()
	body := "[core]\n\trepositoryformatversion = 0\n"
	fs := a.Analyze(context.Background(), exposureResp("https://app.example.com/blog/post", body))
	if len(fs) != 0 {
		t.Fatalf("path matching must be anchored to the pattern path, got %+v", fs)
	}
}

// TestScanEndToEndProvesExposures runs the real Scanner (probe building +
// transport + analyzer) against a catch-all server: the .env probe must be
// reported, the /backup.zip probe must not be, and the probe itself must
// actually go out — a pattern nothing requests can never be a false positive
// but is dead weight, which is how the old .gitignore check shipped.
func TestScanEndToEndProvesExposures(t *testing.T) {
	var (
		mu     sync.Mutex
		probed []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		probed = append(probed, r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/.env":
			_, _ = w.Write([]byte("APP_ENV=production\nDB_PASSWORD=hunter2\n"))
		default:
			// Catch-all: 200 HTML for every path the site does not own.
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(soft404Body(r.URL.Path)))
		}
	}))
	defer srv.Close()

	client := transport.NewClient(transport.WithRetries(0), transport.WithTimeout(5*time.Second))
	defer func() { _ = client.Close() }()

	scanner := NewScanner(&types.Config{Workers: 4, Timeout: 5 * time.Second, FollowRedirects: true}, client)
	scanner.RegisterAnalyzers(NewExposureAnalyzer())
	res := scanner.Scan(context.Background(), []string{srv.URL})

	hasEnv, hasBackup := false, false
	for _, f := range res.Findings {
		switch f.Name {
		case "Exposed .env File":
			hasEnv = true
		case "Exposed Backup File", "Exposed .gitignore":
			hasBackup = true
		}
	}
	if !hasEnv {
		t.Errorf("real .env not reported through the full scan path; findings: %+v", res.Findings)
	}
	if hasBackup {
		t.Errorf("catch-all 200 page reported as an exposed file: %+v", res.Findings)
	}

	mu.Lock()
	defer mu.Unlock()
	sawBackupProbe := false
	for _, p := range probed {
		if p == "/backup.zip" {
			sawBackupProbe = true
		}
	}
	if !sawBackupProbe {
		t.Error("/backup.zip pattern exists but the scanner never probes it")
	}
}

// TestExposurePatternsRequireProof is the invariant behind this whole file:
// every built-in pattern proves itself from the response body. A pattern
// that only checks status/size cannot distinguish the real file from a
// catch-all page and must not ship.
func TestExposurePatternsRequireProof(t *testing.T) {
	a := NewExposureAnalyzer()
	for _, p := range a.patterns {
		if len(p.MagicPrefix) > 0 || len(p.BodyPattern) > 0 {
			continue
		}
		t.Errorf("pattern %q has no body proof (magic or content signature); status+size is not evidence", p.Name)
	}
}

func TestExposurePatternsRejectTheirOwnSoft404(t *testing.T) {
	a := NewExposureAnalyzer()
	// Every built-in pattern must stay silent when a catch-all handler
	// answers the probe path with an HTML page.
	for _, p := range a.patterns {
		resp := exposureResp("https://app.example.com"+p.Path, soft404Body(p.Path))
		for _, f := range a.Analyze(context.Background(), resp) {
			if f.Metadata["path"] != p.Path {
				continue
			}
			t.Errorf("pattern %q fired on a catch-all HTML page: %+v", p.Name, f)
		}
	}
}
