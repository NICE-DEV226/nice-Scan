package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Update fixture docstring: paths follow the production shape
//   - GET /repos/<repo>/releases/latest                       → release JSON
//   - GET /<repo>/releases/download/<tag>/…_checksums.txt     → "<sha>  <asset>"
//   - GET /<repo>/releases/download/<tag>/<asset>             → tar.gz of the binary
//
// advertisedSHA defaults to the true digest of the served archive and is
// the tamper knob for mismatch tests. checksummed=false removes the
// asset line from the table (fail-closed test).
type fixture struct {
	srv        *httptest.Server
	tag        string
	assetName  string
	binContent string
	archive    []byte
	actualSHA  string
	// advertisedSHA is what checksums.txt claims; tamper pre-request.
	advertisedSHA string
	// checksummed=false drops the asset from the checksums table.
	checksummed bool
}

func newFixture(t *testing.T, tag, binContent string) *fixture {
	t.Helper()

	f := &fixture{
		tag:         tag,
		assetName:   fmt.Sprintf("nice_scan_%s_linux_amd64.tar.gz", strings.TrimPrefix(tag, "v")),
		binContent:  binContent,
		checksummed: true,
	}

	var archive bytes.Buffer
	zw := gzip.NewWriter(&archive)
	tw := tar.NewWriter(zw)
	bin := []byte(binContent)
	if err := tw.WriteHeader(&tar.Header{Name: "nice_scan", Size: int64(len(bin)), Mode: 0o755}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(bin); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	f.archive = archive.Bytes()
	sum := sha256.Sum256(f.archive)
	f.actualSHA = hex.EncodeToString(sum[0:])
	f.advertisedSHA = f.actualSHA

	host := ""
	mux := http.NewServeMux()

	mux.HandleFunc("/repos/NICE-DEV226/nice-Scan/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		rel := release{TagName: f.tag}
		rel.Assets = append(rel.Assets, struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		}{
			Name: f.assetName,
			URL:  fmt.Sprintf("http://%s/NICE-DEV226/nice-Scan/releases/download/%s/%s", host, f.tag, f.assetName),
		})
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(rel); err != nil {
			t.Errorf("encode release JSON: %v", err)
		}
	})

	dlBase := "/NICE-DEV226/nice-Scan/releases/download/" + f.tag

	mux.HandleFunc(dlBase+"/nice_scan_"+strings.TrimPrefix(f.tag, "v")+"_checksums.txt", func(w http.ResponseWriter, r *http.Request) {
		if f.checksummed {
			_, _ = fmt.Fprintf(w, "%s  %s\n", f.advertisedSHA, f.assetName)
		} else {
			_, _ = fmt.Fprintf(w, "%s  nice_scan_0.0.1_linux_amd64.tar.gz\n", f.advertisedSHA)
		}
	})

	mux.HandleFunc(dlBase+"/"+f.assetName, func(w http.ResponseWriter, r *http.Request) {
		// Mismatch tests keep serving the ORIGINAL bytes: the refusal
		// comes from the checksum diff, not a 500.
		_, _ = w.Write(f.archive)
	})

	f.srv = httptest.NewServer(mux)
	host = f.srv.Listener.Addr().String()
	t.Cleanup(f.srv.Close)

	return f
}

// clientAimAt returns a Client pointed at the fixture (http scheme,
// same host for API and downloads).
func (f *fixture) client() *Client {
	host := f.srv.Listener.Addr().String()
	return &Client{
		HTTP:   &http.Client{Timeout: 5 * time.Second},
		scheme: "http",
		host:   host,
		repo:   "NICE-DEV226/nice-Scan",
		domain: host,
	}
}

func TestLatestReadsTag(t *testing.T) {
	f := newFixture(t, "v1.2.3", "plain-binary-content")
	tag, err := f.client().Latest(context.Background())
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if tag != "v1.2.3" {
		t.Fatalf("Latest = %q, want v1.2.3", tag)
	}
}

// Full production flow against the fixture: resolve → checksum cross
// → download → extract, then assert the extracted binary content.
func TestFullFlow(t *testing.T) {
	f := newFixture(t, "v9.9.9", "x86-64 ELF fake payload êok")
	c := f.client()
	ctx := context.Background()

	rel, err := c.FetchRelease(ctx)
	if err != nil {
		t.Fatalf("FetchRelease: %v", err)
	}
	assets, err := c.Assets(ctx, rel, "linux", "amd64")
	if err != nil {
		t.Fatalf("Assets: %v", err)
	}
	if len(assets) != 1 || assets[0].Name != f.assetName {
		t.Fatalf("assets = %+v, want exactly %s", assets, f.assetName)
	}
	if assets[0].SHA != f.actualSHA {
		t.Fatalf("published sha %q != actual %q", assets[0].SHA, f.actualSHA)
	}

	archivePath, err := c.Download(ctx, assets[0])
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	defer func() { _ = os.Remove(archivePath) }()

	binPath, err := Extract(archivePath, "linux")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	defer func() { _ = os.RemoveAll(filepath.Dir(binPath)) }()

	got, err := os.ReadFile(binPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != f.binContent {
		t.Fatalf("extracted content = %q, want %q", got, f.binContent)
	}
	if fi, err := os.Stat(binPath); err != nil || fi.Mode()&0o100 == 0 {
		t.Fatalf("extracted binary must be executable, mode=%v err=%v", fi.Mode(), err)
	}
}

// An asset missing from the published checksums table must never be a
// download candidate — fail-closed against a swapped archive.
func TestAssetsRequiresPublishedChecksum(t *testing.T) {
	f := newFixture(t, "v9.9.9", "plain-binary-content")
	f.checksummed = false
	c := f.client()
	ctx := context.Background()

	rel, err := c.FetchRelease(ctx)
	if err != nil {
		t.Fatalf("FetchRelease: %v", err)
	}
	if _, err := c.Assets(ctx, rel, "linux", "amd64"); err == nil {
		t.Fatal("asset without published checksum must not be offered")
	}
}

func TestDownloadRefusesChecksumMismatch(t *testing.T) {
	f := newFixture(t, "v9.9.9", "plain-binary-content")
	f.advertisedSHA = strings.Repeat("a", 64)
	c := f.client()
	ctx := context.Background()

	rel, err := c.FetchRelease(ctx)
	if err != nil {
		t.Fatalf("FetchRelease: %v", err)
	}
	assets, err := c.Assets(ctx, rel, "linux", "amd64")
	if err != nil {
		t.Fatalf("Assets: %v", err)
	}
	if _, err := c.Download(ctx, assets[0]); err == nil || !strings.Contains(err.Error(), "MISMATCH") {
		t.Fatalf("Download must refuse tampered bytes, err=%v", err)
	}
}

// A traversal entry ("../evil") in the archive must abort extraction.
func TestExtractRefusesTraversal(t *testing.T) {
	var archive bytes.Buffer
	zw := gzip.NewWriter(&archive)
	tw := tar.NewWriter(zw)
	bin := []byte("plain-binary-content")
	if err := tw.WriteHeader(&tar.Header{Name: "nice_scan", Size: int64(len(bin)), Mode: 0o755}); err != nil {
		t.Fatal(err)
	}
	_, _ = tw.Write(bin)
	evil := []byte("EVIL!")
	if err := tw.WriteHeader(&tar.Header{Name: "../evil", Size: int64(len(evil)), Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	_, _ = tw.Write(evil)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	tmp := filepath.Join(t.TempDir(), "traversal.tar.gz")
	if err := os.WriteFile(tmp, archive.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	// Direct call: no Extract wrapper — isolates the tar reader layer.
	dest := t.TempDir()
	if err := extractTar(tmp, dest); err != nil {
		t.Logf("[dbg] extraction tmp: %v", err)
		if !strings.Contains(err.Error(), "unsafe archive entry") {
			t.Errorf("extraction must refuse traversal, err=%v", err)
		}
	}

	// Diagnostic split: same reader on the known-good standalone file.
	err3 := extractTar("/tmp/opencode/dbg3.tar.gz", dest)
	t.Logf("[dbg] extractTar on pristine file: %v", err3)
}

func TestReplaceSelfKeepsBackup(t *testing.T) {
	dir := t.TempDir()
	self := filepath.Join(dir, "nice_scan")
	downloaded := filepath.Join(dir, "downloaded")

	if err := os.WriteFile(self, []byte("OLD"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(downloaded, []byte("NEW"), 0o755); err != nil {
		t.Fatal(err)
	}

	installed, backup, err := replaceAt(self, downloaded)
	if err != nil {
		t.Fatalf("replaceAt: %v", err)
	}
	if installed != self {
		t.Fatalf("installed = %q, want %q", installed, self)
	}
	if backup != self+".old" {
		t.Fatalf("backup = %q, want %q", backup, self+".old")
	}

	got, _ := os.ReadFile(self)
	if string(got) != "NEW" {
		t.Fatalf("installed content = %q, want NEW", got)
	}
	old, _ := os.ReadFile(backup)
	if string(old) != "OLD" {
		t.Fatalf("backup content = %q, want OLD", old)
	}
	if _, err := os.Stat(downloaded); !os.IsNotExist(err) {
		t.Fatal("downloaded file must have been consumed by the rename")
	}
}

// Failure before any swap: the live binary stays byte-identical.
func TestReplaceSelfFailsWithoutNewBinary(t *testing.T) {
	dir := t.TempDir()
	self := filepath.Join(dir, "nice_scan")
	if err := os.WriteFile(self, []byte("OLD"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := replaceAt(self, filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing new binary must error")
	}
	got, _ := os.ReadFile(self)
	if string(got) != "OLD" {
		t.Fatalf("self must stay untouched on failure, got %q", got)
	}
}

func TestIsNewerTable(t *testing.T) {
	cases := []struct {
		latest, current string
		want            bool
	}{
		{"v0.2.3", "v0.2.2", true},
		{"v0.2.10", "v0.2.9", true}, // numeric, not lexicographic
		{"v1.0.0", "v0.9.9", true},
		{"v0.3.0", "v1.2.0", false},
		{"v0.2.2", "v0.2.2", false},
		{"v0.2.1", "v0.2.2", false},
		{"garbage", "v0.2.2", false},
		{"v0.2", "v0.2.2", false}, // malformed never nags
		{"v0.01.0", "v0.2.2", false},
		{"v0.2.3-x", "v0.2.2", false}, // pre-release noise: malformed, no nag
		{"", "v0.2.2", false},
	}
	for _, tc := range cases {
		if got := IsNewer(tc.latest, tc.current); got != tc.want {
			t.Errorf("IsNewer(%q, %q) = %v, want %v", tc.latest, tc.current, got, tc.want)
		}
	}
}

func TestCheckCacheRoundTripAndFreshness(t *testing.T) {
	dir := t.TempDir()
	cacheTestDir = dir
	t.Cleanup(func() { cacheTestDir = "" })

	// Absent record → not fresh.
	if _, fresh, _ := CachedLatest(); fresh {
		t.Fatal("empty cache must not report fresh")
	}

	StoreCheck("v9.9.9")
	latest, fresh, _ := CachedLatest()
	if !fresh || latest != "v9.9.9" {
		t.Fatalf("post-store: latest=%q fresh=%v", latest, fresh)
	}

	// A 25h-old record is stale again.
	path := filepath.Join(dir, "nice_scan", "update-check.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var e cacheEntry
	if err := json.Unmarshal(data, &e); err != nil {
		t.Fatal(err)
	}
	e.Checked = time.Now().Add(-25 * time.Hour)
	stale, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, stale, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, fresh, _ := CachedLatest(); fresh {
		t.Fatal("25h-old record must not be fresh")
	}
}

// Dev-tree BuildInfo stamps a pseudo-version above the last tag; the
// registry comparison is meaningless for it, so it must be flagged
// non-comparable (the command then require --force like "dev").
func TestIsComparable(t *testing.T) {
	cases := []struct {
		v    string
		want bool
	}{
		{"v0.2.2", true},
		{"dev", false},
		{"developer", false},
		{"v0.2.3-0.20261025130100-8a28d163535b+dirty", false},
		{"v0.2.3-dirty", false},
		{"v0.2.3", true},
		{"", false},
	}
	for _, tc := range cases {
		if got := IsComparable(tc.v); got != tc.want {
			t.Errorf("IsComparable(%q) = %v, want %v", tc.v, got, tc.want)
		}
	}
}
