package hacker

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"testing"
)

// Phase 3 — filesystem hardening regressions.

func TestReportDirPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions")
	}

	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// NewReportDir creates ./reports/<target>; chdir into a temp workspace
	// so the test never touches the repo tree.
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir tmp: %v", err)
	}
	defer func() {
		if err := os.Chdir(wd); err != nil {
			t.Errorf("restore working dir: %v", err)
		}
	}()

	rd := NewReportDir("perms.example.org")

	info, err := os.Stat(rd.BasePath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&077 != 0 {
		t.Errorf("report dir mode = %o, want no group/world bits (0700)", perm)
	}

	saved := rd.Save("sql_dump", "../evil.txt", []byte("x"))
	if saved == "" {
		t.Fatal("save failed")
	}
	if strings.Contains(saved, "evil.txt") && strings.Contains(saved, "..") {
		t.Errorf("traversal escaped the subdir: %q", saved)
	}
	full, err := os.Stat(saved)
	if err != nil {
		t.Fatal(err)
	}
	if perm := full.Mode().Perm(); perm&007 != 0 {
		t.Errorf("dump file mode = %o, want no world bits (0600)", perm)
	}
}

func TestSanitizeFilenameNeutralizesTraversalAndControl(t *testing.T) {
	got := sanitizeFilename("../../etc/passwd")
	if strings.ContainsAny(got, "/\\.") && strings.Contains(got, "..") {
		t.Errorf("traversal survived: %q", got)
	}

	got = sanitizeFilename("a/b\\c")
	if got != "a_b_c" {
		t.Errorf("separators not normalized: %q", got)
	}

	got = sanitizeFilename("file\nname\x1b[31m.txt")
	if strings.ContainsAny(got, "\n\x1b\r") {
		t.Errorf("control characters survived: %q", got)
	}

	got = sanitizeFilename(strings.Repeat("x", 300))
	if len(got) > 200 {
		t.Errorf("length not capped: %d", len(got))
	}
}

func TestOOBServerBoundedAndLoopbackPost(t *testing.T) {
	a := NewOOBAction()
	srv := a.server
	kb := NewKnowledge("example.com")
	defer srv.Stop()

	res := a.Execute(testCtx(), "", kb, nil)
	_ = res
	if !srv.IsRunning() {
		t.Fatal("server did not start")
	}
	addr := srv.listener.Addr().String()
	if !isLoopbackAddr(addr) {
		t.Fatalf("must bind loopback, got %s", addr)
	}

	// Callback flood well past the cap: storage stays bounded.
	for i := 0; i < 1010; i++ {
		resp, err := http.Post(fmt.Sprintf("http://%s/cb?flood", addr), "text/plain", strings.NewReader(strings.Repeat("A", 64)))
		if err != nil {
			t.Fatalf("callback %d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body) // drain: flood test, copy error not actionable
		_ = resp.Body.Close()
	}
	if got := len(srv.GetCallbacks()); got > oobMaxCallbacks {
		t.Errorf("callbacks unbounded: %d > %d", got, oobMaxCallbacks)
	}

	// Body cap: a 5 MiB POST must be truncated at oobMaxBodySize, not
	// buffered whole.
	huge := strings.Repeat("B", oobMaxBodySize+1024*1024)
	resp, err := http.Post(fmt.Sprintf("http://%s/huge", addr), "application/octet-stream", strings.NewReader(huge))
	if err != nil {
		t.Fatalf("huge callback: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body) // drain: test asserts truncation only
	_ = resp.Body.Close()

	cbs := srv.GetCallbacks()
	if len(cbs) == 0 {
		t.Fatal("no callback recorded")
	}
	last := cbs[len(cbs)-1]
	if len(last.Body) != oobMaxBodySize {
		t.Errorf("body length = %d, want capped %d", len(last.Body), oobMaxBodySize)
	}

	// JSON payload must remain parseable.
	b, err := json.Marshal(last)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"Path":"/huge"`) {
		t.Errorf("callback record malformed: %s", b)
	}
}
