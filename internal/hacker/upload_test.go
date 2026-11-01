package hacker

import (
	"bytes"
	"context"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
)

// The whole point of the multipart rewrite: a spec-compliant server must be
// able to parse the file back out. The old raw-body + top-level
// Content-Disposition produced nothing a real handler could read.
func TestMultipartFileBodyRoundTripsThroughStdlib(t *testing.T) {
	body, ctype, err := multipartFileBody("file", "x.php", "application/x-php", "MARKER-CONTENT",
		map[string]string{"desc": "hello"})
	if err != nil {
		t.Fatalf("builder error: %v", err)
	}
	mt, params, err := mime.ParseMediaType(ctype)
	if err != nil || mt != "multipart/form-data" || params["boundary"] == "" {
		t.Fatalf("Content-Type not a multipart with boundary: %q", ctype)
	}

	br := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	form, err := br.ReadForm(1 << 20)
	if err != nil {
		t.Fatalf("stdlib could not parse our upload body: %v", err)
	}
	defer func() { _ = form.RemoveAll() }()

	if got := form.Value["desc"]; len(got) != 1 || got[0] != "hello" {
		t.Errorf("text field not carried: %v", form.Value)
	}
	fh := form.File["file"]
	if len(fh) != 1 {
		t.Fatalf("file part not parsed as a file: %v", form.File)
	}
	if fh[0].Filename != "x.php" {
		t.Errorf("filename lost: %q", fh[0].Filename)
	}
	opened, err := fh[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = opened.Close() }()
	data, _ := io.ReadAll(opened)
	if string(data) != "MARKER-CONTENT" {
		t.Errorf("file bytes not carried: %q", data)
	}
}

// retrieveUploadMarker must report the stored URL ONLY when the marker is
// actually served back — the executed read that grounds the upload claim.
func TestRetrieveUploadMarkerRequiresReadBack(t *testing.T) {
	stored := func(store map[string]string, mu *sync.Mutex) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" {
				_ = r.ParseMultipartForm(1 << 20)
				fh := r.MultipartForm.File["file"]
				if len(fh) == 0 {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				opened, err := fh[0].Open()
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				defer func() { _ = opened.Close() }()
				data, _ := io.ReadAll(opened)
				mu.Lock()
				store[fh[0].Filename] = string(data)
				mu.Unlock()
				w.WriteHeader(http.StatusOK)
				return
			}
			name := strings.TrimPrefix(r.URL.Path, "/uploads/")
			mu.Lock()
			content, ok := store[name]
			mu.Unlock()
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(content))
		}
	}

	t.Run("stored_and_served", func(t *testing.T) {
		store := map[string]string{}
		srv := httptest.NewServer(stored(store, &sync.Mutex{}))
		defer srv.Close()
		client := transport.NewClient(transport.WithRetries(0), transport.WithTimeout(10*time.Second))
		defer func() { _ = client.Close() }()

		marker := uploadMarker()
		url, ok := retrieveUploadMarker(context.Background(), client, srv.URL+"/file-upload", "test.php", "application/x-php", marker)
		if !ok || !strings.HasSuffix(url, "/uploads/test.php") {
			t.Fatalf("marker was served back but retrieval failed: %q %v", url, ok)
		}
	})

	t.Run("accepted_but_not_retrievable", func(t *testing.T) {
		// Endpoint returns 200 to the POST but never serves the file: the
		// old code called this "SevCritical upload vulnerable". The honest
		// answer is "not retrieved".
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()
		client := transport.NewClient(transport.WithRetries(0), transport.WithTimeout(10*time.Second))
		defer func() { _ = client.Close() }()

		if _, ok := retrieveUploadMarker(context.Background(), client, srv.URL+"/file-upload", "test.php", "application/x-php", uploadMarker()); ok {
			t.Fatal("200-with-no-served-file must not count as a retrieved upload")
		}
	})
}

// End-to-end through UploadAction: a page carrying a file parameter, against
// a store-and-serve backend, yields the confirmed (Medium, never Critical)
// upload finding and hands WebShellAction real POST/origin URLs.
func TestUploadActionConfirmedVerdictIsMediumAndSpawnsRealShell(t *testing.T) {
	var mu sync.Mutex
	store := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			_ = r.ParseMultipartForm(1 << 20)
			if r.MultipartForm == nil || len(r.MultipartForm.File["file"]) == 0 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			fh := r.MultipartForm.File["file"][0]
			opened, _ := fh.Open()
			data, _ := io.ReadAll(opened)
			_ = opened.Close()
			mu.Lock()
			store[fh.Filename] = string(data)
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/uploads/")
		mu.Lock()
		content, ok := store[name]
		mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(content))
	}))
	defer srv.Close()

	_, kb := kbForTest(srv.URL)
	// URL must satisfy hasFileParam ("file" substring) — a crawled upload page.
	kb.AddPage(Page{URL: srv.URL + "/file-upload", Status: 200})
	client := transport.NewClient(transport.WithRetries(0), transport.WithTimeout(10*time.Second))
	defer func() { _ = client.Close() }()

	a := &UploadAction{}
	res := a.Execute(context.Background(), srv.URL, kb, client)

	var confirmed bool
	for _, f := range res.Findings {
		if f.Type == "upload_confirmed" {
			confirmed = true
			if f.Severity == SevCritical {
				t.Errorf("a stored+servable file is not by itself RCE; must not be Critical: %+v", f)
			}
		}
	}
	if !confirmed {
		t.Fatalf("servable upload must confirm, got %+v", res.Findings)
	}
	if len(res.Actions) != 1 {
		t.Fatalf("expected exactly one spawned WebShellAction, got %d", len(res.Actions))
	}
	ws, ok := res.Actions[0].(*WebShellAction)
	if !ok {
		t.Fatalf("spawned action is not a WebShellAction: %T", res.Actions[0])
	}
	if ws.vulnURL == "" || ws.uploadURL == "" {
		t.Errorf("spawned shell must carry real POST + origin URLs, got %+v", ws)
	}
}
