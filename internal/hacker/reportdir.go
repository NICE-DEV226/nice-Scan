package hacker

import (
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
)

type ReportDir struct {
	mu       sync.Mutex
	BasePath string
	Target   string
}

func NewReportDir(target string) *ReportDir {
	name := extractDomain(target)
	safeName := strings.ReplaceAll(name, ":", "_")
	safeName = strings.ReplaceAll(safeName, "/", "_")
	safeName = strings.ReplaceAll(safeName, ".", "_")

	base := filepath.Join("reports", safeName)
	rd := &ReportDir{
		BasePath: base,
		Target:   target,
	}
	rd.ensureDirs()
	return rd
}

func (rd *ReportDir) ensureDirs() {
	dirs := []string{
		rd.BasePath,
		filepath.Join(rd.BasePath, "sql_dump"),
		filepath.Join(rd.BasePath, "lfi_files"),
		filepath.Join(rd.BasePath, "cmd_output"),
		filepath.Join(rd.BasePath, "s3_dump"),
		filepath.Join(rd.BasePath, "shells"),
		filepath.Join(rd.BasePath, "crawl_auth"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0700); err != nil {
			slog.Warn("reportdir: mkdir failed", "dir", d, "error", err)
		}
	}
}

// sanitizeFilename strips path separators, traversal sequences, control
// characters and caps the length. Content-derived names (S3 keys, file
// params) previously flowed in raw.
func sanitizeFilename(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r == '/' || r == '\\':
			b.WriteRune('_')
		case r == '.':
			b.WriteRune(r) // '..' collapses handled below via traversal check
		case r < 0x20 || r == 0x7F:
			b.WriteRune('_') // control chars (incl. CR/LF naming tricks)
		default:
			b.WriteRune(r)
		}
	}
	out := strings.ReplaceAll(b.String(), "..", "_")
	if len(out) > 200 {
		out = out[:200]
	}
	if out == "" || out == "." {
		out = "unnamed"
	}
	return out
}

func (rd *ReportDir) Save(subdir, name string, data []byte) string {
	return rd.save(subdir, sanitizeFilename(name), data)
}

func (rd *ReportDir) SaveWithPrefix(subdir, prefix, name string, data []byte) string {
	return rd.save(subdir, sanitizeFilename(prefix+"_"+sanitizeFilename(name)), data)
}

// save writes extracted content with least-permissive modes: files 0600,
// directories 0700. Dump artifacts (password hashes, exfiltrated files,
// credential blobs) sitting world-readable in ./reports leaked sensitive
// evidence to every local user with a permissive umask (audit finding
// reports-dir-writes). Errors are logged, not silently dropped.
func (rd *ReportDir) save(subdir, name string, data []byte) string {
	rd.mu.Lock()
	defer rd.mu.Unlock()

	// Defense in depth: the sanitized name must never escape the subdir.
	if path.IsAbs(name) || strings.Contains(name, "..") {
		slog.Warn("reportdir: refusing suspicious filename", "name", name)
		return ""
	}

	fullPath := filepath.Join(rd.BasePath, subdir, name)
	if err := rd.ensureDirsFor(subdir); err != nil {
		slog.Warn("reportdir: cannot create directory", "dir", filepath.Join(rd.BasePath, subdir), "error", err)
		return ""
	}
	if err := os.WriteFile(fullPath, data, 0600); err != nil {
		slog.Warn("reportdir: write failed", "path", fullPath, "error", err)
		return ""
	}
	return fullPath
}

func (rd *ReportDir) ensureDirsFor(subdir string) error {
	return os.MkdirAll(filepath.Join(rd.BasePath, subdir), 0700)
}

// ensureDirs creates the standard extraction layout on construction.

func (rd *ReportDir) Base() string {
	return rd.BasePath
}

func (rd *ReportDir) GenerateSummary() string {
	var totalFiles int
	var totalBytes int64

	_ = filepath.Walk(rd.BasePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			totalFiles++
			totalBytes += info.Size()
		}
		return nil
	})

	return fmt.Sprintf("%d files extracted (%.1f KB) in %s",
		totalFiles, float64(totalBytes)/1024, rd.BasePath)
}

func (rd *ReportDir) ListFiles(subdir string) []string {
	var files []string
	dir := filepath.Join(rd.BasePath, subdir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if !e.IsDir() {
			files = append(files, e.Name())
		}
	}
	return files
}
