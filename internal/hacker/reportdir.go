package hacker

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
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
		os.MkdirAll(d, 0755)
	}
}

func (rd *ReportDir) Save(subdir, name string, data []byte) string {
	rd.mu.Lock()
	defer rd.mu.Unlock()

	safeName := strings.ReplaceAll(name, "/", "_")
	safeName = strings.ReplaceAll(safeName, "\\", "_")
	safeName = strings.ReplaceAll(safeName, "..", "_")

	fullPath := filepath.Join(rd.BasePath, subdir, safeName)
	os.WriteFile(fullPath, data, 0644)
	return fullPath
}

func (rd *ReportDir) SaveWithPrefix(subdir, prefix, name string, data []byte) string {
	rd.mu.Lock()
	defer rd.mu.Unlock()

	safeName := strings.ReplaceAll(name, "/", "_")
	safeName = strings.ReplaceAll(safeName, "\\", "_")
	safeName = strings.ReplaceAll(safeName, "..", "_")

	fullPath := filepath.Join(rd.BasePath, subdir, prefix+"_"+safeName)
	os.WriteFile(fullPath, data, 0644)
	return fullPath
}

func (rd *ReportDir) Base() string {
	return rd.BasePath
}

func (rd *ReportDir) GenerateSummary() string {
	var totalFiles int
	var totalBytes int64

	filepath.Walk(rd.BasePath, func(path string, info os.FileInfo, err error) error {
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

func generateReportFilename() string {
	return fmt.Sprintf("reports/attack_%s.html", time.Now().Format("20060102_150405"))
}
