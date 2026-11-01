package hacker

import (
	"os"
	"path/filepath"
	"testing"
)

// Artifact collision: two findings saving under the same name used to
// overwrite each other silently — the first finding's Evidence then pointed
// at the second one's bytes.

func TestReportDirSaveKeepsDistinctArtifacts(t *testing.T) {
	rd := NewReportDir("http://collision.test")
	t.Cleanup(func() { _ = os.RemoveAll(rd.Base()) })

	first := rd.Save("cmd_output", "id.txt", []byte("uid=1000(first)"))
	second := rd.Save("cmd_output", "id.txt", []byte("uid=1000(second)"))

	if first == "" || second == "" {
		t.Fatalf("saves must return their paths: %q %q", first, second)
	}
	if first == second {
		t.Fatalf("second save reused the first path: %s", first)
	}
	a, _ := os.ReadFile(first)
	b, _ := os.ReadFile(second)
	if string(a) != "uid=1000(first)" || string(b) != "uid=1000(second)" {
		t.Fatalf("evidence overwritten: first=%q second=%q", a, b)
	}
	if filepath.Ext(first) != filepath.Ext(second) {
		t.Fatalf("uniquifier must sit before the extension: %s vs %s", first, second)
	}
}
