package engine

import (
	"strings"
	"testing"
	"time"
)

const testSpecYAML = `
openapi: 3.0.0
info: {title: t, version: "1"}
paths:
  /users/{id}:
    get:
      parameters:
        - {name: fields, in: query, required: true}
    post:
      description: state-changing — must never be probed
  /orders:
    get: {}
  /admin/panel:
    get: {}
`

func TestOpenAPIRequestsExpandsPaths(t *testing.T) {
	reqs, err := openAPIRequests("https://api.example.com", []byte(testSpecYAML), 5*time.Second)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := map[string]string{}
	for _, r := range reqs {
		got[r.Method+" "+r.URL] = r.Method
	}

	want := []string{
		"GET https://api.example.com/admin/panel",
		"GET https://api.example.com/orders",
		"GET https://api.example.com/users/1?fields=test",
	}
	for _, w := range want {
		if _, ok := got[w]; !ok {
			t.Errorf("missing probe %q (have %v)", w, got)
		}
	}
	// The POST operation must never become a probe: replaying it
	// unauthenticated would be a state change nobody consented to.
	for m := range got {
		if strings.HasPrefix(m, "POST") {
			t.Errorf("state-changing method leaked into probes: %q", m)
		}
	}
	for _, r := range reqs {
		if r.Origin != "observed" {
			t.Errorf("spec-derived probe must carry observed origin, got %q", r.Origin)
		}
	}
}

func TestOpenAPIRequestsRejectsEmptySpec(t *testing.T) {
	for _, bad := range []string{"", "not: a spec", "paths: {}"} {
		if _, err := openAPIRequests("https://t.example", []byte(bad), time.Second); err == nil {
			t.Errorf("spec %q must be rejected", bad)
		}
	}
}

func TestOpenAPIJSONSpec(t *testing.T) {
	// JSON is valid YAML — one decoder covers both encodings.
	spec := `{"paths":{"/ping":{"get":{}},"/items/{id}":{"get":{}}}}`
	reqs, err := openAPIRequests("https://t.example", []byte(spec), time.Second)
	if err != nil {
		t.Fatalf("json spec: %v", err)
	}
	if len(reqs) != 2 {
		t.Fatalf("json spec produced %d probes, want 2", len(reqs))
	}
}
