package engine

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
	"gopkg.in/yaml.v3"
)

// Grey-box probing from a supplied OpenAPI document.
//
// A spec the operator hands us is declared intent: these paths exist and
// these parameters matter. Feeding them into the normal probe pipeline
// gives coverage a crawler cannot reach (SPAs whose routes live in JS
// bundles, APIs with no HTML surface at all) without changing how any
// finding is proven — the analyzers still judge each response on its own
// evidence.
//
// Safety boundary: only read-only methods become probes. A spec can declare
// POST /admin/delete-users; replaying that unauthenticated would be a
// state-changing request the operator never consented to, so non-GET/HEAD
// operations are skipped entirely.

const openapiMaxProbes = 150

var rxPathParam = regexp.MustCompile(`\{([^}/]+)\}`)

// openAPIMethods is the read-only allow-list, keyed lowercase.
var openAPIMethods = map[string]bool{
	"get": true, "head": true, "options": true,
}

type openAPIParam struct {
	Name     string `json:"name" yaml:"name"`
	In       string `json:"in" yaml:"in"`
	Required bool   `json:"required" yaml:"required"`
}

type openAPIOperation struct {
	Parameters []openAPIParam `json:"parameters" yaml:"parameters"`
	// Other fields (responses, requestBody…) are deliberately ignored:
	// we only need the address of the surface, not its contract.
}

// openAPIRequests parses spec (JSON or YAML — yaml.Unmarshal accepts both)
// and returns probe requests for target. Path parameters get the benign
// value "1" (the most likely to resolve to a real object); required query
// parameters get "test". Paths are sorted and capped so a huge spec cannot
// flood the worker pool.
func openAPIRequests(target string, spec []byte, timeout time.Duration) ([]*types.Request, error) {
	var doc struct {
		Paths map[string]map[string]yaml.Node `yaml:"paths"`
	}
	if err := yaml.Unmarshal(spec, &doc); err != nil {
		return nil, fmt.Errorf("openapi: parse spec: %w", err)
	}
	if len(doc.Paths) == 0 {
		return nil, fmt.Errorf("openapi: spec declares no paths")
	}

	base := strings.TrimRight(target, "/")
	paths := make([]string, 0, len(doc.Paths))
	for p := range doc.Paths {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var reqs []*types.Request
	for _, p := range paths {
		if len(reqs) >= openapiMaxProbes {
			break
		}
		// A path item may be an absolute URL in exotic specs; only its
		// path component is ours to probe — the target supplies the host.
		pathPart := p
		if strings.Contains(p, "://") {
			if u, err := url.Parse(p); err == nil && u.Path != "" {
				pathPart = u.Path
			}
		}
		concrete := rxPathParam.ReplaceAllString(pathPart, "1")

		for method, node := range doc.Paths[p] {
			if !openAPIMethods[strings.ToLower(method)] {
				continue // never replay a state-changing method unauthenticated
			}
			if len(reqs) >= openapiMaxProbes {
				break
			}
			var op openAPIOperation
			if err := node.Decode(&op); err != nil {
				continue
			}

			var b strings.Builder
			b.WriteString(base)
			b.WriteString(concrete)
			var qs []string
			for _, prm := range op.Parameters {
				if prm.In == "query" && prm.Required {
					qs = append(qs, prm.Name+"=test")
				}
			}
			if len(qs) > 0 {
				b.WriteString("?")
				b.WriteString(strings.Join(qs, "&"))
			}
			reqs = append(reqs, &types.Request{
				Method:  strings.ToUpper(method),
				URL:     b.String(),
				Timeout: timeout,
				Origin:  types.PathObserved, // the spec declared it, not our wordlist
			})
		}
	}
	return reqs, nil
}

// loadOpenAPIRequests reads the spec file. A missing or malformed spec
// degrades to zero probes — the flag is an accelerator, never a hard
// dependency of the scan, and the operator sees the count in verbose mode.
func (s *Scanner) loadOpenAPIRequests(target, path string) []*types.Request {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	reqs, err := openAPIRequests(target, data, s.opts.Timeout)
	if err != nil {
		return nil
	}
	return reqs
}
