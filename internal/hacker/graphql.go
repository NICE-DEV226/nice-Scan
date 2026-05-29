package hacker

import (
	"context"
	"fmt"
	"strings"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

type GraphQLAction struct{}

func (a *GraphQLAction) Metadata() ActionMetadata {
	return ActionMetadata{
		Name:        "GraphQL Inspector",
		Description: "Introspection, schema dump, mutation fuzzing",
		Priority:    55,
		Requires:    []string{"has_graphql"},
		Provides:    []string{"has_graphql_schema"},
	}
}

func (a *GraphQLAction) Execute(ctx context.Context, target string, kb *Knowledge, client *transport.Client) ActionResult {
	var findings []Finding
	var spawned []Action

	endpoints := kb.GetEndpoints()
	var graphqlEPs []string

	for _, ep := range endpoints {
		if strings.Contains(ep.Path, "graphql") || strings.Contains(ep.ContentType, "graphql") {
			graphqlEPs = append(graphqlEPs, ep.Path)
		}
	}

	if len(graphqlEPs) == 0 {
		pages := kb.GetPages()
		for _, p := range pages {
			if strings.Contains(p.URL, "graphql") {
				graphqlEPs = append(graphqlEPs, p.URL)
			}
		}
	}

	if len(graphqlEPs) == 0 {
		candidates := []string{"/graphql", "/api/graphql", "/graph", "/gql", "/v1/graphql", "/v2/graphql"}
		for _, c := range candidates {
			testURL := strings.TrimRight(target, "/") + c
			resp, err := client.Do(ctx, &types.Request{
				Method: "POST",
				URL:    testURL,
				Headers: map[string]string{"Content-Type": "application/json"},
				Body:   []byte(`{"query":"{__typename}"}`),
			})
			if err == nil && resp.StatusCode == 200 {
				graphqlEPs = append(graphqlEPs, testURL)
			}
		}
	}

	for _, ep := range graphqlEPs {
		schema, err := graphqlIntrospect(ctx, client, ep)
		if err == nil && schema != "" {
			findings = append(findings, Finding{
				Type:        "graphql_schema",
				Name:        fmt.Sprintf("GraphQL schema exposed at %s", ep),
				Severity:    SevHigh,
				Description: "Introspection enabled — full schema available",
				Evidence:    truncateString(schema, 500),
			})

			mutations := extractMutations(schema)
			if len(mutations) > 0 {
				findings = append(findings, Finding{
					Type:        "graphql_mutations",
					Name:        fmt.Sprintf("GraphQL mutations: %s", strings.Join(mutations, ", ")),
					Severity:    SevHigh,
					Description: "Mutations allow data modification",
					Evidence:    strings.Join(mutations, ", "),
				})

				spawned = append(spawned, &GraphQLMutateAction{
					endpoint:  ep,
					mutations: mutations,
				})
			}
		}
	}

	if len(graphqlEPs) > 0 && len(findings) == 0 {
		findings = append(findings, Finding{
			Type:        "graphql_no_introspect",
			Name:        "GraphQL endpoint found but introspection disabled",
			Severity:    SevMedium,
			Description: fmt.Sprintf("Try field-level fuzzing at %s", graphqlEPs[0]),
		})
	}

	return ActionResult{Findings: findings, Actions: spawned}
}

type GraphQLMutateAction struct {
	endpoint  string
	mutations []string
}

func (a *GraphQLMutateAction) Metadata() ActionMetadata {
	return ActionMetadata{
		Name:        "GraphQL Mutation Fuzzer",
		Description: "Test mutations for privilege escalation and IDOR",
		Priority:    56,
		Requires:    []string{},
		Provides:    []string{},
	}
}

func (a *GraphQLMutateAction) Execute(ctx context.Context, target string, kb *Knowledge, client *transport.Client) ActionResult {
	return ActionResult{
		Findings: []Finding{
			{
				Type:        "graphql_mutation_poc",
				Name:        "GraphQL mutation fuzzing ready",
				Severity:    SevCritical,
				Description: fmt.Sprintf("Mutations to test: %s", strings.Join(a.mutations, ", ")),
				Evidence:    a.endpoint,
			},
		},
	}
}

func graphqlIntrospect(ctx context.Context, client *transport.Client, endpoint string) (string, error) {
	introQuery := `{"query":"query { __schema { types { name fields { name type { name kind } } } } }"}`
	resp, err := client.Do(ctx, &types.Request{
		Method:  "POST",
		URL:     endpoint,
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    []byte(introQuery),
	})
	if err != nil {
		return "", err
	}

	body := string(resp.Body)
	if strings.Contains(body, "__schema") || strings.Contains(body, "types") {
		return body, nil
	}

	introQuery2 := `{"query":"{__schema{types{name fields{name type{name kind}}}}}"}`
	resp2, err := client.Do(ctx, &types.Request{
		Method:  "POST",
		URL:     endpoint,
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    []byte(introQuery2),
	})
	if err != nil {
		return "", err
	}
	return string(resp2.Body), nil
}

func truncateString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "..."
}

func extractMutations(schema string) []string {
	var mutations []string
	seen := make(map[string]bool)
	lowSchema := strings.ToLower(schema)

	mutationIdx := strings.Index(lowSchema, "mutation")
	if mutationIdx == -1 {
		return nil
	}

	fieldIdx := strings.Index(lowSchema[mutationIdx:], "field")
	for fieldIdx != -1 {
		start := mutationIdx + fieldIdx + 5
		start = strings.IndexByte(schema[start:], '{')
		if start == -1 {
			break
		}
		start += mutationIdx + fieldIdx + 5

		nameStart := start + 1
		nameEnd := strings.IndexAny(schema[nameStart:], " \n({")
		if nameEnd == -1 {
			break
		}
		name := schema[nameStart : nameStart+nameEnd]
		name = strings.TrimSpace(name)

		if !seen[name] && name != "" && !strings.HasPrefix(name, "__") {
			seen[name] = true
			mutations = append(mutations, name)
		}

		remaining := schema[start:]
		fieldIdx = strings.Index(strings.ToLower(remaining), "field")
		if fieldIdx == -1 {
			break
		}
		mutationIdx = start + strings.Index(strings.ToLower(schema[start:]), "field")
		fieldIdx = 0
	}
	return mutations
}
