package hacker

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

type S3Action struct{}

func (a *S3Action) Metadata() ActionMetadata {
	return ActionMetadata{
		Name:        "S3 Bucket Enumeration",
		Description: "Check discovered subdomains and patterns for open S3 buckets",
		Priority:    60,
		Requires:    []string{"has_subdomain"},
		Provides:    []string{"has_s3"},
	}
}

func (a *S3Action) Execute(ctx context.Context, target string, kb *Knowledge, client *transport.Client) ActionResult {
	candidates := generateBucketNames(target, kb)
	if len(candidates) > 20 {
		candidates = candidates[:20]
	}

	s3Endpoints := []string{
		"s3.amazonaws.com",
	}

	type check struct {
		url    string
		bucket string
	}

	type bucketResult struct {
		finding Finding
		bucketURL string
	}

	checks := make(chan check)
	results := make(chan bucketResult, 50)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fastClient := transport.NewClient(
				transport.WithTimeout(3*time.Second),
				transport.WithRetries(0),
			)
			defer fastClient.Close()

			for c := range checks {
				select {
				case <-ctx.Done():
					return
				default:
				}

				resp, err := fastClient.Do(ctx, &types.Request{
					Method: "GET",
					URL:    c.url,
				})
				if err != nil {
					continue
				}

				if isPublicBucket(resp) {
					results <- bucketResult{
						finding: Finding{
							Type:        "s3_public",
							Name:        fmt.Sprintf("Public S3 bucket: %s", c.bucket),
							Severity:    SevCritical,
							Description: fmt.Sprintf("Bucket %s is publicly accessible", c.bucket),
							Evidence:    c.url,
						},
						bucketURL: c.url,
					}
				}
			}
		}()
	}

	go func() {
		for _, bucket := range candidates {
			for _, endpoint := range s3Endpoints {
				select {
				case <-ctx.Done():
					close(checks)
					return
				default:
					checks <- check{
						url:    fmt.Sprintf("https://%s.%s", bucket, endpoint),
						bucket: bucket,
					}
				}
			}
		}
		close(checks)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var findings []Finding
	var spawned []Action
	for r := range results {
		findings = append(findings, r.finding)
			spawned = append(spawned, &S3DumpAction{
					bucketURL: r.bucketURL,
					bucket:    extractBucketName(r.bucketURL),
				})
	}

	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Severity > findings[j].Severity
	})

	return ActionResult{Findings: findings, Actions: spawned}
}

func generateBucketNames(target string, kb *Knowledge) []string {
	var candidates []string
	seen := make(map[string]bool)

	domain := extractDomain(target)
	name := strings.Split(domain, ".")[0]

	patterns := []string{
		name, name + "-backup", name + "-backups",
		name + "-data", name + "-files", name + "-assets",
		name + "-static", name + "-media", name + "-uploads",
		name + "-dev", name + "-test", name + "-staging",
		name + "-prod", name + "-logs", name + "-config",
		name + "-db", name + "-database", name + "-storage",
		domain, strings.ReplaceAll(domain, ".", "-"),
		"dev-" + name, "prod-" + name, "test-" + name,
		"backup-" + name, "data-" + name, "static-" + name,
	}

	caps := kb.GetCapabilities()
	for _, c := range caps {
		if c.Name == "has_subdomain" && c.Details != nil {
			if list, ok := c.Details["list"]; ok {
				for _, sd := range strings.Split(list, ", ") {
					sd = strings.TrimSpace(sd)
					sdName := strings.Split(sd, ".")[0]
					sdPatterns := []string{
						sdName, sdName + "-backup", sdName + "-data",
						sdName + "-static", sdName + "-assets",
					}
					for _, p := range sdPatterns {
						if !seen[p] {
							candidates = append(candidates, p)
							seen[p] = true
						}
					}
				}
			}
		}
	}

	for _, p := range patterns {
		if !seen[p] {
			candidates = append(candidates, p)
			seen[p] = true
		}
	}

	return candidates
}

func isPublicBucket(resp *types.Response) bool {
	if resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 307 {
		body := string(resp.Body)
		lowBody := strings.ToLower(body)
		if strings.Contains(lowBody, "listbucketresult") ||
			strings.Contains(lowBody, "contents") ||
			strings.Contains(lowBody, "<key>") ||
			strings.Contains(lowBody, "<name>") ||
			strings.Contains(lowBody, "anonymous") {
			return true
		}
		if !strings.Contains(lowBody, "accessdenied") &&
			!strings.Contains(lowBody, "access denied") &&
			!strings.Contains(lowBody, "notfound") {
			// Possible directory listing
			if len(resp.Body) > 100 && len(resp.Body) < 100000 {
				return true
			}
		}
	}
	return false
}

func extractBucketName(bucketURL string) string {
	// https://bucket-name.s3.amazonaws.com
	trimmed := strings.TrimPrefix(bucketURL, "https://")
	trimmed = strings.TrimPrefix(trimmed, "http://")
	parts := strings.SplitN(trimmed, ".", 2)
	if len(parts) > 0 {
		return parts[0]
	}
	return bucketURL
}
