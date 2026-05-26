package engine

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/nice-scan/nice_scan/internal/transport"
	"github.com/nice-scan/nice_scan/internal/types"
)

type Analyzer interface {
	Name() string
	Analyze(ctx context.Context, resp *types.Response) []types.Finding
}

type Scanner struct {
	client    *transport.Client
	analyzers []Analyzer
	opts      *types.Config
	stats     ScanStats
	mu        sync.Mutex
}

type ScanStats struct {
	Target    string
	Total     int
	Completed int
	Failed    int
	Findings  int
	Workers   int
	StartTime time.Time
	Duration  time.Duration
}

type ScanResult struct {
	Target   string
	Results  []*types.Result
	Findings []types.Finding
	Stats    ScanStats
	Error    error
}

func NewScanner(cfg *types.Config, client *transport.Client) *Scanner {
	return &Scanner{
		client: client,
		opts:   cfg,
	}
}

func (s *Scanner) RegisterAnalyzer(a Analyzer) {
	s.analyzers = append(s.analyzers, a)
}

func (s *Scanner) RegisterAnalyzers(analyzers ...Analyzer) {
	s.analyzers = append(s.analyzers, analyzers...)
}

func (s *Scanner) Scan(ctx context.Context, targets []string) *ScanResult {
	result := &ScanResult{}
	var allResults []*types.Result

	reqs := make([]*types.Request, 0, len(targets))
	for _, target := range targets {
		reqs = append(reqs, &types.Request{
			Method:  "GET",
			URL:     target,
			Timeout: s.opts.Timeout,
		})

		reqs = append(reqs, s.buildProbes(target)...)
	}

	s.mu.Lock()
	s.stats = ScanStats{
		StartTime: time.Now(),
		Total:     len(reqs),
		Target:    formatTargets(targets),
		Workers:   s.opts.Workers,
	}
	s.mu.Unlock()

	results := make(chan *types.Result, len(reqs))

	go s.client.DoBatch(ctx, reqs, results, s.opts.Workers)

	findingMap := make(map[string]types.Finding)

	for res := range results {
		s.mu.Lock()
		if res.Error != nil {
			s.stats.Failed++
		} else {
			s.stats.Completed++
		}
		s.mu.Unlock()

		allResults = append(allResults, res)

		if res.Response != nil {
			findings := s.analyzeResponse(ctx, res.Response)
			res.Findings = findings
			for _, f := range findings {
				key := f.Name
				if existing, ok := findingMap[key]; ok {
					if existing.Evidence != f.Evidence {
						existing.Evidence = existing.Evidence + " | " + f.Evidence
					}
					if f.Confidence > existing.Confidence {
						existing.Confidence = f.Confidence
					}
					findingMap[key] = existing
				} else {
					findingMap[key] = f
				}
			}
		}
	}

	allFindings := make([]types.Finding, 0, len(findingMap))
	for _, f := range findingMap {
		allFindings = append(allFindings, f)
	}

	s.mu.Lock()
	s.stats.Duration = time.Since(s.stats.StartTime)
	s.stats.Findings = len(allFindings)
	stats := s.stats
	s.mu.Unlock()

	result.Target = formatTargets(targets)
	result.Results = allResults
	result.Findings = allFindings
	result.Stats = stats

	return result
}

func (s *Scanner) buildProbes(target string) []*types.Request {
	if s.opts == nil {
		return nil
	}

	probes := []string{
		"/robots.txt",
		"/sitemap.xml",
		"/.env",
		"/.git/config",
		"/admin",
		"/api",
	}

	var reqs []*types.Request
	baseURL := target

	for _, path := range probes {
		reqs = append(reqs, &types.Request{
			Method:  "GET",
			URL:     baseURL + path,
			Timeout: s.opts.Timeout,
		})
	}

	return reqs
}

func (s *Scanner) analyzeResponse(ctx context.Context, resp *types.Response) []types.Finding {
	var findings []types.Finding

	for _, analyzer := range s.analyzers {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		func() {
			defer func() {
				if r := recover(); r != nil {
					slog.Warn("analyzer panicked",
						"analyzer", analyzer.Name(),
						"panic", r,
					)
				}
			}()

			fs := analyzer.Analyze(ctx, resp)
			findings = append(findings, fs...)
		}()
	}

	return findings
}

func (s *Scanner) Close() error {
	return s.client.Close()
}

func formatTargets(targets []string) string {
	if len(targets) == 1 {
		return targets[0]
	}
	return fmt.Sprintf("%s (%d targets)", targets[0], len(targets))
}
