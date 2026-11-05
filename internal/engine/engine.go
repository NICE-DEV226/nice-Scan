package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/detect"
	"github.com/NICE-DEV226/nice-Scan/internal/fingerprint"
	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

type Analyzer interface {
	Name() string
	Analyze(ctx context.Context, resp *types.Response) []types.Finding
}

type Scanner struct {
	client    *transport.Client
	analyzers []Analyzer
	opts      *types.Config
	// canary is this scan's unique reflection token: XSS probes embed it
	// and the XSS analyzer renders opinions only when it round-trips.
	canary string
	// stacks holds the per-target server-side profile classified from the
	// homepage BEFORE any path probe fires; buildProbes conditions on it.
	stacks map[string]fingerprint.Stack
	stats  ScanStats
	mu     sync.Mutex
}

type ScanStats struct {
	Target    string
	Total     int
	Completed int
	Failed    int
	// Refused counts the requests the scope boundary rejected before
	// anything went on the wire. It is separated from Failed because the two
	// mean opposite things to the operator: "the target did not answer" and
	// "the tool never went there". Collapsing them lets a refused scan read
	// as a clean target.
	Refused   int
	Findings  int
	Workers   int
	StartTime time.Time
	Duration  time.Duration
}

type ScanResult struct {
	Target        string
	Results       []*types.Result
	Findings      []types.Finding
	Stats         ScanStats
	Error         error
	AnalyzerNames []string
	// Stacks is the fingerprint-first detail: what the target said it
	// runs, and whether family-specific probes were conditioned on it.
	Stacks []StackReport
}

// StackReport surfaces the conditioning decision to every renderer: the
// operator sees WHICH stack was read from WHICH headers before judging
// why /phpinfo.php was not probed.
type StackReport struct {
	Target      string
	Techs       []string
	Detail      string
	Server      string
	Conditioned bool
}

func NewScanner(cfg *types.Config, client *transport.Client) *Scanner {
	return &Scanner{
		client: client,
		opts:   cfg,
		canary: detect.NewCanary(),
		stacks: map[string]fingerprint.Stack{},
	}
}

// XSSCanary exposes this scan's unique probe token so XSS analyzers can be
// built against exactly the token the probes embed.
func (s *Scanner) XSSCanary() string { return s.canary }

// SeedStack supplies a stack classified EARLIER in the session (shell
// commands, repeated scans of one target): a KNOWN stack skips phase-1's
// homepage GET entirely — the fingerprint condition lives across the whole
// session, not per command. An unknown cached stack is re-read: one cheap
// GET beats conditioning on nothing.
func (s *Scanner) SeedStack(target string, st fingerprint.Stack) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stacks == nil {
		s.stacks = map[string]fingerprint.Stack{}
	}
	if _, exists := s.stacks[target]; !exists {
		s.stacks[target] = st
	}
}

// Stacks copies out the per-target classified stacks (session cache feed).
func (s *Scanner) Stacks() map[string]fingerprint.Stack {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]fingerprint.Stack, len(s.stacks))
	for k, v := range s.stacks {
		out[k] = v
	}
	return out
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

	events := make(chan ScanEvent, 100)
	go s.ScanStream(ctx, targets, events)

	var allFindings []types.Finding

	for evt := range events {
		if evt.Result != nil {
			allResults = append(allResults, evt.Result)
		}
		if evt.Findings != nil {
			allFindings = append(allFindings, evt.Findings...)
		}
		if evt.Done {
			result.Target = evt.Stats.Target
			result.Stats = evt.Stats
			result.Findings = evt.Findings
		}
	}

	result.Results = allResults
	if result.Findings == nil {
		result.Findings = allFindings
	}

	result.AnalyzerNames = make([]string, len(s.analyzers))
	for i, a := range s.analyzers {
		result.AnalyzerNames[i] = a.Name()
	}

	s.mu.Lock()
	for target, st := range s.stacks {
		result.Stacks = append(result.Stacks, StackReport{
			Target:      target,
			Techs:       st.Techs,
			Detail:      st.String(),
			Server:      st.Server,
			Conditioned: st.Known(),
		})
	}
	s.mu.Unlock()

	return result
}

// Baseline performs the single honest GET a target must be read through before
// anything is aimed at it: the homepage response, the stack classified from it,
// and what the registered analyzers make of that one exchange, merged and
// stamped with the same provenance a full scan uses.
//
// It generates no path probes. A caller deciding what to aim at NEXT needs the
// cheapest true read of what the target is, not fifty guesses about what it
// might have — and a response compared to nothing must not be handed a
// differential grade, so the stamp gets an empty baseline.
func (s *Scanner) Baseline(ctx context.Context, target string) (*types.Result, []types.Finding) {
	req := &types.Request{Method: "GET", URL: target, Timeout: s.opts.Timeout, Origin: types.PathObserved}
	resp, err := s.client.Do(ctx, req)
	res := &types.Result{Target: target, Request: req, Response: resp, Error: err}
	if err != nil || resp == nil {
		return res, nil
	}

	s.mu.Lock()
	s.stacks[target] = fingerprint.Classify(resp)
	s.mu.Unlock()

	findings := s.analyzeResponse(ctx, resp)
	stampProvenance(req, resp, findings, "")

	byName := make(map[string]types.Finding, len(findings))
	var merged []types.Finding
	for _, f := range findings {
		if existing, ok := byName[f.Name]; ok {
			byName[f.Name] = mergeFinding(existing, f)
			continue
		}
		byName[f.Name] = f
		merged = append(merged, f)
	}
	res.Findings = merged
	return res, merged
}

// stackProbe is a path probe tagged with the server-side family it only
// makes sense for; family "" means stack-agnostic and always fires.
type stackProbe struct {
	path   string
	family string
}

func (s *Scanner) buildProbes(target string, st fingerprint.Stack) []*types.Request {
	if s.opts == nil {
		return nil
	}

	pathProbes := []stackProbe{
		{"/robots.txt", ""},
		{"/sitemap.xml", ""},
		{"/.env", ""},
		{"/.git/config", ""},
		{"/admin", ""},
		{"/admin/login", ""},
		{"/administrator", fingerprint.FamPHP}, // Joomla-era panel; PHP-only
		{"/login", ""},
		{"/wp-admin", fingerprint.FamWP},
		{"/wp-login.php", fingerprint.FamWP},
		{"/api", ""},
		{"/api/v1", ""},
		{"/api/v2", ""},
		{"/graphql", ""},
		{"/.well-known/security.txt", ""},
		{"/config.json", ""},
		{"/backup", ""},
		{"/backup.zip", ""},
		{"/phpinfo.php", fingerprint.FamPHP},
		{"/info.php", fingerprint.FamPHP},
		{"/debug", ""},
		{"/actuator/health", fingerprint.FamJava},
		{"/actuator/env", fingerprint.FamJava},
		{"/actuator/info", fingerprint.FamJava},
		// swagger-ui / api-docs are shared by Spring AND FastAPI — generic.
		{"/swagger-ui", ""},
		{"/api-docs", ""},
		{"/register", ""},
		{"/signup", ""},
		{"/forgot-password", ""},
		{"/reset-password", ""},
		// Source maps: the ExposureAnalyzer proves them by content, but a
		// pattern never REQUESTED is a pattern that never fires. The CRA
		// layout alone was probed historically, so a Vue/Vite/Webpack app
		// serving maps at the root or /assets never got checked.
		{"/static/js/main.js.map", ""},
		{"/main.js.map", ""},
		{"/assets/index.js.map", ""},
	}

	var reqs []*types.Request
	// Trim a trailing slash so "/admin" concatenations do not become
	// "http://host//admin": an operator who typed "https://target/" (or a
	// crawler-normalized base) otherwise probes a double-slash path that most
	// servers 404 or redirect, silently dropping every path probe.
	baseURL := strings.TrimRight(target, "/")

	for _, p := range pathProbes {
		if !st.Allows(p.family) {
			continue
		}
		reqs = append(reqs, &types.Request{
			Method:  "GET",
			URL:     baseURL + p.path,
			Timeout: s.opts.Timeout,
		})
	}

	// CORS probes
	reqs = append(reqs, &types.Request{
		Method:  "GET",
		URL:     baseURL + "/",
		Headers: map[string]string{"Origin": corsProbeOrigin},
		Timeout: s.opts.Timeout,
		Origin:  types.PathObserved,
	})

	// HTTP Methods probe
	reqs = append(reqs, &types.Request{
		Method:  "OPTIONS",
		URL:     baseURL + "/",
		Timeout: s.opts.Timeout,
		Origin:  types.PathObserved,
	})

	// SQLi probes — common parameter names. The value is the same constant
	// the analyzer matches against, so the probe and its attribution cannot
	// drift apart.
	sqliParams := []string{"id", "q", "search", "page", "name", "user", "cat", "prod", "order", "pid"}

	// XSS probes — canary-tagged reflection shapes. The XSS analyzer
	// renders opinions only when this scan's canary comes back through
	// the wire; there is no keyword matching on foreign pages.
	for _, xp := range detect.XssProbes(s.canary) {
		for _, p := range sqliParams {
			reqs = append(reqs, &types.Request{
				Method:  "GET",
				URL:     baseURL + "/?" + p + "=" + url.QueryEscape(xp.Value),
				Timeout: s.opts.Timeout,
				Origin:  types.PathObserved,
			})
		}
	}

	for _, p := range sqliParams {
		reqs = append(reqs, &types.Request{
			Method:  "GET",
			URL:     baseURL + "/?" + p + "=" + url.QueryEscape(sqliProbePayload),
			Timeout: s.opts.Timeout,
			Origin:  types.PathObserved,
		})
	}

	// Nothing in this function came from the target: every path and every
	// parameter name is the scanner's own hypothesis. Stamping that here, on
	// the way out, is what keeps a hypothesis from being reported with the
	// same confidence as something the site advertised. A probe anchored on
	// the operator's own path (the root, or the target with a query added)
	// keeps PathObserved: the guess there is the parameter, not the path.
	for _, r := range reqs {
		if r.Origin == "" {
			r.Origin = types.PathSynthesized
		}
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

type ScanEvent struct {
	Result   *types.Result
	Findings []types.Finding
	Stats    ScanStats
	Done     bool
	Error    error
}

func (s *Scanner) ScanStream(ctx context.Context, targets []string, events chan<- ScanEvent) {
	defer close(events)

	// ── Phase 1: know the stack before firing anything stack-shaped. ──
	// One honest homepage GET per target, classified into s.stacks; the
	// response then flows through the SAME analysis pipeline the batch
	// results use, so nothing is double-probed and nothing is lost.
	// A target whose stack was seeded KNOWN earlier in the session skips
	// the GET — the fingerprint persists for the whole session.
	var preamble []*types.Result
	for _, target := range targets {
		s.mu.Lock()
		st := s.stacks[target]
		s.mu.Unlock()
		if st.Known() {
			continue
		}
		select {
		case <-ctx.Done():
			continue
		default:
		}
		rootReq := &types.Request{Method: "GET", URL: target, Timeout: s.opts.Timeout, Origin: types.PathObserved}
		start := time.Now()
		resp, err := s.client.Do(ctx, rootReq)
		res := &types.Result{Target: target, Request: rootReq, Response: resp, Error: err, Duration: time.Since(start)}
		if err == nil && resp != nil {
			s.mu.Lock()
			s.stacks[target] = fingerprint.Classify(resp)
			s.mu.Unlock()
		}
		preamble = append(preamble, res)
	}

	// Soft-404 baseline: fingerprint each target's homepage shell. A
	// client-side-routing SPA serves the byte-identical index.html for every
	// unknown path, so "200 on /graphql" carries no signal — the server never
	// routed it. Any probe response matching its target's shell is tagged
	// Soft404 so path/body analyzers refuse to draw conclusions from it.
	baselines := buildBaselines(preamble)

	reqs := s.buildRequests(targets)

	s.mu.Lock()
	s.stats = ScanStats{
		StartTime: time.Now(),
		Total:     len(reqs) + len(preamble),
		Target:    formatTargets(targets),
		Workers:   s.opts.Workers,
	}
	s.mu.Unlock()

	results := make(chan *types.Result, len(reqs)+len(preamble))
	for _, res := range preamble {
		results <- res
	}
	go s.client.DoBatch(ctx, reqs, results, s.opts.Workers)

	findingMap := make(map[string]types.Finding)

	for res := range results {
		select {
		case <-ctx.Done():
			return
		default:
		}

		s.mu.Lock()
		if res.Error != nil {
			s.stats.Failed++
			if isScopeRefusal(res.Error) {
				s.stats.Refused++
			}
		} else {
			s.stats.Completed++
		}
		s.mu.Unlock()

		var newFindings []types.Finding
		if res.Response != nil {
			baselineSig := ""
			if !baselines.isHomepage(res.Request) {
				if sig, ok := baselines.ownerSig(res.Request); ok {
					baselineSig = sig
					if sig == ResponseSig(res.Response) {
						res.Response.Soft404 = true
					}
				}
			}
			findings := s.analyzeResponse(ctx, res.Response)
			stampProvenance(res.Request, res.Response, findings, baselineSig)
			res.Findings = findings
			for _, f := range findings {
				key := f.Name
				if existing, ok := findingMap[key]; ok {
					findingMap[key] = mergeFinding(existing, f)
				} else {
					findingMap[key] = f
					newFindings = append(newFindings, f)
				}
			}
		}

		s.mu.Lock()
		stats := s.stats
		s.mu.Unlock()

		events <- ScanEvent{
			Result:   res,
			Findings: newFindings,
			Stats:    stats,
		}
	}

	allFindings := make([]types.Finding, 0, len(findingMap))
	for _, f := range findingMap {
		allFindings = append(allFindings, f)
	}

	// Active legacy-TLS detection: the passive resp.TLS can never show a
	// version below 1.2 (the Go client refused it during the scan), so a
	// server that still ENABLES TLS 1.0/1.1 is invisible to the analyzer.
	// Probe each HTTPS target once, explicitly downgrading the handshake.
	for _, f := range s.legacyTLSFindings(ctx, targets) {
		if _, dup := findingMap[f.Name]; dup {
			continue
		}
		findingMap[f.Name] = f
		allFindings = append(allFindings, f)
	}

	s.mu.Lock()
	s.stats.Duration = time.Since(s.stats.StartTime)
	s.stats.Findings = len(allFindings)
	stats := s.stats
	s.mu.Unlock()

	events <- ScanEvent{
		Done:     true,
		Stats:    stats,
		Findings: allFindings,
	}
}

func (s *Scanner) buildRequests(targets []string) []*types.Request {
	var reqs []*types.Request
	for _, target := range targets {
		// The root GET itself is no longer batched: phase 1 of ScanStream
		// already fetched and analyzed it (that fetch IS the fingerprint).
		s.mu.Lock()
		st := s.stacks[target]
		s.mu.Unlock()
		reqs = append(reqs, s.buildProbes(target, st)...)
	}
	return reqs
}

func (s *Scanner) Close() error {
	return s.client.Close()
}

// formatTargets renders the target label used in stats/events.
func formatTargets(targets []string) string {
	if len(targets) == 1 {
		return targets[0]
	}
	return fmt.Sprintf("%s (%d targets)", targets[0], len(targets))
}

// legacyTLSFindings runs the active downgrade probe once per distinct HTTPS
// host in the target list (a rescan of the same origin must not re-dial).
func (s *Scanner) legacyTLSFindings(ctx context.Context, targets []string) []types.Finding {
	seen := map[string]bool{}
	var out []types.Finding
	for _, t := range targets {
		u, err := url.Parse(t)
		if err != nil || !strings.EqualFold(u.Scheme, "https") {
			continue
		}
		host := u.Hostname()
		port := u.Port()
		if port == "" {
			port = "443"
		}
		key := host + ":" + port
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ProbeLegacyTLS(ctx, t)...)
	}
	return out
}

// baselineSet maps each scanned target to the signature of its homepage shell,
// so a probe that merely re-served that shell (a soft-404 / SPA catch-all) can
// be tagged before it reaches the path-dependent analyzers.
type baselineSet struct {
	homepage map[string]bool // the exact root-GET request URLs (the references)
	bases    []baseEntry
}

type baseEntry struct {
	base string // homepage URL with any trailing slash trimmed
	sig  string // signature of the homepage shell response
}

func buildBaselines(preamble []*types.Result) baselineSet {
	bs := baselineSet{homepage: make(map[string]bool, len(preamble))}
	for _, res := range preamble {
		if res == nil || res.Request == nil || res.Response == nil || res.Error != nil {
			continue
		}
		bs.homepage[res.Request.URL] = true
		bs.bases = append(bs.bases, baseEntry{
			base: strings.TrimRight(res.Request.URL, "/"),
			sig:  ResponseSig(res.Response),
		})
	}
	return bs
}

// isHomepage reports whether a request IS one of the reference root GETs. The
// homepage is the baseline itself and is never tagged Soft404 — it is analyzed
// in full (that fetch is the fingerprint and the only honest read of the shell).
func (bs baselineSet) isHomepage(req *types.Request) bool {
	if req == nil {
		return true // a response with no recorded request cannot be attributed
	}
	return bs.homepage[req.URL]
}

// ownerSig returns the shell signature of the target whose base is the longest
// URL-boundary prefix of req.URL. Boundary means the remainder is empty or
// starts with '/' or '?', so "https://a.com" never claims "https://a.com.evil".
func (bs baselineSet) ownerSig(req *types.Request) (string, bool) {
	if req == nil {
		return "", false
	}
	best := -1
	var sig string
	for _, b := range bs.bases {
		if underBase(req.URL, b.base) && len(b.base) > best {
			best = len(b.base)
			sig = b.sig
		}
	}
	if best < 0 {
		return "", false
	}
	return sig, true
}

func underBase(u, base string) bool {
	if base == "" || !strings.HasPrefix(u, base) {
		return false
	}
	rest := u[len(base):]
	return rest == "" || rest[0] == '/' || rest[0] == '?'
}

// ResponseSig is the identity of a served page: status + content-type + a
// digest of the body. A probe whose sig equals its target's homepage sig was
// answered by the catch-all shell, not by a distinct endpoint.
func ResponseSig(r *types.Response) string {
	sum := sha256.Sum256(r.Body)
	return fmt.Sprintf("%d|%s|%s", r.StatusCode, r.ContentType, hex.EncodeToString(sum[:]))
}

// isScopeRefusal separates "the boundary said no" from "the target did not
// answer". They are opposite facts about the scan, and a report that cannot
// tell them apart lets a refused scan be read as a clean one.
func isScopeRefusal(err error) bool {
	return errors.Is(err, types.ErrOutOfScope) || errors.Is(err, types.ErrInternalTarget)
}

// stampProvenance records, for every finding an analyzer returned from one
// response, the exchange that produced it, whether the scanner or the target
// named the path, and what the response was compared against.
//
// It happens here rather than inside the analyzers because this is the one
// place that holds all three facts at once. An analyzer knows what it saw;
// only the loop knows which probe it was answering and whether that probe was
// a wordlist guess.
func stampProvenance(req *types.Request, resp *types.Response, findings []types.Finding, baselineSig string) {
	for i := range findings {
		if findings[i].Prov == nil {
			findings[i].Prov = &types.Provenance{}
		}
		p := findings[i].Prov

		if p.RequestURL == "" {
			if req != nil && req.URL != "" {
				p.RequestURL = req.URL
			} else {
				p.RequestURL = resp.RequestURL
			}
		}
		if p.RequestMethod == "" && req != nil {
			p.RequestMethod = req.Method
		}
		if p.PathOrigin == "" && req != nil {
			p.PathOrigin = req.Origin
		}

		if resp.Soft404 {
			p.AddMethod(types.MethodSoft404Baseline)
			if p.BaselineRef == "" {
				p.BaselineRef = baselineSig
			}
			// Byte-identical to the shared shell: the server never routed
			// this path, so nothing about it was shown. Recording the
			// comparison is useful to a consumer; letting it count as
			// support for the finding would be the opposite.
			if p.Grade != types.GradeProven {
				p.Grade = types.GradeUnverified
			}
		} else if baselineSig != "" {
			// The other half of the same comparison, and the half that
			// used to be thrown away: this response was measured against
			// the target's own shell and DIFFERED, so the server did route
			// this path. That is a real signal and no artifact — exactly
			// what GradeIndicated is for.
			p.AddMethod(types.MethodBaselineDifferential)
			if p.BaselineRef == "" {
				p.BaselineRef = baselineSig
			}
		}
		// Only a recorded differential earns a grade. Leaving it unset keeps
		// an un-migrated analyzer's finding readable through the Confidence
		// ladder instead of silently demoting it to unverified.
		if p.Grade == "" && len(p.Methods) > 0 {
			p.Grade = types.DeriveGrade(p.Methods)
		}
	}
}

// mergeFinding folds a repeat report of the same finding name into the record
// already held. Evidence accumulates (it is per-probe text), confidence takes
// the max, and provenance merges by rank so the probe that actually proved the
// finding keeps its identity instead of being overwritten by whichever
// duplicate arrived second.
func mergeFinding(existing, incoming types.Finding) types.Finding {
	if existing.Evidence != incoming.Evidence {
		existing.Evidence = existing.Evidence + " | " + incoming.Evidence
	}
	if incoming.Confidence > existing.Confidence {
		existing.Confidence = incoming.Confidence
	}
	existing.Prov = types.MergeProvenance(existing.Prov, incoming.Prov)
	return existing
}
