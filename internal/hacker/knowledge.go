package hacker

import "sync"

type Knowledge struct {
	mu           sync.RWMutex
	target       string
	capabilities []Capability
	findings     []Finding
	credentials  []Credential
	sessions     []SessionToken
	endpoints    []Endpoint
	pages        []Page
	jsFiles      []string
	secrets      []string
	scannerState []string
	jwts         []JWTToken
	chainSteps   []ChainStep
	parentURLs   map[string]string
	checkedPaths map[string]bool
	Session      *SessionManager
	ReportDir    *ReportDir
}

func NewKnowledge(target string) *Knowledge {
	return &Knowledge{
		target:       target,
		parentURLs:   make(map[string]string),
		checkedPaths: make(map[string]bool),
		Session:      NewSessionManager(),
		ReportDir:    NewReportDir(target),
	}
}

func (kb *Knowledge) AddFinding(f Finding) {
	kb.mu.Lock()
	defer kb.mu.Unlock()
	kb.findings = append(kb.findings, f)
	kb.deriveCapabilities(f)
}

// deriveCapabilities flips has_* capabilities by keyword matching over the
// finding text. Finding Name/Type/Description/Evidence routinely carry
// remote-controlled content (introspection bodies, crawled URLs, page text,
// third-party lists), so everything derived here is by construction a "hint":
// it records that remote text mentioned a keyword, never that the scanner
// verified the corresponding weakness. Hint capabilities can guide passive or
// same-target probing, but never credentialed or state-changing actions, and
// never contribute to risk chains or scores.
func (kb *Knowledge) deriveCapabilities(f Finding) {
	capMap := map[string]string{
		"graphql":   "has_graphql",
		"jwt":       "has_jwt",
		"login":     "has_login",
		"register":  "has_register",
		"reset":     "has_reset",
		"upload":    "has_upload",
		"admin":     "has_admin",
		"api":       "has_api",
		"s3":        "has_s3",
		"cors":      "has_cors",
		"xss":       "has_xss",
		"sqli":      "has_sqli",
		"idor":      "has_idor",
		"token":     "has_token",
		"secret":    "has_secret",
		"subdomain": "has_subdomain",
	}
	for key, capName := range capMap {
		if containsFold(f.Name, key) || containsFold(f.Type, key) ||
			containsFold(f.Description, key) || containsFold(f.Evidence, key) {
			if !kb.hasCapability(capName) {
				kb.capabilities = append(kb.capabilities, Capability{
					Name:   capName,
					Origin: OriginHint,
					Target: kb.target,
					Details: map[string]string{
						"evidence":  truncateEvidence(f.Evidence),
						"derivedBy": "text-match (remote-controlled input; unverified)",
					},
				})
			}
		}
	}
}

func truncateEvidence(s string) string {
	if len(s) > 200 {
		return s[:197] + "..."
	}
	return s
}

func (kb *Knowledge) capability(name string) *Capability {
	for i := range kb.capabilities {
		if kb.capabilities[i].Name == name {
			return &kb.capabilities[i]
		}
	}
	return nil
}

func (kb *Knowledge) hasCapability(name string) bool {
	for _, c := range kb.capabilities {
		if c.Name == name {
			return true
		}
	}
	return false
}

func (kb *Knowledge) AddCredential(c Credential) {
	kb.mu.Lock()
	defer kb.mu.Unlock()
	kb.credentials = append(kb.credentials, c)
}

func (kb *Knowledge) AddEndpoint(e Endpoint) {
	kb.mu.Lock()
	defer kb.mu.Unlock()
	kb.endpoints = append(kb.endpoints, e)
}

func (kb *Knowledge) AddPage(p Page) {
	kb.mu.Lock()
	defer kb.mu.Unlock()
	kb.pages = append(kb.pages, p)
	for _, js := range p.JSFiles {
		if !containsStr(kb.jsFiles, js) {
			kb.jsFiles = append(kb.jsFiles, js)
		}
	}
}

func (kb *Knowledge) AddJSScript(url string) {
	kb.mu.Lock()
	defer kb.mu.Unlock()
	if !containsStr(kb.jsFiles, url) {
		kb.jsFiles = append(kb.jsFiles, url)
	}
}

func (kb *Knowledge) AddSession(s SessionToken) {
	kb.mu.Lock()
	defer kb.mu.Unlock()
	kb.sessions = append(kb.sessions, s)
	if !kb.hasCapability("has_token") {
		kb.capabilities = append(kb.capabilities, Capability{
			Name:   "has_token",
			Origin: OriginVerified,
			Target: kb.target,
		})
	}
}

// AddCapability records a capability observed by a scanner action. Callers
// that only relay remote-controlled text (passive recon lists, crawled page
// bodies) must set Origin explicitly to OriginHint; executed evidence keeps
// Origin empty and is recorded as verified.
func (kb *Knowledge) AddCapability(c Capability) {
	kb.mu.Lock()
	defer kb.mu.Unlock()
	for _, existing := range kb.capabilities {
		if existing.Name == c.Name {
			return
		}
	}
	if c.Origin == "" {
		c.Origin = OriginVerified
	}
	kb.capabilities = append(kb.capabilities, c)
}

// HasVerifiedCapability reports whether a capability claimed by an action's
// Requires list is backed by executed evidence. Remote-text hints do not
// count: sensitive actions must never unlock from content an attacker could
// plant on the target.
func (kb *Knowledge) HasVerifiedCapability(name string) bool {
	kb.mu.RLock()
	defer kb.mu.RUnlock()
	return kb.hasVerifiedCapability(name)
}

func (kb *Knowledge) hasVerifiedCapability(name string) bool {
	for _, c := range kb.capabilities {
		if c.Name == name && c.Origin == OriginVerified {
			return true
		}
	}
	return false
}

func (kb *Knowledge) AddJWT(j JWTToken) {
	kb.mu.Lock()
	defer kb.mu.Unlock()
	kb.jwts = append(kb.jwts, j)
	if !kb.hasCapability("has_jwt") {
		kb.capabilities = append(kb.capabilities, Capability{
			Name:   "has_jwt",
			Origin: OriginVerified,
			Target: kb.target,
		})
	}
	if j.Algorithm == "none" || len(j.Raw) > 0 {
		kb.Session.AddToken(j.Raw)
	}
}

func (kb *Knowledge) GetJWTs() []JWTToken {
	kb.mu.RLock()
	defer kb.mu.RUnlock()
	out := make([]JWTToken, len(kb.jwts))
	copy(out, kb.jwts)
	return out
}

func (kb *Knowledge) AddChainStep(s ChainStep) {
	kb.mu.Lock()
	defer kb.mu.Unlock()
	kb.chainSteps = append(kb.chainSteps, s)
}

// AddSecret records a secret the scanner actually captured (leaked key,
// dumped password file content, extracted credential blob). This is executed
// evidence: it flips has_secret and drives the highest risk tier in reports.
func (kb *Knowledge) AddSecret(s string) {
	kb.mu.Lock()
	defer kb.mu.Unlock()
	if !containsStr(kb.secrets, s) {
		kb.secrets = append(kb.secrets, s)
		if !kb.hasCapability("has_secret") {
			kb.capabilities = append(kb.capabilities, Capability{
				Name:   "has_secret",
				Origin: OriginVerified,
				Target: kb.target,
			})
		}
	}
}

// AddScannerState records scanner bookkeeping strings (OOB callback URLs,
// generated PoC markers, tool session identifiers). These are not secrets
// observed on the target: they must never flip has_secret or feed risk
// scoring. It exists to keep the previous misuse of AddSecret for such
// strings from fabricating "critical data breach" results.
func (kb *Knowledge) AddScannerState(s string) {
	kb.mu.Lock()
	defer kb.mu.Unlock()
	if !containsStr(kb.scannerState, s) {
		kb.scannerState = append(kb.scannerState, s)
	}
}

func (kb *Knowledge) GetScannerState() []string {
	kb.mu.RLock()
	defer kb.mu.RUnlock()
	out := make([]string, len(kb.scannerState))
	copy(out, kb.scannerState)
	return out
}

func (kb *Knowledge) MarkChecked(path string) {
	kb.mu.Lock()
	defer kb.mu.Unlock()
	kb.checkedPaths[path] = true
}

func (kb *Knowledge) IsChecked(path string) bool {
	kb.mu.RLock()
	defer kb.mu.RUnlock()
	return kb.checkedPaths[path]
}

func (kb *Knowledge) SetParentURL(child, parent string) {
	kb.mu.Lock()
	defer kb.mu.Unlock()
	if _, ok := kb.parentURLs[child]; !ok {
		kb.parentURLs[child] = parent
	}
}

func (kb *Knowledge) GetFindings() []Finding {
	kb.mu.RLock()
	defer kb.mu.RUnlock()
	out := make([]Finding, len(kb.findings))
	copy(out, kb.findings)
	return out
}

func (kb *Knowledge) GetCapabilities() []Capability {
	kb.mu.RLock()
	defer kb.mu.RUnlock()
	out := make([]Capability, len(kb.capabilities))
	copy(out, kb.capabilities)
	return out
}

func (kb *Knowledge) GetCredentials() []Credential {
	kb.mu.RLock()
	defer kb.mu.RUnlock()
	out := make([]Credential, len(kb.credentials))
	copy(out, kb.credentials)
	return out
}

func (kb *Knowledge) GetEndpoints() []Endpoint {
	kb.mu.RLock()
	defer kb.mu.RUnlock()
	out := make([]Endpoint, len(kb.endpoints))
	copy(out, kb.endpoints)
	return out
}

func (kb *Knowledge) GetPages() []Page {
	kb.mu.RLock()
	defer kb.mu.RUnlock()
	out := make([]Page, len(kb.pages))
	copy(out, kb.pages)
	return out
}

func (kb *Knowledge) GetJSScripts() []string {
	kb.mu.RLock()
	defer kb.mu.RUnlock()
	out := make([]string, len(kb.jsFiles))
	copy(out, kb.jsFiles)
	return out
}

func (kb *Knowledge) GetSecrets() []string {
	kb.mu.RLock()
	defer kb.mu.RUnlock()
	out := make([]string, len(kb.secrets))
	copy(out, kb.secrets)
	return out
}

func (kb *Knowledge) GetSessions() []SessionToken {
	kb.mu.RLock()
	defer kb.mu.RUnlock()
	out := make([]SessionToken, len(kb.sessions))
	copy(out, kb.sessions)
	return out
}

func (kb *Knowledge) GetChainSteps() []ChainStep {
	kb.mu.RLock()
	defer kb.mu.RUnlock()
	out := make([]ChainStep, len(kb.chainSteps))
	copy(out, kb.chainSteps)
	return out
}

func (kb *Knowledge) Target() string {
	return kb.target
}

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func containsFold(s, substr string) bool {
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			sc := s[i+j]
			tc := substr[j]
			if sc >= 'A' && sc <= 'Z' {
				sc += 32
			}
			if tc >= 'A' && tc <= 'Z' {
				tc += 32
			}
			if sc != tc {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
