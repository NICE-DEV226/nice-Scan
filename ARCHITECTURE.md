# NICE_SCAN — Architecture & Techniques

## Vue d'ensemble

**NICE_SCAN** est un moteur de reconnaissance et d'audit de sécurité moderne écrit en Go 1.24. Il combine analyse passive (détection de technologies, en-têtes, TLS, vulnérabilités) et active (exploitation de formulaires, IDOR, escalade de privilèges).

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI (Cobra)                          │
│   scan │ audit │ tech │ tls │ exploit │ shell                │
└──────────────────────────┬──────────────────────────────────┘
                           │
                    ┌──────┴──────┐
                    │  Transport  │  ← connexions pool, retry, rate-limit
                    └──────┬──────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
   ┌────┴────┐       ┌────┴────┐       ┌─────┴─────┐
   │  Scan   │       │ Exploit │       │   Shell   │
   │ Engine  │       │  Engine │       │ BubbleTea │
   └────┬────┘       └────┬────┘       └───────────┘
        │                 │
   ┌────┴────┐      ┌─────┴──────┐
   │ 12+     │      │ Login      │
   │Analyseurs│     │ IDOR       │
   │         │      │ Privesc    │
   │         │      │ Token      │
   │         │      │ Register   │
   │         │      │ Reset      │
   │         │      │ Session    │
   └─────────┘      └────────────┘
```

---

## Structure du projet

```
security_tool/
├── cmd/nice_scan/main.go      ← Point d'entrée CLI (cobra)
├── internal/
│   ├── types/                  ← Types fondamentaux
│   ├── transport/              ← Client HTTP (pool, retry, rate-limit)
│   ├── engine/                 ← Moteur de scan passif (12 analyseurs)
│   ├── exploit/                ← Moteur d'exploitation active (7 modules)
│   ├── fingerprint/            ← Détection de technologies (165 signatures)
│   ├── output/                 ← Affichage terminal / JSON / HTML
│   ├── tui/                    ← Dashboard interactif temps réel
│   └── shell/                  ← Shell interactif persistent
├── docs/architecture/          ← Documentation technique
└── go.mod                      ← Dépendances (bubbletea, lipgloss, cobra)
```

---

## 1. Couche Transport (`internal/transport/`)

### Technique : Client HTTP avec pool de connexions, retry et rate-limiting

```
Client HTTP
├── http.Client avec transport personnalisé
│   ├── Keep-Alive (30s)
│   ├── HTTP/2 forcé (ForceAttemptHTTP2)
│   ├── Connexions max : 200 idle, 20 par hôte
│   └── Proxy configurable
├── Do()       → 1 requête avec retry + rate-limit
├── Get()      → GET simplifié
├── DoBatch()  → Pool de workers concurrents (64 par défaut)
├── RateLimiter → Token bucket (rafraîchissement par goroutine)
└── RequestStats → Compteurs (total, success, failed, retried, rate-limited)
```

### Stratégie de retry
- Retry sur : timeout, rate-limit (429), erreurs serveur (5xx)
- Backoff exponentiel avec jitter aléatoire
- Maximum : 2 retries par défaut

### Rate-limiting
- Algorithme : Token bucket
- Rate configurable (0 = illimité)
- Bloque la goroutine jusqu'à disponibilité d'un token

---

## 2. Moteur de Scan (`internal/engine/`)

### Architecture : Pipeline d'analyseurs

```
Scanner
├── RegisterAnalyzers() ← Enregistre les analyseurs
├── buildProbes()       ← Construit les requêtes de sonde
│   ├── 28 chemins sensibles (/admin, /wp-admin, /.env, /graphql...)
│   ├── 10 paramètres SQLi (?id=1', ?q=1'...)
│   ├── 10 paramètres XSS (?q=<script>, ?q=<img...)
│   └── 1 requête OPTIONS CORS
├── Scan()              ← Exécute via DoBatch() + analyse chaque réponse
└── ScanStream()        ← Version streaming pour TUI/shell
```

### Les 12 Analyseurs

#### a) Fingerprint — Détection de technologies
- **Méthode** : 165 signatures regex sur headers, cookies, HTML, URL, CSP, scripts, meta tags
- **Extraction de version** : Groupes de capture regex dans headers, cookies, HTML
- **Types** : Serveurs web, CDN, WAF, hébergement, frameworks frontend/backend, CMS, clouds, BDD, analytics, librairies JS, proxies, protocoles API

#### b) Headers — Analyse des en-têtes de sécurité
- **En-têtes vérifiés** : Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Server, X-Powered-By
- **Cookies** : Vérifie Secure, HttpOnly, SameSite

#### c) TLS — Analyse de configuration TLS
- **Version** : Détection TLS 1.0 → 1.3
- **Ciphers** : Détection de ciphers faibles (RC4, CBC, 3DES, EXPORT)
- **Certificat** : Extraction SAN (Subject Alternative Names)

#### d) Exposures — Fichiers sensibles exposés
- **Chemins sondés** : /.env, /.git/config, source maps, listage de répertoires, robots.txt, sitemap.xml, backup.zip, .gitignore
- **Détection** : Statut HTTP + motifs dans le corps

#### e) SQLi — Injection SQL
- **Méthode** : Détection basée sur les erreurs
- **Patterns** : 10 bases de données (MySQL, PostgreSQL, MSSQL, Oracle, SQLite, DB2, HSQLDB, Firebird, CockroachDB, Generic)
- **Déclencheur** : Paramètres comme `?id=1'`, `?q=1"` injectés dans les sondes

#### f) XSS — Cross-Site Scripting
- **Méthode** : Détection de vecteurs XSS dans le HTML renvoyé
- **Contextes** : 20 patterns (balises `<script>`, attributs `onerror`/`onload`, protocole `javascript:`, `eval()`, `<svg>`, `<iframe>`, etc.)
- **Confidence** : Basée sur le contexte de l'injection

#### g) CORS — Cross-Origin Resource Sharing
- **Vulnérabilités** : Wildcard + credentials (Critique), Reflet d'origine, Origine null, Wildcard PUT/Headers

#### h) HTTP Methods — Méthodes HTTP risquées
- **Détection** : Parse les headers `Allow`/`Public`
- **Méthodes dangereuses** : TRACE/TRACK (XST), PUT (upload), DELETE, CONNECT, PATCH

#### i) Tokens — Extraction de tokens et JWT
- **Extraction** : Bearer tokens, cookies de session (PHPSESSID, JSESSIONID, etc.), access tokens, API keys, secrets, Basic auth
- **Décodeur JWT** : Décode header + payload, détection `alg: none`, `HS256` key confusion, rôles/claims admin
- **Flags cookies** : Vérifie Secure, HttpOnly, SameSite

#### j) Auth — Détection d'authentification
- **Formulaires** : Login, register, password reset
- **Énumération** : Messages d'erreur différenciés (utilisateur existe vs mot de passe incorrect)
- **Panneaux admin** : Chemins communs (/admin, /wp-admin, /administrator...)

#### k) Privesc — Indicateurs d'escalade de privilèges
- **IDOR** : Paramètres numériques dans l'URL (`?id=`, `?user_id=`)
- **Rôles** : Paramètres de rôle/statut dans URL/body
- **Mots-clés** : admin, root, moderator, premium, pro, vip dans les réponses

#### l) Extract — Extraction de données sensibles
- **Patterns** : Emails, téléphones, IPs internes (RFC1918), clés privées, clés API, AWS keys, tokens GitHub/Slack/Google, SSN, cartes de crédit, JWT claims, chaînes de connexion BDD

---

## 3. Moteur d'Exploitation (`internal/exploit/`)

### a) Login Bruteforce
1. **Découverte de formulaires** : Parse le HTML pour trouver des formulaires avec champ password
2. **Extraction** : Action URL, noms de champs (username/password), méthode (POST/GET), champs cachés
3. **Fallback** : Si aucun formulaire trouvé, tente les chemins d'admin courants
4. **Analyse de réponse** : Redirect (302 ≠ login page), keywords (dashboard/welcome), taille du body, messages d'erreur

### b) IDOR Enumeration
- **Query-based** : Teste 18 noms de paramètres (`id`, `user_id`, `pid`, `uid`...) avec une plage numérique
- **Path-based** : Teste 16 patterns REST (`/users/1`, `/api/users/1`, `/profile/1`)
- **Détection** : Compare les tailles de réponse (différence > 100 octets → suspect)

### c) Role / Privilege Escalation
- **Param tampering** : 43 paires paramètre=valeur via GET et POST
- **Header tampering** : 16 en-têtes HTTP (X-Admin, X-Role, X-Forwarded-For, X-Original-URL)
- **Détection** : Code 200 avec contenu, redirect sans login, différence de taille vs baseline

### d) Token / Session Reuse
- **Bearer tokens** : Teste les tokens JWT sur 24 endpoints protégés
- **Cookies session** : Teste les cookies sur les endpoints (sauf admin/upgrade)

### e) Account Registration
- **Découverte** : Chemins communs (/register, /signup, /api/register)
- **Payloads** : 5 profils (standard, admin, pro, vip)
- **Extraction de champs** : Parse le HTML du formulaire pour les noms exacts

### f) Password Reset
- **Énumération d'utilisateurs** : Compare les réponses (taille, contenu) entre emails existants et inexistants
- **Fuite de token** : Regex sur les tokens de reset dans le HTML/URL

### g) Session Fixation
- **Réutilisation** : Cookie pré-authentification réutilisé sur endpoints protégés
- **Flags** : Vérifie Secure, HttpOnly, domaine, path

---

## 4. Fingerprint (`internal/fingerprint/`)

### Technique : Matching multi-couche

```
Signature
├── Headers  : regex sur nom + valeur d'en-tête HTTP
├── Cookies  : regex sur nom + valeur de cookie
├── HTML     : regex dans le body de la réponse
├── URL      : regex sur le chemin URL
├── URLHash  : hash de l'URL complète
├── Script   : regex dans les balises <script>
├── CSP      : regex dans Content-Security-Policy
├── Meta     : regex dans les balises <meta>
├── Favicon  : hash MD5 du favicon
└── Version  : regex avec groupe de capture pour extraction
```

Exemple pour **Vercel** :
```go
{
    Name: "Vercel",
    Headers: []string{"Server: Vercel"},
    Categories: []string{"hosting", "serverless"},
    Confidence: 0.92,
    Type: "hosting",
}
```

---

## 5. Affichage (`internal/output/`)

### Terminal (LipGloss)
- Bannière ASCII art
- Dashboard : target, progression, workers, durée
- Grille des modules d'analyse (● = actif)
- Findings groupés par sévérité avec couleurs :
  - Critical/High → Rouge (`#F7768E`)
  - Medium → Orange (`#FFB347`)
  - Low → Cyan (`#7DCFFF`)
  - Info → Gris (`#565F89`)

### JSON
- Structure complète : target, stats, findings (type, sévérité, description, preuve)

### HTML
- Rapport autonome avec CSS inline
- Score de risque (X/100)
- Badges de sévérité (CRITICAL → rouge, HIGH → orange...)
- Sections par type : technologies, secrets, expositions
- Style : Graphite/slate design

---

## 6. Shell interactif (`internal/shell/`)

### Technique : Bubble Tea avec session persistante
- **Texte saisi** : Champ personnalisé avec historique
- **Scroll** : Molette souris, PgUp/PgDown, Shift+↑/↓
- **Autocomplétion** : Tab pour les noms de commandes
- **Session** : Suivi des targets scannées et findings cumulés
- **Execution** : Chaque commande est lancée dans une goroutine

---

## 7. Dashboard interactif (`internal/tui/`)

### Technique : Bubble Tea streaming
- Met à jour en temps réel via `ScanStream()`
- Affiche la cible, la progression, le nombre de findings
- Spinner d'activité pendant le scan
- Quitte avec `q` ou `Ctrl+C`

---

## Commandes CLI

| Commande | Usage | Description |
|----------|-------|-------------|
| `scan` | `scan <url>` | Scan complet (12 modules, ~52 requêtes) |
| `audit` | `audit <url>` | Scan verbose + rapport HTML auto |
| `tech` | `tech <url>` | Détection de technologies uniquement |
| `tls` | `tls <url>` | Analyse TLS uniquement |
| `exploit` | `exploit <url> --all` | Exploitation active (7 modules) |
| `shell` | `shell` | Shell interactif persistent |

### Drapeaux globaux
- `-w` : Workers concurrents (défaut: 64)
- `--timeout` : Timeout par requête (défaut: 15s)
- `--retries` : Tentatives max (défaut: 2)
- `--rate-limit` : Requêtes/seconde (0 = illimité)
- `--proxy` : Proxy HTTP
- `-R` : Rapport HTML
- `-j` : Sortie JSON
- `-v` : Mode verbose
- `--header` : En-têtes personnalisés
- `--cookie` : Cookie à inclure

---

## Dépendances

| Bibliothèque | Rôle |
|---|---|
| `github.com/spf13/cobra` | CLI (commandes, flags, help) |
| `github.com/charmbracelet/bubbletea` | TUI framework (shell, dashboard) |
| `github.com/charmbracelet/bubbles` | Composants Bubble Tea (input, spinner) |
| `github.com/charmbracelet/lipgloss` | Styles terminaux (couleurs, bordures) |

---

## Flux d'exécution typique

```
1. nice_scan scan example.com -R rapport.html
2.   ├── Cobra parse les flags
3.   ├── buildClient() crée le transport (pool, retry, rate-limit)
4.   ├── Scanner.RegisterAnalyzers() enregistre les 12 analyseurs
5.   ├── scanner.Scan()
6.   │   ├── buildProbes() → 52 requêtes
7.   │   ├── client.DoBatch() → pool de 64 workers
8.   │   │   ├── Requête GET initiale
9.   │   │   ├── 28 sondes de chemins
10.  │   │   ├── 10 sondes SQLi
11.  │   │   ├── 10 sondes XSS
12.  │   │   ├── 1 OPTIONS CORS
13.  │   │   └── 2 requêtes supplémentaires (cookies, etc.)
14.  │   └── Pour chaque réponse : analyzer.Analyze()
15.  │       ├── fingerprint → Vercel, Cloudflare...
16.  │       ├── headers → CSP manquant, HSTS...
17.  │       ├── tls → TLS 1.3...
18.  │       ├── exposures → /.env, robots.txt...
19.  │       ├── sqli → Erreurs SQL...
20.  │       ├── xss → Vecteurs <script>...
21.  │       ├── cors → Wildcard ACAO...
22.  │       ├── methods → TRACE, PUT...
23.  │       ├── tokens → JWT, cookies...
24.  │       ├── auth → Formulaires, admin...
25.  │       ├── privesc → IDOR, rôles...
26.  │       └── extract → Emails, tokens API...
27.  ├── renderer.RenderResult() → Terminal coloré
28.  └── report.RenderHTML() → Fichier HTML
```
