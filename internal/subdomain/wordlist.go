package subdomain

import "errors"

// Errors returned by Discover.
var (
	ErrEmptyDomain       = errors.New("subdomain: empty or unparseable domain")
	ErrMissingDependency = errors.New("subdomain: Resolver and CT source are both required")
)

// CommonLabels is a bounded list of high-frequency hostnames used to seed the
// brute channel. It is a CANDIDATE generator, not a verdict: a name here is
// only ever confirmed when the CT family independently lists it and it resolves
// live. Kept to well-known infrastructure/service names so the DNS load stays
// modest and the candidate set stays meaningful.
var CommonLabels = []string{
	"www", "api", "app", "admin", "dashboard", "dev", "staging", "stage",
	"test", "qa", "beta", "alpha", "prod", "production", "internal",
	"portal", "customer", "support", "help", "docs", "doc", "blog", "news",
	"mail", "email", "smtp", "imap", "pop", "mx", "webmail", "mx1", "mx2",
	"ftp", "ssh", "git", "gitlab", "github", "svn", "ci", "cdn", "static",
	"assets", "media", "img", "images", "video", "files", "download",
	"db", "database", "mysql", "postgres", "pg", "redis", "mongo", "cache",
	"search", "solr", "elastic", "kibana", "logs", "log", "monitor",
	"metrics", "grafana", "prometheus", "status", "health", "ping",
	"auth", "login", "sso", "oauth", "id", "identity", "account", "accounts",
	"secure", "vpn", "remote", "intranet", "extranet", "office", "proxy",
	"gateway", "gw", "edge", "origin", "edge1", "api1", "api2", "api3",
	"v1", "v2", "old", "new", "legacy", "mobile", "m", "touch", "shop",
	"store", "cart", "checkout", "payments", "pay", "billing", "invoice",
	"web", "www2", "www3", "site", "sites", "home", "main", "root",
	"beta-app", "canary", "preview", "sandbox", "demo", "trial", "poc",
	"backup", "bak", "archive", "archive1", "mirror", "mirror1", "ns1",
	"ns2", "ns3", "dns", "resolver", "smtp2", "relay", "outlook", "autodiscover",
	"discover", "autodiscover", "cpanel", "whm", "webmin", "admin2",
	"manage", "manager", "console", "panel", "control", "cp", "pma", "phpmyadmin",
	"jenkins", "teamcity", "build", "deploy", "release", "releases",
	"hooks", "webhook", "webhooks", "cron", "worker", "workers", "jobs",
	"queue", "task", "tasks", "batch", "report", "reports", "analytics",
	"track", "tracking", "stats", "metric", "telemetry", "sentry",
	"graphql", "rest", "grpc", "rpc", "ws", "wss", "socket", "realtime",
	"live", "stream", "streaming", "upload", "uploads", "thumb", "avatar",
	"imap2", "pop3", "webdisk", "calendar", "cal", "meet", "teams", "chat",
	"xmpp", "jabber", "irc", "smtp-relay", "mail2", "mail3", "zpush",
}
