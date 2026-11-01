package fingerprint

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// Stack is the server-side technology profile of a target, classified from
// ONE real response (the homepage fetched before any path probe fires).
// Its purpose is conditioning: a Python server does not answer to
// /phpinfo.php, /wp-login.php or /actuator/env any more than a Java server
// answers to /wp-admin. Before this existed every command sprayed the
// same static tech-agnostic battery at every target — noise for the
// operator, load for the target, and dead rows in reports.
//
// Known() is the honesty gate: family-specific probes are skipped only
// when the response actually said something. With no signal at all the
// scanner keeps the full list (absence of evidence is not evidence of a
// different stack) and the report says so.
type Stack struct {
	// Techs are human labels in first-seen order ("WordPress", "PHP",
	// "nginx").
	Techs []string
	// Server / PoweredBy are the raw header values the classification
	// rested on — evidence stays in the operator's hands.
	Server    string
	PoweredBy string
	families  map[string]bool
	// signals counts how many INDEPENDENT stack signals were seen; >0
	// means Known() and justifies skipping foreign-family probes.
	signals int
}

// Family labels used for conditioning. Keep in sync with the family tags
// on probe lists in engine and hacker.
const (
	FamPHP     = "php"
	FamWP      = "wordpress"
	FamJava    = "java"
	FamASPNet  = "aspnet"
	FamNode    = "node"
	FamPython  = "python"
	FamRuby    = "ruby"
	FamDrupal  = "drupal"
	FamLaravel = "laravel"
)

var (
	stkWpContent   = regexp.MustCompile(`(?i)wp-content/|wp-includes/`)
	stkWpGenerator = regexp.MustCompile(`(?i)<meta[^>]+generator[^>]+WordPress`)
	stkLaravel     = regexp.MustCompile(`(?i)laravel|X-CSRF-TOKEN" value=|/build/id/versions/`)
	stkJenkins     = regexp.MustCompile(`(?i)X-Hudson|Jenkins-Version`)
	stkDjango      = regexp.MustCompile(`(?i)django|__prefix__`)
)

func NewStack() Stack {
	return Stack{families: map[string]bool{}}
}

// Has reports whether the family was detected.
func (st Stack) Has(family string) bool {
	return st.families[family]
}

// Known reports whether at least one server-side stack signal was seen.
// Only then may family-specific probes be skipped for foreign families.
func (st Stack) Known() bool { return st.signals > 0 }

// Allows is the conditioning rule itself: a probe tagged with a family
// runs when that family was detected, or when nothing was detected at all.
func (st Stack) Allows(family string) bool {
	if family == "" || !st.Known() {
		return true
	}
	return st.families[family]
}

// String renders the detail line operators see before probes:
// "PHP, WordPress (Server: nginx/1.18, X-Powered-By: PHP/7.4)" — or the
// honest "unknown — full probe set kept" when there is no signal.
func (st Stack) String() string {
	base := "unknown — full probe set kept"
	if len(st.Techs) > 0 {
		base = strings.Join(st.Techs, ", ")
	}
	var raw []string
	if st.Server != "" {
		raw = append(raw, "Server: "+st.Server)
	}
	if st.PoweredBy != "" {
		raw = append(raw, "X-Powered-By: "+st.PoweredBy)
	}
	if len(raw) > 0 {
		return base + " (" + strings.Join(raw, ", ") + ")"
	}
	return base
}

func (st *Stack) mark(family, label string) {
	if st.families == nil {
		st.families = map[string]bool{}
	}
	if !st.families[family] {
		st.families[family] = true
		st.Techs = append(st.Techs, label)
	}
	st.signals++
}

// Classify reads the stack from a real response: headers, cookies, and a
// body-marker sweep. It never guesses from a port or a file extension in
// a URL; every signal is a byte the server sent.
func Classify(resp *types.Response) Stack {
	st := NewStack()
	if resp == nil || resp.Headers == nil {
		return st
	}
	h := resp.Headers

	st.Server = cleanStackHeader(h.Get("Server"))
	st.PoweredBy = cleanStackHeader(h.Get("X-Powered-By"))

	switch pv := strings.ToLower(st.PoweredBy); {
	case strings.Contains(pv, "php"):
		st.mark(FamPHP, "PHP")
	case strings.Contains(pv, "express"):
		st.mark(FamNode, "Node (Express)")
	case strings.Contains(pv, "asp.net"):
		st.mark(FamASPNet, "ASP.NET")
	}

	sv := strings.ToLower(st.Server)
	switch {
	case strings.Contains(sv, "apache"):
		// Apache ships PHP far more often than not, but the server string
		// alone does not run it: record the label, not the family.
		st.techOnly("Apache")
	case strings.Contains(sv, "iis"):
		st.mark(FamASPNet, "IIS/ASP.NET")
	case strings.Contains(sv, "jetty"), strings.Contains(sv, "tomcat"),
		strings.Contains(sv, "coyote"), strings.Contains(sv, "weblogic"),
		strings.Contains(sv, "wildfly"):
		st.mark(FamJava, "Java")
	case strings.Contains(sv, "gunicorn"), strings.Contains(sv, "uvicorn"),
		strings.Contains(sv, "tornado"), strings.Contains(sv, "simplehttp"):
		st.mark(FamPython, "Python")
	case strings.Contains(sv, "puma"):
		st.mark(FamRuby, "Ruby (Puma)")
	}

	for _, kv := range []struct{ header, family, label string }{
		{"X-AspNet-Version", FamASPNet, "ASP.NET"},
		{"X-AspNetMvc-Version", FamASPNet, "ASP.NET MVC"},
		{"X-Runtime", FamRuby, "Ruby on Rails"},
	} {
		if h.Get(kv.header) != "" {
			st.mark(kv.family, kv.label)
		}
	}
	if stkJenkins.MatchString(headerBlob(h)) {
		st.mark(FamJava, "Jenkins")
	}

	for _, c := range respCookies(h) {
		switch strings.ToLower(c) {
		case "phpsessid":
			st.mark(FamPHP, "PHP")
		case "jsessionid":
			st.mark(FamJava, "Java")
		case "asp.net_sessionid", "arrfinity", ".aspxauth", ".aspnetauth":
			st.mark(FamASPNet, "ASP.NET")
		case "connect.sid":
			st.mark(FamNode, "Node (Express)")
		case "csrftoken", "sessionid", "django_session":
			st.mark(FamPython, "Python (Django)")
		case "_rails_session", "request_mime_type_of_user":
			st.mark(FamRuby, "Ruby on Rails")
		case "laravel_session":
			st.mark(FamLaravel, "Laravel")
			st.mark(FamPHP, "PHP")
		}
	}

	body := string(resp.Body)
	if stkWpContent.MatchString(body) || stkWpGenerator.MatchString(body) {
		st.mark(FamWP, "WordPress")
		st.mark(FamPHP, "PHP")
	}
	if strings.Contains(strings.ToLower(body), "drupal") && strings.Contains(body, "sites/default/") {
		st.mark(FamDrupal, "Drupal")
		st.mark(FamPHP, "PHP")
	}
	if stkLaravel.MatchString(body) {
		st.mark(FamLaravel, "Laravel")
		st.mark(FamPHP, "PHP")
	}
	if strings.Contains(body, "__NEXT_DATA__") {
		st.mark(FamNode, "Node (Next.js)")
	}
	if strings.Contains(sv, "asp.net") || strings.Contains(strings.ToLower(body), ".aspx") {
		st.mark(FamASPNet, "ASP.NET")
	}
	_ = stkDjango // reserved: cookie signals already cover Django; body marker is noisy

	return st
}

// techOnly records a visible product label without claiming a scripting
// family — it does NOT count as a conditioning signal, because "Apache"
// says nothing about /phpinfo.php existing.
func (st *Stack) techOnly(label string) {
	if st.families == nil {
		st.families = map[string]bool{}
	}
	for _, t := range st.Techs {
		if t == label {
			return
		}
	}
	st.Techs = append(st.Techs, label)
}

func cleanStackHeader(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 60 {
		v = v[:60] + "…"
	}
	return v
}

func headerBlob(h http.Header) string {
	var b strings.Builder
	for k, vs := range h {
		b.WriteString(k)
		b.WriteByte(':')
		for _, v := range vs {
			b.WriteString(v)
			b.WriteByte(';')
		}
	}
	return b.String()
}

func respCookies(h http.Header) []string {
	var names []string
	for _, line := range h.Values("Set-Cookie") {
		name := line
		if i := strings.IndexByte(line, '='); i > 0 {
			name = strings.ToLower(line[:i])
		}
		names = append(names, name)
	}
	return names
}
