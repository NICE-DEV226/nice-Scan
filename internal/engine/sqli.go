package engine

import (
	"context"
	"fmt"
	"regexp"

	"github.com/nice-scan/nice_scan/internal/types"
)

var (
	dbErrorPatterns = []struct {
		db      string
		pattern *regexp.Regexp
	}{
		{"MySQL", regexp.MustCompile(`(?i)SQL\s+syntax.*?MySQL|You have an error in your SQL syntax|Warning.*?mysql_|MariaDB server|driver.*?mysql`)},
		{"PostgreSQL", regexp.MustCompile(`(?i)PostgreSQL|ERROR:\s+.*?pg_|driver.*?postgres|psql`)},
		{"MSSQL", regexp.MustCompile(`(?i)Microsoft\s+SQL\s+Server|Driver.*?SQL\s*Server|OLEDB|SQLServer|\[SQL Server\]`)},
		{"Oracle", regexp.MustCompile(`(?i)Oracle\s+Driver|ORA-[0-9]{5}|oracle\.jdbc`)},
		{"SQLite", regexp.MustCompile(`(?i)SQLite|sqlite_.*?\(|SQLITE_ERROR`)},
		{"DB2", regexp.MustCompile(`(?i)DB2|IBM\s+DB2|db2_\w+`)},
		{"HSQLDB", regexp.MustCompile(`(?i)HSQLDB|org\.hsqldb`)},
		{"Firebird", regexp.MustCompile(`(?i)Firebird|interbase`)},
		{"CockroachDB", regexp.MustCompile(`(?i)cockroach`)},
		{"Generic", regexp.MustCompile(`(?i)unclosed quotation mark|quot;|division by zero|pg_|mysqli_|sqlite_|odbc_`)},
	}

	sqliErrorIndicators = []*regexp.Regexp{
		regexp.MustCompile(`(?i)unclosed\s+quotation\s+mark`),
		regexp.MustCompile(`(?i)unclosed\s+quote`),
		regexp.MustCompile(`(?i)unexpected\s+end\s+of\s+SQL`),
		regexp.MustCompile(`(?i)mysql_fetch|mysql_num_rows|mysql_query`),
		regexp.MustCompile(`(?i)supplied\s+argument\s+is\s+not\s+a\s+valid`),
		regexp.MustCompile(`(?i)Column\s+not\s+found`),
		regexp.MustCompile(`(?i)Unknown\s+column`),
		regexp.MustCompile(`(?i)Table\s+.*?doesn't\s+exist`),
		regexp.MustCompile(`(?i)Syntax\s+error\s+in\s+string`),
		regexp.MustCompile(`(?i)Warning.*?mysql_`),
		regexp.MustCompile(`(?i)Conversion\s+failed`),
		regexp.MustCompile(`(?i)Invalid\s+query\s+string`),
	}
)

type SQLiAnalyzer struct{}

func NewSQLiAnalyzer() *SQLiAnalyzer {
	return &SQLiAnalyzer{}
}

func (a *SQLiAnalyzer) Name() string {
	return "sqli"
}

func (a *SQLiAnalyzer) Analyze(ctx context.Context, resp *types.Response) []types.Finding {
	if resp == nil || len(resp.Body) == 0 {
		return nil
	}

	var findings []types.Finding
	body := string(resp.Body)

	for _, sq := range sqliErrorIndicators {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		if sq.MatchString(body) {
			var matchedDB string
			for _, db := range dbErrorPatterns {
				if db.pattern.MatchString(body) {
					matchedDB = db.db
					break
				}
			}
			if matchedDB == "" {
				matchedDB = "Unknown"
			}

			findings = append(findings, types.Finding{
				Type:        types.FindingMisconfig,
				Name:        fmt.Sprintf("SQL Injection — %s", matchedDB),
				Severity:    types.SeverityCritical,
				Description: fmt.Sprintf("Database error message detected indicating possible SQL injection — %s", matchedDB),
				Evidence:    fmt.Sprintf("DB Error: %s", extractSnippet(body, sq.String(), 80)),
				Confidence:  0.85,
				Metadata: map[string]string{
					"database": matchedDB,
					"request_url": resp.RequestURL,
				},
			})
			return findings
		}
	}

	for _, db := range dbErrorPatterns {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		if db.pattern.MatchString(body) {
			findings = append(findings, types.Finding{
				Type:        types.FindingMisconfig,
				Name:        fmt.Sprintf("Database Information Disclosure — %s", db.db),
				Severity:    types.SeverityMedium,
				Description: fmt.Sprintf("Response contains database fingerprint or error pattern indicating %s usage", db.db),
				Evidence:    fmt.Sprintf("Pattern: %s: %s", db.db, extractSnippet(body, db.pattern.String(), 80)),
				Confidence:  0.6,
				Metadata: map[string]string{
					"database": db.db,
					"request_url": resp.RequestURL,
				},
			})
		}
	}

	return findings
}

func hasAnyError(body string) bool {
	for _, re := range sqliErrorIndicators {
		if re.MatchString(body) {
			return true
		}
	}
	return false
}
