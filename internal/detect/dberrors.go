package detect

import "regexp"

// sqlErrorPatterns are anchored, error-message-shaped DB signatures. Every
// pattern must look like a database ERROR TEXT, not a product mention:
// the previous word lists credited any page discussing "Oracle" or
// carrying `&quot;` HTML entities as a SQL injection surface.
var sqlErrorPatterns = []struct {
	db      string
	pattern *regexp.Regexp
}{
	{"MySQL", regexp.MustCompile(`(?i)you have an error in your [Ss][Qq][Ll] syntax|warning:.{0,40}mysql_(fetch|num_rows|query)|mysqli?_(query|error|fetch)\(|SQLSTATE\[42000\].{0,40}MariaDB|MariaDB server version`)},
	{"PostgreSQL", regexp.MustCompile(`(?i)pg_query\(\)\s*\[?|ERROR:\s{1,2}syntax error at or near|psql:[A-Z0-9]+\]\s*(ERROR|FATAL)|PostgreSQL query failed`)},
	{"MSSQL", regexp.MustCompile(`(?i)Microsoft OLE DB Provider for SQL Server|\[SQL Server\]|Unclosed quotation mark after the character string|Incorrect syntax near`)},
	{"Oracle", regexp.MustCompile(`(?i)ORA-\d{5}:|oracle\.jdbc\.driver`)},
	{"SQLite", regexp.MustCompile(`(?i)sqlite3\.(OperationalError|ProgrammingError|QueryError)|SQLITE_ERROR:|SQLite3::query\(\)|no such (column|table):`)},
	{"DB2", regexp.MustCompile(`(?i)DB2 SQL error|SQLCODE=\-\d{4,}`)},
	{"HSQLDB", regexp.MustCompile(`(?i)org\.hsqldb\.jdbc`)},
	{"Firebird", regexp.MustCompile(`(?i)Dynamic SQL Error|firebirdql|interbase error`)},
}

// SQLErrorMatch reports the first anchored database error signature in
// body, with the match offset for evidence windows. A second return of
// false means: no evidence of an SQL error message — the caller must not
// claim one.
func SQLErrorMatch(body string) (db string, idx int, ok bool) {
	for _, p := range sqlErrorPatterns {
		loc := p.pattern.FindStringIndex(body)
		if loc != nil {
			return p.db, loc[0], true
		}
	}
	return "", -1, false
}
