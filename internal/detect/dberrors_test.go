package detect

import "testing"

func TestSQLErrorMatchAnchored(t *testing.T) {
	cases := []struct {
		name string
		body string
		db   string
	}{
		{"mysql classic", `<b>Warning</b>:  mysqli_query(): You have an error in your SQL syntax; near 'x'`, "MySQL"},
		{"postgres psql", `psql:ERROR:  syntax error at or near "FROM"`, "PostgreSQL"},
		{"pg_query bracket", `PHP Fatal error: pg_query() [<a href='function.pg-query'>]: Query failed`, "PostgreSQL"},
		{"mssql asp", `[Microsoft][ODBC SQL Server Driver][SQL Server]Line 1: Incorrect syntax near 'x'.`, "MSSQL"},
		{"mssql unclosed", `Unclosed quotation mark after the character string '`, "MSSQL"},
		{"ora code", `ORA-00933: SQL command not properly ended`, "Oracle"},
		{"jdbc oracle", `java.sql.SQLException: oracle.jdbc.driver.T4CTTIoer.processError`, "Oracle"},
		{"sqlite python", `sqlite3.OperationalError: no such column: secret`, "SQLite"},
		{"sqlite php", `SQLite3::query(): SQLITE_ERROR: near "SELECT": syntax error`, "SQLite"},
		{"db2", `DB2 SQL error: SQLCODE=-104, SQLSTATE=42601`, "DB2"},
		{"firebird", `Dynamic SQL Error -SQL error code = -104`, "Firebird"},
	}
	for _, c := range cases {
		if db, _, ok := SQLErrorMatch(c.body); !ok || db != c.db {
			t.Fatalf("%s: expected %s, got %q ok=%v", c.name, c.db, db, ok)
		}
	}
}

func TestSQLErrorMatchRejectsProductMentions(t *testing.T) {
	// The previous keyword lists credited any page mentioning the DB
	// product name, or any HTML-escaped text. None of these describe an
	// error message.
	murmurs := []string{
		`<h1>We run PostgreSQL 15 behind a load balancer</h1>`,
		`<p>SQLite is a lightweight serverless database engine.</p>`,
		`<div class="product">Oracle Database 23ai — enterprise edition</div>`,
		"Welcome to MySQL training week 3. See &quot;schedule&quot;.",
		`<script>console.log("ora- error codes are interesting");</script>`,
		`<title>Cockroach Cloud — the database blog</title>`,
	}
	for _, body := range murmurs {
		if db, _, ok := SQLErrorMatch(body); ok {
			t.Fatalf("product mention must not match; matched %q on %q", db, body)
		}
	}
	if _, _, ok := SQLErrorMatch(""); ok {
		t.Fatal("empty body must not match")
	}
}
