// Fixture file for flagmap's regression suite — deliberately NOT meant to
// compile; only its syntax shape matters.
package main

import (
	"database/sql"
	"net/http"
	"os/exec"
)

var db *sql.DB

func searchHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// parameterized query — the tainted value never touches the SQL string
	db.Query("SELECT * FROM users WHERE name = ?", name)  // safe: SQL Injection
}

func pingHandler() {
	// fixed, non-tainted arguments
	exec.Command("ping", "-c", "1", "localhost")  // safe: Command Injection
}

func goHandler(w http.ResponseWriter, r *http.Request) {
	// same-origin relative redirect — not an open redirect
	http.Redirect(w, r, "/dashboard", 302)  // safe: Open Redirect
}

