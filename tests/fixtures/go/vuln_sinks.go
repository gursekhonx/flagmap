// Fixture file for flagmap's regression suite — deliberately NOT meant to
// compile (no real imports for mux/sql.DB wiring); only its syntax shape
// matters, since the scanner works on the parse tree, not a built binary.
package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"
)

var db *sql.DB

func searchHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	query := "SELECT * FROM users WHERE name = '" + name + "'"
	db.Query(query)  // ruleid: SQL Injection
}

func pingHandler(w http.ResponseWriter, r *http.Request) {
	// exec.Command does NOT invoke a shell, so a tainted trailing argv
	// entry (e.g. exec.Command("ping", "-c", "1", host)) isn't actually
	// shell-injectable — only a tainted PROGRAM NAME (arg0) is, which is
	// what flagmap's Go sink (and the pre-existing regex patterns) check.
	bin := r.FormValue("bin")
	exec.Command(bin)  // ruleid: Command Injection
}

func readHandler(w http.ResponseWriter, r *http.Request) {
	fname := r.URL.Query().Get("fname")
	os.Open(fname)  // ruleid: Path Traversal / LFI
}

func serveHandler(w http.ResponseWriter, r *http.Request) {
	fname := r.FormValue("fname")
	http.ServeFile(w, r, fname)  // ruleid: Path Traversal / LFI
}

func goHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	http.Redirect(w, r, target, 302)  // ruleid: Open Redirect
}

func echoHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	fmt.Fprintf(w, name)  // ruleid: Cross-Site Scripting (XSS)
}

func inlineHandler() {
	http.HandleFunc("/inline", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		db.QueryRow("SELECT * FROM users WHERE id = " + id)  // ruleid: SQL Injection
	})
}

func runQuery(q string) {
	db.Exec(q)  // ruleid: SQL Injection
}

func searchHandler2(w http.ResponseWriter, r *http.Request) {
	// one-hop interprocedural: `q` is tainted at the call site below, which
	// must seed runQuery's own `q` parameter for the sink inside it to fire.
	name := r.URL.Query().Get("name")
	runQuery("SELECT * FROM users WHERE name = '" + name + "'")
}

func rowsHandler(w http.ResponseWriter, r *http.Request) {
	// idiomatic Go: result discarded into (rows, err), not a plain
	// single-name assignment — the sink inside the call must still fire.
	name := r.URL.Query().Get("name")
	sql2 := "SELECT * FROM users WHERE name = '" + name + "'"
	rows, err := db.Query(sql2)  // ruleid: SQL Injection
	_ = rows
	_ = err
}

func gorillaHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	db.Query("SELECT * FROM users WHERE id = " + id)  // ruleid: SQL Injection
}
