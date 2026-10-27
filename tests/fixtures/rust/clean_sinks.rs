fn search_safe(req: &HttpRequest, conn: &Connection) {
    let name = req.query_string();
    // parameterized query — the placeholder string (checked) and the
    // bound value (a separate argument, not checked) are kept apart.
    conn.execute("SELECT * FROM users WHERE name = $1", &[&name]);  // safe: SQL Injection
}

fn ping_safe(conn: &Connection) {
    // fixed, non-tainted argument
    conn.execute("SELECT 1", []);  // safe: SQL Injection
}

fn read_file_safe() {
    // fixed, non-tainted path
    File::open("/etc/hostname");  // safe: Path Traversal / LFI
}
