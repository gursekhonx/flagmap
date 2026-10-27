fn search(req: &HttpRequest, conn: &Connection) {
    let name = req.query_string();
    let sql = "SELECT * FROM users WHERE name = '".to_string() + name + "'";
    conn.execute(&sql, []);  // ruleid: SQL Injection
}

fn ping(req: &HttpRequest) {
    let host = req.query_string();
    conn.query(&host, []);  // ruleid: SQL Injection
}

fn read_file(req: &HttpRequest) {
    let fname = req.query_string();
    File::open(fname);  // ruleid: Path Traversal / LFI
}

fn run_query(sql: &str, conn: &Connection) {
    conn.execute(sql, []);  // ruleid: SQL Injection
}

fn search2(req: &HttpRequest, conn: &Connection) {
    // one-hop interprocedural: `sql` is tainted at the call site below,
    // which must seed run_query's own `sql` parameter for the sink inside
    // it to fire.
    let name = req.query_string();
    let sql = "SELECT * FROM users WHERE name = '".to_string() + name + "'";
    run_query(&sql, conn);
}

struct App {
    conn: Connection,
}

impl App {
    // one-hop interprocedural through a &self METHOD: self.run_search(term)
    // never passes `self` as an explicit argument (same as every other
    // language's implicit receiver) — self_parameter has to be excluded
    // from run_search's own parameter list, or every real parameter's
    // index is off by one and seeding silently fails for every &self
    // method in the codebase, not just this one.
    fn search3(&self, req: &HttpRequest) {
        let term = req.query_string();
        self.run_search(term);
    }

    fn run_search(&self, term: &str) {
        self.conn.execute(term, []);  // ruleid: SQL Injection
    }
}
