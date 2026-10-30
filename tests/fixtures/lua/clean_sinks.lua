function search_safe(req)
  local args = ngx.req.get_uri_args()
  local name = args.name
  -- parameterized query — the tainted value never touches the SQL string
  db:query("SELECT * FROM users WHERE name = ?", name)  -- safe: SQL Injection
end

function ping_safe()
  -- fixed, non-tainted argument
  os.execute("echo hello")  -- safe: Command Injection
end

function go_safe()
  -- same-origin relative path — not an open redirect
  ngx.redirect("/dashboard")  -- safe: Open Redirect
end

function read_file_safe(req)
  -- cross-line sanitizer case: tonumber() guarantees fname can only ever
  -- be a plain number by the time it reaches io.open() — no same-line
  -- regex exists for this vuln/language pair at all, so this is a pure
  -- AST-taint-tracking test.
  local args = ngx.req.get_uri_args()
  local fname = args.fname
  fname = tonumber(fname)
  io.open(fname)  -- safe: Path Traversal / LFI
end
