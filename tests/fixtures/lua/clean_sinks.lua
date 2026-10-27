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
