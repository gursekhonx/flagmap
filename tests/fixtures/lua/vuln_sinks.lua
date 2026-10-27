function search(req)
  local args = ngx.req.get_uri_args()
  local name = args.name
  local sql = "SELECT * FROM users WHERE name = '" .. name .. "'"
  db:query(sql)  -- ruleid: SQL Injection
end

function ping(req)
  local args = ngx.req.get_uri_args()
  local host = args.host
  local cmd = "ping -c 1 " .. host
  os.execute(cmd)  -- ruleid: Command Injection
end

function read_file(req)
  local args = ngx.req.get_uri_args()
  local fname = args.fname
  io.open(fname)  -- ruleid: Path Traversal / LFI
end

function go(req)
  local args = ngx.req.get_uri_args()
  local url = args.url
  ngx.redirect(url)  -- ruleid: Open Redirect
end

function calc(req)
  local args = ngx.req.get_uri_args()
  local expr = args.expr
  load(expr)  -- ruleid: Command Injection / RCE
end

function run_query(sql)
  db:query(sql)  -- ruleid: SQL Injection
end

function search2(req)
  -- one-hop interprocedural: `sql` is tainted at the call site below,
  -- which must seed run_query's own `sql` parameter for the sink inside
  -- it to fire.
  local args = ngx.req.get_uri_args()
  local name = args.name
  run_query("SELECT * FROM users WHERE name = '" .. name .. "'")
end

local Handler = {}

function Handler:process(req)
  -- one-hop interprocedural through Lua's colon-method OOP style: the
  -- function's own registered name must be the bare "run_search", not the
  -- qualified "Handler:run_search" its definition's name field literally
  -- spells out, or the call site below (which only ever resolves the bare
  -- method name) can never match it.
  local args = ngx.req.get_uri_args()
  local term = args.term
  self:run_search(term)
end

function Handler:run_search(term)
  local sql = "SELECT * FROM products WHERE name LIKE '%" .. term .. "%'"
  db:query(sql)  -- ruleid: SQL Injection
end
