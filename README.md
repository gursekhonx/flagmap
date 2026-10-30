# flagmap

A CLI tool that scans CTF challenge source code (PHP, Python, Node/JS, C#/
ASP.NET Core, Java, Go, Ruby, Lua, Rust) and flags common web-exploitation
vulnerability patterns, misconfigurations, exposed secrets/loot (`.git`,
flag-shaped strings, stray keys), and known-CVE pinned dependencies
(Log4Shell, old PHPMailer, etc.) — with a short explanation and a
suggested starting payload or action for each one. It also correlates
findings into likely **attack chains** (e.g. an upload bug plus an Apache
misconfig = RCE) and ranks a **"Start Here"** shortlist so you know what
to try first.

Built for jeopardy-style CTFs (like CyberSci regionals) where web challenges
sometimes hand you the source code. Instead of eyeballing every file, point
flagmap at the folder and get a triaged list of what's worth trying first.

## Architecture (v1.6.0)

**All eight supported languages are matched structurally**, via
[`tree-sitter`](https://tree-sitter.github.io/tree-sitter/) parse trees
(`flagmap/ast_engine.py`), not regex. Earlier versions matched everything
with regex, and a recurring category of bug kept coming back during testing
against real CTF repos: a quote inside a string literal breaking a
quote-excluding character class, catastrophic backtracking on a huge
minified line, a construction spread across multiple lines, a variable name
coincidentally matching an unrelated token (an f-string prefix, a method
name on an unrelated object). None of those were missing vulnerability
*knowledge* — they were regex losing to the fact that source code is a
tree, not a sequence of lines. Matching the actual parse tree instead:

- is invariant to quote style, nesting, whitespace, and line breaks — a
  tainted f-string/template-literal/encapsed-string is recognized by its
  AST shape (an `interpolation`/`template_substitution`/embedded
  `variable_name` node), not by a regex trying to not-match the wrong quote
  character;
- scopes taint tracking per function instead of "same file, textual
  proximity" — a variable in one function can no longer be confused with a
  same-named variable in another;
- does one hop of interprocedural taint tracking — if a route handler reads
  request data and hands it to a plain helper function, the helper's own
  parameter is seeded as tainted for that one call, so the bug doesn't go
  unnoticed just because it lives one function away from the request read;
- treats "is the tainted variable the call's receiver or its argument" as
  just a different field of the same call node, instead of needing two
  separate detection mechanisms for the two shapes.

Lua and Rust were the last two languages ported (v1.3.0), closing out what
Go/Java/Ruby started in v1.1.0/v1.2.0. Note that `taint.py`'s "taint-lite"
layer only ever covered PHP/Python/JS in the first place — **Go, Java,
Ruby, Lua and Rust all had zero cross-statement taint tracking before their
respective ports**, not a worse version of it; only single-line regex
patterns in `patterns.py` applied before. So none of these five ports were
"regex → AST" — each was "no taint flow at all → real taint flow."

As of v1.3.0, `taint.py`'s regex-based `find_tainted_sinks`/
`find_format_string_sinks` functions are effectively **fallback-only**:
every language flagmap supports now has an AST path, so those functions
only run at all if a language's tree-sitter grammar package isn't
installed — and even then, they only ever had source/sink tables for
Python/JS/PHP, so Go/Java/Ruby/Lua/Rust get *no* taint-lite coverage in
that fallback case either (same "regex-only, no taint tracking" situation
as before any of these languages were ported — see "Install" below for
why this is an unlikely edge case in practice). `taint.py`'s
`SEVERITY_BY_VULN`/`WHY_BY_VULN`/`PAYLOAD_BY_VULN` maps are a separate,
still fully-live piece of that file — both engines share them for every
language, ported or not.

Each port surfaced its own structural wrinkle the others didn't have:

- **Go**: `:=`/`=` always wrap both sides in an `expression_list` (to
  support multi-value assignment and the idiomatic `result, err :=
  someCall()` pattern), so a single generic "left field, right field"
  assumption doesn't work — see `_assign_lhs_rhs`'s Go branch for how a
  single right-hand expression still gets walked for sinks even when the
  left side has multiple names and can't be cleanly taint-propagated to
  one of them.
- **Java**: path-opening calls (`new File(path)`, `new
  FileInputStream(path)`) are constructor calls
  (`object_creation_expression`), not `method_invocation` — same reason
  PHP's `include`/`require` needed their own pseudo-sink table
  (`JAVA_PATH_CONSTRUCTOR_SINKS`) rather than fitting the regular
  call-shaped `SINKS`.
- **Ruby**: Rails' XSS footgun isn't a sink *function* at all — ERB
  auto-escapes by default, so the vulnerability is calling `.html_safe` (a
  receiver-slot sink, like PHP's `save()`) on tainted data to explicitly
  turn escaping back off, not passing tainted data to some dangerous
  function.
- **Lua**: `..` string concatenation (not a method call) builds most
  tainted SQL/shell strings, so taint still has to flow *through* a binary
  operator node, not just a call's arguments. Colon-call sugar
  (`obj:method(x)` ⇒ implicit `obj` receiver, `x` as the only explicit
  arg) needed its own three-way dispatch in `_call_info` alongside plain
  `identifier` calls and `.`-dot calls. `execute` was deliberately mapped
  only to Command Injection (`os.execute`), not also SQL Injection, because
  some Lua DB drivers also name their raw-query method `execute` — one
  callee name can only point at one vuln class in `SINKS`, so the
  less-ambiguous mapping was kept and the regex layer left to catch the
  DB-driver case independently.
- **Rust**: `Command::new`/bare `.new()` were deliberately **not** added as
  sinks — `new()` is Rust's universal constructor-method convention, so
  treating it as a sink would flag practically every struct in a typical
  codebase. `format!`-built SQL was also deliberately left uncovered here:
  macro arguments live inside an opaque `token_tree` node with no normal
  expression-grammar shape to match against, so that case is left to the
  pre-existing regex layer rather than forcing an AST match that doesn't
  fit the grammar.

**Three index-alignment bugs, found and fixed during the Lua/Rust port**:
every language's implicit method receiver (`self`, `this`, a colon-call's
qualifying object) is excluded from a call site's explicit argument list —
and the called function's own declared-parameter list has to exclude that
same implicit receiver too, one-for-one, or every real parameter after it
is off by one position relative to the call-site arguments, which silently
breaks one-hop interprocedural taint seeding for every such method in the
codebase, not just one. This class of bug showed up three times:

- **Lua**: `function Handler:run_search(term)`'s *definition-site* name
  field is the whole `method_index_expression` ("Handler:run_search"), not
  the bare method name — so it was being registered under a name a
  bare-method-name call site (`self:run_search(term)`) could never resolve
  to. Fixed in `_func_def_name` by pulling out just the `method`/`field`
  sub-field's text for Lua's `method_index_expression`/
  `dot_index_expression` name shapes.
- **Rust**: `&self` is its own distinct `self_parameter` node type (not a
  regular `parameter`), and it was being recorded as a placeholder
  parameter slot in `_param_names` instead of being skipped — shifting
  every subsequent real parameter's index by one. Fixed by skipping
  `self_parameter` entirely rather than reserving a slot for it.
- **Python (pre-existing, not introduced by this port — found while
  checking whether the same bug class was systemic)**: Python's `self`
  has no distinct node type marking it — it's an ordinary `identifier`
  parameter — so `self.run_query(x)` calling into `def run_query(self,
  q):` was silently misaligning every real parameter the same way. Fixed
  with a new `_is_python_self_param` helper (checks both class-body
  ancestry and that the literal name is `self`/`cls`, so a `@staticmethod`
  whose real first parameter isn't named either of those is left alone)
  wired into `_param_names`. JS and PHP were checked and are unaffected —
  neither grammar represents `this`/`$this` as an explicit parameter at
  all, so there was nothing to misalign.

**LDAP Injection (v1.4.0)** is the first new vuln class added after all 8
languages reached AST parity, and it's a useful case study in picking sink
names deliberately: Python has two popular LDAP libraries
(`python-ldap`/`ldap3`) whose search methods put the filter argument at
*different* positional indices, so rather than pick one and get the other
wrong, only `python-ldap`'s more specific names (`search_s`/`search_st`/
`search_ext`/`search_ext_s`) were added — `ldap3`'s bare `.search()` was
left out entirely. PHP's `ldap_search`/`ldap_list`/`ldap_read` carry an
unambiguous `ldap_` prefix, so they were added without any such caveat.
Java's JNDI `DirContext.search(name, filterExpr, cons)` reuses the same
generic `"search"` name problem as Java's own pre-existing `"execute"` sink
(`ExecutorService.execute(Runnable)` could share it) — accepted for the
same reason that one was: every AST finding is already tagged
`confidence="possible"`, specifically to cover cases exactly like this
where the callee name alone can't fully disambiguate which API is meant.

**Sanitizer-call taint-clearing (v1.13.0)** came out of stress-testing
flagmap against real external repos instead of only its own hand-built
fixtures (DVWA, NodeGoat, Pygoat, RailsGoat, DVWS-Node — see "Testing"):
DVWA ships a genuinely-patched "impossible" difficulty level per vuln
category, and running flagmap against it surfaced a real AST-engine false
positive — `$id = $_GET['id']; $id = intval($id); ...fopen($id)...` was
still being flagged, because the AST engine tracked `$id` as tainted from
its first assignment and never noticed the second assignment made it safe.
A numeric cast/parse is a provable guarantee regardless of what the
attacker sent — `intval()`/`(int)`/`(float)` in PHP, `int()`/`float()` in
Python, `parseInt()`/`parseFloat()`/`Number()` in JS, `tonumber()` in Lua —
so `_is_sanitizer_expr()` recognizes a bare call to one of these (or a PHP
numeric cast expression) on the right-hand side of a re-assignment and
explicitly clears that variable from the scope's tainted set
(`state.tainted.discard(name)`), not just skips adding new taint to it.
Deliberately scoped narrow: only a *bare* call to one of these exact names
(a same-named method on some unrelated object, `foo.intval()`, does **not**
count — `is_method` is checked and rejected) and only numeric casts/parses,
not string-sanitizer functions (`htmlspecialchars`, `escape`, etc. stay
out of this table — those neutralize XSS specifically and are handled by
the separate `PHP_SAFE_ECHO_WRAPPER_RE` echo-context check, not blanket
taint-clearing, since a string that's HTML-safe isn't necessarily SQL-safe
or path-safe too).

**Important scope note, stated plainly so this isn't oversold**: this only
ever affects the AST taint engine's own cross-statement tracking. It has
**no effect on `patterns.py`'s same-line regex layer**, which matches
textually (e.g. `fopen($fname, ...)` next to a `$fname` that looks
GET-shaped) regardless of what happened to that variable on an earlier
line. Concretely, this fix does **not** suppress the actual DVWA
`exec/source/impossible.php` false positive that motivated it — that
specific finding comes from a same-line Command Injection regex matching
`shell_exec('ping ' . $target)` irrespective of any `escapeshellarg()`
call earlier in the function, and teaching the regex layer itself about
preceding sanitization is a separate, larger piece of work not attempted
here. What this *does* fix is the narrower, AST-only version of the same
shape (a cast/parse several lines before a sink, with nothing GET/POST-
shaped textually present on the sink's own line) — see
`tests/fixtures/*/clean_sinks.*`'s `read_file_safe`-style cases for exactly
the shape this covers.

**Misconfiguration scanning (`config_scanner.py`) stays regex-based for
every file type**, deliberately — Dockerfiles, `nginx.conf`, `.env`, and
similar config formats are simple key/value or directive-per-line formats
with none of the nesting/quoting complexity that broke regex for *code*, so
there was no real problem there to fix.

If `tree-sitter` and its per-language grammar packages aren't installed,
flagmap still works — it quietly falls back to the regex engine for
Python/JS/PHP too (the same behavior as pre-1.0 versions) rather than
erroring out; for Go/Java/Ruby/Lua/Rust that fallback means no taint
tracking at all, same as before any of these five were ported (see above).
Each language's grammar is imported in its own `try/except` in
`ast_engine.py`, so e.g. not having `tree-sitter-go` installed only drops
Go back to the regex engine — it doesn't take the other languages down
with it. Install the grammars to get the structural engine's accuracy
improvements: `pip install tree-sitter tree-sitter-python
tree-sitter-javascript tree-sitter-php tree-sitter-go tree-sitter-java
tree-sitter-ruby tree-sitter-lua tree-sitter-rust` (also listed in
`setup.py`'s `install_requires`).

## What it catches

**Code vulnerabilities** (PHP, Python, Node/JS, C#/ASP.NET Core, Java, Go,
Ruby/Rails, Lua, Rust):

- SQL Injection (string-built queries, including a simple "variable assigned
  from user input, used a few lines later" taint check)
- Command Injection / RCE (`system`, `exec`, `eval`, `shell_exec`, etc.)
- Unsafe Deserialization (`pickle.loads`, PHP `unserialize`, `yaml.load`,
  `node-serialize`)
- Path Traversal / LFI (`include`, `fopen`, `open`, `send_file`,
  `readFileSync`, etc. fed from user input)
- Server-Side Template Injection / SSTI (`render_template_string`, EJS,
  Handlebars, Nunjucks)
- SSRF (`requests`/`urlopen`/`pycurl` in Python, `axios`/`fetch`/`http.get` in
  Node, `curl_setopt`/`file_get_contents` in PHP, fed from request data)
- Unrestricted File Upload (`move_uploaded_file`, Flask `.save()`, `multer()`
  with no extension/type allowlist)
- Cross-Site Scripting / XSS (reflected `echo`/`print` in PHP, unescaped
  template returns in Flask, `.innerHTML =`/`res.send()` in JS)
- XXE (DOMDocument/simplexml in PHP, lxml/xmltodict in Python) — with
  whole-file false-positive suppression for recognized safe-parsing
  markers (`defusedxml`, `resolve_entities=False`,
  `libxml_disable_entity_loader(true)`); see `xxe_guard.py` and
  "Best-effort heuristics" below
- ReportLab Paragraph Injection (added v1.11.0, Python) —
  `reportlab.platypus.Paragraph(text, style)` fed a tainted `text` value,
  either cross-line via the AST taint engine or same-line via a regex
  backstop. Not a generic "templating" bug like SSTI above: ReportLab
  parses `Paragraph()`'s text as its own mini-markup language no matter
  what (`<font color="...">`, `<a>`, `<img>`, ...), and on
  `reportlab<=3.6.12` a crafted `color` attribute escapes the library's
  `rl_safe_eval()` sandbox for outright RCE (CVE-2023-33733) — also
  tracked as a known-vulnerable dependency, see "Vulnerable
  Dependencies". Added after a real PDF-generator CTF challenge (title/
  content/section fields piped straight into `Paragraph()`) came back
  with zero findings from flagmap despite this being the intended bug.
- Open Redirect (`header("Location: ".$_GET...)`, Flask `redirect()`, Express
  `res.redirect()` from request data)
- NoSQL Injection (MongoDB `find()`/`update()` with the whole filter taken
  from the request body)
- Mass Assignment (`**request.json` into a constructor, `findByIdAndUpdate`
  with the raw request body)
- Prototype Pollution (`_.merge`/`deepmerge` into `{}` from request data)
- JWT / Auth Token Weaknesses (`verify=False`, `alg: none` accepted, missing
  algorithm allowlist)
- Weak Cryptography (MD5/SHA1 for password hashing, AES/DES in ECB mode)
- Insecure Randomness (`random`/`Math.random()`/`rand()` used for
  tokens/passwords/OTPs instead of a CSPRNG)
- CORS Misconfiguration (reflected/wildcard origin, especially with
  credentials enabled)
- Host Header Injection (`$_SERVER['HTTP_HOST']`, `request.host`,
  `req.headers.host` used to build URLs)
- Debug Mode Enabled (Flask `debug=True`, Django `DEBUG=True`, forced
  `display_errors`)
- Weak Auth Logic (PHP loose `==` type juggling, `strcmp` bypass, hardcoded
  secrets)
- Missing CSRF Protection (best-effort: a POST form with no CSRF token
  anywhere in the file)
- Missing Authorization / IDOR (best-effort, added v1.6.0, Python/JS/PHP/
  Go/Java/Ruby: an id read straight from the request/route — either an
  explicit extraction call or the route's own id-named parameter — handed
  to a lookup/update/delete call, with no ownership check anywhere in the
  function or the decorator/annotation above it. A bare login-required
  check does NOT count as that ownership check — see "Best-effort
  heuristics" for exactly what does and the real false-positive/negative
  tradeoffs of a check this coarse)
- GraphQL / Query Injection (a query/mutation document built with `%`
  formatting or template-literal interpolation instead of GraphQL variables)
- LDAP Injection (AST-matched since v1.4.0, Python/PHP/Java): a search
  filter string built from request data and passed to python-ldap's
  `search_s`/`search_st`/`search_ext`/`search_ext_s`, PHP's `ldap_search`/
  `ldap_list`/`ldap_read`, or Java JNDI's `DirContext.search` — lets an
  attacker inject extra filter clauses (an always-true `|` branch) to
  bypass an auth check or dump directory entries outside the intended
  query. Deliberately not covered for Node (`ldapjs`) or Ruby (`net-ldap`):
  both pass the filter as a field inside an options/hash argument rather
  than a plain positional string, which doesn't fit the arg-slot sink
  model any cleaner than the IDOR/absence-of-check cases in "What it can't
  catch" — forcing a match there would mean reaching into an object
  literal's keys, a different and much more false-positive-prone kind of
  check than anything else in `SINKS`.
- SSRF (AST-matched since v1.5.0, in addition to the existing regex
  coverage, Python/PHP/JS): `urlopen()` (Python), `file_get_contents()`
  (PHP), `fetch()` (JS) with a URL built from request data *anywhere
  upstream in the function or one hop away in a helper* — e.g. `urlopen("http://" +
  host + "/status")` where `host` came from a request read several lines
  earlier, which the existing regex can't reach (its bare-variable rule
  only matches when the *entire* argument is a single identifier token,
  and its same-line rule needs the request read literally on that line).
  When the sink call's argument genuinely is a single bare identifier on
  one line, the pre-existing regex rule already catches that same shape
  and scanner.py's cross-engine dedup (same file/line/vuln_name) keeps
  the regex finding rather than emitting both — by long-standing design
  (see `scanner.py`'s `seen` set), not new to this port. Deliberately did
  NOT add `requests.get/post/...`, `axios.get/post/...`, or `http(s).get`
  as sinks: `get`/`post` are near-universal method names (plain dict/Map
  access, any ORM/cache/client `.get()` — `request.args.get()`, a taint
  *source* in this very table, is itself a `.get()` call) and would be a
  far riskier collision than anything else accepted in `SINKS`; the regex
  layer still covers those same-line and bare-variable.
- Sensitive Data Exposure in Logs (passwords/secrets/tokens/hashes passed to
  `logger.debug`/`console.log`/`error_log` — common with structured loggers
  whose output ends up in a dashboard or log aggregator)
- Multi-line-aware SQL Injection: an f-string/template-literal/C#
  interpolated string with real SQL structure (`SELECT...FROM`,
  `INSERT...INTO`, etc.) and an interpolated variable is flagged at its
  *construction* site, even when it's assigned to a variable and executed
  several lines later — not just when the query is built inline inside the
  `execute()`/`query()` call itself
- C#-specific: JWT signature bypass (`ReadJwtToken()` instead of
  `ValidateToken()`, disabled signature validation), EF Core/ADO.NET raw SQL
  via interpolated strings, `BinaryFormatter`/`TypeNameHandling.All`
  deserialization RCE, `Html.Raw()` XSS, `Process.Start` command injection
- Stored/second-order XSS: a bare `echo $row['field'];` of a DB-stored value
  with no `htmlspecialchars()`/`h()` wrapper (the taint-lite layer only
  tracks superglobals, so this catches the shape it structurally can't)
- `addslashes()` misused as an XSS defense near request data (it only
  escapes quotes/backslashes — it does not stop a `</script>` tag breakout)
- Path Traversal / Zip Slip (`zipfile`/`tarfile` `.extract()`/`.extractall()`
  calls, which are unsafe unless member names are validated first)
- Insecure session tokens built from a plain `base64.b64encode(username)`
  with no signature/secret — trivially forgeable for any account
- JWT `verify_signature` explicitly set to anything other than a literal
  `True` (commonly a variable that can resolve to `None`/`False`)
- Java (AST-matched since v1.2.0, see "Architecture"): `executeQuery`/
  `executeUpdate`/`execute` with a SQL string built from
  `request.getParameter`/`getParameterValues`/`getHeader`/`getQueryString`
  *anywhere upstream in the method* (not just a same-line concatenation),
  `Runtime.getRuntime().exec()` with a tainted command, `new
  File`/`FileInputStream`/`FileReader`/`FileOutputStream`/`FileWriter` with
  a tainted path, `response.sendRedirect()` with a tainted target — plus
  the regex layer's own unsafe deserialization (`readObject()` — ysoserial
  gadget-chain territory), `ProcessBuilder` concatenation, a defaults-only
  `DocumentBuilderFactory` (XXE), `MessageDigest.getInstance("MD5"/"SHA-1")`,
  `java.util.Random` used for tokens, which still run alongside it
- Go (AST-matched since v1.1.0, see "Architecture"): `db.Query`/`QueryRow`/
  `Exec` with a SQL string built from `r.FormValue`/`r.URL.Query().Get`/
  `mux.Vars`/`chi.URLParam` *anywhere upstream in the function* (not just a
  same-line `fmt.Sprintf`), `exec.Command()` with a tainted program name,
  `os.Open`/`ReadFile`/`Create`/`http.ServeFile` with a tainted path,
  `http.Redirect` with a tainted target, `fmt.Fprintf`/`Fprint` writing
  request data straight to the `ResponseWriter` (XSS) — plus the regex
  layer's own `fmt.Sprintf`-based SQL/SSTI/SSRF/mass-assignment/
  insecure-randomness checks, which still run alongside it
- Ruby/Rails (AST-matched since v1.2.0, see "Architecture"): `execute`/
  `exec_query` with a SQL string built from `params[...]`/`request.params`/
  `cookies[...]`/`request.headers` *anywhere upstream in the method*,
  `system`/`IO.popen` with a tainted command, `File.open` with a tainted
  path, `Marshal.load`/`YAML.load` with tainted data, `redirect_to` with a
  tainted target, and `.html_safe` called ON tainted data (ERB's
  auto-escaping explicitly turned back off — a receiver-slot sink, not an
  argument one) — plus the regex layer's own string-interpolated
  `where()`/`find_by_sql()`, `params.permit!` mass assignment, `render
  inline: params` SSTI, which still run alongside it
- Lua (AST-matched since v1.3.0, see "Architecture"): `..`-concatenated SQL
  passed to a colon-call query method (`db:query(...)`, `conn:execute(...)`)
  with the tainted value built *anywhere upstream in the function* (not
  just a same-line concatenation), `os.execute()`/`load()`/`loadstring()`
  with a tainted command/code string, `io.open()` with a tainted path,
  `ngx.redirect()` with a tainted target — plus the regex layer's own
  checks, which still run alongside it
- Rust (AST-matched since v1.3.0, see "Architecture"; intentionally light
  coverage — Rust's safety guarantees remove most of what flagmap targets):
  `.query`/`.execute` with a SQL string built from a tainted HTTP-request
  value *anywhere upstream in the function or `&self` method*, `File::open`
  with a tainted path — plus the regex layer's own bare-variable
  `Command::new()`, `format!`-built SQL (deliberately left to regex — see
  "Architecture"), bare-variable filesystem calls, and `unsafe`-block
  manual-review flag, which still run alongside it
- EJS `<%- %>` and Handlebars `{{{ }}}` — the raw/unescaped-output tags of
  their respective template engines (the escaped forms are `<%=` / `{{ }}`)
- A hand-rolled recursive merge utility with no guard of its own (`key in
  target` walking the prototype chain) — Prototype Pollution that survives
  even when an upstream parser blocklists `__proto__`/`constructor`
- Puppeteer/Playwright `page.goto()` fed a bare variable — SSRF via an
  admin/review bot visiting an attacker-chosen URL, a different API shape
  than HTTP-client SSRF (axios/requests/curl)
- A stored value pulled out of a collection by index and written straight
  into the response (`res.end(items[i])`) — stored XSS/CSS-injection that
  taint-lite can't see because the source is a prior storage write, not a
  superglobal
- Go: a raw `map[string]string`/`map[string]interface{}` request-handler
  declaration instead of a typed struct — Go's shape of Mass Assignment if
  that map is later re-marshaled into a downstream API call unfiltered
- Ruby `.constantize` on a hash/params-indexed string — unsafe dynamic class
  instantiation that can load *any* class currently in memory (a well-known
  Rails RCE/SSRF/file-read gadget chain) with attacker-supplied constructor
  arguments
- Go SSRF-via-reverse-proxy (`http.NewRequest(req.Method, url, ...)` built
  from the inbound request and a dynamically-constructed target) and
  bare-variable `uint8/16/32(...)` narrowing casts (Integer
  Overflow/Truncation — silently wraps a value that exceeded the smaller
  type's range, desyncing a length-prefixed format or size check)
- PHP `define('...SECRET...'/'...PASSWORD...'/'...KEY...', 'literal')` —
  the `define()`-constant idiom for the same hardcoded-secret problem as a
  `$var = "value"` assignment
- A narrow JSP `<%= request.getParameter(...) %>` / `<%= request.getAttribute(...) %>`
  direct-output XSS (deliberately narrow: JSP's `<%= %>` tag has no "safe"
  form to contrast against, so this only catches the direct-from-request
  subset, not e.g. a stored/DB value reflected the same way)
- Unrestricted File Upload via the *receiver* shape, not just an argument:
  `f.save(path)` where `f` itself came from `request.files[...]` a few lines
  earlier (distinct from, and complementary to, the argument-based taint
  check above)
- Format String Injection (Python): a template string built up piece by
  piece with `+=` (rather than being a single literal) that's later passed
  as the control string to its own `.format(...)` call — if any
  concatenated piece can carry attacker-influenced text (a log file, a
  stored value, a header), that text's own `{...}` syntax gets interpreted
  against whatever kwargs are given, which can walk object attributes to
  leak secrets
- Source code embedded directly in a Dockerfile heredoc (`RUN cat <<EOF >
  app.js ... EOF`) rather than written as its own file — a surprisingly
  common shape for small single-file challenges, which an extension-based
  file walk can never see on its own. flagmap pulls the heredoc body back
  out and runs it through the exact same pattern/taint pipeline as a normal
  file, attributed to a synthetic `Dockerfile (heredoc -> app.js, from line
  N)` path so findings still point somewhere useful

**Misconfigurations** (Dockerfile, docker-compose, nginx/apache, .env,
vsftpd.conf, redis.conf, my.cnf, php.ini, sshd_config, Kubernetes manifests):

- Containers running as root / privileged / sharing the host namespace
- Docker socket mounted into a container or pod (common escape-to-host path)
- Hardcoded secrets in Dockerfiles, compose files, or `.env`
- Anonymous/writable FTP, unauthenticated Redis, MySQL `skip-grant-tables`
- Directory listing enabled (nginx `autoindex`, Apache `Options Indexes`)
- `allow_url_include`/`register_globals` enabled in `php.ini` (RFI-class bugs)
- SSH `PermitRootLogin`/`PermitEmptyPasswords` set to yes
- Database/admin ports published to the host network unnecessarily
- Dangerous Apache `AddType application/x-httpd-php .jpg`-style directives
  (makes uploaded images/text files execute as PHP — a common upload-to-RCE
  primitive, checked in both generic Apache configs and `.htaccess` files)
- Terraform `output` blocks whose name suggests a credential but aren't
  marked `sensitive = true` (leaks into `.tfstate`/CI logs in cleartext)
- `.sh` provisioning/bootstrap scripts: HashiCorp Vault started with
  `server -dev` (auto-unseals with a well-known, logged root token), plus
  Redis/MongoDB started with protection/auth explicitly disabled
- JavaScript sourcemap (`.map`) files shipped alongside a production build
  (sniffed by content shape — `"mappings"`/`"sources"` keys — not just the
  extension) — anyone can unmap minified JS back into readable source,
  commonly exposing internal logic or hardcoded secrets never meant to be
  client-visible

This list keeps growing — see "Extending it" below, and the project's commit
history for real CyberSci challenges this was tested against.

**Loot / Recon** (`loot.py`, added v1.7.0) — printed in its own section,
*before* Code Vulnerabilities, and ranked first in "Start Here" regardless
of severity, because every one of these needs zero exploitation: the
action is "open the file" or "run one git command", not "find and trigger
a bug". A category genuinely distinct from both "code vulnerability" and
"misconfiguration" — these are packaging mistakes in how the challenge
source itself was handed out, not bugs in the challenge's logic:

- **Exposed `.git` directory** — `scanner.py`'s main source walk and
  `config_scanner.py`'s walk both deliberately skip `.git` (noise for "scan
  the code for bugs"), but that's exactly the signal here: `loot.py` does
  its own separate walk that doesn't skip it, flags its mere presence, and
  suggests `git log -p --all` / `git show --all` directly — deleted files,
  old credentials, and a pre-swap flag are all common finds this way.
- **Exposed `.env` file**, **`.htpasswd`**, **SSH private keys**
  (`id_rsa`/`id_dsa`/`id_ecdsa`/`id_ed25519`, by exact filename) — presence
  alone is the finding.
- **Backup/editor-leftover files** (`.bak`, `~`, `.swp`, `.orig`) — often
  served as raw, unexecuted source if the extension was never blocked at
  the web server, and even just in a source handout worth diffing against
  the real file for anything redacted.
- **Loose database dump files** (`.sql`, `.sqlite`, `.sqlite3`) — likely
  real table data: user records, password hashes, sometimes the flag
  itself.
- **Hardcoded flag-shaped strings** (`flag{...}`/`CTF{...}` and
  case variants, requiring real alphanumeric content inside the braces —
  tightened after this check, run against flagmap's own source during
  development, flagged its own docstring's illustrative `flag{...}`
  example) — scanned across every file in the tree, not just recognized
  source-code extensions, since a stray flag left in a `.txt`/`.md`/`.log`
  file is just as real a find as one left in `.py`.
- **PEM-format private key material** and **AWS access key IDs**
  (`AKIA[0-9A-Z]{16}`) embedded directly in any file's content — the two
  content-based checks kept deliberately narrow (see `loot.py`'s module
  docstring for why a broader "any secret-looking string" check was left
  out: that's the existing hardcoded-credential regex's job for
  recognized source files, and a weaker duplicate of it here would just
  be noise).

Every finding here carries `"likely"` confidence, not `"possible"` —
unlike a tainted-sink match (a pattern that *might* be exploitable
depending on code this tool can't fully see), a `.git` folder or a
flag-shaped string being present is not probabilistic: it's a fact about
what's in the tarball you were just handed.

**Vulnerable Dependencies** (`deps.py`, added v1.8.0) — a fourth category,
printed in its own section between Loot/Recon and Code Vulnerabilities,
and ranked second in "Start Here" (after loot, ahead of everything else):
a package manifest or lockfile pins an *exact* version, and that exact
version has a well-known CVE.

This is deliberately **not** a general SCA (software composition
analysis) tool — it doesn't call out to any live CVE/OSV database (that
would mean network access to a service that's often rate-limited or paid,
and would make results depend on what's reachable at scan time rather
than being reproducible). Instead it ships a small, hand-curated,
offline table (`CVE_TABLE` in `deps.py`) of CVEs that come up again and
again specifically in CTF/training contexts:

- **Log4Shell** and its three follow-on CVEs (`org.apache.logging.log4j:log4j-core` < 2.17.1, Java/`pom.xml`)
- **SnakeYAML** unsafe-deserialization RCE (`org.yaml:snakeyaml` < 1.26 and < 1.31)
- **PyYAML** unsafe `yaml.load()` RCE (`pyyaml` < 5.1)
- **Old PHPMailer** — three chained CVEs across < 5.2.18 / < 5.2.22 / < 6.0.6
  (`phpmailer/phpmailer`, PHP/`composer.lock`)
- **Struts2** `CVE-2017-5638` — the Equifax-breach Content-Type OGNL RCE
  (`org.apache.struts:struts2-core`, branch-aware: < 2.3.32 / < 2.5.10.1)
- **Rails** `CVE-2020-8165` — Marshal-based cache-store deserialization RCE
  (`rails`, branch-aware: < 5.2.4.3 / < 6.0.3.1)
- **Django** `CVE-2022-28346` — `QuerySet` SQL injection (branch-aware
  across the 2.2/3.2/4.0 lines)
- **lodash** `CVE-2021-23337` (< 4.17.21) and **minimist** prototype
  pollution (`CVE-2020-7598` < 1.2.3, `CVE-2021-44906` < 1.2.6)
- **Pillow** `CVE-2022-22817` (< 9.0.0) and **urllib3** `CVE-2021-33503`
  ReDoS (< 1.26.5)
- **ReportLab** `CVE-2023-33733` (< 3.6.13, added v1.11.0) — the same
  `rl_safe_eval()` sandbox-escape RCE the "ReportLab Paragraph Injection"
  app-code check above is named after; this entry catches it from the
  pinned-version side even in a file where the app code itself looks
  fine at a glance.

Parsed manifests/lockfiles: `requirements.txt` (exact `==` pins only —
a range like `flask>=1.0` tells you nothing about what actually got
installed, so it's skipped, never guessed at), `Pipfile.lock`,
`package-lock.json` (npm v1 and v2/v3 shapes), `yarn.lock`,
`Gemfile.lock`, `composer.lock`, and `pom.xml` (skipping any `<version>`
that's actually an unresolved `${property}` placeholder — same
never-guess rule). Each is parsed by regex/line-scanning rather than a
full JSON/XML parse, same style as the rest of flagmap, so a partial or
slightly malformed file still yields whatever lines do match and keeps a
real line number, rather than an all-or-nothing exception.

Self-tested on first attempt with zero false positives this time (unlike
loot.py's self-caught docstring bug): running it against flagmap's own
repo found only the matches inside its own test fixtures, nothing
spurious from `setup.py`'s loose `>=` version ranges.

Known limitation, stated plainly rather than glossed over: this table
reflects what's well-known as of when it was written, nothing more. It
will go stale, and it covers maybe a dozen CVEs out of the thousands that
exist. Treat a clean result as "no *well-known* bad pin found", never as
"this dependency tree is clean." Severities here are capped at `"high"` —
flagmap's severity scale everywhere else only has three tiers
(high/medium/low), and adding a fourth `"critical"` tier just for this
check would have silently broken sort order in the CLI and in "Start
Here" rather than doing anything useful.

## Install

As of v1.3.0, flagmap depends on `tree-sitter` plus a grammar package for
each of its 8 supported languages for the structural matching engine (see
"Architecture" above). It still *works* without them — any language whose
grammar isn't installed falls back to the regex engine (see "Architecture"
for what that costs) — but install them to get the accuracy improvement:

```bash
cd flagmap
pip install -e .
```

`pip install -e .` pulls in `tree-sitter` and all 8 grammar packages
(`tree-sitter-python`/`-javascript`/`-php`/`-go`/`-java`/`-ruby`/`-lua`/
`-rust`) automatically via `install_requires` in `setup.py`. This gives you
a `flagmap` command. Or just run it without installing:

```bash
python3 -m flagmap <path>
```

## Usage

```bash
# scan a folder (the extracted challenge source)
flagmap ./challenge_source

# scan a single file
flagmap ./challenge_source/app.py

# only show high-severity, high-confidence findings
flagmap ./challenge_source --severity high --min-confidence likely

# machine-readable output (includes both "findings" and "chains")
flagmap ./challenge_source --json

# no color (for piping/logging)
flagmap ./challenge_source --no-color

# skip the attack-chain correlation and/or the Start Here shortlist
flagmap ./challenge_source --no-chains --no-start-here

# also write a shareable Markdown writeup (e.g. to paste/drop for your team)
flagmap ./challenge_source --export-md report.md

# only show findings in files that changed since an earlier snapshot
# (e.g. the organizers just pushed a patched "v2" of the challenge)
flagmap ./challenge_source_v2 --diff-against ./challenge_source_v1

# print the installed version
flagmap --version
```

Output is split into up to six sections (plus `--export-md`, which renders
the same findings/chains as a standalone Markdown file alongside whatever
else you asked for — see "Sharing results with a team" below — and
`--diff-against`, which narrows all of them to files changed since a
previous snapshot — see "Re-scanning a patched challenge" below):

1. **Loot / Recon** — exposed `.git`, `.env`/keys, backup files, hardcoded
   flag-shaped strings. Needs zero exploitation, so it's printed first and
   ranked first in "Start Here" regardless of severity. See "Loot / Recon".
2. **Vulnerable Dependencies** — a manifest/lockfile pins an exact version
   with a well-known CVE (Log4Shell, old PHPMailer, ...), each with a
   suggested upgrade under `fix:`. Ranked second in "Start Here", after
   loot. See "Vulnerable Dependencies".
3. **Code Vulnerabilities** — exploitable bugs in the app's source, each
   with a suggested payload under `try:`.
4. **Misconfigurations** — infra/config issues like a Dockerfile running as
   root or a wildcard CORS origin, each with a suggested remediation under
   `fix:`. This scan runs automatically alongside the code scan — no
   separate flag needed.
5. **Attack Chains** — findings correlated into a likely exploit path (e.g.
   an upload bug + a dangerous Apache `AddType` = direct RCE, or a root
   container + any RCE primitive = no privilege-escalation step needed).
   This is a plain co-occurrence check over the findings already produced —
   not new scanning or dataflow analysis — so treat a chain like any other
   `possible`-confidence finding: a strong hint of where to look first, not
   a guarantee the path is real. See `chains.py`.
6. **Start Here** — a ranked shortlist of the 3-5 highest-value findings:
   loot first, then known-CVE dependencies, then everything else by
   attack-chain membership, severity, and confidence. Built for the moment
   you open a report and just want to know what to click on first.

### Sharing results with a team (`--export-md`, added v1.10.0)

`--export-md FILE` renders the exact same findings and chains as a
standalone `.md` file (`report_md.py`) — same sections, same grouping,
same "Start Here" ranking, just Markdown instead of ANSI-colored terminal
text — in addition to whatever the normal run already prints (works
alongside `--json` too; they're independent outputs from the same scan).
Built because CyberSci and most jeopardy CTFs are played in teams, usually
over Discord/Slack, under a clock: the person who ran flagmap is rarely
the only one who needs the results, and reading them off a terminal means
re-describing them by hand in chat. This makes "paste it in Discord" or
"drop it in the team's shared doc" a straight file hand-off instead.

### Re-scanning a patched challenge (`--diff-against`, added v1.12.0)

`--diff-against OLD_PATH` restricts the report to findings in files that
are new or changed (by byte content, not mtime) relative to a previous
snapshot of the same challenge — built for the specific moment an
organizer announces a patch mid-competition ("v2 is up, the old bug is
fixed") and the real question is "what did they touch, and is there
anything NEW in exactly those files" (a patch is itself a common place
for a *second* bug to slip in). Re-reading a full report by eye to spot
that defeats the point of having a scanner.

Deliberately diffs two plain directory snapshots (`diffscan.py`), not two
git refs: a CTF handout is essentially never its own git repository — if
one WERE shipped, that's itself a loot/recon finding (see "Loot /
Recon") — so there's nothing to assume the player has been committing
to. "Point it at the folder you already downloaded" needs no setup.
Works alongside every other flag, including `--json` (the summary lands
in a top-level `"diff"` key) and `--export-md`.

## How it decides what to flag

Two layers:

1. **Direct patterns** — regex rules matched per line, per language
   (e.g. `os.system(f"...")`, `unserialize($_GET[...])`).
2. **Taint-lite** — a lightweight, single-file heuristic: it notices when a
   variable is assigned from user input (`$x = $_GET[...]`, `x =
   request.args.get(...)`), tracks simple re-assignment chains, and flags
   when that variable later reaches a dangerous sink (`query()`, `system()`,
   `include()`, `eval()`, etc.) — even if the superglobal isn't used inline
   on that exact line.

This is **not** real taint/dataflow analysis — no control flow, no general
sanitizer detection (the AST engine's taint-lite layer recognizes one
narrow, provably-safe case — numeric casts/parses, see "Architecture"'s
"Sanitizer-call taint-clearing" — but nothing broader than that, and the
regex layer recognizes none at all). It's built to catch the specific patterns
that show up constantly in intentionally-vulnerable CTF code. Every finding
is tagged `likely` or `possible` confidence so you know which ones are worth
checking first. Treat it as a fast triage pass, not ground truth — always
verify the actual code path.

Matches inside files/directories that look like test fixtures (`tests/`,
`test_*.py`, `*.spec.js`, etc.) are suppressed for the handful of rules that
are expected to fire constantly on legitimate test data (e.g. a hardcoded
`password = "testpassword123"` in a unit test) — see `scanner.is_test_file()`
and `patterns.NOISY_IN_TEST_FILES`.

Any single line over 5,000 characters is skipped before any regex touches it
(`scanner.MAX_LINE_LEN`). Real, hand-written vulnerable source is never a
100,000-character single line — only vendored/minified assets (a bundled
`tailwindcss.js`, `jquery.min.js`, etc.) are, and running pattern regexes
with nested quantifiers against a line that long is catastrophic-
backtracking territory that can hang the whole scan with no error and no
partial output. This cap also protects the config-file line checks.

The taint-source regexes (`taint.SOURCE_PATTERNS`) match anywhere on the
right-hand side of an assignment, not just immediately after `=` — real code
constantly wraps the superglobal/request access in `isset(...) ? ... : ''`,
a type cast, or a default fallback (`request.args.get('q', '') or 'x'`), and
an over-anchored regex misses taint entirely the moment it's not the very
first thing on the line.

## Best-effort heuristics

Two checks in flagmap are deliberately a third, looser category than
everything above: not "a dangerous call exists" (direct patterns) and not
"a tainted value reaches a dangerous call" (taint-lite/AST), but "a check
that *should* be here doesn't seem to be anywhere in this file/function."
Proving a negative like that from source text alone is, honestly, not
fully solvable — see "What it can't catch" for why absence-of-a-check bugs
are flagmap's hardest category in general. These two exist anyway because
the alternative (refusing to try at all) throws away a signal that's
genuinely useful often enough to be worth a "possible"-confidence flag,
as long as it's never oversold as more than that. A third, related check
runs the same "whole-file textual signal, not real data-flow" logic in
reverse — suppressing a finding when a safety marker *is* present, rather
than flagging when a check seems absent.

- **Missing CSRF Protection** (`csrf.py`) — the original of the two: a
  `<form method="post">` with no mention of "csrf" anywhere in the same
  file. Deliberately whole-file, not per-form: no cross-file/template-
  include awareness, no JS-based CSRF header checks. Catches the "plain
  HTML form, no token field, no middleware" shape that's extremely common
  in intentionally-vulnerable CTF apps; misses anything where the token
  lives in a layout/include the scanner isn't looking at, and can false-
  positive on a file that has CSRF protection phrased in a way that never
  spells out the literal substring "csrf".
- **Missing Authorization / IDOR** (`idor.py`, added v1.6.0) — the newer
  and considerably more involved of the two. For each function in an
  AST-supported language (Python/JS/PHP/Go/Java/Ruby — Lua/Rust skipped,
  same "rare fit" reasoning their `SINKS` tables already use), it checks
  three things: (1) does this function read an id-like value from the
  request/route — either an explicit extraction call (`request.args.get`,
  `req.params.id`, `$_GET['id']`, `params[:id]`, Go's
  `r.URL.Query().Get`/`mux.Vars`/`chi.URLParam`, Java's `getParameter`) or
  the function's *own parameter* literally being named `id`/`user_id`/
  `order_id`/etc. (the equally-common Flask/Express/Laravel/Rails
  route-path-binding idiom, where there's no extraction call at all —
  `@app.route("/orders/<int:order_id>") def view(order_id): ...`); (2)
  does it hand that value to something lookup/mutation-shaped (`find`,
  `findById`, `where`, `filter_by`, `get_object_or_404` (Django's own
  distinct idiom — SQLAlchemy/ActiveRecord-style `.filter_by().first()`
  chains don't cover it), `update`, `delete`, `destroy`, ...); and (3) is
  there no sign, anywhere in the function OR up to 5 lines
  above it (to catch a decorator/annotation sitting directly on top), of
  an *ownership* check. That third part is the one worth being precise
  about: it deliberately does **not** treat a bare authentication check
  (`@login_required`, `@jwt_required`, "isAuthenticated") as a mitigating
  signal, on purpose — that proves the request comes from *some*
  logged-in user, not that it's the *right* user for *this* resource,
  and treating it as sufficient would make the check fire on approximately
  nothing, including the exact "logged in as anyone, no ownership check,
  can touch anyone's record" shape that IS the textbook CTF IDOR bug. It
  *does* recognize an ownership check folded directly into the lookup
  itself (`filter_by(id=order_id, user_id=current_user.id)`,
  `where(id: order_id, user_id: current_user.id)`) — current_user/owner_id/
  user_id-style keywords inside the SAME call that does the lookup still
  count — as well as a separate explicit compare afterward, a
  policy/authorize call (Pundit's `policy(...)`, Rails' `authorize!`,
  CanCan's `can?`), Laravel's `Auth::id()`, and Spring's `@PreAuthorize`
  (which also reasonably suppresses a genuinely admin-only route, where a
  per-user ownership concept doesn't apply in the first place). Function
  boundaries are found precisely by reusing `ast_engine.py`'s existing
  tree-sitter parse + `SCOPE_NODE_TYPES` table rather than a second,
  worse regex-based brace/indentation counter — everything *inside* that
  boundary is still plain regex over the function's own text, deliberately,
  in the same "textual signal, not real data-flow" spirit as the CSRF
  check. Known blind spots, stated as plainly as everything in "What it
  can't catch": ownership enforced at the database layer (row-security,
  tenant-scoped connections) is invisible to a source-text check by
  construction; ownership checked in a *different* function this one
  calls is invisible too (no interprocedural reasoning here — not even
  the one-hop seeding the real taint engine does); a genuinely
  no-ownership-concept route (a health check with an unrelated `id` query
  param) can still false-positive, because nothing here understands what
  a resource is *for*; and any ownership check phrased in a way the
  keyword list above doesn't recognize is a false negative. If this
  flags something, the right response is to read the function, not to
  trust the label — exactly the same advice "What it can't catch" gives
  for every category it refuses to even attempt.

  Shipping this against more than its own curated fixtures turned up
  five real gaps before it could be trusted at all, in the same spirit
  as the index-alignment bugs the Lua/Rust port found: a self-collision
  where the id-EXTRACTION call itself (`request.args.get(...)`) also
  satisfied the lookup-sink check (bare `"get("` was in that list —
  removed, since every Flask/Express route's own extraction line would
  otherwise count as its own "lookup"); a missed Express idiom
  (`req.params.id`, plain dot-property access, arguably the *more*
  common shape than the dict-style access originally covered); missed
  camelCase parameter names (`$orderId`/`orderId` vs. the originally
  snake_case-only `order_id` check — fixed with a normalization step,
  not just more alternation branches, since PHP/Java/JS routinely use
  the different convention Python/Ruby don't); Go's extraction idioms
  (`r.URL.Query().Get`, `mux.Vars`, `chi.URLParam`) not resembling any
  other language's shape at all; and Django's `get_object_or_404` not
  being recognized as a lookup call. All five are fixed and locked into
  the fixtures now, but the pattern is worth naming plainly: a
  best-effort heuristic like this one earns trust from how hard it's
  been stress-tested against real framework idioms, not from how
  reasonable its design sounds on paper.

- **XXE guard awareness** (`xxe_guard.py`, added v1.9.0) — not a new
  finding, a false-positive *suppressor* for the existing "XML External
  Entity (XXE)" pattern matches (`patterns.py`'s XXE regexes are blanket
  "this XML-parsing call exists" matches with no way to see whether the
  parser was configured safely somewhere else in the file). If a
  recognized safe-parsing marker appears **anywhere** in the same file —
  Python: `defusedxml` used anywhere, `resolve_entities=False`, or
  `no_network=True`; PHP: `libxml_disable_entity_loader(true)` — every
  XXE finding in that whole file is dropped, not just ones textually
  near the marker. This is deliberately coarse: a real per-call,
  taint-aware "is THIS specific parser instance safe" check would need
  the same cross-line object-flow tracking the IDOR check above and the
  AST taint engine do for their own sinks — a bigger lift than this
  narrow false-positive fix justifies on its own. Known trade-off, same
  honesty as everywhere else in this section: a file that uses an unsafe
  parser for one XML input and a safe one for another will have its
  genuine unsafe-parser finding wrongly suppressed too if any safe marker
  appears anywhere in that same file. Accepted on purpose — a flood of
  false positives on every file that merely imports `defusedxml` is a
  far more common failure mode than that specific split-file shape, and
  leaving it unfixed was actively misleading (flagmap was flagging
  `defusedxml.ElementTree.fromstring(...)` — a call that exists
  specifically to BE safe — identically to a raw, unguarded one).
  Regression-tested as a matched pair per language (`vuln_sinks.*` has
  an unguarded `ruleid` case, `clean_sinks.*` has the identical call
  shape with the guard present, asserting `safe`) — and writing that
  pair caught a real bug before release: the first draft's explanatory
  code comments on the *unguarded* fixture cases literally said things
  like "no `libxml_disable_entity_loader(true)` anywhere in this file",
  which of course made that string appear in the file, which made the
  guard fire and suppress the very finding the fixture existed to
  assert — the exact same self-referential trap `loot.py`'s own
  docstring fell into with its flag-shaped-string example a checkpoint
  earlier. Fixed by rewording those comments to describe the absence
  without quoting the literal marker text.

## What it can't catch (on purpose)

A few recurring bug shapes get found in testing over and over, confirmed as
real, and then deliberately **not** turned into a pattern, because forcing
one would either be a no-op or a false-positive generator:

- **Missing authorization / IDOR, precisely** — a route that reads an id
  from the request with no check that the current user actually owns that
  id. This is an *absence* of a check, not a syntax shape; a regex can't
  tell "no comparison to the current user anywhere in this function" from
  "there's a comparison, it's just not visible on this line." As of
  v1.6.0 there IS a best-effort heuristic for exactly this shape
  (`idor.py`, "Missing Authorization / IDOR" in "What it catches") — it
  does not solve the underlying problem stated above, which is still true;
  it just accepts the same trade the pre-existing CSRF check already made
  for a different absence-of-a-check bug (see "Best-effort heuristics")
  rather than refusing to try at all. Treat every finding from it as "a
  human skim would flag this too, go look", never as "confirmed."
- **LLM-tool functions with no enforced access control** — the same
  absence-of-a-check problem, specific to `@tool`-decorated functions whose
  only access control is prose in a system prompt. Not covered by the IDOR
  heuristic above: that one looks for a *missing comparison to the current
  user*, which presupposes a conventional request/response web route in
  the first place — an LLM tool function's "access control" is prose in a
  system prompt the scanner never sees, so there's no code-level absence to
  even point at.
- **Known-CVE'd pinned dependencies/base images, beyond the curated table
  in `deps.py`** (e.g. `FROM traefik:v3.4.5` shipping a public dashboard
  path-traversal CVE, or any package/CVE pair not in `deps.py`'s hand-
  picked list — see "Vulnerable Dependencies") — the vulnerable code isn't
  in the challenge's own source at all, so no amount of pattern coverage
  over *this* repo's files would ever see it, and `deps.py` only covers
  manifests/lockfiles for 5 ecosystems against ~a dozen curated CVEs, not
  container base images or the long tail of everything else. A *general*
  version of this needs a live CVE/OSV-style dependency-version lookup
  across every ecosystem and every base image — a fundamentally different
  (and much more infrastructure-heavy) kind of check than the offline
  curated table this tool ships instead.
- **Pure logic/semantic confusion bugs** — e.g. a signature that's verified
  correctly over raw bytes, but the *meaning* of those bytes is then
  re-derived a different way (OCR, a different parser) than what was
  actually signed. There's no dangerous call or tainted sink to anchor a
  pattern on; the bug is in what the code *means*, not what it calls.
- **Race conditions / timing bugs** — inherently about execution order
  across requests, not something visible in a single read of the source.
- **Control-flow/escaping logic bugs** — e.g. a regex meant to escape a
  hash-fragment that has an off-by-one in what it excludes, or a function
  that's missing a `return` on one branch so execution falls through into
  code meant for a different case. The *call shapes* here are completely
  ordinary (a regex, a function); the bug is in what the logic actually
  does, which is a program-semantics question, not a pattern-matching one.
- **Known-CVE'd dependency *interaction*, not just a pinned version** — two
  individually-fine components (e.g. a specific HTTP/1.1 parser library
  plus a specific reverse proxy) that disagree on how to parse an edge-case
  request, opening a request-smuggling window. Same fundamental ceiling as
  the pinned-base-image case above (needs a CVE/OSV-style lookup across
  *dependency pairs*, not source-pattern matching), but worth calling out
  separately since here it's an interaction between two otherwise-correct
  pieces of code, not a single obviously-outdated line.
- **Browser/HTTP-parsing quirks exploited as a technique** — e.g.
  "cookie sandwiching" (wrapping a legitimate cookie value in attacker
  values so a vulnerable parser's prefix/suffix matching gets confused
  about which value is real). The application code doing the comparison is
  often entirely reasonable-looking; the bug lives in an implicit
  assumption about how the *browser* serializes cookies, not in a
  recognizable dangerous-call shape.

If you hit one of these, that's expected — it's a sign to read the code
yourself, not a flagmap bug report.

## Example output

```
──────────────────────── flagmap 1.0.0 ─────────────────────────
 scanned: ./challenge_source
 3 finding(s) across 2 class(es)  [2 high · 1 medium] · 1 attack chain detected
────────────────────────────────────────────────────────────────

── Code Vulnerabilities ──
▶ SQL Injection  (1 match)
  [HIGH/possible] app.php:9
    $result = $conn->query($sql);
    why:  Variable assigned from user input earlier in the file is used
          inside a query call here. (tainted var: `sql`)
    try:  ' OR 1=1 -- 

── Attack Chains ──
⚡ [HIGH] SQLi -> Dump Weak-Hashed Credentials -> Crack Offline
    path: Use the SQLi to dump the users table -> crack the weak hashes -> log in as that user
    why:  The SQL injection gives you the password-hash column; the weak-hashing
          finding means those hashes are cheap to crack offline.
    based on: app.php:9 (SQL Injection), register.php:40 (Weak Cryptography)

── Start Here ──
  1. [HIGH/possible] SQL Injection — app.php:9  (part of an attack chain)
  2. [MEDIUM/possible] Weak Cryptography — register.php:40  (part of an attack chain)
```

## Project layout

```
flagmap/
  flagmap/
    __init__.py
    __main__.py          # python -m flagmap entry point
    cli.py                # argparse CLI, report formatting
    scanner.py            # file walking + dispatch to the AST engine (all 8 langs) or regex-only fallback (if a grammar's missing)
    ast_engine.py          # tree-sitter structural matching + scoped taint tracking (all 8 supported languages)
    patterns.py            # the code vuln pattern database (regex; all languages, runs alongside the AST engine too)
    taint.py              # severity/why/payload maps (shared by both engines) + legacy regex taint-lite, now fallback-only (py/js/php)
    heredoc.py             # pulls source embedded in Dockerfile heredocs back out for scanning
    csrf.py                 # best-effort missing-CSRF form check
    idor.py                # best-effort missing-authorization/IDOR check (see "Best-effort heuristics")
    loot.py                # recon: exposed .git/.env/keys/flag-shaped strings (see "Loot / Recon")
    deps.py                # curated known-CVE pinned-dependency table + manifest/lockfile parsers (see "Vulnerable Dependencies")
    xxe_guard.py            # whole-file XXE false-positive suppression (see "Best-effort heuristics")
    report_md.py            # standalone Markdown report renderer (--export-md, see "Sharing results with a team")
    diffscan.py              # two-snapshot file-diffing (--diff-against, see "Re-scanning a patched challenge")
    chains.py              # attack-path correlation over a scan's findings
    config_patterns.py    # the misconfiguration pattern database
    config_scanner.py      # file walking + checks (Dockerfile/nginx/.env/etc.)
  setup.py
  sample_challenge/       # sample vulnerable files for testing
```

## Testing

`scripts/run_regression.py` is the regression safety net — run it after any
change to `patterns.py` / `ast_engine.py` / `taint.py` before calling the
change done, instead of manually re-running old CTF repos to eyeball the
diff every time:

```
python3 scripts/run_regression.py -v
```

Fixtures live under `tests/fixtures/<language>/` and carry their own
expectations as trailing comment markers (same idea as semgrep's own test
convention):

```python
cur.execute(f"...{name}...")   # ruleid: SQL Injection   <- must fire, exact vuln_name
cur.execute("SELECT 1", (x,))  # safe                     <- must NOT fire anything
echo h($name);                 # safe: XSS                <- must not fire THIS vuln (others OK)
```

Each fixture file is both documentation of a known-good/known-bad shape and
a standing assertion that it keeps behaving that way. Add a `ruleid`/`safe`
line whenever a new sink, source, or false-positive guard is added, so the
next change can't silently regress it without the suite catching it.

`loot.py` gets its own convention under `tests/fixtures/loot/<case>/`,
since a whole-directory presence check (a `.git` folder, a leftover
`.env` file) has no single line to put a `ruleid`/`safe` comment on:
each case folder holds an `EXPECTED.txt` (one `vuln_name` per line) next
to an `app/` subfolder that's the actual tree to scan, and the harness
asserts the set of categories `find_loot()` reports on `app/` is *exactly*
the set listed — not "at least these", so a stray new false positive
(like `loot.py`'s own docstring once tripping its own flag-shaped-string
check during development) fails the suite just as loudly as a missed
true positive would.

`deps.py` reuses the exact same `EXPECTED.txt` + `app/` convention under
`tests/fixtures/deps/<case>/`, for the same reason (a manifest/lockfile
match has a file and a line, but there's no source-code "line of code" to
hang a `ruleid`/`safe` marker on in the usual sense) — except the
expected strings are `find_vulnerable_deps()`'s own `package@version
(CVE)` text, not the fuller `"Known-Vulnerable Dependency: ..."` string
`scanner.py` wraps it in for display, keeping the fixture's expectations
pinned to `deps.py`'s own output rather than to how another module
happens to format it. `case1` exercises all 7 parsers in one pass
(`requirements.txt`, `Pipfile.lock`, `package-lock.json`, `yarn.lock`,
`Gemfile.lock`, `composer.lock`, `pom.xml`) plus three deliberate
false-positive guards: a loose `requests>=2.0` range (must be skipped,
not guessed at), a `pom.xml` dependency pinned to a `${property}`
placeholder (same), and a handful of packages/versions with no CVE_TABLE
entry at all (`flask`, `express`, `monolog/monolog`, etc. — must produce
nothing).

`report_md.py` deliberately has no fixture category of its own: it's a
pure renderer over `Finding`/`Chain` objects the regression suite above
already exercises and validates, with no detection logic of its own to
regress — the risk there is a rendering bug (bad Markdown, a crash on
empty findings), not a wrong finding, so it's covered by manual CLI
smoke-testing during development (`--export-md` against a populated
scan, an empty-findings scan, and alongside `--json`) rather than a
fourth `EXPECTED.txt`-style convention that would just be asserting the
same findings all over again under a different name.

`diffscan.py` is the opposite case — real logic worth its own fixtures
(added/modified/unchanged-file detection, not just rendering) — so it
gets a fifth `EXPECTED.txt` convention under `tests/fixtures/diffscan/
<case>/`: an `old/` and a `new/` directory (two snapshots) instead of a
single `app/`, and the expected set is the relative paths (relative to
`new/`) `find_changed_files()` must report as changed. `case1` covers
all three shapes at once: a file identical in both (must NOT appear), a
file with the same name but different bytes in each (must appear), and a
file that exists only in `new/` (must appear) — plus a file that exists
only in `old/`, to confirm a removed file doesn't crash or wrongly appear
(it can't produce a finding in the new scan either way, so it's outside
what this check even needs to assert).

**A third validation layer, beyond this repo's own fixtures**: hand-built
fixtures only ever catch what whoever wrote them thought to write — they
can't surface a false positive nobody anticipated. So alongside the
`EXPECTED.txt`/`ruleid`/`safe` suite above, flagmap gets periodically
stress-tested against real, external vulnerable-by-design repos (DVWA,
OWASP NodeGoat, Pygoat, RailsGoat, DVWS-Node), which exist specifically to
be exploited and usually ship a "fixed"/"impossible"-difficulty reference
implementation per vuln category to check false positives against. This
is where the v1.13.0 sanitizer-call taint-clearing fix came from (DVWA's
`exec/source/impossible.php`) and where ReportLab Paragraph Injection
(v1.11.0) came from originally too (a real user-submitted challenge, not
one of these corpora) — real code surfaces gaps a curated fixture set
won't think to include. Not automated into `run_regression.py` (these
repos are large, licensed separately, and not vendored into this repo),
so this is a manual periodic exercise, not something CI runs on every
change — a finding worth keeping gets turned into a proper fixture here,
same as every other check in this file was.

Do **not** run this (or anything else in the repo) from inside a stale venv
with an old editable install of flagmap sitting in it — that shadows the
live source with whatever version was `pip install -e`'d there and produces
false failures that look like real regressions. Plain `python3
scripts/run_regression.py` from the repo root, with flagmap's dependencies
on the normal `python3` interpreter's path, is the reliable way to run it.

## Extending it

- New code-vuln rule → add to `RAW_PATTERNS` in `patterns.py`: each entry is
  `(name, language, regex, severity, why, payload, confidence)`.
- New language → add its extension(s) to `EXTENSION_LANGUAGE` in
  `patterns.py`, then add `RAW_PATTERNS` entries tagged with that language
  name.
- New taint sink, any of the 8 AST-supported languages → add an entry to
  `SINKS` in `ast_engine.py`: `callee_name: (vuln_name, slot, var_set)`,
  where `slot` is `"argN"` (the Nth argument must be tainted) or
  `"receiver"` (the object the method is called ON must be tainted), and
  `var_set` is `"tainted"` (the normal request-input taint) or `"built"`
  (the Format String Injection signal — see its definition for what that's
  for). Add the matching `SEVERITY_BY_VULN`/`WHY_BY_VULN`/`PAYLOAD_BY_VULN`
  entries in `taint.py` (both engines share these maps) if it's a new vuln
  name. A new *source* (beyond `request.args/form/json/files`-style
  superglobal access) goes in `SOURCE_TEXT_RE`.
- New taint sink, a language with no tree-sitter grammar installed
  (regex-fallback path) → add an entry to `SINKS` in `taint.py` (and the
  matching maps as above) — note this only ever had table entries for
  Python/JS/PHP, so it's only worth extending if you specifically need
  taint-lite coverage for the no-grammar-installed case.
- Porting a new language to the AST engine → tree-sitter has a grammar
  package for most mainstream languages. The work is: add it to `_PARSERS`
  in `ast_engine.py`, then fill in that language's row in each of
  `SCOPE_NODE_TYPES`/`CALL_NODE_TYPES`/`ASSIGN_NODE_TYPES`/
  `IDENTIFIER_NODE_TYPE`/`SOURCE_TEXT_RE`/`SOURCE_CANDIDATE_NODE_TYPES` by
  inspecting that grammar's node types and field names (`parser.parse(...)`
  then print the tree — the module's own development process for every
  language ported so far was exactly this). The call-site/taint-propagation
  logic itself (`_walk`, `_matched_taint_source`, the interprocedural
  seeding) is already language-generic and needs no changes. One thing
  worth checking explicitly for any new language: if it has an implicit
  method receiver (`self`/`this`/colon-call sugar), make sure
  `_param_names` excludes it from the callee's own parameter list the same
  way the call site excludes it from arguments — see "Architecture"'s
  "three index-alignment bugs" note for why skipping this silently breaks
  one-hop seeding for every method in that language.
- New misconfiguration rule → add to `LINE_CHECKS_RAW` in `config_patterns.py`
  under the right category (or a new one), same tuple shape plus a `fix`
  string instead of `payload`. For something that needs absence-detection
  (like "no USER directive anywhere") or combining two lines, add it to
  `_whole_file_checks()` in `config_scanner.py` instead.
- New config file type → add a filename/extension/content rule to
  `classify_config_file()` in `config_scanner.py`.
- New attack chain → add an `add(...)` call in `find_chains()` in
  `chains.py`: name two or more existing `vuln_name` substrings to correlate
  on, a short "A -> B -> C" path description, and why the combination
  matters. No new scanning needed — chains only look at findings already
  produced.

## Roadmap ideas

- ~~AST-based matching per language instead of regex~~ — done for all 8
  supported languages: Python/JS/PHP in v1.0.0, Go in v1.1.0, Java/Ruby in
  v1.2.0, Lua/Rust in v1.3.0 (see "Architecture").
- ~~Loot/recon scanning (exposed `.git`, hardcoded flags, stray keys,
  backup files)~~ — added in v1.7.0, see "Loot / Recon". A genuinely
  different kind of check than everything else in flagmap, not an
  incremental extension of the taint-tracking/pattern-matching approach —
  worth having because in practice a meaningful share of CTF points come
  from exactly this category, not from the "intended" vulnerability.
- ~~Known-vulnerable pinned dependency versions (Log4Shell, SnakeYAML, old
  PHPMailer, Struts2, Rails, Django, lodash/minimist, Pillow/urllib3,
  PyYAML, ...)~~ — added in v1.8.0 via `deps.py`, see "Vulnerable
  Dependencies". Deliberately scoped to a small curated table of
  well-known, exact-version-only matches, not a general SCA tool against
  a live CVE/OSV database — the "What it can't catch" entry below still
  applies to that broader, harder version of the problem.
- ~~ReportLab Paragraph Injection (CVE-2023-33733)~~ — added in v1.11.0:
  an AST taint-engine sink (`Paragraph`), a same-line regex backstop, and
  a `deps.py` CVE_TABLE entry, all at once. Not something this roadmap
  anticipated — found by running flagmap against a real user-submitted
  CyberSci-style challenge (a Flask PDF-generator app piping `title`/
  `content`/section fields straight into `reportlab.platypus.Paragraph()`)
  that came back with zero findings despite that being the intended bug.
  Worth naming as a reminder of where new coverage ideas actually come
  from in practice: real challenges run through the tool, not just
  brainstorming from a list of "vuln classes that exist."
- ~~LDAP Injection~~ — added in v1.4.0 for Python/PHP/Java (see
  "Architecture" and "What it catches"); Node/Ruby intentionally skipped,
  their LDAP libraries put the filter inside an options/hash argument
  rather than a plain positional string.
- ~~SSRF~~ — added real AST taint-tracking in v1.5.0 for Python
  (`urlopen`)/PHP (`file_get_contents`)/JS (`fetch`) — see "What it
  catches"; `requests.get/post`/`axios.get/post`/`http(s).get` were
  deliberately left to the regex layer (too generic a name to add
  safely — see "What it catches" for why).
- ~~Missing Authorization / IDOR~~ — added as a best-effort heuristic in
  v1.6.0 for Python/JS/PHP/Go/Java/Ruby (see "Best-effort heuristics" and
  "What it catches"). This does not mean the underlying problem is
  "solved" — the "What it can't catch" entry for this is still accurate
  about the fundamental limit, the heuristic just accepts the same
  coarse, low-confidence trade the CSRF check already made rather than
  refusing to try.
- Considered two more business-logic/"logical vuln" heuristics in the
  same spirit as IDOR, and deliberately held off on both — writing down
  why, the same way every other deliberate non-decision in this file
  does, rather than silently not mentioning them:
  - **Client-controlled price/amount tampering** (a request body field
    like `price`/`amount`/`total` trusted directly into an order/payment
    total instead of a server-side catalog lookup) — the CTF/real-world
    bug class is real, but unlike an id with no ownership check, a
    client-supplied amount is NOT inherently suspicious on its own (a
    "pay what you want" donation flow, a custom quote field, a tip
    amount are all legitimate uses of the exact same shape). A
    precise-enough version would need to recognize "a product/catalog
    lookup by id happened elsewhere in this function, AND the client
    amount is used instead of (or alongside, overriding) that lookup's
    own price" — a correlation IDOR's ownership check doesn't need to
    make. Shipping the naive version (any client-supplied amount used in
    a total, full stop) would be the generic-collision problem all over
    again, except worse: not a naming collision, a *semantic* one, where
    the "vulnerable" and "legitimate" shapes are the literally the same
    code pattern.
  - **TOCTOU/race condition on a balance or stock check** (`if
    balance >= amount: balance -= amount` as two separate statements
    instead of one atomic update/transaction — the classic "coupon race
    condition"/double-spend CTF category) — rejected for a different
    reason: recognizing "no atomicity" well would mean recognizing *every*
    language/ORM's atomic-update idiom (Django's `F()` expressions,
    SQLAlchemy's `update().where(...).values(...)`, a raw atomic
    `UPDATE ... SET x = x - ? WHERE x >= ?`, `SELECT ... FOR UPDATE`,
    Rails' `with_lock`/`transaction do`, a mutex/lock primitive, ...) to
    avoid flagging code that already does this correctly just in a
    shape the check doesn't recognize. That's a much larger, much
    higher-false-positive-risk surface to get right than IDOR's ownership
    check turned out to be, and getting it wrong here is worse than not
    having it: a security tool that cries wolf on correctly-written
    atomic code trains people to ignore it. Worth revisiting if a
    narrower, safer signal turns up (e.g. flagging only the specific
    "separate read-then-write with no lock/transaction keyword anywhere
    in the function" shape, which is at least a well-defined absence to
    check for) — not attempted this round.
- Looked at SSTI beyond Python's `render_template_string` (EJS/
  Handlebars/Nunjucks), XXE (DOMDocument/lxml parser config), and NoSQL
  Injection (MongoDB `find()`/`update()`/Mongoose) for the same AST
  taint-tracking treatment SQLi/SSRF/LDAP got, and deliberately held off
  on all three at the time — XXE has since gotten a narrower, cheaper
  fix instead of the full AST treatment (~~whole-file safe-parser-marker
  suppression~~ — added in v1.9.0 via `xxe_guard.py`, see "Best-effort
  heuristics" — chosen over full taint-tracking because the thing worth
  fixing wasn't "is the parsed data tainted" (the XML body itself is the
  attack payload, so it always is) but "was this specific parser
  configured safely," which a one-call-one-sink taint model doesn't
  represent any better than a whole-file marker check does, for
  meaningfully more engineering cost). SSTI and NoSQL Injection remain
  held off, for their original reasons: EJS's `render`/`compile` and Handlebars' `compile`
  either reuse Express's own extremely common `res.render(viewName, data)`
  method name (a much higher-traffic collision than anything accepted
  elsewhere in `SINKS`) or need a two-call correlation (`compile()` then
  invoking its return value) `SINKS`'s one-call-one-sink model doesn't
  fit; MongoDB/Mongoose's `find`/`findOne`/`update` are even more generic
  than `get`/`post` were for SSRF (collides with `Array.prototype.find`,
  any custom repository class, jQuery-ish `.find()`) and NoSQL Injection
  already has narrower, safer regex coverage (README: "the *whole* filter
  taken from the request body") that a blanket AST sink would mostly
  just duplicate at higher false-positive risk. Still open if a cleaner,
  less collision-prone angle turns up.
- Full interprocedural taint tracking (currently one hop only — a helper
  function's own parameters get seeded from its call sites, but taint
  doesn't propagate further than that, and each *file* is still analyzed
  independently of every other file)
- ~~Recognize common sanitizer calls (a validated cast) as taint-clearing~~
  — the numeric-cast half added in v1.13.0 via `ast_engine.py`'s
  `_is_sanitizer_expr()`/`SANITIZER_CALLS`/`PHP_SAFE_CAST_TYPES` (see
  "Architecture"'s "Sanitizer-call taint-clearing"), found the same way
  ReportLab Paragraph Injection was — stress-testing flagmap against real
  external vulnerable-by-design repos (DVWA, NodeGoat, Pygoat, RailsGoat,
  DVWS-Node) surfaced it as an actual false positive rather than it being
  anticipated here first. The `dict.get()`-against-a-fixed-mapping/
  allowlist half of this idea is **not** done — that needs recognizing a
  specific *mapping literal* as the allowlist, a different and harder
  shape than "this call always returns a safe type no matter its input,"
  and remains open.
- ~~A `--diff` mode to scan only files changed ... for when challenge
  authors release a patched version~~ — added in v1.12.0 as
  `--diff-against`/`diffscan.py`, see "Re-scanning a patched challenge".
  Built against two plain directory snapshots rather than a git baseline
  as originally imagined here — a CTF handout being its own git repo
  isn't a reasonable thing to assume (and if one is shipped as one,
  that's loot.py's job to flag, not this feature's job to require).
- ~~Export findings straight into a writeup template~~ — added in v1.10.0
  via `--export-md`/`report_md.py`, see "Sharing results with a team".
  Renders the exact same findings/chains print_report() already computes,
  just as Markdown instead of terminal text, so there's no second
  detection code path to keep in sync — only a second renderer.
