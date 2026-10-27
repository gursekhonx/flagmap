# flagmap

A CLI tool that scans CTF challenge source code (PHP, Python, Node/JS, C#/
ASP.NET Core, Java, Go, Ruby, Lua, Rust) and flags common web-exploitation
vulnerability patterns — with a short explanation and a suggested starting
payload for each one. It also correlates findings into likely **attack
chains** (e.g. an upload bug plus an Apache misconfig = RCE) and ranks a
**"Start Here"** shortlist so you know what to try first.

Built for jeopardy-style CTFs (like CyberSci regionals) where web challenges
sometimes hand you the source code. Instead of eyeballing every file, point
flagmap at the folder and get a triaged list of what's worth trying first.

## Architecture (v1.5.0)

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
- XXE (DOMDocument/simplexml in PHP, lxml/xmltodict in Python)
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
- SSRF (AST-matched since v1.4.0, in addition to the existing regex
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
- Java (AST-matched since v1.1.0, see "Architecture"): `executeQuery`/
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
- Ruby/Rails (AST-matched since v1.1.0, see "Architecture"): `execute`/
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

# print the installed version
flagmap --version
```

Output is split into up to four sections:

1. **Code Vulnerabilities** — exploitable bugs in the app's source, each
   with a suggested payload under `try:`.
2. **Misconfigurations** — infra/config issues like a Dockerfile running as
   root or a wildcard CORS origin, each with a suggested remediation under
   `fix:`. This scan runs automatically alongside the code scan — no
   separate flag needed.
3. **Attack Chains** — findings correlated into a likely exploit path (e.g.
   an upload bug + a dangerous Apache `AddType` = direct RCE, or a root
   container + any RCE primitive = no privilege-escalation step needed).
   This is a plain co-occurrence check over the findings already produced —
   not new scanning or dataflow analysis — so treat a chain like any other
   `possible`-confidence finding: a strong hint of where to look first, not
   a guarantee the path is real. See `chains.py`.
4. **Start Here** — a ranked shortlist of the 3-5 highest-value findings,
   prioritizing anything that's part of a detected attack chain, then by
   severity, then by confidence. Built for the moment you open a report and
   just want to know what to click on first.

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

This is **not** real taint/dataflow analysis — no control flow, no scope
awareness, no sanitizer detection. It's built to catch the specific patterns
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

## What it can't catch (on purpose)

A few recurring bug shapes get found in testing over and over, confirmed as
real, and then deliberately **not** turned into a pattern, because forcing
one would either be a no-op or a false-positive generator:

- **Missing authorization / IDOR** — a route that reads an id from the
  request with no check that the current user actually owns that id. This
  is an *absence* of a check, not a syntax shape; a regex can't tell "no
  comparison to the current user anywhere in this function" from "there's
  a comparison, it's just not visible on this line."
- **LLM-tool functions with no enforced access control** — the same
  absence-of-a-check problem, specific to `@tool`-decorated functions whose
  only access control is prose in a system prompt.
- **Known-CVE'd pinned dependencies/base images** (e.g. `FROM traefik:v3.4.5`
  shipping a public dashboard path-traversal CVE) — the vulnerable code
  isn't in the challenge's own source at all, so no amount of pattern
  coverage over *this* repo's files would ever see it. This needs a
  CVE/OSV-style dependency-version lookup, a fundamentally different kind
  of check than source-pattern matching.
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
- ~~LDAP Injection~~ — added in v1.4.0 for Python/PHP/Java (see
  "Architecture" and "What it catches"); Node/Ruby intentionally skipped,
  their LDAP libraries put the filter inside an options/hash argument
  rather than a plain positional string.
- ~~SSRF~~ — added real AST taint-tracking in v1.4.0 for Python
  (`urlopen`)/PHP (`file_get_contents`)/JS (`fetch`) — see "What it
  catches"; `requests.get/post`/`axios.get/post`/`http(s).get` were
  deliberately left to the regex layer (too generic a name to add
  safely — see "What it catches" for why).
- More vuln classes that are currently regex-only for most/all languages
  could get the same treatment: SSTI beyond Python's
  `render_template_string` (EJS/Handlebars/Nunjucks), XXE
  (DOMDocument/lxml parser config), and NoSQL Injection (MongoDB
  `find()`/`update()` with a raw request-body filter) are the next most
  CTF-common candidates.
- Full interprocedural taint tracking (currently one hop only — a helper
  function's own parameters get seeded from its call sites, but taint
  doesn't propagate further than that, and each *file* is still analyzed
  independently of every other file)
- Recognize common sanitizer/allowlist calls (`dict.get()` against a fixed
  mapping, a validated cast) as taint-clearing, to cut down on the
  structurally-correct-but-practically-safe findings the broader
  route-parameter seeding in v1.0.0 can produce (e.g. a URL path segment
  used only as a key into a fixed allowlist dict)
- A `--diff` mode to scan only files changed vs. a git baseline, for when
  challenge authors release a patched version
- Export findings straight into a writeup template
- Absence-of-authorization-check heuristics (IDOR / missing access control
  on an identity-shaped route parameter) — flagged in testing as a real,
  recurring miss, but needs a scanner-level check rather than a line regex
  to avoid heavy false positives
