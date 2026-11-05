# flagmap — Full Capability Reference

The complete list of every vulnerability class, misconfiguration, loot/recon
check, and known-CVE dependency flagmap looks for — and, just as
importantly, the bug shapes it deliberately does **not** try to catch, and
why. This is the detailed reference; [README.md](README.md) has a short
summary and a quick start. The *why* behind each specific rule (which real
repo/challenge it was found against, what false positive it fixed) lives in
[ARCHITECTURE.md](ARCHITECTURE.md).

## What it catches

**Code vulnerabilities** (PHP, Python, Node/JS, C#/ASP.NET Core, Java, Go,
Ruby/Rails, Lua, Rust):

- SQL Injection (string-built queries, including a simple "variable assigned
  from user input, used a few lines later" taint check, and — PHP only,
  added v1.15.0, see `sql_construct.py` and ARCHITECTURE.md — a query built
  via "." concatenation or inline interpolation spanning multiple physical
  lines, independent of patterns.py's single-line regexes)
- Command Injection / RCE (`system`, `exec`, `eval`, `shell_exec`, etc., and
  — added v1.24.0, Groovy/Jenkinsfile only, best-effort, see
  `jenkins_pipeline_guard.py` and ARCHITECTURE.md's "Best-effort
  heuristics" section — a Jenkins declarative pipeline's own `string`
  build parameter, referenced directly or via a one-hop `env.X = params.Y`
  alias, inside a `sh` step's own body: Jenkins substitutes that text as
  literal shell input before invoking `/bin/sh`, so anyone able to
  trigger a parameterized build controls part of the command the agent
  runs. Regex-only, same two-independent-signals discipline as the IDOR/
  CSRF checks below — there's no tree-sitter-groovy grammar in this
  codebase, and Groovy's parenthesis-free `sh '''...'''` command syntax
  wouldn't reach the generic AST/taint-lite sink matchers even if there were)
- Unsafe Deserialization (`pickle.loads`, PHP `unserialize`, `yaml.load`,
  `node-serialize`)
- Path Traversal / LFI (`include`, `fopen`, `open`, `send_file`,
  `readFileSync`, etc. fed from user input; and — added v1.34.0, see
  ARCHITECTURE.md — PHP's `readfile()`, tracked through the AST taint
  engine's cross-statement tracking the same way `fopen()` already was;
  and, v1.35.0, an aiohttp `web.static(...)`/`add_static(...)` route with
  `follow_symlinks=True`, which skips the in-root check entirely on
  aiohttp < 3.9.2, CVE-2024-23334)
- Server-Side Template Injection / SSTI (`render_template_string`, EJS,
  Handlebars, Nunjucks)
- SSRF (`requests`/`urlopen`/`pycurl` in Python, `axios`/`fetch`/`http.get` in
  Node, `curl_setopt`/`file_get_contents` in PHP, fed from request data.
  The coarse, taint-blind `fetch(var, ...)`-style JS backstop no longer
  fires, added v1.20.0, inside a file with no server-route signal
  anywhere — a plain browser `fetch()` call isn't SSRF at all; see
  `ssrf_fetch_guard.py` and ARCHITECTURE.md's "Best-effort heuristics" section)
- JavaScript in an HTML page's inline `<script>` blocks (added v1.43.0, see
  `inline_script.py`/ARCHITECTURE.md): bodies of inline JS script tags in
  `.html`/`.htm` files are re-scanned with every JS rule at the page's real
  line numbers — previously only `.js`/`.ts` files met those rules
- Unrestricted File Upload (`move_uploaded_file`, Flask `.save()`, `multer()`
  with no extension/type allowlist; and — added v1.37.0, see
  ARCHITECTURE.md — a PHP destination path built by concatenating a
  `"dir/"` literal with the client's `$_FILES[...]['name']`, with or
  without `basename()`, whatever write call follows it)
- Cross-Site Scripting / XSS (reflected `echo`/`print` in PHP, unescaped
  template returns in Flask, `.innerHTML =`/`res.send()` in JS, and — added
  v1.23.0, see ARCHITECTURE.md — React's `dangerouslySetInnerHTML={{__html:
  ...}}` given a non-literal value, the React-specific analog of a plain
  `.innerHTML =` assignment that had zero coverage before; and — added
  v1.28.0, see `jsp_cookie_xss_guard.py`/ARCHITECTURE.md — a JSP
  `<%= %>` tag echoing a variable assigned from a `Cookie`'s own
  `.getValue()` inside a `request.getCookies()` loop, with no escaping
  call in the tag. Distinct from the narrow JSP `<%= request.
  getParameter(...) %>` rule described further below, which only matches
  `request.getParameter()`/`getAttribute()` called directly inside the
  `<%= %>` tag — this catches the cookie-sourced case that rule
  deliberately leaves out)
- XXE (DOMDocument/simplexml in PHP, lxml/xmltodict in Python) — with
  whole-file false-positive suppression for recognized safe-parsing
  markers (`defusedxml`, `resolve_entities=False`,
  `libxml_disable_entity_loader(true)`); see `xxe_guard.py` and
  ARCHITECTURE.md's "Best-effort heuristics" section
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
  `res.redirect()` from request data; and — added v1.33.0, see
  ARCHITECTURE.md — an allowlist that checks a parsed URL's `.hostname`
  against an expected one but never its `.protocol`, letting a
  `javascript://<same-hostname>/<payload>` URL pass the check and then
  execute as code if the validated value reaches a navigation sink like
  `window.location = ...` — script execution, not just a redirect)
- NoSQL Injection (MongoDB `find()`/`update()` with the whole filter taken
  from the request body; and — added v1.41.0, see ARCHITECTURE.md, any
  language — a `$regex` operator whose pattern is an unescaped variable,
  a prefix oracle / ReDoS if it carries request data)
- Mass Assignment (`**request.json` into a constructor, `findByIdAndUpdate`
  with the raw request body; and — added v1.38.0, see
  `token_mass_assign_guard.py`/ARCHITECTURE.md, Python — the whole request
  form/JSON dict, directly or via a variable, passed as the payload of a
  token-minting call like `jwt.encode(...)`/`create_token(...)`, so every
  submitted field becomes a signed claim)
- ORM Injection / Filter Leak (added v1.39.0, see ARCHITECTURE.md,
  Python: a whole request dict unpacked into an ORM lookup —
  `Model.objects.filter(**request.data)`, `.exclude/.get(**...)`,
  SQLAlchemy `filter_by(**...)` — so the client picks lookup keys and can
  traverse relations, e.g. `created_by__password__startswith`, as a
  boolean oracle on fields the API never returns)
- Prototype Pollution (`_.merge`/`deepmerge` into `{}` from request data;
  and — added v1.29.0, see `class_pollution_guard.py`/ARCHITECTURE.md —
  Python's version of the same bug, sometimes called "class pollution": a
  hand-rolled recursive merge that loops over a dict's `.items()` and
  calls `setattr(obj, key, value)` with the loop's own key/value variables
  and no denylist on dunder names, letting a crafted nested dict walk
  `__class__` → `__init__` → `__globals__` to overwrite arbitrary module
  globals. Filed under this same vuln name since it's the identical
  construct in a different language — see the hand-rolled-merge JS bullet
  further below for that language's version; and — added v1.32.0, see
  `forin_prefix_pollution_guard.py`/ARCHITECTURE.md — a third shape: a
  `for...in` loop variable filtered with `.startsWith(prefix)`, stripped
  with `.slice()`, and bracket-assigned onto a fresh object with no
  `__proto__`/`constructor` denylist, a hand-rolled "flatten a
  prefixed/namespaced set of keys" idiom distinct from both the
  deep-merge-library and the recursive-merge shapes)
- JWT / Auth Token Weaknesses (`verify=False`, `alg: none` accepted, missing
  algorithm allowlist; and — added v1.31.0, see ARCHITECTURE.md — the
  opposite problem: an algorithms allowlist that's present but mixes an
  HMAC family (HS256/384/512) with an asymmetric family (RS/ES/PS
  256/384/512) against the same verification key, the classic JWT
  "algorithm confusion" attack — an RSA/EC public key isn't secret, so it
  can be replayed as the HMAC secret for a forged HS256 token)
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
  secrets; and — added v1.36.0, see `xff_trust_guard.py`/ARCHITECTURE.md,
  Python/JS/Go/PHP — a client IP read from the `X-Forwarded-For`/
  `X-Real-IP` header in a file that also makes an IP-allowlist decision
  with it, since that header is client-controlled)
- Missing CSRF Protection (best-effort: a POST form with no CSRF token
  anywhere in the file)
- Missing Authorization / IDOR (best-effort, added v1.6.0, Python/JS/PHP/
  Go/Java/Ruby: an id read straight from the request/route — either an
  explicit extraction call or the route's own id-named parameter — handed
  to a lookup/update/delete call, with no ownership check anywhere in the
  function or the decorator/annotation above it. A bare login-required
  check does NOT count as that ownership check — see ARCHITECTURE.md's "Best-effort heuristics" section for exactly what does and the real false-positive/negative
  tradeoffs of a check this coarse. Upgraded to "likely" confidence,
  added v1.16.0, when the same function's lookup DOES filter by a
  per-user ownership key whose own value is read straight from the
  request rather than the session — see `owner_param_guard.py` and
  ARCHITECTURE.md's "Best-effort heuristics" section. A JS-specific false positive suppressed,
  added v1.19.0: the bare-id-named-parameter fallback no longer fires on
  a plain client-side function whose only "lookup-shaped call" is a
  jQuery DOM method (`.find()`, etc.) textually colliding with the
  lookup-sink vocabulary, in a file with no server-route signal anywhere
  — see `jquery_dom_guard.py` and ARCHITECTURE.md's "Best-effort heuristics" section)
- Missing Authentication Check (best-effort, added v1.15.0, Python/JS/
  PHP/Go/Java/Ruby: a function that reads a username/email/login value
  straight from the request AND grants a new session/token/cookie
  somewhere in its body, with no sign of a credential check anywhere in
  the function or its decorator/annotation. Requires both — reading an
  identity claim alone, or granting a session alone, each describe
  plenty of ordinary, correctly-checked code too; see ARCHITECTURE.md's "Best-effort heuristics" section for the stubborne-style case this was built for and its
  known false positives/negatives)
- GraphQL / Query Injection (a query/mutation document built with `%`
  formatting or template-literal interpolation instead of GraphQL
  variables, and — Python only, added v1.25.0, see ARCHITECTURE.md — a
  variable named like a GraphQL query/document built via plain `+` string
  concatenation instead, anchored on the variable's own name since the
  GraphQL-shaped literal text itself can live in separate constants a
  single line can't see)
- Hardcoded Secret in Source (added v1.26.0, any language — see
  ARCHITECTURE.md): a signing/encryption key (`SECRET_KEY`, `JWT_SECRET`,
  `SESSION_SECRET`, `API_KEY`, `PRIVATE_KEY`, `ENCRYPTION_KEY`, `AES_KEY`,
  `SIGNING_KEY`, case-insensitive, as a bare assignment or a dict-key
  assignment like Flask's `app.config["SECRET_KEY"] = ...`) assigned
  directly as a string literal rather than read from the environment or a
  secrets manager. Distinct from the existing Dockerfile/compose/`.env`
  "Hardcoded Secret in ..." misconfiguration checks below — this one
  catches the same underlying mistake one layer deeper, baked directly
  into application source
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
  whose output ends up in a dashboard or log aggregator. The JS rule no
  longer fires, added v1.21.0, when every keyword match on the line came
  from inside a quoted string literal — a log message that happens to
  mention "password" in its own prose, not an actual value being logged;
  see `log_message_guard.py` and ARCHITECTURE.md's "Best-effort heuristics" section)
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
  calls, which are unsafe unless member names are validated first; and —
  added v1.27.0, see `zipslip_guard.py`/ARCHITECTURE.md — a manual
  extraction loop that never calls `.extract()`/`.extractall()` at all,
  instead walking `.infolist()`/`.filelist`/`.namelist()` itself and
  joining each entry's own `.filename` into a destination path via
  `os.path.join(...)`, with no real path-containment check anywhere in
  the file. That second check is deliberately strict about what counts
  as "real": a bare `".." in name`-style substring test does NOT suppress
  it, only a genuine containment-verification idiom does (`.resolve()`
  chained with `.relative_to(`/`.is_relative_to(`, `os.path.realpath(`
  chained with `.startswith(`, or `os.path.commonpath(`))
- Insecure session tokens built from a plain `base64.b64encode(username)`
  with no signature/secret — trivially forgeable for any account
- JWT `verify_signature` explicitly set to anything other than a literal
  `True` (commonly a variable that can resolve to `None`/`False`)
- Java (AST-matched since v1.2.0, see ARCHITECTURE.md): `executeQuery`/
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
- Go (AST-matched since v1.1.0, see ARCHITECTURE.md): `db.Query`/`QueryRow`/
  `Exec` with a SQL string built from `r.FormValue`/`r.URL.Query().Get`/
  `mux.Vars`/`chi.URLParam` *anywhere upstream in the function* (not just a
  same-line `fmt.Sprintf`), `exec.Command()` with a tainted program name,
  `os.Open`/`ReadFile`/`Create`/`http.ServeFile` with a tainted path,
  `http.Redirect` with a tainted target, `fmt.Fprintf`/`Fprint` writing
  request data straight to the `ResponseWriter` (XSS) — plus the regex
  layer's own `fmt.Sprintf`-based SQL/SSTI/SSRF/mass-assignment/
  insecure-randomness checks, which still run alongside it
- Ruby/Rails (AST-matched since v1.2.0, see ARCHITECTURE.md): `execute`/
  `exec_query` with a SQL string built from `params[...]`/`request.params`/
  `cookies[...]`/`request.headers` *anywhere upstream in the method*,
  `system`/`IO.popen` with a tainted command, `File.open` with a tainted
  path, `Marshal.load`/`YAML.load` with tainted data, `redirect_to` with a
  tainted target, and `.html_safe` called ON tainted data (ERB's
  auto-escaping explicitly turned back off — a receiver-slot sink, not an
  argument one) — plus the regex layer's own string-interpolated
  `where()`/`find_by_sql()`, `params.permit!` mass assignment, `render
  inline: params` SSTI, which still run alongside it
- Lua (AST-matched since v1.3.0, see ARCHITECTURE.md): `..`-concatenated SQL
  passed to a colon-call query method (`db:query(...)`, `conn:execute(...)`)
  with the tainted value built *anywhere upstream in the function* (not
  just a same-line concatenation), `os.execute()`/`load()`/`loadstring()`
  with a tainted command/code string, `io.open()` with a tainted path,
  `ngx.redirect()` with a tainted target — plus the regex layer's own
  checks, which still run alongside it
- Rust (AST-matched since v1.3.0, see ARCHITECTURE.md; intentionally light
  coverage — Rust's safety guarantees remove most of what flagmap targets):
  `.query`/`.execute` with a SQL string built from a tainted HTTP-request
  value *anywhere upstream in the function or `&self` method*, `File::open`
  with a tainted path — plus the regex layer's own bare-variable
  `Command::new()`, `format!`-built SQL (deliberately left to regex — see
  ARCHITECTURE.md), bare-variable filesystem calls, and `unsafe`-block
  manual-review flag, which still run alongside it
- EJS `<%- %>` and Handlebars `{{{ }}}` — the raw/unescaped-output tags of
  their respective template engines (the escaped forms are `<%=` / `{{ }}`)
- A hand-rolled recursive merge utility with no guard of its own (`key in
  target` walking the prototype chain) — Prototype Pollution that survives
  even when an upstream parser blocklists `__proto__`/`constructor`
  (Python's version of this same hand-rolled-merge shape, via `setattr()`
  and `__class__`/`__globals__` instead of `__proto__`/`constructor`, is
  covered too — see the Prototype Pollution bullet above and
  `class_pollution_guard.py`, v1.29.0; a third, non-recursive JS shape —
  a `for...in` loop variable filtered/stripped by a literal prefix and
  bracket-assigned with no denylist at all — is covered too, see
  `forin_prefix_pollution_guard.py`, v1.32.0)
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
  subset, not e.g. a stored/DB value reflected the same way — though the
  cookie-sourced subset of that gap is now covered too, see the Cross-Site
  Scripting bullet above and `jsp_cookie_xss_guard.py`, v1.28.0)
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
  itself. Suppressed, added v1.18.0, for a `.sql` file that follows a
  recognized versioned-migration naming convention (Flyway's
  `V<version>__<description>.sql`, or a bare numeric prefix) AND sits
  inside a `db`/`migration(s)`/`migrate`-named directory — a real
  schema-setup script, not a leaked dump; see `migration_guard.py` and
  ARCHITECTURE.md's "Best-effort heuristics" section.
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
- **Gotenberg** < 8.1.0 (added v1.30.0) — no assigned CVE, but a
  well-known-in-CTFs local-file-read/SSRF primitive built into the
  HTML-to-PDF conversion service itself (a converted document's
  `<iframe>`/`<img>` could reach `file://` paths and internal URLs,
  unrestricted through 8.0.3). The first entry keyed by a *container
  base image* (`FROM gotenberg/gotenberg:8.0.3` in a Dockerfile) rather
  than a language-ecosystem manifest — see "Parsed manifests/lockfiles"
  below for how that's matched.
- **strapi-plugin-email-designer** (any version, added v1.40.0) — no
  assigned CVE and no fixed release known: the plugin renders email
  templates with the same unsandboxed lodash template Strapi core fixed as
  CVE-2023-22621, so editing a template is server-side JavaScript
  execution. The first entry with `fixed_in=None` ("no fix exists"),
  which the table now supports for exactly that case.

Parsed manifests/lockfiles: `requirements.txt` (exact `==` pins only —
a range like `flask>=1.0` tells you nothing about what actually got
installed, so it's skipped, never guessed at), `Pipfile.lock`,
`package-lock.json` (npm v1 and v2/v3 shapes), `yarn.lock`,
`Gemfile.lock`, `composer.lock`, and `pom.xml` (skipping any `<version>`
that's actually an unresolved `${property}` placeholder — same
never-guess rule), plus, as of v1.30.0, `Dockerfile`/`Dockerfile.*`'s own
`FROM image:tag` line (matched only when it's an exact pin that's
actually in the curated table — a `FROM builder` build-stage reference
has no colon and never matches, and `FROM image`/`FROM image:latest`
with no real pin is left to the separate "Unpinned Base Image Tag"
config check, see below). Each is parsed by regex/line-scanning rather
than a full JSON/XML parse, same style as the rest of flagmap, so a
partial or slightly malformed file still yields whatever lines do match
and keeps a real line number, rather than an all-or-nothing exception.

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
  for a different absence-of-a-check bug (see ARCHITECTURE.md's "Best-effort heuristics" section)
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
  over *this* repo's files would ever see it. As of v1.30.0 `deps.py` does
  look at `FROM image:tag` lines too, not only language-ecosystem
  manifests (one curated entry so far: `gotenberg/gotenberg` < 8.1.0, from
  a real DownUnderCTF challenge whose entire bug was that exact pin — see
  "Vulnerable Dependencies"), but that only narrows this gap, it doesn't
  close it: still 5 language ecosystems plus one container image against
  roughly a dozen curated CVEs total, not the long tail of every other
  base image and package/CVE pair that exists (the `traefik` example above
  still isn't covered). A *general* version of this needs a live CVE/OSV-
  style dependency-version lookup across every ecosystem and every base
  image — a fundamentally different (and much more infrastructure-heavy)
  kind of check than the offline curated table this tool ships instead.
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

