# Changelog

Every shipped change, in order. This was originally written as a running
"roadmap ideas, struck through as they're done" list, which is why each
entry explains what real repo or challenge motivated it rather than just
naming the feature — that reasoning is kept here rather than trimmed, since
"why this exists" is as useful as "what changed." See
[ARCHITECTURE.md](ARCHITECTURE.md) for the full technical detail behind any
entry below.

- ~~AST-based matching per language instead of regex~~ — done for all 8
  supported languages: Python/JS/PHP in v1.0.0, Go in v1.1.0, Java/Ruby in
  v1.2.0, Lua/Rust in v1.3.0 (see ARCHITECTURE.md).
- ~~Loot/recon scanning (exposed `.git`, hardcoded flags, stray keys,
  backup files)~~ — added in v1.7.0, see CAPABILITIES.md. A genuinely
  different kind of check than everything else in flagmap, not an
  incremental extension of the taint-tracking/pattern-matching approach —
  worth having because in practice a meaningful share of CTF points come
  from exactly this category, not from the "intended" vulnerability.
- ~~Known-vulnerable pinned dependency versions (Log4Shell, SnakeYAML, old
  PHPMailer, Struts2, Rails, Django, lodash/minimist, Pillow/urllib3,
  PyYAML, ...)~~ — added in v1.8.0 via `deps.py`, see "Vulnerable
  Dependencies". Deliberately scoped to a small curated table of
  well-known, exact-version-only matches, not a general SCA tool against
  a live CVE/OSV database — the CAPABILITIES.md's "What it can't catch" section entry below still
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
  ARCHITECTURE.md and CAPABILITIES.md); Node/Ruby intentionally skipped,
  their LDAP libraries put the filter inside an options/hash argument
  rather than a plain positional string.
- ~~SSRF~~ — added real AST taint-tracking in v1.5.0 for Python
  (`urlopen`)/PHP (`file_get_contents`)/JS (`fetch`) — see "What it
  catches"; `requests.get/post`/`axios.get/post`/`http(s).get` were
  deliberately left to the regex layer (too generic a name to add
  safely — see CAPABILITIES.md for why).
- ~~Missing Authorization / IDOR~~ — added as a best-effort heuristic in
  v1.6.0 for Python/JS/PHP/Go/Java/Ruby (see ARCHITECTURE.md and CAPABILITIES.md). This does not mean the underlying problem is
  "solved" — the CAPABILITIES.md's "What it can't catch" section entry for this is still accurate
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
  suppression~~ — added in v1.9.0 via `xxe_guard.py`, see ARCHITECTURE.md's "Best-effort heuristics" section — chosen over full taint-tracking because the thing worth
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
  ARCHITECTURE.md's "Sanitizer-call taint-clearing"), found the same way
  ReportLab Paragraph Injection was — stress-testing flagmap against real
  external vulnerable-by-design repos (DVWA, NodeGoat, Pygoat, RailsGoat,
  DVWS-Node) surfaced it as an actual false positive rather than it being
  anticipated here first. The `dict.get()`-against-a-fixed-mapping/
  allowlist half of this idea is **not** done — that needs recognizing a
  specific *mapping literal* as the allowlist, a different and harder
  shape than "this call always returns a safe type no matter its input,"
  and remains open.
- ~~Suppress noise from vendored/third-party library files checked
  directly into app source trees~~ — added in v1.14.0 via
  `vendor_guard.py`, see ARCHITECTURE.md's "Vendored-library noise
  suppression". Also found via the same real-repo stress-testing pass
  (RailsGoat this time, not DVWA) — not anticipated ahead of time either.
  Deliberately scoped to the two specific rules actually observed causing
  this (bare `eval()`, bare `.innerHTML=`), not a blanket "ignore findings
  in files that look vendored" rule — a real taint-tracked finding inside
  a vendored file still fires exactly as before.
- ~~A `--diff` mode to scan only files changed ... for when challenge
  authors release a patched version~~ — added in v1.12.0 as
  `--diff-against`/`diffscan.py`, see README.md's "Re-scanning a patched challenge" section.
  Built against two plain directory snapshots rather than a git baseline
  as originally imagined here — a CTF handout being its own git repo
  isn't a reasonable thing to assume (and if one is shipped as one,
  that's loot.py's job to flag, not this feature's job to require).
- ~~Export findings straight into a writeup template~~ — added in v1.10.0
  via `--export-md`/`report_md.py`, see README.md's "Sharing results with a team" section.
  Renders the exact same findings/chains print_report() already computes,
  just as Markdown instead of terminal text, so there's no second
  detection code path to keep in sync — only a second renderer.
- ~~Missing Authentication Check (a function that grants a session for a
  claimed identity with no credential check at all)~~ — added in v1.15.0
  via `authn_guard.py`, see ARCHITECTURE.md.
  Not anticipated on this roadmap ahead of time either — found by testing
  flagmap against a real attached CyberSci-style challenge whose `Login`
  RPC had no password field on the request at all, just an unconditional
  session grant for whatever username was supplied. A genuinely new
  absence-of-a-check category, distinct from IDOR (no resource/ownership
  concept here) and from the pre-existing Weak Auth Logic check (which
  catches a credential check done *wrong*, not one that's entirely
  missing).
- ~~Correct the advice on an Unsafe Deserialization finding when a
  hand-rolled validator actually guards the call~~ — added in v1.15.0 via
  `pickle_guard.py`, see ARCHITECTURE.md. Not
  a new finding or a suppressor — the same real challenge above restricted
  its pickle stream to a safe-opcode allowlist immediately before
  deserializing, making flagmap's default "craft a `__reduce__` gadget"
  advice actively wrong for that call site; this swaps in advice about
  checking what the allowlist still permits instead, without touching
  whether the finding itself fires. Python-only for now — the same
  guarded-deserialization idiom in PHP/Node/Ruby is each its own
  ecosystem-specific shape, left open rather than guessed at without a
  real example to design against.
- ~~Catch SQL built via PHP string concatenation/interpolation spanning
  more than one physical line~~ — added in v1.15.0 via `sql_construct.py`,
  see ARCHITECTURE.md. Found by testing flagmap against OWASP Mutillidae
  II — a whole DAO class (`SQLQueryHandler.php`) full of exactly the SQL
  injection it exists to demonstrate, every instance of it built via "."
  concatenation or inline interpolation across 2-4 physical lines, and
  flagmap's existing single-line PHP regexes couldn't reach any of it.
  Python's "+"/"%" and JS's "+" string concatenation can span multiple
  lines the same way — left open, same discipline as everything else
  here, until a real example motivates it rather than guessing ahead.
- ~~Recognize an IDOR "ownership check" that's itself bypassable because
  its value comes from the request, not the session~~ — added in v1.16.0
  via `owner_param_guard.py`, see ARCHITECTURE.md's "Best-effort heuristics" section. Found testing
  flagmap against OWASP Juice Shop (the first JS/TS real-world target
  tested — see ARCHITECTURE.md's "Testing" section): several routes filter a lookup by both an id
  AND a `UserId` field, but that `UserId` is read straight from the
  request body, making the "check" exactly as attacker-controlled as the
  id. Deliberately an upgrade on the existing IDOR finding, not a
  loosened suppression — widening `idor.py`'s own ownership vocabulary to
  recognize this shape as "a real check" would have made the finding
  disappear entirely, which is the opposite of what was needed.
- ~~Suppress `loot.py`'s "Database dump file present" check for a
  legitimate, version-controlled schema-migration script~~ — added in
  v1.18.0 via `migration_guard.py`, see ARCHITECTURE.md. Found testing flagmap against WebGoat (Java) — 15 Flyway
  migration scripts following the standard `V<version>__<description>.sql`
  convention all fired as "leaked data dump" findings purely from the
  bare `.sql` extension. Requires two independent naming-convention
  signals together (recognized versioned filename AND a
  `db`/`migration(s)`/`migrate` directory segment) before suppressing,
  specifically so a real abandoned dump can't be hidden by accident —
  same discipline as `vendor_guard.py`'s own conservative, filename-only
  signals.
- ~~Suppress idor.py's bare-parameter-name-fallback IDOR finding when
  it's really a jQuery DOM-method name collision~~ — added in v1.19.0
  via `jquery_dom_guard.py`, see ARCHITECTURE.md. Also found testing flagmap against WebGoat, this time in
  two JS files: WebGoat's own `MenuView.js` and the bundled
  `jquery-ui-1.10.4.js`, both with a function taking a parameter
  literally named `id` (an HTML element id) whose jQuery `.find()` call
  textually matches `LOOKUP_SINK_RE`'s ORM vocabulary. Suppresses only
  when no explicit request-extraction call exists in the function AND
  no server-route signal exists anywhere in the file — reusing
  `vendor_guard.py`'s own `is_vendor_file()` as a bypass for that second
  check once jQuery UI's real Autocomplete widget (`function(request,
  response)`, an ordinary naming convention with nothing to do with
  HTTP) turned out to defeat a naive version of it.
- ~~Suppress the taint-blind JS SSRF regex on a plain client-side
  fetch() call~~ — added in v1.20.0 via `ssrf_fetch_guard.py`, see
  ARCHITECTURE.md. Same WebGoat pass, two
  more JS files: `webauthn.js` and `security-misconfiguration-task2.js`
  both call `fetch(url, ...)` from plain browser code with no server
  concept anywhere — SSRF means tricking a *server*, and a browser
  making its own fetch call crosses no trust boundary at all. Reuses
  `jquery_dom_guard.py`'s "is this file unambiguously client-side"
  predicate, factored out into `js_clientside_guard.py` for both guards
  to share — and narrowed in the process, dropping `request.`/
  `response.` as signals after they turned out to collide with the
  Fetch API's own standard `fetch(url).then(function(response) {...})`
  promise-chain idiom, found and fixed before this shipped.
- ~~Suppress the JS "Sensitive Data Exposure in Logs" rule when the
  keyword match is inside a log message string, not a real value~~ —
  added in v1.21.0 via `log_message_guard.py`, see ARCHITECTURE.md. Same WebGoat pass: `console.error("Unable
  to load password storage training data", error)` flagged purely
  because the message text contains "password," with no actual
  sensitive value anywhere in the call. Fixed by stripping quoted
  string literals off the flagged line (keeping a backtick template
  literal's interpolated expressions) and re-checking the same rule
  against what's left, rather than narrowing the rule's own keyword
  list. This category had zero regression fixtures in any language
  before this fix.
- ~~Recognize Java/Maven's own test-file naming conventions in
  `is_test_file()`~~ — added in v1.22.0, see ARCHITECTURE.md. Last of the same WebGoat pass:
  `src/it/java/org/owasp/webgoat/RegistrationUITest.java` hardcodes a
  test credential that `is_test_file()` should have suppressed but
  didn't, because it only knew Python/JS-style conventions and generic
  path segments, never Java/Maven's own `*Test.java`/`*IT.java`/
  `src/it/java/...` conventions. Added both, case-sensitive against the
  PascalCase boundary specifically to avoid matching ordinary class
  names like `Submit.java`/`Contest.java`. No standard fixture could be
  added for this one — every fixture already lives under
  `tests/fixtures/...`, which the pre-existing `tests/` segment check
  already matches unconditionally — so it was verified directly against
  the real file and a dozen adversarial cases instead; see ARCHITECTURE.md's "Testing" section.
- ~~Map `.tsx` to the JS language tag, and give `.ts`/`.tsx` their own
  dedicated tree-sitter grammar~~ — added in v1.23.0, see ARCHITECTURE.md.
  Found auditing flagmap against CyberSci's own official past-challenges
  repo (`CyberSci/PastChallenges`): nationals-2024-25's defence challenges
  ship real React+Remix frontends (`voter_registry`, `candidate_registry`)
  whose route/component files are `.tsx` — an extension with no entry in
  `EXTENSION_LANGUAGE` at all before this, so every one of those 20 real
  files was skipped outright, invisible to both the regex layer and the AST
  engine. Mapping it to `"js"` alone wasn't enough, though: a top-level
  TypeScript-only construct like an `interface` declaration isn't a
  localized, recoverable parse error under plain `tree-sitter-javascript` —
  its error recovery folds the interface AND every real function after it
  in the same file into one bogus `statement_block`/`labeled_statement`
  subtree, silently breaking taint tracking for the rest of the file
  (confirmed via direct AST dumps). Fixed by giving `.ts`/`.tsx` their own
  `tree-sitter-typescript` grammar (`_PARSERS_BY_EXT` in `ast_engine.py`,
  keyed by real file extension, falling back to plain JS if the package
  isn't installed), confirmed via side-by-side parse-tree comparison to
  produce `has_error=False` on the exact problem shape with identical
  node-type names to plain JS for every construct the taint walker relies
  on — so none of the existing "js"-keyed tables needed to change.
- ~~React's `dangerouslySetInnerHTML={{__html: ...}}` as an XSS sink~~ —
  added in v1.23.0 via a `patterns.py` regex rule, see CAPABILITIES.md.
  Found in the same CyberSci audit: nationals-2024-25's `candidate_registry`
  defence challenge renders a voter's submitted question text and a
  candidate's answer text through this exact prop straight from an API
  response, with zero sanitization anywhere — stored XSS, and previously
  invisible to flagmap despite being the canonical React DOM-XSS primitive
  (unlike a plain `.innerHTML =` assignment, which was already covered).
  Matches only a non-literal `__html` value (a bare identifier, member
  expression, or template literal with an interpolation), not a static
  quoted string — the regex's first draft had a backtracking bug that let
  its negative lookahead match a static literal anyway by letting the
  preceding `\s*` backtrack to zero width; fixed by moving the whitespace
  inside the lookahead itself.
- ~~Jenkins declarative-pipeline build-parameter injection into a `sh`
  step (Groovy/Jenkinsfile)~~ — added in v1.24.0 via
  `jenkins_pipeline_guard.py`, see ARCHITECTURE.md and CAPABILITIES.md.
  Found continuing the CyberSci audit into nationals-2025-26's
  "deployment_hell" defence challenge: its Jenkins pipeline declares a
  `string(name: 'projectName', ...)` build parameter, aliases it to an env
  var (`env.PROJECT_NAME = params.projectName`), and interpolates that var
  straight into a `sh '''...${PROJECT_NAME}...'''` step in both
  `deploy-app.groovy` and `build-and-upload.groovy` — Jenkins substitutes
  that text as literal shell input before invoking `/bin/sh`, so anyone
  able to trigger a parameterized build gets command execution on the
  agent. Zero coverage before this: flagmap had no Groovy/Jenkinsfile
  language at all, AST or regex. Added as a regex-only, two-signal
  whole-file check (declared parameter name, plus a reference to it or
  its env-var alias inside an `sh` step's own body) rather than a 9th
  AST-backed language — no `tree-sitter-groovy` grammar exists in this
  codebase, and Groovy's parenthesis-free `sh '''...'''` command syntax
  wouldn't reach the generic taint-lite sink matcher's `name\s*\(` pattern
  even if there were. Caught and fixed two of its own bugs during
  development: the `sh`-step regex's bare `\bsh\b` anchor first matched
  the literal word "sh" wherever it appeared, including inside an
  unrelated stage-name string ending in "...multi-line sh" immediately
  before its own closing quote — fixed by anchoring to the start of a
  trimmed line instead, which is how every real `sh` step is actually
  written. And the variable-reference regex's `\$\{?(\w+)\}?` alternative
  matched `${params.projectName}` as the literal word "params" (`\w+`
  stops at the property-access dot), never reaching "projectName" at all
  — fixed by adding an optional `(?:params\.)?` prefix inside that same
  alternative. Verified zero false positives across every other
  `.groovy` file in the full 4-snapshot corpus (`exfilAwsKeys.groovy`,
  `pluginExport.groovy` ×2, `approveScripts.groovy`), and confirmed true
  on both real vulnerable files.
- ~~GraphQL query built via plain Python "+" concatenation, not just "%"
  formatting~~ — added in v1.25.0, see ARCHITECTURE.md and
  CAPABILITIES.md. Found in the real CyberSci nationals-2025-26
  "quote_vault" web challenge's api/app.py: `query_text =
  _PATH_TEMPLATE_PREFIX + id_raw + _PATH_TEMPLATE_SUFFIX`, where
  `id_raw` is a Flask `<path:...>` route parameter (the actual
  attacker-facing injection point for the challenge's master-flag
  boolean-blind SQLi, chained through this GraphQL injection) and the
  two TEMPLATE constants are plain string literals defined on separate
  earlier lines. Neither existing Python GraphQL rule fired: there's no
  `%` formatting on this line at all, and the GraphQL-shaped literal
  text (`"{ quote(id: "` / `") { id value author ... } }"`) lives in
  those separate constants, invisible to a same-line regex. Added a
  third rule anchored on the assigned-to variable's own name (containing
  "query"/"graphql"/"gql", case-insensitive) built via `+`
  concatenation of at least two bareword/attribute operands — the same
  variable-naming-convention trade several other rules in this file
  already make (e.g. the Python SQL Injection rule's own `$sql`/`$query`
  fallbacks), needed here specifically because the literal content this
  construction site actually produces isn't visible on the line that
  builds it. Verified zero false positives across the full 4-snapshot
  corpus (only the real line fires; the five pre-existing `%`-formatting
  hits in underground-bank's main.py are unaffected) and confirmed true
  on the real file.
- ~~Signing/encryption key hardcoded directly as a source string literal~~
  — added in v1.26.0, see ARCHITECTURE.md and CAPABILITIES.md. Found in
  the real CyberSci nationals-2025-26 "assault_and_battery" web
  challenge's `crypto/jwt.py` line 9: `SECRET_KEY =
  "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"`, a
  JWT HS256 signing key baked straight into source rather than read from
  the environment — a source-review CTF player (or anyone with repo
  access) can forge any token signed with it on sight. None of flagmap's
  existing "Hardcoded Secret in ..." checks caught this: those all look
  at Dockerfiles, compose files, and `.env` files for misconfiguration —
  nothing was looking at hardcoded secrets baked into the application's
  own Python/JS/etc. source. Added as a new `generic`-language
  `RAW_PATTERNS` regex matching a small curated vocabulary of
  signing/encryption-key variable and dict-key names (`SECRET_KEY`,
  `JWT_SECRET`, `SESSION_SECRET`, `API_KEY`, `PRIVATE_KEY`,
  `ENCRYPTION_KEY`, `AES_KEY`, `SIGNING_KEY`) assigned a quoted string
  literal at least 8 characters long — both the bare `NAME = "..."` shape
  and Flask's dict-key `app.config["NAME"] = "..."` shape, and (since
  every `RAW_PATTERNS` regex in this file is compiled case-insensitively)
  matching `app.secret_key` just as readily as `SECRET_KEY`. Verified
  against the full 4-snapshot corpus: exactly 4 real hits, all genuine —
  `assault_and_battery/crypto/jwt.py:9`, nationals-2024-25
  `history-stealer/webapp/app.py:10` (`app.secret_key =
  "supersecretkey"`), and both `UnauthorizedAndroidApp1`/`2`
  `main.py:8` — with zero false positives anywhere else. Surfaced a
  structural limitation of the regression harness itself along the way:
  `is_test_file()` treats any path containing a `tests`/`specs` segment
  as a test file, every fixture in this suite necessarily lives under
  `tests/fixtures/...`, and this rule's payload is (correctly)
  registered in `NOISY_IN_TEST_FILES` — so the harness can only assert
  this rule's *suppression*, never its raw "fires" case, the same
  limitation the pre-existing "Weak Auth Logic" hardcoded-credential rule
  already has. The positive case was instead verified directly against
  the real, non-test-pathed corpus above.
- ~~Zip Slip via manual zip extraction, not just a bare `.extract()`/
  `.extractall()` call~~ — added in v1.27.0, see ARCHITECTURE.md and
  CAPABILITIES.md. Found in the real CyberSci nationals-2024-25
  "history-stealer" web challenge's `webapp/app.py` `/file_upload` route
  (lines 111-151) — the code's own comment literally says "Extracting
  ZIP (vulnerable to Zip Slip)...". It even TRIES to check for traversal
  (`if raw_name.startswith("/") or ".." in raw_name:`), but the "fix" is
  backwards: it normalizes the traversal-laden name into an absolute
  path (`os.path.normpath(os.path.join("/", raw_name))`) and writes
  there anyway, instead of rejecting the entry. flagmap already had a
  "Path Traversal / Zip Slip" rule, but it only matches a literal
  `.extract(`/`.extractall(` call — this file calls neither; it manually
  walks `zip_ref.infolist()` and writes each member's bytes itself via
  `zip_ref.open(member)` + `open(dest_path, "wb")`, a shape the existing
  rule has no way to see. Added `zipslip_guard.py`, a Python-only,
  whole-file, two-signal best-effort check firing under the SAME vuln
  name (`Path Traversal / Zip Slip`): (1) a variable assigned from a zip
  member's own `.filename`
  (from `.infolist()`/`.filelist`, or the loop variable itself when
  iterating `.namelist()`) that's (2) later joined into a destination
  path via `os.path.join(...)` — fired only when the file also appears
  to write somewhere (`open(..., "wb")`/`shutil.copyfileobj`/`.write(`)
  and never demonstrates a real containment check anywhere
  (`.resolve()`...`.relative_to(`/`.is_relative_to(`, `os.path.realpath(`
  +`.startswith(`, or `os.path.commonpath(`). Deliberately does NOT treat
  a bare `".." in name`-style substring test as proof of safety, since
  the real motivating bug has exactly that test and still gets it wrong
  — only an actual path-containment verification idiom suppresses it.
  Verified against the full 4-snapshot corpus: `grep` for `zipfile`/
  `ZipFile` usage anywhere in the corpus turns up exactly two files —
  the vulnerable one (fires, at the exact `os.path.normpath(os.path.join(
  "/", raw_name))` line) and that same challenge's own
  `solve_files/create_zip.py` (only ever *creates* a zip, confirmed zero
  false positive since it touches none of this check's signals).
- ~~JSP cookie-sourced XSS, not just a direct `request.getParameter()`/
  `getAttribute()` call inside `<%= %>`~~ — added in v1.28.0, see
  ARCHITECTURE.md and CAPABILITIES.md. From this point on, evidence for
  new flagmap checks also comes from publicly released past challenges
  of OTHER web-exploitation CTFs in the same style as CyberSci's own
  nationals/regionals (not just CyberSci's own archive) — this entry's
  motivating evidence is DownUnderCTF 2025's public "sweet_treat" web
  challenge (`DownUnderCTF/Challenges_2025_Public` on GitHub), found
  while auditing it the same way the CyberSci corpus was audited:
  running flagmap, then checking its findings against the challenge's
  own published `WRITEUP.md`. `patterns.py` already has a JSP XSS rule,
  but its own comment is explicit about the line it draws: it ONLY
  matches `request.getParameter(...)`/`request.getAttribute(...)` called
  directly inside a `<%= %>` tag, on the same line — deliberately, to
  avoid a blanket "any non-literal `<%= %>`" rule firing on nearly every
  JSP page. That line leaves a real gap on the other side of it: a
  cookie's value, read out through `Cookie[] request.getCookies()` + a
  `for (Cookie c : cookies)` loop + `c.getValue()`, assigned to a plain
  variable, and THAT variable echoed raw several lines later — never a
  `request.getParameter()`/`getAttribute()` call anywhere on the line.
  Confirmed in TWO separate files in the same challenge
  (`index.jsp:48` and `admin/admin-review.jsp:94`, both
  `<html lang="<%= lang %>">`), and `index.jsp` even defines and
  correctly uses its own `escapeHtml(...)` helper for a DIFFERENT value
  two lines later — proof the developer knew to escape and simply missed
  this one spot. Added `jsp_cookie_xss_guard.py`, a three-signal
  whole-file check: a `for (Cookie <var> : ...)` loop's own loop
  variable, that SAME variable's `.getValue()` assigned to a plain
  variable, and that variable referenced inside a `<%= %>` tag with no
  recognized escaping call (`escapeHtml(`, `StringEscapeUtils.
  escapeHtml4(`, `fn:escapeXml(`, `Encode.forHtml(`,
  `ESAPI.encoder().encodeForHTML(`). Caught and fixed one of its own
  precision bugs during development: an earlier draft matched ANY
  `\w+.getValue()` assignment, which would have wrongly treated
  `admin/admin.jsp`'s unrelated `HttpSession s = entry.getValue();`
  (iterating a `Map<String, HttpSession>`, nothing to do with cookies)
  as cookie-tainted — fixed by requiring the `.getValue()` receiver to
  be the exact variable bound by a real `Cookie` loop. Verified against
  both the CyberSci corpus (count unchanged, confirming zero
  cross-contamination) and the full DownUnderCTF 2024+2025 public
  archive: exactly the two real hits, zero false positives elsewhere.
- ~~Python "class pollution" (the Python analog of JS Prototype
  Pollution — a hand-rolled recursive merge calling `setattr()` with an
  attacker-controlled attribute name and no denylist on dunder names)~~
  — added in v1.29.0, see ARCHITECTURE.md and CAPABILITIES.md. From
  DownUnderCTF 2024's public "co2" web challenge and its sequel "co2v2"
  (`DownUnderCTF/Challenges_2024_Public`), which share the EXACT same
  `merge()` helper verbatim — real, duplicated evidence of the same
  shape, not a one-off:
  ```python
  def merge(src, dst):
      for k, v in src.items():
          ...
          else:
              setattr(dst, k, v)
  ```
  `co2`'s route handler merges a fresh JSON body straight into a
  `Feedback()` instance with zero key filtering. Since `setattr()`
  doesn't special-case dunder names, `{"__class__": {"__init__":
  {"__globals__": {"flag": "true"}}}}` walks the instance's own class,
  to its constructor, to that function's module globals, and overwrites
  the module-level `flag` variable directly — the exact gadget chain in
  the writeup's linked reference article, "Prototype pollution in
  Python". `patterns.py` already had two JS-only Prototype Pollution
  rules (one for `_.merge`/`deepmerge({}, req.body)`, one for the
  homemade `instanceof Object && key in target` merge shape) but nothing
  for Python's equivalent at all. Added `class_pollution_guard.py`, a
  two-signal whole-file check filed under the SAME vuln name as the JS
  rules (both describe the identical class of bug, just different
  languages and magic-attribute vocabularies): a `for k, v in
  <dict>.items():` loop, and a `setattr(obj, k, v)` call elsewhere in
  the file using those exact two variable names — not provable taint,
  the same trade the existing JS homemade-merge rule already makes, on
  the theory that a generic merge helper written this way is rarely fed
  only trusted, fully-known keys. Caught and fixed a self-referential
  documentation trap during development, the same kind `xxe_guard.py`'s
  own docstring warns about: an early draft of this module's own
  docstring quoted the real vulnerable code verbatim (`for k, v in
  src.items():` plus `setattr(dst, k, v)`), which meant the module's own
  source file satisfied both of its own detection signals and
  self-flagged three times — fixed by paraphrasing the illustrative
  example (parenthesized tuple-unpacking, `dst.__setattr__(...)` instead
  of `setattr(...)`) so the docstring is no longer syntactically
  identical to what it describes. Verified against both the CyberSci
  corpus (count unchanged) and the full DownUnderCTF 2024+2025 archive
  (`grep -rl "setattr("` across the whole archive turns up exactly these
  two files): exactly the two real hits, at the exact real `setattr(dst,
  k, v)` line in each, zero false positives elsewhere.
- ~~Known-vulnerable *pinned container base images*, not just language
  package manifests~~ — added in v1.30.0, see ARCHITECTURE.md and
  CAPABILITIES.md. From DownUnderCTF 2024's public "hah-got-em" web
  challenge, whose entire `src/Dockerfile` is three lines with no
  application source at all:
  ```dockerfile
  FROM gotenberg/gotenberg:8.0.3
  COPY flag.txt /etc/flag.txt
  CMD ["gotenberg", "--api-port=1337"]
  ```
  The challenge's own goal is to read `/etc/flag.txt`, and the entire
  bug is the vendored image version: Gotenberg (HTML-to-PDF conversion
  via Chromium) placed no restriction on a converted document's
  `<iframe>`/`<img>` tags reaching `file://` paths or internal-network
  URLs through 8.0.3, fixed in 8.1.0 — a local-file-read/SSRF primitive
  built into the service itself. flagmap scanned this directory and
  found nothing but a generic "Container Runs as Root" misconfig — a
  complete miss of the intended vulnerability, because `deps.py`'s
  CVE_TABLE only ever looked at language-ecosystem manifests
  (requirements.txt, package-lock.json, pom.xml, etc.), never at a
  Dockerfile's own `FROM` line, even though a CTF "vulnerable
  dependency" challenge can just as easily vendor an entire container
  image instead of a language package. Added a `"docker"` ecosystem to
  the existing CVE_TABLE (one curated entry so far: gotenberg/gotenberg,
  fixed in 8.1.0) and a small `parse_dockerfile_from()` parser matching
  `FROM <image>:<tag>` lines — same exact-version-pin matching logic
  every other entry in the table already uses, just keyed by image name
  instead of package name. Deliberately narrow by construction rather
  than by denylist: a bare `FROM builder` referencing an earlier
  multi-stage build stage's name has no colon and never matches at all
  (no stage-name list needed), and `FROM image` / `FROM image:latest`
  with no real pin is left alone since config_patterns.py's existing
  "Unpinned Base Image Tag" check already covers that case — this one
  only speaks to an exact version that's actually in the curated table.
  `Dockerfile.prod`/`Dockerfile.dev`-style names are matched too, same
  naming convention config_scanner.py's own "dockerfile" category
  already uses. Verified: 190/190 regression (a new `deps/case2`
  fixture, in addition to the real hit, exercises an unrelated
  real-looking pin that isn't in the table, a multi-stage stage-name
  reference, the exact fixed version, and an explicit `:latest` tag —
  confirming none of those produce a false positive); the CyberSci
  corpus's finding count is unchanged (392, no Dockerfile in that
  archive pins a tracked image); and scanning the real `hah-got-em`
  challenge now reports exactly the one real
  `gotenberg/gotenberg@8.0.3` finding, alongside the pre-existing
  generic root-user misconfig rather than instead of it.
- ~~JWT "algorithm confusion" (an `algorithms` allowlist that accepts
  BOTH an HMAC family and an asymmetric family against the same key)~~
  — added in v1.31.0, see ARCHITECTURE.md and CAPABILITIES.md. From
  DownUnderCTF 2024's public "i-am-confusion" web challenge
  (`src/main-app/server.js`):
  ```js
  const verifyAlg = { algorithms: ['HS256','RS256'] }
  ...
  jwt.verify(cookie['auth'], publicKey, verifyAlg, (err, decoded_jwt) => { ... })
  ```
  The app signs every token with RS256 only (`jwt.sign(payload,
  privateKey, { algorithm: 'RS256' })`), but the verify call's allowlist
  accepts HS256 too, against the SAME `publicKey` variable. Since an
  RSA public key isn't secret, an attacker fetches it and re-signs a
  forged `{"user":"admin"}` token with alg:HS256 using the public key's
  own bytes as the HMAC secret — `jwt.verify()` has no way to tell "this
  key was only ever meant for RS256" from a single call with a mixed
  allowlist, so the forged signature passes. The challenge's own
  writeup walks through exactly this attack. flagmap already had a
  `"generic"` JWT rule for a verify call with the algorithms allowlist
  missing *entirely* (`jwt\.verify\s*\(\s*\w+\s*,\s*\w+\s*\)`, "low"/
  "possible" — added earlier, its own comment even names this exact
  attack as the risk) but nothing for the allowlist being *present* and
  simply wrong, which is what the real challenge does and a strictly
  more common real-world shape (teams who bother writing an explicit
  allowlist at all tend to get it wrong this way, not leave it off).
  Added a second `"generic"` pattern: a single-line regex matching an
  `algorithms` list literal (covers both the JS object-property spelling
  and Python/PyJWT's keyword-arg spelling — both use `[...]` with quoted
  algorithm names, just `:` vs `=`) containing at least one HS256/384/512
  entry together with at least one RS/ES/PS 256/384/512 entry, in either
  order. Deliberately doesn't also try to confirm the verify key itself
  is a public/certificate value on the same line: by the time an
  allowlist mixes both families at all there is no key that is
  simultaneously a safe HMAC secret and a legitimate asymmetric public
  key, so the mixed-allowlist shape alone is the signal — "high"/
  "likely", since every major JWT library's own docs call this
  combination out as unsafe, not merely "possible." Verified against
  both corpora: CyberSci's finding count and its 13 pre-existing JWT
  hits are both unchanged (none of that archive's JWT findings mix
  algorithm families — `voter_registry.py`'s `algorithms=["HS256"]` is
  single-family, for instance), and the full DownUnderCTF 2024+2025
  archive goes from 90 to 92 findings — exactly the two real hits (the
  challenge's `src/` and `publish/` copies of the same `server.js`),
  zero false positives elsewhere. Added JS fixtures (`vuln_sinks.js`/
  `clean_sinks.js`) mirroring the real mixed-family case plus two
  single-family negatives, since no dedicated fixture coverage existed
  yet for this corner of the JWT rule family at all.
- ~~JS/TS Prototype Pollution via a prefix-filtered `for...in` key,
  stripped and bracket-assigned with no `__proto__`/`constructor`
  denylist~~ — added in v1.32.0, see ARCHITECTURE.md and
  CAPABILITIES.md. From DownUnderCTF 2024's public "prisoner-processor"
  web challenge (`src/app/src/index.ts`):
  ```ts
  const getSignedData = (data: any): any => {
    const signedParams: any = {};
    for (const param in data) {
      if (param.startsWith(SIGNED_PREFIX)) {
        const keyName = param.slice(SIGNED_PREFIX.length);
        signedParams[keyName] = data[param];
      }
    }
    return signedParams;
  };
  ```
  `for...in` walks every enumerable property NAME of `data`, including
  one an attacker names `"signed.__proto__"` in their JSON body. This
  function filters by the literal `"signed."` prefix, strips it with
  `.slice()`, and bracket-assigns the result onto a fresh plain object
  with zero check against `__proto__`/`constructor`/`prototype` —
  `signedParams["__proto__"] = ...` pollutes `Object.prototype` process-
  wide. The challenge's own writeup uses exactly this to bypass this
  function's sibling signature check, since `Object.entries()` (used to
  compute the HMAC) never enumerates inherited properties the way
  `for...in` does. `patterns.py` already had two JS Prototype Pollution
  rules — a deep-merge library call, and a hand-rolled RECURSIVE merge
  whose own `key in target` guard is itself the gadget — but neither
  matches this file: no library call, no recursion, just a flat loop, a
  prefix filter, a strip, and a bracket write.

  Added `forin_prefix_pollution_guard.py`, filed under the same
  `"Prototype Pollution"` vuln name. An early design only required a
  `for...in` loop plus a bracket-assignment using the loop variable (or
  a simple derived alias) — rejected during development once it was
  tested against the ordinary `for (const k in obj) { out[k] =
  obj[k]; }` shallow-copy idiom, an extremely common, completely benign
  pattern that it would have flagged constantly. Narrowed instead to
  four required signals, one more than this project's usual two-to-
  three: (1) a `for (const/let/var V in ...)` loop; (2) a
  `V.startsWith(...)` prefix check on that loop variable anywhere in the
  file; (3) a variable `K` declared as `V.slice(...)` (the prefix-
  stripped name); (4) a bracket assignment `obj[K] = ...` elsewhere using
  that exact derived variable. This "filter by prefix, strip it, use the
  bare suffix as a brand-new property name" idiom is rare outside this
  specific "flatten a namespaced set of fields" pattern, unlike a bare
  copy loop. Verified against both corpora: CyberSci's finding count is
  unchanged (392 — no file in that archive has this four-signal
  combination, confirming the narrower design doesn't just trade one
  false-positive source for another), and the full DownUnderCTF
  2024+2025 archive goes from 92 to 93 — exactly the one real hit, with
  the two pre-existing, unrelated class-pollution hits (`co2`/`co2v2`)
  still present and unchanged alongside it. Self-scan of the new module
  and `scanner.py` came back clean. Added dedicated fixtures
  (`tests/fixtures/js/forin_prefix_pollution_vuln.ts`/`clean.ts`, same
  isolated-file convention as `jsp_cookie_xss_*.jsp`/
  `class_pollution_*.py`, since this is a whole-file check): the real
  shape, plus three negatives each missing exactly one of the four
  signals — proving every one of them is load-bearing, including the
  ordinary shallow-copy loop that motivated narrowing the design in the
  first place.
- ~~Open Redirect allowlist that checks `.hostname` but never
  `.protocol` — a `javascript:` scheme bypass that escalates an intended
  redirect mitigation into script execution~~ — added in v1.33.0, see
  ARCHITECTURE.md. From DownUnderCTF 2024's public "waifu" web challenge
  (`src/app/src/utils/response.ts`):
  ```ts
  const redirectUrl = new URL(redirectTo, process.env.BASE_URL);
  // Prevent open redirect
  if ((redirectUrl.hostname ?? '') !== new URL(defaultRedirect).hostname) {
    redirectTo = defaultRedirect;
  }
  const encodedRedirect = encode(redirectTo);
  res.send(BROWSER_REDIRECT.replace("{REDIRECT}", encodedRedirect));
  // BROWSER_REDIRECT embeds it as: window.location = "{REDIRECT}";
  ```
  The mitigation checks only `.hostname`, never `.protocol`. `new URL()`
  parses the hostname the same way regardless of scheme, so
  `javascript://waifu-app:3000/<payload>` has the SAME hostname as the
  real app and sails through this exact check, carrying an
  attacker-chosen scheme. The validated string is then assigned to
  `window.location` — a browser navigating to a `javascript:` URL
  executes it as code, regardless of any HTML-entity escaping applied to
  the string (`encode()` here does nothing to stop this, since it's not
  a markup-escaping bug: it's scheme confusion). The challenge's own
  writeup walks through exactly this to steal an admin session via a
  webhook. flagmap's existing "Open Redirect" rules all target the
  simpler "no allowlist at all" shape; this is the same underlying
  mistake (an under-validated redirect-ish target) with a worse outcome,
  so it's filed under the same vuln name rather than a new one.

  Added a single-line regex: two separate `.hostname` references joined
  by an equality/inequality comparison on the same line (the canonical
  "compare a parsed URL's hostname against an expected one" allowlist
  idiom), with no `.protocol` reference anywhere on that line. Severity
  "high" (script execution, not just phishing-redirect), confidence
  "possible" (doesn't try to prove the compared URL is attacker-tainted,
  or that `.protocol` isn't checked on some other line — same trade
  several existing best-effort rules in this file already make).
  Verified against both corpora: CyberSci's 2 pre-existing Open Redirect
  hits are unchanged (confirmed via git-stash diff), and the full
  DownUnderCTF 2024+2025 archive goes from 93 to 94 findings — exactly
  the one real hit; a pre-existing, unrelated Open Redirect finding in
  2025's `file_upload/appupload.py` (from an existing rule) is also
  confirmed unchanged by the same diff, so DUCTF 2025's total stays at
  146. Self-scan of `patterns.py` adds zero new self-matches (the new
  rule's own illustrative comment happens to contain the exact
  `.hostname`/`.hostname` shape it describes, but the rule is scoped to
  `"js"`, and `patterns.py` itself is a `.py` file, so it's never even
  evaluated against it). Added fixtures to `tests/fixtures/js/
  vuln_sinks.js`/`clean_sinks.js`: the real hostname-only shape, and a
  safe counterpart that also compares `.protocol` on the same line.
- ~~PHP `readfile()` missing from the AST taint engine's sink table~~ —
  added in v1.34.0, see ARCHITECTURE.md. From DownUnderCTF 2024's public
  "sniffy" web challenge (`src/audio.php`):
  ```php
  $file = 'audio/' . $_GET['f'];
  if (!file_exists($file)) { http_response_code(404); die; }
  $mime = mime_content_type($file);
  if (!$mime || !str_starts_with($mime, 'audio')) { http_response_code(403); die; }
  header("Content-Type: $mime");
  readfile($file);
  ```
  `$file` is correctly identified as tainted (the assignment line itself
  contains `$_GET['f']`), but `readfile()` — PHP's standard way to stream
  a file straight to the response, exactly the "serve this static asset"
  shape an LFI challenge is built around — simply wasn't in
  `ast_engine.py`'s PHP `SINKS` table at all, so flagmap reported nothing
  despite correctly tainting the variable. (The MIME-type check in
  between is an insufficient allowlist, not a path-containment check —
  the challenge's own solve script bypasses it by poisoning the PHP
  session file's own content with repeated `M.K.` bytes, a ProTracker
  module-file magic signature, so `mime_content_type()` reports the
  session file itself as an audio type. That bypass technique is content-
  sniffing-specific and not something a source-level static scanner
  could reasonably model; the generalizable, catchable half of this bug
  is simply "tainted path reaches `readfile()`", which is what this fix
  addresses.) First discovered by adding `"readfile"` to `taint.py`'s
  legacy regex-based PHP `SINKS` table, which turned out to be dead code
  for this file: PHP is AST-supported, so `scanner.py` always runs
  `ast_engine.py` instead of `taint.py` for `.php` files (confirmed zero
  effect, then reverted) — the fix had to go in `ast_engine.py`'s own,
  separate PHP `SINKS` table instead. Verified against both corpora:
  CyberSci's finding count is unchanged (392, confirmed by git-stash
  diff — no file in that archive has a tainted variable reaching
  `readfile()`), and the full DownUnderCTF 2024+2025 archive goes from
  94 to 95 — exactly the one real hit. Self-scan of `ast_engine.py` came
  back clean. Added fixtures to `tests/fixtures/php/vuln_sinks.php`/
  `clean_sinks.php`: the real cross-statement shape (concatenated path,
  `readfile()` several lines later, through an unrelated `file_exists()`
  check in between), and a safe counterpart calling `readfile()` on a
  fixed literal path.
- ~~aiohttp static routes registered with `follow_symlinks=True`~~ —
  added in v1.35.0, see ARCHITECTURE.md. From DownUnderCTF 2023's public
  "static-file-server" beginner web challenge (`app.py`):
  ```python
  web.static('/files', './files', follow_symlinks=True)
  ```
  aiohttp's static handler skips its "is the resolved path still inside
  the static root?" check entirely when `follow_symlinks=True`
  (CVE-2024-23334, every aiohttp release before 3.9.2), so the request
  path itself is a traversal: `curl --path-as-is
  http://HOST/files/../../../../flag.txt`. flagmap reported nothing —
  there's no request object on this line at all, since the URL path is
  the implicit input for every static route, so no taint-based rule could
  ever see it. Added a single-line Python pattern under "Path Traversal /
  LFI" matching `web.static(...)`/`add_static(...)` with
  `follow_symlinks=True`. The Dockerfile installs aiohttp unpinned, so a
  `deps.py` entry wouldn't have caught this one; the code shape is the
  signal. Verified: 204/204 regression (new `ruleid` plus two `safe`
  cases — default and explicit `follow_symlinks=False`); CyberSci,
  DUCTF 2024 and DUCTF 2025 unchanged (392/95/146); DUCTF 2023 goes from
  99 to 100, exactly the real hit; `patterns.py` self-scan unchanged at 8.
- ~~Client-IP allowlist decided from the `X-Forwarded-For` header~~ —
  added in v1.36.0, see ARCHITECTURE.md and CAPABILITIES.md. Three real
  occurrences across two DownUnderCTF years: 2023's "proxed" and
  "actually-proxed" share the same Go `secret_server`
  (`xff := r.Header.Values("X-Forwarded-For")` → last entry becomes `ip`
  → `if ip != "31.33.33.7"` gates the flag), and 2025's "sodium"
  (`forwarded_for = headers.get("x-forwarded-for", "")` → `if
  forwarded_for not in config.authorized_ips` → 403). The header is set
  by the client — a proxy only appends to it — so all three are bypassed
  by sending the allowed IP yourself (twice, in "actually-proxed", whose
  hand-written proxy only appends to the first copy). flagmap reported
  nothing for any of them. Added `xff_trust_guard.py`, a two-signal
  whole-file check under the existing "Weak Auth Logic" name: (1) a
  READ of `X-Forwarded-For`/`X-Real-IP` from the request
  (`Header.Get/Values`, `headers.get`/`headers[...]`, `req.get`,
  `$_SERVER[HTTP_X_...]`, `environ`), deliberately excluding a dict
  literal that SETS the header and a proxy comparing a header name to
  that string; and (2) an IP-allowlist-shaped decision anywhere in the
  same file (equality against a literal dotted-quad, or membership in an
  `*ips`/`allowlist`/`trusted*`-named collection). Fires on the read
  line. Hit a self-referential trap on the first self-scan: the module
  docstring quoted the real header reads and the real IP comparison, so
  it satisfied both of its own signals — paraphrased with placeholders.
  Verified: 208/208 regression (dedicated Go and Python vuln/clean
  fixtures — clean cases are a logging-only read and an outbound dict
  setting the header); CyberSci unchanged at 392 (its one
  `X-Forwarded-For` mention is an attack bot *setting* the header, which
  correctly doesn't fire); DUCTF 2023 100 → 102 and DUCTF 2025 146 → 147,
  exactly the three real hits; DUCTF 2024 unchanged; both
  `xff_trust_guard.py` and `scanner.py` self-scan clean.
- ~~PHP upload destination path built from the client's
  `$_FILES[...]['name']`, written without `move_uploaded_file()`~~ —
  added in v1.37.0, see ARCHITECTURE.md. From DownUnderCTF 2023's public
  "xxd-server" beginner challenge: `$upload_path = $upload_dir . '/' .
  basename($_FILES['file-upload']['name']);` followed by
  `file_put_contents($upload_path, ...)`. `basename()` stops traversal
  but keeps the client's extension, and the app's `.htaccess` still
  executes `.php`, so uploading `shell.php` is RCE (the ASCII column of
  the hex dump still carries a short `<?= ... ?>`). The existing PHP
  upload rule only keys on `move_uploaded_file(`. Added a single-line
  rule keyed on the destination path itself — a `"dir/"` literal
  concatenated with `$_FILES[...]['name']`, optionally via `basename()` —
  rather than on `file_put_contents`, which writes every kind of file.
  Verified: 211/211 regression (ruleid on the real shape; safe on
  reading the name's extension for an allowlist and on echoing the name);
  per-finding corpus diff shows only DUCTF 2023 102 → 103 — the real
  line — with CyberSci (392), DUCTF 2024 (95) and DUCTF 2025 (147)
  unchanged; `patterns.py` self-scan unchanged at 8.
- ~~Whole request form/JSON dict minted into a token as its claims~~ —
  added in v1.38.0, see ARCHITECTURE.md and CAPABILITIES.md. From
  DownUnderCTF 2023's public "grades-grades-grades" challenge
  (`src/routes.py`): `jwt_data = request.form.to_dict()` then
  `jwt_cookie = current_app.auth.create_token(jwt_data)`. Every submitted
  field becomes a signed JWT claim, and the app's `requires_teacher`
  trusts `is_teacher` — the solve is one signup POST with `is_teacher=1`
  added. The existing Python Mass Assignment pattern only matches a
  one-line double-star unpack of the request. Added
  `token_mass_assign_guard.py` (two whole-file signals: a variable
  assigned the entire request payload as a dict, and that variable as
  the first argument of `jwt.encode`/a `*create*…token*`-style minting
  call; a direct whole-request argument also matches). The new module's
  first self-scan flagged its own docstring via the *existing* Mass
  Assignment regex (it quoted that rule's shape) — reworded. Verified:
  216/216 regression with dedicated vuln/clean fixtures (clean: claims
  built from chosen fields; a whole-request dict only stored in a DB);
  per-finding corpus diff shows only DUCTF 2023 103 → 104, the real line;
  guard and `scanner.py` self-scan clean.
- ~~ORM lookup injection: a whole request dict unpacked into
  `.filter()`~~ — added in v1.39.0, see ARCHITECTURE.md and
  CAPABILITIES.md. From DownUnderCTF 2023's public "secureblog" DRF view:
  `Article.objects.filter(**request.data)`. The client picks the lookup
  keys, and `created_by__password__startswith` turns the endpoint into a
  character-by-character oracle on the author's password hash (the
  challenge's `pass_leak.py`). New single-line Python rule under a new
  name, "ORM Injection / Filter Leak" (not a write, so not Mass
  Assignment; parameterized SQL, so not SQL Injection), covering
  `filter/exclude/get/filter_by` with DRF/Flask/Django whole-request
  dicts. The existing Python Mass Assignment pattern now steps aside on
  ORM lookup lines so one line isn't reported under both names — and
  while testing that, found and fixed a pre-existing bug in it: a
  trailing `\b` after the alternation meant its `get_json()` branch could
  never match (no word boundary between two `)`), so
  `Model(**request.get_json())` was silently missed. Verified: 221/221
  regression (new ruleid cases for both rules via `get_json()`, safe case
  for code-chosen lookup keys); per-finding corpus diff shows only DUCTF
  2023 104 → 106, the real line in `src/` and `publish/`; all other
  corpora unchanged; `patterns.py` self-scan unchanged at 8.
- ~~Vulnerable npm plugin with no fixed release
  (`strapi-plugin-email-designer`)~~ — added in v1.40.0, see
  ARCHITECTURE.md and CAPABILITIES.md. From DownUnderCTF 2023's public
  "strapi-in" challenge: the lockfile resolves the plugin at 2.1.2, which
  renders email templates with the same unsandboxed lodash template
  Strapi core fixed as CVE-2023-22621 — a saved template containing
  `<%= ... process.binding("spawn_sync") ... %>` runs a shell. flagmap
  only reported the `.env`. The plugin never shipped a fix (upstream
  issue #123), so `CVE_TABLE` entries now accept `fixed_in=None`
  ("no fixed release known"), handled explicitly in `_matches_entry`
  rather than via a made-up sentinel version. Verified: new
  `deps/case3` fixture (plugin expected; fixed lodash 4.17.21 and Strapi
  4.12.4 quiet), 222/222 regression; per-finding corpus diff shows only
  DUCTF 2023 106 → 110 (`package-lock.json` and `yarn.lock` in `src/`
  and `publish/`); `deps.py` self-scan unchanged at its pre-existing 2.
- ~~MongoDB `$regex` operator fed a variable~~ — added in v1.41.0, see
  ARCHITECTURE.md and CAPABILITIES.md. From DownUnderCTF 2023's public
  "crossedmonkes" challenge: `{'search_id': {'$regex': search}}` with
  `search` from `?search=`, one function away. A client-supplied regex
  is a prefix oracle on the field (`^6`, `^6a`, ...), and the view's
  `?redirect_to=` branch makes match/no-match observable cross-site —
  the intended XS-leak. Existing NoSQL rules only covered a whole request
  body used as the filter. Added a single-line `"generic"` rule: a
  quoted or bare `$regex` key whose value is an identifier, excluding
  `re.escape(...)`/`escapeRegExp(...)`. Verified: 227/227 regression
  (Python and JS ruleid; literal and escaped safe cases); per-finding
  corpus diff shows only DUCTF 2023 110 → 114 (two lines × `src/` and
  `publish/`); `patterns.py` self-scan unchanged at 8.
- ~~False positives: SQL Injection reported on *tagged* template
  literals (`sql\`...${x}\``, `db\`...${x}\``)~~ — fixed in v1.42.0, see
  ARCHITECTURE.md. Found running the LA CTF archive (UCLA's public
  challenge repo) — the first non-DownUnderCTF external corpus. Three real
  challenges (2025 "arclbroth" with `secure-sqlite`, 2026
  "bobles-and-narnes"/"narnes-and-bobles" with Bun's built-in SQL) produced
  30 "SQL Injection" findings, every one on a tagged template like
  `` sql`SELECT * FROM users WHERE username=${username}` ``. A tag function
  receives the literal pieces and the interpolated values separately and
  binds the values as parameters — these lines are the *safe* way to write
  SQL, and none of them is the challenges' real bug (a `secure-sqlite` quirk
  in one, Bun's array-of-objects `VALUES` expansion in the other). The JS
  "SQL structure in a template literal" pattern now requires that the
  opening backtick not be directly preceded by an identifier, `.`, `)` or
  `]` — i.e. not a tag. Untagged templates (`` const q = `SELECT...${x}` ``,
  `` db.query(`...${x}`) ``, `` sql.unsafe(`...${x}`) ``) still fire.
  Verified: 231/231 regression (new untagged `ruleid`; `sql`/`db`/
  `prisma.$queryRaw` tagged `safe` cases); per-finding corpus diff: LA CTF
  195 → 165, exactly the 30 tagged-template lines removed, nothing else;
  CyberSci and all three DUCTF archives unchanged.
- ~~JavaScript inside an HTML page's inline `<script>` blocks was never
  matched against any JS rule~~ — added in v1.43.0, see ARCHITECTURE.md
  and CAPABILITIES.md. From LA CTF 2025's public "mavs-fan" challenge,
  whose whole client side is inline script in `public/post/post.html`:
  `document.getElementById('post-content').innerHTML = post.message;` —
  stored XSS the admin bot triggers. flagmap chooses one language per
  file by extension, so `.html` files only ever met the "html" and
  "generic" rules; the identical line in a `.js` file would have been
  flagged. Added `inline_script.py`, which finds inline JavaScript script
  bodies (skipping `src=` scripts and non-JS `type`s such as templates
  and JSON) and re-scans them as "js" with the real path and real line
  numbers (everything outside a script body is blanked to spaces, so even
  columns line up). "generic" rules are left out of that second pass
  because they already ran over the whole file. Surfacing inline JS also
  surfaced a pre-existing precision gap in the DOM-XSS rule: it exempted
  only `innerHTML = ""`, so constant markup like `btn.innerHTML =
  'Loading<span class="spinner"></span>';` was flagged. It now exempts any
  single complete string literal with no interpolation and nothing after
  it but `;` or a comment — in `.js` files too. Verified: 235/235
  regression (new `inline_script_vuln.html`/`_clean.html` fixtures:
  the real shape; prose outside a script, a `text/template` body, and a
  constant assignment as safe). Per-finding corpus diff: LA CTF 165 → 173
  (all four mavs-fan inline sinks, plus two in each of two `solve.html`
  files); DUCTF 2024 95 → 96 ("zoo-feedback-form" writes a server response
  into `innerHTML`); CyberSci 392 → 393 — four new inline-script sinks
  (history-stealer's upload rows, three templated maps in
  factory_defaults) and three constant-markup assignments in `.js` files
  correctly dropped.
- ~~Jinja2/Django `{{ value | safe }}` template output~~ — added in
  v1.44.0, see ARCHITECTURE.md and CAPABILITIES.md. Two real LA CTF
  challenges: 2024 "ctf-wiki" (`{{ description | safe }}` over
  `markdown(description)`, which keeps raw HTML — the intended stored XSS)
  and 2026 "blogler" (`{{ blog["content"]|safe }}` over mistune output).
  Autoescaping is the default; `|safe` is the explicit opt-out, and
  nothing in flagmap looked at template files for it. Added an
  `"html"`-language rule matching `|safe` inside `{{ ... }}`. Also in this
  release: `inline_script.py`'s own docstring self-matched the generic
  `eval(` rule on its post-release self-scan — reworded. Verified:
  240/240 regression (`jinja_safe_vuln.html`/`_clean.html`: both real
  shapes; plain `{{ }}`, `|e`/`|urlencode`, and a filter whose name merely
  contains "safe" as safe); per-finding corpus diff: LA CTF 173 → 175,
  exactly the two templates; all other corpora unchanged.
- ~~HTML escaping with JS `.replace("<", "&lt;")` (string pattern,
  first occurrence only)~~ — added in v1.45.0, see ARCHITECTURE.md and
  CAPABILITIES.md. From LA CTF 2026's public "job-board" challenge, whose
  `htmlEscape()` is a line-by-line port of Python's `html.escape()` —
  `s = s.replace("<", "&lt;")` and so on. JavaScript's `String.replace()`
  with a string pattern replaces only the first occurrence, so the solve
  payload starts with `<>&'"` and the `<script>` after it goes through
  untouched. Added a single-line JS rule: `.replace(` with a one-character
  HTML-special string literal and an entity as the replacement. `/g`
  regexes and `replaceAll()` don't match. The corpus diff then turned up a
  second real instance nobody had pointed at: LA CTF 2025 "old-site"'s
  guestbook renders every stored message through
  `.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")`.
  Verified: 245/245 regression (three `ruleid` lines from the real shape;
  `/&/g` and `replaceAll` as safe); per-finding corpus diff: LA CTF 175 →
  181 (five job-board lines, one old-site line); every other corpus
  unchanged; `patterns.py` self-scan unchanged at 8.
- ~~Node AEAD decryption whose authentication tag is never enforced~~ —
  added in v1.46.0, see ARCHITECTURE.md and CAPABILITIES.md. Two real LA
  CTF challenges, the same app before and after a partial fix. 2023
  "zero-trust" decrypts its `iv.tag.ciphertext` session cookie with
  `createDecipheriv("aes-256-gcm", ...)`, `setAuthTag(...)` and
  `update(ct)` — never `.final()`, which is where Node compares the tag —
  so the cookie is bit-flippable CTR and the solve rewrites
  `{"tmpfile":"/tmp/..."}` to `/flag.txt`. 2026 "single-trust" adds
  `.final()` but no `authTagLength`, so Node accepts a 1-byte tag: same
  bit-flip, then 256 guesses. Added `aead_decipher_guard.py`: for each
  AEAD `createDecipheriv` (GCM/CCM/OCB/ChaCha20-Poly1305), "high" if
  `.final()` is never called on that decipher's variable before the next
  cipher is created, else (GCM) "medium" if the call has no
  `authTagLength`. Scoping the `.final()` search mattered: zero-trust's
  *encrypting* object is also named `cipher` and does call `.final()`.
  Verified: 249/249 regression (dedicated vuln/clean fixtures, including
  that same-name encrypt-then-decrypt shape, a fully correct decipher,
  and CBC); per-finding corpus diff: LA CTF 181 → 183, exactly the two
  real lines; all other corpora unchanged; guard and `scanner.py`
  self-scan clean.
- ~~Time-based (v1) UUIDs from the JS `uuid` package~~ — added in
  v1.47.0, see ARCHITECTURE.md and CAPABILITIES.md. From LA CTF 2023's
  public "uuid-hell" challenge: every session id, admin ones included, is
  `uuid.v1({'node': [...], 'clockseq': ...})` with node and clock sequence
  fixed, so the only unknown is the creation time. The page lists md5
  hashes of admin ids; the solve brackets the time from the player's own
  cookie and cracks a few hex digits with hashcat. flagmap only flagged the
  md5 calls. Added a single-line JS "Insecure Randomness" rule for
  `uuid.v1(` and the aliased `{ v1: x } = require('uuid')` / `import { v1
  as x } from 'uuid'` forms. Verified: 253/253 regression (both forms
  `ruleid`, v4 `safe`); per-finding corpus diff: LA CTF 183 → 184, the
  real line only; `patterns.py` self-scan unchanged at 8.
- ~~Stored XSS through an in-memory Map: request data `.set()` on one
  route, `.get()` into an HTML `.send()` on another~~ — added in v1.48.0,
  see ARCHITECTURE.md and CAPABILITIES.md. Two real LA CTF 2023
  challenges: "california-state-police" (`reports.set(id, crime)` with
  `crime = req.body.crime`, then
  `res.type("text/html").send(reports.get(req.params.id))`) and "metaverse"
  (`posts.set(id, content)`, then the same send through a template
  `.replace()`). The read, the store and the send are three statements in
  different handlers, and the AST taint engine doesn't follow values
  through a Map, so nothing fired. Added `store_html_xss_guard.py`: a
  variable bound from `req.body/query/params` (plain or destructured) →
  `STORE.set(key, that value)` → a `.send(` line containing `STORE.get(`
  with an HTML content type set on it or the three lines before. Verified:
  257/257 regression (dedicated fixtures; clean: JSON responses from a
  request-filled store — hptla's real shape — and HTML from a store that
  only holds constants); per-finding corpus diff: LA CTF 184 → 186,
  exactly the two real lines; all other corpora unchanged; guard and
  `scanner.py` self-scan clean.
- ~~Exposed Mercurial `.hg` directory~~ — added in v1.49.0, see
  ARCHITECTURE.md and CAPABILITIES.md. From LA CTF 2023's public
  "my-chemical-romance" challenge, which serves `static/` with its `.hg`
  repository inside it: the solve reads `.hg/dirstate` to learn the
  source file's name, then dumps `.hg/store/data/gerard__way2001.py.i`
  (or simply `hg clone`s the site and backs out the commit that removed
  the flag). `loot.py` has flagged an exposed `.git` since its first
  version but knew nothing about Mercurial. Added the same presence check
  for `.hg`, with an `hg log -p` / `hg clone http://...` suggestion.
  Verified: 258/258 regression (new `loot/case4` with a `.hg` under a
  static root); per-finding corpus diff: LA CTF 186 → 187, the real
  directory only; everything else unchanged; `loot.py` self-scan clean.
- ~~Python SQL built with `str.format()` away from the `execute(` line;
  and SQL-construction rules that couldn't see past a quote~~ — added /
  fixed in v1.50.0, see ARCHITECTURE.md. From LA CTF 2023's public
  "85-reasons-why" challenge (`app/views.py`): `execute(\` on one line,
  then `text("select parent as PID from images where b85_image = '{}' AND
  ...".format(spic))` on the next. The only `.format()` SQL rule required
  `execute(` on the same line. Added the `.format()` twin of the existing
  "SQL structure in an f-string" construction-site rule — and while
  testing it, found both rules shared a blind spot: `["'][^"']*` stops at
  the first quote of either kind, so `"... WHERE x = '{}'"` (SQL quoting a
  value inside a double-quoted Python string — the most common shape)
  never matched unless `execute(` was on the same line. Both rules now
  have one alternative per Python quote style. Verified: 261/261
  regression (real shape `ruleid`; a non-SQL `.format()` and a bound
  `text(":img")` parameter `safe`); per-finding corpus diff: LA CTF
  187 → 189 (`views.py:62`, plus a second rule now also matching
  `populate_db.py:45`, which was already reported); DUCTF 2025 147 → 148
  (an f-string SQL payload in a solve script); CyberSci, DUCTF 2023/2024
  unchanged; `patterns.py` self-scan unchanged at 8.
