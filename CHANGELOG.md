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
