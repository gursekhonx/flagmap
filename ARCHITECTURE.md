# flagmap — Architecture & Design Notes

This is the technical deep-dive: how the detection engine is built, why it's
built that way, and the real false positives/negatives found during testing
that motivated each change. If you just want to install and run flagmap,
see [README.md](README.md). For a terse per-version changelog, see
[CHANGELOG.md](CHANGELOG.md). For the full list of what flagmap catches (and
deliberately doesn't), see [CAPABILITIES.md](CAPABILITIES.md).

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
as before any of these languages were ported — see README.md's "Install" section for
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

**Vendored-library noise suppression (`vendor_guard.py`, v1.14.0)** is the
other finding from the same real-repo stress-testing pass, found against a
different corpus repo — RailsGoat, not DVWA. Rails' pre-Webpacker asset
pipeline convention checks third-party JS straight into
`app/assets/javascripts/`, with no `vendor/`/`node_modules/` directory for
`scanner.SKIP_DIRS` to exclude by path: a jQuery DataTables plugin, the
HTML5 Shiv polyfill, Google's AJAX API loader, and an IcoMoon icon-font's
IE7/8 shim all ended up sitting directly next to RailsGoat's own
hand-written controllers, and every one of them tripped `patterns.py`'s
two broadest, least context-aware regexes — a bare `eval(...)` anywhere
(`"Command Injection / RCE"`, language `"generic"`) and a bare
`.innerHTML = ...` assignment (`"Cross-Site Scripting (XSS) — DOM-based"`)
— purely from each library's own ordinary, unexploitable use of those
shapes (feature detection, DOM shims), six separate times across four
files, none of it RailsGoat's own intended bug. `vendor_guard.is_vendor_file()`
combines five independent, deliberately conservative signals (the jQuery-
plugin filename convention, a `.min.js`/`.min.css` suffix, a short curated
list of well-known always-vendored filenames, a webfont file sitting in
the same directory, and a license/version banner comment near the top of
the file) — any one is enough, and each was picked specifically because
it almost never matches hand-written, intentionally-vulnerable CTF source.
`scanner.py` only suppresses the same two specific rules this problem was
actually observed on (reusing the exact `NOISY_IN_TEST_FILES` mechanism's
shape, just keyed on a sibling `NOISY_IN_VENDOR_FILES` set and a new
`is_vendor_file()` check instead of `is_test_file()`) — nothing else in
flagmap treats a vendor-shaped file any differently, so a real taint-
tracked finding (SQLi, SSRF, ...) inside one still fires exactly as
before.

**SQL-construction-site matching for PHP "." concatenation and inline
interpolation (`sql_construct.py`, v1.15.0)** came out of testing flagmap
against OWASP Mutillidae II — the first fresh real-world repo tested
since the DVWA/NodeGoat/Pygoat/RailsGoat/DVWS-Node pass that found the
v1.13.0/v1.14.0 fixes. Mutillidae's `classes/SQLQueryHandler.php` is a
textbook DAO/handler class: every one of its ~15 query-building methods
(`getUserAccount`, `getUserAccountByID`, `getAccountByClientId`,
`authenticateByClientCredentials`, ...) assembles a raw SQL string by
joining literal fragments with a function parameter via PHP's "."
operator or inline `"...$var..."` interpolation, split across 2-4
physical lines for readability — and flagmap's SQL Injection coverage
came back with **zero** findings anywhere in that file, despite it being
packed with exactly the SQL injection the whole class exists to
demonstrate. Both of patterns.py's PHP SQL-Injection regexes structurally
could not reach this shape: one needs the dangerous call itself on the
same physical line as the literal string, the other needs the assigned-to
variable literally named `$sql`/`$query` *and* the concatenated value to
be a `$_GET`/`$_POST`/etc. superglobal by name, on that one line. Here the
sink is a custom wrapper method (`executeQuery()` — not a name flagmap's
sink list can safely recognize without colliding with every other
`execute*`-named method in any other codebase), the variable is named
`$lQueryString`, the tainted-looking values are function parameters, and
the query spans several lines. `sql_construct.py` walks the same
tree-sitter parse tree every other AST-based check in this file already
builds, looking for a "." concatenation chain or an inline-interpolated
`encapsed_string` whose literal portions read as a SQL query shape
(`SELECT...FROM`/`INSERT...INTO`/`UPDATE...SET`/`DELETE...FROM`) and which
joins in at least one non-literal operand — the same "match the query's
own shape, not provable taint" philosophy patterns.py's existing Python
f-string/JS template-literal construction-site rules already use,
extended to a language whose construction-site queries routinely span
more than one physical line. Verified against DVWA as an adversarial
precision check (chosen because its `impossible.php` reference files are
exactly the corpus that caught the v1.13.0 false positive): 38 raw hits
across DVWA's PHP tree, every one in a `low.php`/`medium.php`/`high.php`
intentionally-vulnerable file or its setup/seed-data code, zero in any
`impossible.php` file.

**TypeScript parsing, confirmed rather than assumed (v1.16.0)**:
`EXTENSION_LANGUAGE` has always mapped `.ts` to the `"js"` language, and
`ast_engine.py` has never had a dedicated `tree-sitter-typescript`
grammar — `.ts` files are parsed with plain `tree-sitter-javascript`,
which doesn't understand TypeScript-only syntax (type annotations,
interfaces, generics, decorators). This was never actually tested
against a real TypeScript codebase before OWASP Juice Shop (the first
JS/TS real-world target tested, see "Testing") — and it turned out to
work well enough in practice: `tree-sitter-javascript` is fault-tolerant
rather than crashing on unrecognized syntax, and the TypeScript-specific
parts a route handler actually needs flagmap to see through (object
literals, template-literal/string-concatenation sink arguments, function/
callback boundaries for the AST-based checks) parse correctly regardless
of the type annotations layered around them. Both of Juice Shop's famous
SQLi routes (`routes/login.ts`, `routes/search.ts`) were caught correctly,
and `idor.py`'s function-boundary detection worked well enough on real
`.ts` route handlers for `owner_param_guard.py` (below) to be built and
verified against them. Not a guarantee that every TypeScript construct
parses cleanly — just confirmation, from a real and fairly large
TypeScript codebase, that the existing `.ts` → `"js"` mapping was never
the gap it might have looked like on paper.

**The v1.16.0 confirmation above turned out to be incomplete, and `.tsx`
got its own dedicated grammar as a result (v1.23.0)**: Juice Shop's real
`.ts` route handlers apparently never happen to mix a top-level
TypeScript-only declaration (an `interface`, specifically) with a real
sink in the *same* file, so v1.16.0's "fault-tolerant, parses fine in
practice" conclusion held there — but it isn't actually what
`tree-sitter-javascript` does with that shape. Found auditing flagmap
against CyberSci's own official past-challenges repo
(`CyberSci/PastChallenges`): nationals-2024-25's defence challenges ship
real React+Remix frontends (`voter_registry`, `candidate_registry`) whose
route/component files are `.tsx`, an extension `EXTENSION_LANGUAGE` had no
entry for at all before this version — so those 20 real files were never
even opened, let alone parsed, which is a different and worse gap than the
one v1.16.0 checked. Adding `.tsx → "js"` and then testing a realistic
`.tsx` file that actually declares a TypeScript `interface` (the way a
typed React component's props almost always do) surfaced the real
problem: dumping the raw parse tree showed `tree-sitter-javascript`
doesn't recover from an `interface` block the way it recovers from, say,
a type annotation on a single parameter. It misparses `interface Foo {`
as the start of a labeled statement, and its error recovery then folds
the interface's body AND every statement after it in the file — including
the real `function` declaration and the real sinks inside it — into one
bogus `statement_block` subtree that the taint walker's scope/call-site
logic never descends into correctly. Not a few findings missed on a
corrupted line; every sink in the rest of the file goes dark at once.
Fixed by giving `.ts`/`.tsx` a dedicated `tree-sitter-typescript` grammar
instead of reusing plain JS's (`_PARSERS_BY_EXT` in `ast_engine.py`, keyed
by the real file extension read off `path`, checked before falling back
to `_PARSERS["js"]` so a system without `tree-sitter-typescript` installed
degrades to the old — mostly-fine, per v1.16.0 — behavior rather than
breaking). Confirmed via side-by-side parse-tree dumps that the dedicated
grammar produces `has_error=False` on the exact `interface`-plus-sink
shape that broke plain JS, and that every node-type name the taint walker
and `SCOPE_NODE_TYPES`/`CALL_NODE_TYPES`/`SINKS` rely on (`call_expression`,
`member_expression`, `variable_declarator`, `function_declaration`,
`jsx_attribute`, `lexical_declaration`, `object`, etc.) is identical
between the two grammars — so this is parser selection only, and none of
the existing `"js"`-keyed lookup tables needed to change. Verified
end-to-end against `tests/fixtures/js/tsx_extension_mapping.tsx`: a SQL
Injection and an SSRF finding past the `interface` block, previously
invisible, both fire correctly now alongside the DOM-XSS finding that
(by coincidence of where it sat in the file) was already firing before
this fix.

**React's `dangerouslySetInnerHTML` had zero XSS coverage (v1.23.0)**:
same CyberSci audit, same `candidate_registry` challenge —
`frontend/src/pages/questions/Questions.js` renders a voter's submitted
question text and a candidate's answer text through
`dangerouslySetInnerHTML={{ __html: question.question_text }}` straight
from an API response, no sanitization anywhere: textbook stored XSS, and
React does not escape this value itself (that's the entire point of the
"dangerously" in the prop's name). Confirmed via grep across
`patterns.py`, `ast_engine.py`, and `taint.py` that this sink — unlike a
plain `.innerHTML =` assignment, which flagmap has always caught — had no
coverage anywhere, despite being the canonical React DOM-XSS primitive in
any real React/Next/Remix codebase, CyberSci's included. Added as a
`patterns.py` regex rule matching `dangerouslySetInnerHTML={{ __html:
EXPR }}` only when `EXPR` isn't a plain quoted string literal (a static,
hardcoded markup fragment carries no attacker input and is a legitimate,
common use of the prop). The first draft of that exclusion,
`__html\s*:\s*(?!["'])`, had a backtracking bug: placing the negative
lookahead right after a greedy `\s*` let the quantifier backtrack to
zero-width specifically to satisfy the lookahead at the position *before*
the whitespace, so it wrongly matched `__html: '<hr/>'` (a safe static
literal) anyway — caught via direct `re.search()` debugging showing the
match span stopped at the colon with no trailing whitespace consumed.
Fixed by moving the optional whitespace inside the lookahead itself
(`__html\s*:(?!\s*["'])`), re-verified against a static literal (no
match), a bare member-expression value (matches), and a template literal
with a real interpolation (matches, since a backtick string is never "just
a static string" the way a single/double-quoted one is).

**Jenkins declarative-pipeline parameter injection — a 9th language that
deliberately isn't one (`jenkins_pipeline_guard.py`, v1.24.0)**: continuing
the CyberSci audit into nationals-2025-26's "deployment_hell" defence
challenge, whose Jenkins pipeline (`service/jenkins/scripts/
deploy-app.groovy`, `build-and-upload.groovy`) declares a
`string(name: 'projectName', ...)` build parameter, aliases it to an env
var one stage earlier (`env.PROJECT_NAME = params.projectName`), and
interpolates that var straight into a `sh '''...${PROJECT_NAME}...'''`
step. Jenkins substitutes `${PROJECT_NAME}` as literal shell text before
handing the script to `/bin/sh` — the Groovy quoting used to write the
step (`'''`, which does NOT GString-interpolate at the Groovy level at
all) is irrelevant, since Jenkins' own `sh` step treats its whole string
argument as a shell script regardless; the substitution happens in the
shell, not in Groovy. Anyone able to trigger a parameterized build (on
many real Jenkins installs, that's "Build" permission, sometimes even
anonymous) therefore controls part of the command the agent executes.
Zero coverage before this version: flagmap had no Groovy/Jenkinsfile
language at all, neither AST nor regex.

Deliberately NOT built as a 9th `tree-sitter`-backed AST language, even
though that's the pattern every other multi-file-shape check in this
project follows (sql_construct.py, idor.py, authn_guard.py all walk a real
parse tree). Two reasons, both concrete rather than "AST is more work
generically": no `tree-sitter-groovy` grammar exists anywhere in this
codebase's dependency tree, so adding one would mean vetting and wiring
in a 9th grammar for a single evidenced pattern; and even with that
grammar, the real files above write their `sh` step using Groovy's
parenthesis-free "command syntax" (`sh '''...'''`, not `sh('''...''')`),
which the *existing* taint-lite regex engine's generic sink matcher in
`taint.py` (`\b(sinkname)\s*\(`, hard-coded to require an opening paren
right after the sink name) couldn't reach either — so even a full AST
port would still need a Groovy-specific sink-matching path for this one
call shape, not a reuse of the existing per-language tables the way
`.ts`/`.tsx` reused `"js"`'s. Given that, a lightweight whole-file regex
check — same two-independent-signals discipline as `csrf.py`'s
form-plus-no-token-anywhere check and `jquery_dom_guard.py`'s
param-plus-no-server-signal check — was the better-scoped fix: (1) every
`string(name: 'X', ...)` parameter name declared anywhere in the file,
plus every `env.Y = params.X` direct alias found the same way, forms the
tainted-name set; (2) every `sh` step's own body (parenthesis-free or
parenthesized/`script:`-keyed, single/double/triple-quoted, spanning
multiple physical lines for the triple-quoted case) is checked for a
`${NAME}`/`$NAME`/`params.NAME` reference to any name in that set. Fires
only when both signals land in the same file — a `sh` step with no
parameter-derived variable anywhere in its body, or a parameter declared
but never used in any `sh` step (both deliberately included in this
version's own fixture, see "Testing"), are each left alone.

Caught and fixed two of its own bugs during development, same discipline
as every other guard in this project:
- The `sh`-step regex's first draft anchored on a bare `\bsh\b` word
  boundary, which matches the literal word "sh" wherever it appears as
  its own token — including inside this version's own first fixture
  attempt, where a descriptive stage name ending in "...multi-line sh"
  sat immediately before its own closing Groovy string quote. To a
  word-boundary matcher, "sh" followed by a quote looks exactly like the
  start of a real `sh` step; it then consumed everything up to the next
  quote as a fake "step body" and missed the real steps entirely. Fixed
  by anchoring to the start of a (whitespace-trimmed) line instead of a
  bare word boundary — every real Jenkinsfile `sh` step is written as its
  own statement starting a line, so this is both safer and loses no real
  coverage.
- The variable-reference regex's `\$\{?(\w+)\}?` alternative, meant to
  catch a plain `${NAME}`/`$NAME` reference, matched `${params.projectName}`
  as the single word "params" — `\w+` stops at the first non-word
  character, and a property-access `.` isn't one, so it never reached
  "projectName" at all. The captured name "params" isn't any real
  parameter, so this silently matched nothing rather than erroring,
  which is exactly the quiet failure mode this kind of regex bug tends to
  produce. Fixed by adding an optional `(?:params\.)?` prefix inside that
  same alternative, so `${params.projectName}` and `${PROJECT_NAME}` both
  correctly resolve to the parameter name.

Verified against the full 4-snapshot corpus: zero findings on every other
`.groovy` file present (`exfilAwsKeys.groovy`, `pluginExport.groovy`
(both copies), `approveScripts.groovy` — none of which reference any
declared build parameter inside a `sh` step), and correct hits on both
real vulnerable files, at exactly the lines containing the real
`${PROJECT_NAME}`-interpolating `sh` steps.

**GraphQL injection via plain "+" concatenation, not just "%" formatting
(v1.25.0)**: continuing the same CyberSci audit into nationals-2025-26's
"quote_vault" web challenge's `api/app.py`. The challenge's own solve
script chains two bugs for its master flag: a URL-path-based GraphQL
injection (`GET /api/quotes/<path:id_raw>` wraps `id_raw` straight into a
query template, letting a player close the implicit `quote(id: <PATH>)`
selection and chain a new top-level field) that reaches a second,
genuinely vulnerable resolver doing boolean-blind SQLi. flagmap's
AST/taint engine already caught the SQLi half on its own merits (an
f-string SQL query, line 158) — but the GraphQL half, the actual
attacker-facing entry point, was invisible:

```python
_PATH_TEMPLATE_PREFIX = "{ quote(id: "
_PATH_TEMPLATE_SUFFIX = ") { id value author { name } } }"
...
query_text = _PATH_TEMPLATE_PREFIX + id_raw + _PATH_TEMPLATE_SUFFIX
```

Both existing Python GraphQL rules require either a triple-quoted string
followed by `%` formatting, or a quoted string formatted with `%(...)`
near the word "query"/"mutation" — neither condition holds here at all:
there's no `%` anywhere on this line, just plain `+` concatenation. And
unlike every other construction-site rule in this file, the GraphQL-
shaped literal text that would normally anchor a "does this look like a
query document" check isn't even on this line — it lives in
`_PATH_TEMPLATE_PREFIX`/`_PATH_TEMPLATE_SUFFIX`, two plain string
constants assigned several lines earlier, invisible to a same-line regex
and not worth chasing with cross-line literal-value tracking for one
example. Instead, anchored on the one signal that IS on this line: the
assigned-to variable's own name contains "query" (also matches "graphql"/
"gql", case-insensitive) AND it's built by concatenating at least two
bareword/attribute-access operands with `+`. Same variable-naming-
convention trade several other rules in this file already accept (the
Python SQL Injection rule's own implicit `$sql`/`$query`-style
conventions, idor.py's bare-parameter-name fallback) — not provable taint,
just "this is what a GraphQL query construction site looks like when you
can't see its literal content." Verified against the full 4-snapshot
corpus: fires only on the one real line, leaves the five pre-existing
`%`-formatting hits in underground-bank's `main.py` untouched, and no new
false positives anywhere else.

**Hardcoded Secret in Source — any language (v1.26.0)**: continuing the
same CyberSci audit, into nationals-2025-26's "assault_and_battery" web
challenge's `crypto/jwt.py`:

```python
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
```

A JWT HS256 signing key, assigned as a plain string literal right in
application source rather than read from the environment or a secrets
manager. For a source-review CTF (the whole genre this tool targets),
that's not a hardening nitpick — it's a flag-shaped bug on its own: anyone
who can read this file can forge or decrypt anything signed/encrypted with
the literal sitting right there. flagmap already had several "Hardcoded
Secret in ..." checks, but all of them look at *configuration*:
Dockerfiles, compose files, `.env` files — nothing was looking at the
application's own `.py`/`.js`/etc. source for the same mistake baked in
one layer deeper. Added a new `RAW_PATTERNS` entry tagged `"generic"`
(so it runs against every language's regex layer, not just one) matching
a small curated vocabulary of signing/encryption-key names — `SECRET_KEY`,
`JWT_SECRET`, `SESSION_SECRET`, `API_KEY`, `PRIVATE_KEY`,
`ENCRYPTION_KEY`, `AES_KEY`, `SIGNING_KEY` — assigned a quoted string
literal of at least 8 characters, in either a bare `NAME = "..."` shape or
a dict-key shape (`app.config["NAME"] = "..."`, Flask's own convention).
Deliberately a fixed vocabulary list rather than any-variable-assigned-a-
long-string-literal: the latter would fire on every API response fixture,
every test password, every base64 blob in the corpus. The trade is the
usual one for a `"generic"`-tagged regex rule in this file — real recall
on the small set of names CTF challenges and real apps actually use for
this, at the cost of missing an oddly-named variable (`FLASK_SIGNING_BLOB
= "..."` wouldn't match). Because every `RAW_PATTERNS` regex in this file
is compiled with `re.IGNORECASE` (see `patterns.py`'s `COMPILED_PATTERNS`
construction), the vocabulary match is case-insensitive for free — which
turned out to matter for one of the four real corpus hits below
(`app.secret_key`, lowercase, Flask's own idiomatic spelling).

Verified against the full 4-snapshot corpus: exactly four real hits, all
genuine secrets baked into source, zero false positives anywhere else —
`assault_and_battery/crypto/jwt.py:9` (the motivating case above),
nationals-2024-25's `history-stealer/webapp/app.py:10`
(`app.secret_key = "supersecretkey"`), and both
`UnauthorizedAndroidApp1/main.py:8` and `UnauthorizedAndroidApp2/main.py:8`
(`SECRET_KEY = "2UmgQru0xd0Xe1Xp2gGBCZev3"` / a one-character-different
sibling value — two separate challenge variants sharing the same bug).

This fix also surfaced a real, structural limitation of the regression
harness rather than a bug in the rule itself. `is_test_file()` (in
`scanner.py`) suppresses this rule's payload — correctly, via
`NOISY_IN_TEST_FILES` — on any path with a `tests`/`specs`-style path
segment, because a hardcoded `SECRET_KEY` in an actual test
fixture/example-config file is expected, not a finding. But every fixture
in this entire regression suite necessarily lives under
`tests/fixtures/...`, which itself contains a `tests` segment — so there
is no location inside this harness where the rule's raw "fires" case can
ever be asserted with a `# ruleid:` marker; only its suppression, via a
`# safe:` marker, is assertable here. This is the exact same limitation
the pre-existing "Weak Auth Logic" hardcoded-credential rule already has
(confirmed: no fixture anywhere in the suite asserts that rule's positive
case either) — not a new gap, just the second time this project has run
into it. The fixtures added for this rule (`tests/fixtures/python/vuln_sinks.py`
and `clean_sinks.py`) exercise the suppression path only, with the real
positive case verified directly against the live corpus instead, as
described above.

**Zip Slip via manual extraction, not just a bare `.extract()`/
`.extractall()` call — `zipslip_guard.py` (v1.27.0)**: found in the real
CyberSci nationals-2024-25 "history-stealer" web
challenge's `webapp/app.py` `/file_upload` route. The challenge accepts an
uploaded `.zip` and manually walks its entries to extract them — its own
comment literally says `# Extracting ZIP (vulnerable to Zip Slip)...`:

```python
if raw_name.startswith("/") or ".." in raw_name:
    dest_path = os.path.normpath(os.path.join("/", raw_name))
else:
    dest_path = os.path.join(unzip_path, raw_name)
...
with zip_ref.open(member) as src, open(dest_path, "wb") as dst:
    shutil.copyfileobj(src, dst)
```

What makes this interesting (and what makes it a real detection-design
problem, not just "add a regex for `zipfile`"): the code doesn't just
forget to check for traversal — it checks, and gets the fix backwards.
On detecting `..` or a leading `/`, instead of REJECTING the entry, it
normalizes the name against `/` and writes to the resulting absolute
path anyway. A zip entry named `../../etc/cron.d/evil` sails straight
through: the `".." in raw_name` branch fires, `os.path.normpath(os.path
.join("/", "../../etc/cron.d/evil"))` resolves to `/etc/cron.d/evil`, and
the file gets written there. This matters for detection specifically
because it rules out the laziest possible check: "does this file
contain a `..`-substring test near a zip extraction." It does — and the
bug is still live. Any suppression logic for this check has to look for
evidence the path was actually *verified* to stay inside the extraction
root, not just evidence that someone *thought about* traversal.

flagmap already had a rule for this vuln class — `patterns.py`'s
`"Path Traversal / Zip Slip"` entry, which matches a bare `\.(?:extractall|
extract)\s*\(` call. But this file calls neither: it doesn't trust the
standard library's own extraction method at all, it manually walks
`zip_ref.infolist()` and writes each member's bytes itself via
`zip_ref.open(member)` plus `open(dest_path, "wb")` — a shape the
existing regex has no way to see, since there's no `.extract(`/
`.extractall(` call anywhere in the file for it to match. So the
existing rule fires zero times on the real bug, confirmed directly.
`zipslip_guard.py` is a new best-effort, whole-file, two-signal module,
reporting under that SAME existing vuln name (`Path Traversal / Zip
Slip`) since both rules describe the identical underlying bug — this is
a second detection path for it, not a new vuln category — built in
the same family as `jenkins_pipeline_guard.py`: regex-only (there's no
dedicated AST sink category that would fit — the taint here flows from a
zip entry's own metadata, not from `request.args`/`request.form`-style
superglobal access, so `ast_engine.py`'s `SOURCE_TEXT_RE` convention
doesn't apply), and deliberately collects its signals from the whole
file's text rather than one line, because the real bug spans several
non-adjacent statements (the member-filename assignment, the traversal
"check", and the eventual `open(dest_path, "wb")`).

The two required signals: (1) a variable assigned from a zip member's own
`.filename` attribute (`raw_name = member.filename`, from iterating
`.infolist()`/`.filelist`) OR the loop variable itself when iterating
`.namelist()` (which yields plain filename strings directly, no `.filename`
attribute needed); and (2) that same variable later appearing inside an
`os.path.join(...)` call anywhere in the file. Both are required, plus a
whole-file write-sink check (`open(..., "wb")`/`shutil.copyfileobj(`/
`.write(`) to confirm the computed path actually gets used, before this
ever fires. The suppression side is the one that needed the most care,
for exactly the reason above: rather than looking for any traversal-
sounding substring, it only recognizes genuine containment-verification
idioms — `Path(...).resolve()` chained with `.relative_to(`/
`.is_relative_to(`, `os.path.realpath(` chained with `.startswith(`, or
`os.path.commonpath(` — anywhere in the file. None of those appear in the
real vulnerable file (confirmed: it has no `.resolve()`, no
`commonpath`, nothing beyond the broken `..`-substring test), so the
check correctly fires there, at the exact `os.path.normpath(os.path.join(
"/", raw_name))` line.

Deliberately scoped to Python only — the only real evidence for this
vuln class anywhere in the 4-snapshot corpus is this one file, found via
`grep -rl "zipfile\|ZipFile"` across the whole corpus. That same grep
turns up exactly one other hit: this same challenge's own
`solve_files/create_zip.py`, which only ever *creates* a zip
(`zipfile.ZipFile(..., "w")`, `.write(local_path, arcname)` to build the
attack payload for the solve script) and never extracts one — it never
assigns a variable from a `.filename` attribute or a `.namelist()` loop,
so it touches none of this module's signals and produces zero findings,
confirmed directly. Two dedicated fixtures were added rather than
extending `vuln_sinks.py`/`clean_sinks.py` as usual, because this check's
signals are collected across an entire file's text — mixing it into a
file that's already full of unrelated `open(`/`os.path.join(` calls and
sanitizer-sounding comments would make the fixture's pass/fail depend on
content far away from the actual test case. `tests/fixtures/python/
zipslip_vuln.py` mirrors the real bug's shape closely (including the same
backwards `..`-check pattern); `zipslip_clean.py` is the same shape with
a genuine `.resolve()`/`.relative_to()` containment check added, proving
the suppression path actually works and isn't just "never fires."

Known blind spots, stated as plainly as every other guard module's: no
interprocedural/control-flow proof that the computed path is truly
reached (a file that happens to have an unrelated `open(..., "wb")` call
elsewhere, plus the two taint signals, could in principle false-positive
— not observed in this corpus, but acknowledged); no coverage for any
zip-handling library beyond the stdlib `zipfile` module's own
`.infolist()`/`.namelist()`/`.filelist`; and a correctly-guarded
extraction using a containment idiom outside the three recognized ones
(e.g., a hand-rolled check this module doesn't know to look for) would be
wrongly flagged. Accepted on the same terms as every other best-effort
guard in this file — real signal on zero prior coverage, confirmed true
on the one real motivating bug, confirmed to produce no stray hits
anywhere else in the corpus.

**Starting with this entry, evidence also comes from other CTFs in
CyberSci's own style, not only CyberSci's own archive.** The CyberSci
corpus audit had worked through every web-relevant folder worth a
careful look; to keep finding real gaps rather than guessing at
speculative ones, the next step was pulling in full public source +
writeup releases from OTHER web-exploitation CTFs built the same way
CyberSci's nationals/regionals are — custom Flask/FastAPI/PHP/Go/Ruby
apps with one or two intended bugs each, shipped with a Docker Compose
stack and (crucially, for verifying flagmap's output against ground
truth) a published solve script and writeup. `DownUnderCTF/
Challenges_2025_Public` and `Challenges_2024_Public` (GitHub) were the
first such source: 17 web challenges across two years, every one with
its own `WRITEUP.md` and `solve/solve.py`. The same audit method
applies as before — run flagmap, read the writeup, and only add a check
when flagmap visibly missed a *real*, confirmed line of the actual bug
the writeup describes. Most of the 17 challenges turned out to already
be fully covered (several, like Go integer-truncation and Python
format-string injection via `.format()`, by rules precise enough to
land on the exact right line on the first try) or to be out of scope by
the same standards the CyberSci audit used (pure client-side JS
sandbox-escape puzzles, HTTP request-smuggling/cookie-ordering attacks
that live in the HTTP stack rather than any one line of source, a
hand-rolled binary session-serialization integer-overflow bug unique to
one challenge's own custom wire format). This entry's "sweet_treat" gap
below is the one that was real.

**JSP cookie-sourced XSS — `jsp_cookie_xss_guard.py` (v1.28.0)**: found
in DownUnderCTF 2025's public "sweet_treat" web challenge.
`patterns.py` already has a dedicated JSP XSS rule (its own comment
explains the trade-off): it matches `<%= request.getParameter(...) %>`/
`<%= request.getAttribute(...) %>` — a request value read and printed
on the SAME line — and deliberately nothing broader, because "any
non-literal `<%= %>`" would fire on nearly every JSP page (JSP's `<%=
%>` tag has no "safe" form to contrast against, unlike most templating
engines). That's a reasonable line, but the real challenge's bug sits
just past it, in two separate files:

```java
String lang = "en";
Cookie[] cookies = request.getCookies();
if (cookies != null) {
    for (Cookie c : cookies) {
        if ("language".equals(c.getName())) {
            lang = c.getValue();
        }
    }
}
...
<html lang="<%= lang %>">
```

Never a `request.getParameter()`/`getAttribute()` call anywhere near the
`<%= %>` tag — the taint arrives several lines earlier, through a
`Cookie[]` loop and a `.getValue()` call, into a plain local variable.
`index.jsp` and `admin/admin-review.jsp` both have the identical shape
(same cookie name, `"language"`, same variable name, `lang`), and
`index.jsp` is the clincher for this being a real, not theoretical, gap:
it defines its own `escapeHtml(String s)` helper and correctly calls it
two lines later for a different value (`<%= escapeHtml(user) %>`) — the
developer plainly knew JSP needs manual escaping and simply missed this
one cookie-sourced spot, exactly the "escaped everywhere except here"
shape this project's rules are written to catch.

`jsp_cookie_xss_guard.py` is a three-signal, whole-file, regex-only
module (no AST sink category fits JSP's mixed scriptlet/template syntax
at all): (1) a `for (Cookie <var> : ...)` loop; (2) that same loop
variable's own `.getValue()` assigned to a plain variable anywhere in
the file; (3) that variable referenced inside a `<%= %>` tag with none
of a short list of recognized escaping calls (`escapeHtml(`,
`StringEscapeUtils.escapeHtml4(`, `fn:escapeXml(`, `Encode.forHtml(`,
`ESAPI.encoder().encodeForHTML(`) present in the same tag. Requiring
signal (2)'s receiver to be the EXACT variable bound by signal (1)'s
loop, rather than matching any `\w+.getValue()` assignment at all,
caught a real precision bug during development: an earlier draft used
the looser form, and `admin/admin.jsp` — in the very same challenge —
has `HttpSession s = entry.getValue();`, iterating a `Map<String,
HttpSession>`'s entries (a same-named method on a completely unrelated,
non-attacker-controlled type). The looser draft would have treated `s`
as cookie-tainted; nothing in this corpus happened to echo `s` through a
`<%= %>` tag, so it produced no VISIBLE false positive, but the latent
imprecision was real and worth fixing before it hit a file that did.

Verified two ways: against the CyberSci corpus, where the total finding
count is unchanged (confirming zero cross-contamination from a check
gated on `.jsp` files, which don't exist anywhere in that corpus), and
against the full DownUnderCTF 2024+2025 public archive, where it fires
exactly twice — `index.jsp:48` and `admin/admin-review.jsp:94`, the two
real bugs — with no other hits anywhere, including in the three other
`.jsp` files in the same challenge that read cookies the same way but
never echo them (`edit_profile.jsp`, confirmed correctly silent: it
reads the same `lang` cookie but never prints it anywhere).

Deliberately scoped to the cookie-sourced case only, not the broader
"any variable later used in a `<%= %>` tag that originated from a
database read" case also present in the same challenge (`aboutMe`,
sourced from a SQL query result in `admin-review.jsp`) — deciding which
DB reads count as "tainted" at all is a much harder line to draw safely
without a second real, corroborating occurrence the way the cookie case
has (two files, same exact shape). Known blind spots: no cross-file/
include tracking; a variable name reused for an unrelated purpose later
in the same file could in principle false-positive (not observed); and
an escaping helper under a name this module doesn't recognize would be
wrongly flagged. Accepted on the same terms as every other best-effort
guard in this project.

**Missing Authentication Check (`authn_guard.py`, v1.15.0) and guarded-
deserialization advice (`pickle_guard.py`, v1.15.0)** both came out of
testing flagmap against a real attached CTF challenge rather than a
public repo this time — a MetaCTF-style gRPC/protobuf service ("stubborne")
whose `Login` RPC issued a brand-new session for any client-supplied
username with no password field on the request at all, and whose `Submit`
RPC deserialized a pickle blob only after passing it through a hand-rolled
opcode allowlist that excludes every gadget-capable opcode. Neither gap
fit an existing rule: the first is a genuinely new absence-of-a-check
category (not IDOR — there's no specific resource/ownership concept
here), and the second isn't a new finding at all, just wrong advice on an
existing one (flagmap's default "craft a `__reduce__` gadget" suggestion
for Unsafe Deserialization is actively misleading once a real filter sits
in front of the call). `authn_guard.py` reuses `idor.py`'s AST
function-boundary approach and fires only when a function both reads an
identity claim from the request and grants a session/token/cookie, with
no credential-check hint anywhere in the function or its 5-line header
lookback (same `_HEADER_LOOKBACK_LINES` convention as `idor.py`).
`pickle_guard.py` does not add or suppress a finding — it mutates an
existing "Unsafe Deserialization" finding's `why`/`payload` in place when
a validator-shaped call sharing the same argument text runs immediately
before the deserializing call in the same function, pointing the advice
at what the validator still permits instead of a blanket RCE suggestion.
Both are covered in full in "Best-effort heuristics" below, including the
self-referential false-positive bugs each one caught in its own
docstring/fixtures during development — the same recurring trap this
project has hit with `loot.py`, `xxe_guard.py`, and `vendor_guard.py`
before it.

**Versioned-migration suppression for `loot.py`'s dump-file check
(`migration_guard.py`, v1.18.0)** came out of testing flagmap against
WebGoat (OWASP's own official Java training platform, the first real
corpus tested after expanding into Java) — WebGoat ships each lesson's
own schema setup as Flyway migrations
(`src/main/resources/lessons/sqlinjection/db/migration/V2019_09_26_5__challenge_assignment.sql`,
`src/main/resources/db/container/V1__init.sql`), and `loot.py`'s
"Database dump file present" check — a bare `.sql` extension match,
unconditionally — flagged all 15 of them as leaked data dumps, which
they aren't: version-controlled DDL/seed scripts the challenge author
committed on purpose. Like `vendor_guard.py`, this suppresses rather
than removes a check, gated on two independent, deliberately
conservative signals that must BOTH hold (filename follows a recognized
migration-tool naming convention, AND the path sits under a
`db`/`migration(s)`/`migrate`-named directory) — a real, abandoned dump
file is extremely unlikely to satisfy both by accident, which is what
keeps this from hiding a genuine leaked-dump finding. Confirmed as a
true negative (still fires correctly) against a loose, non-conforming
`.sql` file and against DVWA's own `database/*.sql` setup scripts, which
don't follow the versioned-migration naming convention and so are
correctly left alone — see "Best-effort heuristics" for the full
two-signal rationale.

**jQuery DOM-method false positives in idor.py's bare-parameter-name
fallback (`jquery_dom_guard.py`, v1.19.0)** — also found testing flagmap
against WebGoat, in two of its JS files rather than its Java lessons:
`static/js/goatApp/view/MenuView.js` (WebGoat's own hand-written
front-end) and the bundled `static/js/libs/jquery-ui-1.10.4.js`. Both
have a function taking a parameter literally named `id` — an HTML
element id, not a database row id — whose body calls jQuery's own
`.find()` DOM-selector method, which textually matches `idor.py`'s
`LOOKUP_SINK_RE` (there for `Model.find(id)`-style ORM calls). This only
reaches `idor.py`'s bare-parameter-name fallback path — the one designed
for the Flask/Express/Rails route-bound-id idiom when no
`req.params`/`request.args`-style extraction call exists anywhere in the
body — so `jquery_dom_guard.py` suppresses a fallback-only finding when
the whole file shows no sign of being server-route code at all (no
`req.`/`res.`/`request.`/`response.` reference, no
`require("express"/...)`, no `app.get(`/`router.get(`-style call
anywhere). That whole-file scan has its own false positive, caught
during this fix's own development: jQuery UI's real Autocomplete widget
names its `source` callback `function(request, response)` as a plain
variable-naming convention with nothing to do with HTTP, which made the
whole-file scan treat jquery-ui-1.10.4.js as server-side and never reach
the real false positive a few hundred lines later in the same file.
Fixed by reusing `vendor_guard.py`'s own, independently-tested
`is_vendor_file()` as a bypass: a file it already recognizes as vendored
skips the server-signal scan entirely, since bundled library code can
coincidentally use `request`/`response` as ordinary local names for
reasons that have nothing to do with being a route handler. Deliberately
scoped to only the bare-parameter-name fallback path — an explicit
`req.params.id`-style extraction anywhere in the function is left
completely untouched, since that's strong, specific evidence the
function really is handling an HTTP request, and narrowing
`LOOKUP_SINK_RE`'s vocabulary there would risk false negatives on real
Express/Rails IDOR bugs. Confirmed true-negative (same finding counts as
before) against DVWA, Juice Shop, and Mutillidae's own IDOR findings,
including that Juice Shop's `payment.ts`/`address.ts`/`wallet.ts`
upgrades from `owner_param_guard.py` above are untouched.

**Client-side JS false positives in the taint-blind SSRF regex
(`ssrf_fetch_guard.py`, v1.20.0), and a narrowed shared signal
(`js_clientside_guard.py`, v1.20.0)** — continuing the same WebGoat pass,
this time `lessons/webauthn/js/webauthn.js` and `lessons/
securitymisconfiguration/js/security-misconfiguration-task2.js`: both
call `fetch(url, ...)` with a plain variable, which trips `patterns.py`'s
taint-blind JS SSRF regex (the "possible"-confidence entry that exists
as a backstop for "an outbound request built from a variable that might
trace back to a request parameter" — not the separate, "likely"-
confidence entry that requires a literal `req.query`/`req.params`/
`req.body` in the same match, which was never at risk here). Both files
are pure browser scripts — there's no SSRF concept to find at all, since
SSRF specifically means tricking a *server* into making a request from
its own privileged position; a browser making its own fetch() call
crosses no trust boundary. `ssrf_fetch_guard.py` suppresses that one
regex entry's findings using the exact same "is this file unambiguously
client-side" predicate `jquery_dom_guard.py` introduced in v1.19.0 —
factored out into its own module, `js_clientside_guard.py`, specifically
so this second guard could reuse it rather than re-deriving a slightly
different copy. That extraction also narrowed the signal itself: the
v1.19.0 version included the long forms `request.`/`response.`, which
turned out to collide with a SECOND common JS convention beyond jQuery
UI's Autocomplete widget — the Fetch API's own standard promise-chain
idiom, `fetch(url).then(function(response) { return response.json(); })`,
names its resolved value `response` in essentially every piece of
client-side code that calls `fetch()` at all. Since this new guard needs
to recognize a file as client-side specifically *because* it calls
`fetch()`, keeping `response.` as a signal would have made the "no
server signal" check next to useless for exactly the files it most
needs to clear — found and fixed during this fix's own development,
caught before it ever shipped. The short forms `req.`/`res.` are kept:
real Express/Koa/Fastify handler code overwhelmingly uses them by
convention, and neither has collided with anything in any real corpus
tested so far. Confirmed true-negative against the project's own
`tests/fixtures/js/vuln_sinks.js` SSRF case (a real `app.get("/proxy",
...)` route reading `req.query.url`, wall-to-wall Express signals) and
against DVWA/Juice Shop/Mutillidae's own SSRF findings — none of which
are JS, so none were ever in scope for this guard to begin with.

**Log-message-string false positives in "Sensitive Data Exposure in
Logs" (`log_message_guard.py`, v1.21.0)** — one more from the same
WebGoat pass: `lessons/passwordstorage/js/password-storage.js` has
`.catch((error) => console.error("Unable to load password storage
training data", error))`, flagged purely because the literal string
"Unable to load password storage training data" contains the word
"password" — the actual logged argument is `error`, a generic JS
`Error` object with no password data at all. The JS version of this
rule had no syntactic marker to lean on the way its Python and PHP
siblings do (each additionally requires either keyword-argument syntax
or the language's own variable sigil immediately before the sensitive
word, so a plain string message never matches either of those two —
see "Best-effort heuristics" for the exact shapes, written carefully
enough not to trip their own rules); JS identifiers and string contents
look identical to a keyword-only regex, so this is the first language
where the false positive was even possible. Fixed, not by narrowing the
JS regex itself, but by a separate check: strip every quoted string
literal off the flagged line (keeping a backtick template literal's
`${...}` interpolated expressions in place, so a genuine leak written
as `` console.log(`password is ${password}`) `` still matches after
stripping) and re-run the exact same compiled regex against what's
left — if nothing matches, every keyword occurrence on that line was
message text, not a real reference, and the finding is dropped. This
rule had zero regression fixtures in any language before this fix;
`tests/fixtures/js/log_message_cases.js` now covers the false positive,
a bare-variable true positive, and the template-literal-interpolation
true positive in one file.

**Java/Maven test-file conventions missing from `is_test_file()`
(`scanner.py`, v1.22.0)** — the fourth and last finding from the same
WebGoat pass: `src/it/java/org/owasp/webgoat/RegistrationUITest.java`
hardcodes a real-looking test credential as part of a Selenium UI test
for the registration lesson, which trips the hardcoded-password rule —
exactly the expected, intentional kind of noise `is_test_file()` exists
to suppress for files recognized as test fixtures. It wasn't recognized
because `is_test_file()` only knew Python/JS-style conventions
(`test_foo.py`, `foo_test.py`, `foo.spec.js`) and generic path segments
(`test`, `tests`, `__tests__`, `spec`, `specs`) — it had never seen
Java/Maven's own conventions: Surefire's default unit-test include
patterns (`Test*.java`, `*Test.java`, `*Tests.java`, `*TestCase.java`)
and Failsafe's default integration-test include patterns (`*IT.java`,
`*ITCase.java`, `*IntegrationTest.java`), plus Failsafe's conventional
`src/it/java/...` integration-test source root (a sibling of
`src/test/java/...`, which the existing `test`-segment check already
caught). Both are real, stable, documented Maven plugin defaults, not a
guess. Added as two checks: a `src/.../it/...` path-segment match (an
`it` segment immediately preceded by a `src` segment — deliberately
narrow, so it doesn't also match an i18n resource folder like
`resources/it/` for Italian translations, which has no `src` segment
right before it), and a filename check against the PascalCase
prefix/suffixes above. The filename check is deliberately
case-sensitive and checked against the original, non-lowercased
basename — a case-insensitive bare substring check for "test"/"it"
would wrongly match ordinary class names that merely end in those
letters, like `Submit.java` or `Contest.java`; matching the capital
letter that starts `Test`/`IT`/etc. is what actually respects Java's
PascalCase word boundary. Confirmed this eliminates the real WebGoat
false positive and introduces no regressions across the full suite or
any of the four corpora tested so far (WebGoat, DVWA, Juice Shop,
Mutillidae) — including deliberately leaving DVWA's own unrelated
`vulnerabilities/sqli/test.php` alone: its bare "test" filename stem
doesn't match any Java convention (it isn't one), and it turned out to
be a genuine, intentional finding (a leftover DB-connectivity script
with a real hardcoded credential against a specific host), not a false
positive, so broadening `is_test_file()` to catch bare `test.<ext>`
filenames was deliberately *not* done — it would have hidden a real bug
instead of a test artifact.

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
`test_*.py`, `*.spec.js`, Java/Maven's `*Test.java`/`*IT.java`/
`src/it/java/...`, etc.) are suppressed for the handful of rules that
are expected to fire constantly on legitimate test data (e.g. a hardcoded
`password = "testpassword123"` in a unit test) — see `scanner.is_test_file()`
and `patterns.NOISY_IN_TEST_FILES`. The Java/Maven conventions (`Test*.java`,
`*Test.java`/`*Tests.java`/`*TestCase.java` for Surefire unit tests,
`*IT.java`/`*ITCase.java`/`*IntegrationTest.java` plus the `src/it/java/...`
source root for Failsafe integration tests) were added in v1.22.0 after a
real WebGoat `RegistrationUITest.java` false positive — see "Architecture"
for the full writeup, including why a bare `test.<ext>` filename stem is
deliberately still *not* covered (it caught a genuine DVWA bug, not a test
artifact, when checked).

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
fully solvable — see CAPABILITIES.md's "What it can't catch" section for why absence-of-a-check bugs
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
  trust the label — exactly the same advice CAPABILITIES.md's "What it can't catch" section gives
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

- **Missing Authentication Check** (`authn_guard.py`, added v1.15.0) —
  the newest of the absence-of-a-check heuristics, found against a real
  MetaCTF-style gRPC challenge whose `Login` RPC handler looked up a user
  by a client-supplied username and unconditionally issued a brand-new
  session token for it — no password field even existed on the request,
  let alone a check. Not IDOR (no specific resource/ownership concept
  here), not Weak Auth Logic (that's for a check that exists but is done
  *wrong*; this is a check that doesn't exist at all), not CSRF — flagmap
  had no rule shape for "this function grants access for a claimed
  identity with nothing verifying it" before this. Fires only when BOTH
  are true in the same function (Python/JS/PHP/Go/Java/Ruby, via
  `ast_engine.py`'s function-boundary detection, same as `idor.py`): it
  reads a username/email/login value straight from the request, AND it
  grants a new session/token/cookie somewhere in its body. Deliberately
  requires both — reading an identity claim alone is true of almost any
  correctly-checked login handler too, and granting a session alone is
  true of plenty of unrelated code (a CSRF-token refresh, a shopping-cart
  id) that has nothing to do with authentication. Deliberately broad and
  inclusive about what counts as "a check happened", unlike `idor.py`'s
  narrow ownership vocabulary: the bare word "password" counts on its
  own, same as a real (if weak) `bcrypt`/`jwt.decode`/`authenticate(`
  call — the point isn't proving the check is *correct*, only that
  *something* was attempted, so a bad comparison still suppresses this
  (that's `patterns.py`'s existing Weak Auth Logic rule's job to catch
  instead). Caught a real self-referential bug during development, same
  trap as `xxe_guard.py`'s own fixtures before it: the vulnerable test
  fixture's explanatory comment said the missing check's name out loud
  ("no password check anywhere..."), which made the word appear in the
  very function being asserted as unguarded, suppressing the finding the
  fixture existed to prove. Fixed the same way that earlier trap was —
  describing the absence without naming the literal term.

- **Deserialization-guard-aware advice** (`pickle_guard.py`, added
  v1.15.0) — not a new finding or a suppressor, a *rewrite* of the advice
  on an existing one. The same real challenge above restricted its pickle
  stream to a curated safe-opcode allowlist (via `pickletools.genops()`,
  excluding `REDUCE`/`GLOBAL`/`BUILD` — everything that could call into
  application code) immediately before deserializing — and flagmap's
  default Unsafe Deserialization advice ("craft a payload with a reduce-
  based gadget calling a shell command") is actively wrong there: that
  payload gets rejected by the allowlist before the deserializer ever
  runs it. If a validator-shaped call (name containing `validate`/
  `sanitize`/`restrict`/`allowlist`/...) sharing the exact same argument
  text runs immediately before the deserializing call in the same
  function, the finding's advice is swapped to point at checking what
  the allowlist still permits instead — in the motivating case, a
  perfectly ordinary `pickle.dumps()` of a plain dict of booleans was
  already enough to reach the intended result through the allowed
  opcodes alone, no RCE gadget needed at all. Deliberately does not try
  to judge whether the validator is actually sound — that would mean
  understanding arbitrary hand-rolled filtering logic well enough to find
  holes in it, which is closer to the actual security research this kind
  of challenge is testing than something a textual heuristic should
  responsibly claim to do. Python-only for now (pickle itself is a Python
  concept; the equivalent guarded-deserialization idioms in PHP/Node/Ruby
  are each their own ecosystem-specific shape, left for a future pass
  rather than guessed at without a real example to design against).

- **Bypassable-ownership upgrade** (`owner_param_guard.py`, added
  v1.16.0) — like `pickle_guard.py`, not a new finding, a confidence
  upgrade on an existing one. Found testing flagmap against OWASP Juice
  Shop (JS/TS): `routes/payment.ts`, `address.ts`, and `wallet.ts` all
  share the exact same shape —
  `CardModel.findOne({ where: { id: req.params.id, UserId: req.body.UserId } })`.
  `idor.py` correctly flags this (an id read from the request handed to a
  lookup call) at the usual "possible" confidence, with why-text saying
  there's no sign of an ownership check — not quite right here: there IS
  a per-user filter, `UserId: req.body.UserId`, `idor.py`'s
  `OWNERSHIP_HINT_RE` just doesn't recognize camelCase `UserId` (it only
  matches the literal `user_id` spelling). The tempting "fix" — widen
  `OWNERSHIP_HINT_RE` to recognize `UserId` too — would make things
  *worse*: idor.py would then treat this as a real check and go silent,
  missing the actual bug. The ownership value itself, `req.body.UserId`,
  is just as attacker-controlled as the `id` it's supposedly protecting:
  changing one request field reads or edits anyone's card, address, or
  wallet. So instead of loosening the suppression, `owner_param_guard.py`
  searches the IDOR finding's whole enclosing function (same AST
  scope-walk idiom as `idor.py`/`pickle_guard.py`) for a user/owner/
  account-id-shaped key whose own value comes from the same per-language
  request-read idioms `idor.py`'s `ID_PARAM_RE` already recognizes (not
  `req.user`/`current_user`/session reads — those are the legitimate,
  trusted form of the same check), and when found, raises the finding to
  "likely" with sharper, more specific advice. Confirmed true-negative
  against DVWA and Mutillidae (no upgrades fired in either). Known
  precision tradeoff, found in practice against Juice Shop's large
  `placeOrder()` handler: searching the *whole* function means the
  upgrade can be triggered by a bypassable filter on a different lookup
  than the one the original id actually reaches, not necessarily the
  exact call next to it — see the module's docstring.

- **Versioned-migration suppression for `loot.py`'s dump-file findings**
  (`migration_guard.py`, added v1.18.0) — like `vendor_guard.py`,
  suppresses rather than removes a check, this time `loot.py`'s
  "Database dump file present"/"SQLite database file present" presence
  checks. Found testing flagmap against WebGoat: 15 legitimate Flyway
  migration scripts
  (`src/main/resources/lessons/sqlinjection/db/migration/V2019_09_26_5__challenge_assignment.sql`,
  `src/main/resources/db/container/V1__init.sql`, ...) all fired as
  "leaked data dump" findings, purely from the bare `.sql` extension
  match. Unlike `vendor_guard.py`'s four signals (any ONE is enough),
  this requires BOTH of its two signals together before suppressing: (1)
  the filename follows a recognized migration-tool versioned-naming
  convention — Flyway's `V<version>__<description>.sql` (digits,
  optionally `.`/`_`-separated, then a literal `__`), or a bare
  numeric-prefix convention (`001_create_users.sql`); (2) the path
  contains a `db`/`migration(s)`/`migrate` directory segment. The plain
  `db` segment (not just `migration`/`migrate`) is deliberately included
  because Flyway only *defaults* to `db/migration` — a project can point
  it anywhere, and in WebGoat's own case the container-setup script sits
  under `db/container`, not anything with "migration" in the name at
  all. Requiring both signals together, rather than either alone, is
  what keeps a real dump dropped somewhere unrelated (`backup.sql` in an
  uploads folder, or even a `V1__init.sql`-named file sitting outside
  any `db`/migration-style directory) from being hidden by accident —
  confirmed still fires correctly in both of those cases, and verified
  true-negative (no change in findings) against DVWA's own
  `database/*.sql` setup scripts, which don't follow the
  versioned-migration naming convention at all. Naming-convention-only,
  never content-based — this module never opens the file, same
  limitation `vendor_guard.py`'s own filename signals accept: a real
  dump deliberately renamed to look like a migration and dropped into a
  `db/migration/`-style folder would slip past undetected. That's an
  intentional tradeoff in favor of never hiding a true positive, not an
  oversight.

- **jQuery DOM-method false positives in the IDOR fallback path**
  (`jquery_dom_guard.py`, added v1.19.0) — removes (not downgrades —
  there's no sharper advice to give on a finding that shouldn't exist)
  an existing "Missing Authorization / IDOR" finding when it came from
  `idor.py`'s bare-id-parameter-name fallback (designed for the Flask/
  Express/Rails route-bound-id idiom, see `idor.py`'s own docstring) in
  a plain client-side JS function. Found testing flagmap against
  WebGoat's `static/js/goatApp/view/MenuView.js` and bundled
  `static/js/libs/jquery-ui-1.10.4.js`: both have a function taking a
  parameter literally named `id` (an HTML element id) that calls
  jQuery's own `.find()` — which textually matches `LOOKUP_SINK_RE`'s
  `find(`-for-ORM-calls vocabulary purely by coincidence. Suppresses
  only when BOTH (1) no explicit `req.params.id`-style extraction call
  (idor.py's own `ID_PARAM_RE`) exists anywhere in the enclosing
  function — that's left completely untouched, since it's strong,
  specific evidence this really is server-route code, and narrowing the
  lookup-sink vocabulary there would risk false negatives on real
  Express/Rails IDOR bugs — AND (2) no sign of server-route code (no
  `req.`/`res.`/`request.`/`response.` reference, no
  `require("express"/...)`, no `app.get(`/`router.get(`-style call)
  anywhere in the whole file. Signal (2) is skipped entirely, straight
  to signal (1), for a file `vendor_guard.py`'s own `is_vendor_file()`
  already recognizes as vendored by filename/content convention — this
  is what actually let the fix reach jQuery UI's own false positive:
  its real Autocomplete widget names its `source` callback
  `function(request, response)` as an ordinary variable-naming
  convention with nothing to do with HTTP, which first made the
  whole-file scan wrongly treat the entire bundled library as
  server-side and never reach the real false positive at all — caught
  during this fix's own development, the same self-review discipline
  every precision guard in this project has needed at least once.
  Confirmed true-negative against DVWA, Mutillidae, and Juice Shop's own
  IDOR findings (including the `owner_param_guard.py` upgrades above,
  all unaffected).

- **Client-side-fetch false positives in the SSRF backstop**
  (`ssrf_fetch_guard.py`, added v1.20.0) — removes a "SSRF (Server-Side
  Request Forgery)" finding that came from `patterns.py`'s taint-blind
  JS regex (`fetch(var, ...)`/`axios.get(var)`/`http.get(var)`, the
  "possible"-confidence entry — identified by a stable substring of its
  own why-text, never the separate "likely"-confidence entry that
  requires a literal `req.query`/`req.params`/`req.body` in the same
  match) inside a file with no server-route signal anywhere. Found
  testing flagmap against WebGoat's `lessons/webauthn/js/webauthn.js`
  and `lessons/securitymisconfiguration/js/security-misconfiguration-
  task2.js`: both call `fetch(url, ...)` from plain browser code, with
  no server-side request-handling concept anywhere in either file — SSRF
  specifically means tricking a *server* into using its own privileged
  network position on an attacker's behalf, which a browser's own fetch
  call can't do regardless of where the URL came from. Reuses the exact
  same "is this file unambiguously client-side" predicate
  `jquery_dom_guard.py` introduced in v1.19.0, factored out into its own
  module (`js_clientside_guard.py`) specifically so this guard didn't
  need a second, slightly-diverging copy of it. That extraction also
  narrowed the predicate itself, added v1.20.0: the original included
  `request.`/`response.` as signals, which collided with the Fetch
  API's own standard promise-chain idiom
  (`fetch(url).then(function(response) { return response.json(); })` —
  `response.json()` is how essentially every piece of client-side code
  that calls `fetch()` consumes the result), making the "no server
  signal" check next to useless for exactly the files this guard most
  needs to clear. Caught and fixed during this fix's own development,
  before it shipped. Confirmed true-negative against the project's own
  `tests/fixtures/js/vuln_sinks.js` SSRF case (a real Express
  `app.get("/proxy", ...)` route reading `req.query.url`) and against
  DVWA/Juice Shop/Mutillidae's own SSRF findings, none of which are JS.

- **Log-message-string false positives in "Sensitive Data Exposure in
  Logs"** (`log_message_guard.py`, added v1.21.0) — removes a JS
  "Sensitive Data Exposure in Logs" finding whose keyword match came
  entirely from inside a quoted string literal rather than a real
  variable/property reference. Found testing flagmap against WebGoat's
  `lessons/passwordstorage/js/password-storage.js`: a
  `console.error("Unable to load password storage training data",
  error)` call flagged purely because that human-readable message
  string contains the word "password" — the actual argument logged is a
  generic `Error` object. Unlike the Python and PHP versions of this
  rule, which already require keyword-argument syntax or the language's
  own variable sigil immediately before the sensitive word (and so
  never had this false positive to begin with), the JS rule has no such
  marker available — a bare keyword inside a string and a bare keyword
  as a real reference look identical to it. Fixed with a separate
  check, not a narrower regex: strip every quoted string literal off
  the flagged line, keeping a backtick template literal's `${...}`
  interpolated expressions in place of the literal text around them,
  and re-run the SAME compiled rule against what's left. If nothing
  matches, every occurrence was message text and the finding is
  dropped; if the keyword survives — a real second argument sitting
  outside any string, or a variable interpolated into a template
  literal — the finding is left completely alone, since those are
  exactly the real leaks this rule exists to catch. This rule had zero
  regression fixtures in any language before this fix;
  `tests/fixtures/js/log_message_cases.js` now covers all three shapes
  (the message-only false positive, a bare-variable true positive, and
  a template-literal-interpolation true positive) in one file.

- **Java/Maven test-file conventions in `is_test_file()`** (`scanner.py`,
  added v1.22.0) — recognizes two more test-fixture naming conventions
  so the handful of noisy rules in `NOISY_IN_TEST_FILES` get suppressed
  on them the same way they already were for `test_*.py`/`*.spec.js`/a
  `tests/` directory segment: Maven Surefire's default unit-test include
  patterns (`Test*.java`, `*Test.java`, `*Tests.java`, `*TestCase.java`)
  and Failsafe's default integration-test include patterns (`*IT.java`,
  `*ITCase.java`, `*IntegrationTest.java`), plus Failsafe's conventional
  `src/it/java/...` integration-test source root. Found testing flagmap
  against WebGoat's `src/it/java/org/owasp/webgoat/
  RegistrationUITest.java`, a Selenium UI test hardcoding a registration
  test credential. The filename check is deliberately case-sensitive
  against the original basename — a case-insensitive bare substring
  check for "test"/"it" would also match ordinary class names that
  merely end in those letters, like `Submit.java` or `Contest.java`;
  only matching the capital letter that actually starts
  `Test`/`Tests`/`TestCase`/`IT`/`ITCase`/`IntegrationTest` respects
  Java's PascalCase word boundary. The `src/.../it/...` path check
  requires an `it` segment immediately preceded by a `src` segment, so
  it doesn't also match an i18n resource folder like `resources/it/`
  for Italian translations. Deliberately did NOT extend this to a bare
  `test.<ext>` filename stem: DVWA's `vulnerabilities/sqli/test.php`
  has exactly that name and also trips a noisy rule, but turned out on
  inspection to be a genuine, intentional finding (a leftover
  DB-connectivity script with a real hardcoded credential against a
  specific host), not a test artifact — suppressing it would have
  hidden a real bug. See "Testing" for why this fix has no fixture of
  its own.

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

`migration_guard.py`'s suppression gets two more `tests/fixtures/loot/`
cases rather than one, specifically because the harness's set-equality
check can't distinguish "this file's finding was correctly suppressed"
from "a different file in the same tree produced the same finding
anyway" — a single case mixing a suppressed migration script with a
genuine loose dump would pass even if the suppression silently broke,
since the dump's own finding keeps the vuln_name in the expected set
regardless. `case2`'s `app/` holds only two Flyway-convention scripts
(`db/migration/V1__init.sql` and the broader `db/container/V2__seed.sql`
signal) and its `EXPECTED.txt` is empty — this is what actually proves
suppression fires, since any regression shows up as an unexpected
"Database dump file present" appearing where the set must stay empty.
`case3`'s `app/` holds only a loose `dump.sql` and a `V1__init.sql`
sitting in a plain `uploads/` folder (right filename, wrong directory)
— `EXPECTED.txt` lists "Database dump file present" for both, proving
the two-signals-required-together logic isn't quietly dropped to one.

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

The v1.22.0 Java/Maven extension to `is_test_file()` also has **no**
standard fixture category — but for a structural reason none of the
suppression-guard cases above hit: every fixture file already lives
under `tests/fixtures/<language>/...`, and `tests` is itself one of the
generic path segments `is_test_file()` already matches, so it returns
`True` for every fixture regardless of filename. There's no way to
build a "should NOT be suppressed" control case for this inside the
standard fixture tree — any Java fixture, named however, is already
caught by the pre-existing `tests/` segment check before the new
filename logic even runs. Same precedent as `owner_param_guard.py` and
`pickle_guard.py` above: verified directly instead, with a dozen
adversarial cases run straight through `is_test_file()` covering the
real WebGoat path (`src/it/java/org/owasp/webgoat/
RegistrationUITest.java`, now `True`), the false-positive-avoidance
edge cases (`Submit.java`, `Contest.java`, both still `False`), the
i18n-folder distinction (`resources/it/messages.properties`, still
`False` — no `src` segment immediately before `it`), and confirmation
that every pre-existing Python/JS/Ruby convention keeps behaving
exactly as before. Then confirmed end-to-end against the real file via
`scan_path()`: the WebGoat `RegistrationUITest.java` finding disappears,
the full regression suite still passes unchanged (no fixture could be
added, so no fixture count changed either), and a cross-corpus check
across WebGoat, DVWA, Juice Shop, and Mutillidae shows only the two
intended WebGoat findings vanish — nothing else moves.

`vendor_guard.py`'s filename-shaped signals (the jQuery-plugin naming
convention, `.min.js`/`.min.css`, the curated known-vendor-basename list,
and the license-banner scan) get a regular `ruleid`/`safe` fixture —
`tests/fixtures/js/jquery.fake-plugin.min.js` (suppressed, same file
content as the control case) alongside the existing
`tests/fixtures/js/vuln_sinks.js` (not suppressed — see its
`renderUserBio` case) — because both live entirely inside one file's own
name and text, exactly what that convention already checks. Its one
*directory*-shaped signal — a webfont file sitting next to the script,
the IcoMoon/Font-Awesome packaging pattern `lte-ie7.js` actually used —
is deliberately **not** given its own fixture category: it was verified
directly against the real RailsGoat file that motivated it (confirmed
suppressed) rather than built out into a sixth `EXPECTED.txt` convention,
since that would mean inventing a new multi-file directory-comparison
harness for one edge signal materially narrower in scope than loot.py's
or diffscan.py's (which each cover a whole category of check, not one
signal inside a five-signal heuristic) — a disproportionate amount of new
harness machinery for what it would add. Worth revisiting if this signal
turns out to matter more in practice than the other four.

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

`authn_guard.py` gets a regular `ruleid`/`safe` fixture under
`tests/fixtures/python/authn_cases.py` and `tests/fixtures/js/
authn_cases.js` — same convention as every other AST-based check, since
this one has a single line (the session-grant) to hang the marker on just
like `idor.py`'s fixtures do. Each covers four shapes: the vulnerable case
itself (identity read + session grant + no credential check), a safe
twin with an otherwise-identical shape but a real `check_password_hash`/
`bcrypt.compare` call (must NOT fire despite looking almost the same), a
session-grant with no identity read at all (a refresh endpoint — must NOT
fire), and an identity read with no session grant at all (a plain profile
lookup — must NOT fire). Found and fixed a real self-referential bug in
the Python fixture itself before it was considered done — its vulnerable
case's own explanatory comment named the missing check by its usual
literal term, which made that term appear inside the very function being
asserted as unguarded and suppressed the finding the fixture existed to
assert. The fix followed this project's established convention: describe
what's absent without spelling out the term that would trigger the
pattern meant to detect its absence.

`sql_construct.py` gets regular `ruleid`/`safe` entries inside the
existing `tests/fixtures/php/vuln_sinks.php` and `clean_sinks.php` files
rather than a category of its own — it produces ordinary "SQL Injection"
findings, just reached a different way, so it fits the same convention
every other AST-based PHP check already uses. Three cases: a multi-line
"." concatenation (the actual Mutillidae shape), a single-line inline
interpolation, and a safe case proving the "at least one non-literal
operand" gate — a "." chain joining only string literals, with no
variable anywhere in it — correctly produces nothing.

`pickle_guard.py` deliberately has **no** fixture category of its own, for
the same reason `report_md.py` has none: `run_regression.py`'s harness
only asserts which `vuln_name`s fire on which lines, never the text
content of a finding's `why`/`payload` — and `pickle_guard.py` doesn't
change whether anything fires, only rewrites the advice text on a finding
that already does. There's no `ruleid`/`safe` marker convention that could
express "this finding's advice text should mention the validator" without
inventing a new assertion shape solely for one module, so this was instead
verified directly: isolated test cases confirming the advice swap happens
only when a validator-shaped call precedes the deserializing call sharing
its argument, and gets left alone when either condition doesn't hold, plus
direct confirmation against the real stubborne challenge's `server.py`
that the `_sanitize_state`-guarded finding at line 105 gets the rewritten
advice while the unguarded findings in `Login()`/`Profile()` keep their
original RCE-gadget advice unchanged.

`owner_param_guard.py` gets a regular `ruleid` case added to
`tests/fixtures/js/idor_cases.js` (the shape still has to fire as an
ordinary "Missing Authorization / IDOR" finding either way, which the
harness CAN assert) — but, same reasoning as `pickle_guard.py` immediately
above, the confidence upgrade itself has no fixture category of its own,
since the harness only checks vuln_name presence per line, never
confidence or why/payload text. Verified directly instead: the new fixture
case confirmed at "likely" via a direct `scan_path()` check, plus
confirmation against the real Juice Shop files that motivated it
(`payment.ts`/`address.ts`/`wallet.ts`, all upgraded) and true-negative
confirmation against DVWA and Mutillidae (zero upgrades in either, despite
both having their own IDOR-adjacent findings).

`jquery_dom_guard.py` gets two new standalone fixture files rather than a
case added to `idor_cases.js`, because the suppression only applies to a
file with NO server-route signal anywhere, and `idor_cases.js` is wall-
to-wall `app.get(`/`req.`/`res.` by design — adding a case there would
never actually exercise the suppression at all.
`tests/fixtures/js/clientside_dom_cases.js` holds the main motivating
shape (bare `id` parameter, jQuery `.find()`, zero server signals) with
a `safe: Missing Authorization / IDOR` marker on the finding's own
anchor line (the function's signature line itself, since this only ever
fires via idor.py's bare-parameter fallback, which has no extraction
call to point at instead). Writing that fixture's own module comment
caught a live instance of the exact self-referential trap this project
keeps hitting — the comment originally spelled out the literal `req.`/
`res.`/`request.`/`response.` trigger text while describing their
absence, which made the file match its own suppression's gating check
and silently fail to prove anything; rephrased without spelling out the
trigger shapes, same fix pattern as `loot.py`'s and `vendor_guard.py`'s
own docstrings before it.
`tests/fixtures/js/jquery-widget-fake.js` is named to match
`vendor_guard.py`'s own jQuery-plugin filename convention specifically
to exercise the `is_vendor_file()` bypass path: it includes the
`function(request, response)` red herring that originally blocked this
fix in the real jQuery UI file, right alongside the real false-positive
shape, so a regression that drops the vendor bypass shows up as a
missing `safe` assertion rather than silently stopping being tested at
all.

`ssrf_fetch_guard.py` gets its own standalone fixture for the same
reason `jquery_dom_guard.py`'s did: `tests/fixtures/js/vuln_sinks.js`'s
real SSRF case is wall-to-wall Express signals by design, so adding a
case there would never exercise the suppression.
`tests/fixtures/js/clientside_fetch_cases.js` holds a plain
`fetch(url, ...)` call inside a function with zero server-route signals
anywhere, with a `safe: SSRF (Server-Side Request Forgery)` marker on
the `fetch()` call's own line (the regex-based rule anchors there
directly, unlike the AST-scope-anchored IDOR fallback case above). No
separate vendor-bypass fixture was added for this guard specifically —
`is_clientside_js()`'s vendor path is shared code already exercised by
`jquery-widget-fake.js` above, not a second implementation that could
independently regress.

`log_message_guard.py` is the first fixture this rule has ever had, in
any language — `tests/fixtures/js/log_message_cases.js` covers all
three shapes in one file: the message-only false positive (`safe`), a
bare second-argument true positive (`ruleid`, proving a real reference
sitting outside any string is never touched), and a template-literal-
interpolation true positive (`ruleid`, proving the strip keeps a
genuine `${...}`-interpolated leak intact rather than discarding it
along with the surrounding template literal).

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

