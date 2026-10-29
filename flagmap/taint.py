"""
taint.py — lightweight, single-file "taint-lite" tracking.

Pure regex pattern matching misses the extremely common CTF pattern of:
    $user = $_POST['username'];
    ...
    $sql = "... " . $user . " ...";

This module does a cheap two-pass scan per file:
  1. Find variable names assigned directly from a user-input source.
  2. Flag any line later in the file where that variable name appears
     inside a known dangerous sink call (query, system, include, open, eval, ...).

This is NOT real taint analysis (no control-flow, no sanitization detection,
no scope awareness) — it's a heuristic to catch the single-hop "store then use"
pattern that's everywhere in intentionally-vulnerable CTF challenges. Findings
from this layer are always tagged confidence="possible".
"""

import re
from dataclasses import dataclass
from typing import List

# Regexes that find "variable = <user input source>" per language.
SOURCE_PATTERNS = {
    # The RHS is allowed to be anything on the line (`.*`) rather than
    # requiring the superglobal/request access to come immediately after
    # `=` — real code constantly wraps it in isset()/ternaries/casts, e.g.
    # `$q = isset($_GET['q']) ? (string)$_GET['q'] : '';` or
    # `name = request.args.get('name', '') or 'default'`. Matching is still
    # done one line at a time, so this can't runaway across the file.
    "php": re.compile(r"""\$(\w+)\s*=.*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*['"]?\w+['"]?\s*\]"""),
    "python": re.compile(r"""(\w+)\s*=.*request\.(?:args|form|values|json|files)(?:\.get\(|\[)"""),
    "js": re.compile(r"""(?:const|let|var)\s+(\w+)\s*=.*req\.(?:query|params|body)\.?\w*"""),
}

# FastAPI / typed-framework style: route params are bound directly as
# function arguments (e.g. `async def fetch_url(url: str):` under an
# @app.get(...) decorator) rather than read from a request object. These
# are just as attacker-controlled as Flask's request.args, so they need
# their own source detection. Matches a plain typed parameter, skipping
# anything that looks like a dependency-injected object (Depends(...)).
ROUTE_DECORATOR_RE = re.compile(r"""@\w+\.(?:get|post|put|delete|patch|route)\s*\(""")
FASTAPI_PARAM_RE = re.compile(
    r"""(\w+)\s*:\s*(?:str|int|float|UUID|Optional\[[^\]]+\])\s*(?:=\s*[^,)]+)?(?:,|\))"""
)

# Regexes that find "variable = <anything>" per language, used for taint
# PROPAGATION: if the right-hand side mentions an already-tainted variable,
# the left-hand side becomes tainted too (e.g. $sql = "..." . $user . "...").
ASSIGNMENT_PATTERNS = {
    "php": re.compile(r"""\$(\w+)\s*=\s*(.+)"""),
    "python": re.compile(r"""^\s*(\w+)\s*=\s*(.+)"""),
    "js": re.compile(r"""(?:const|let|var)\s+(\w+)\s*=\s*(.+)|(\w+)\s*=\s*(.+)"""),
}

# Dangerous sink call names per language — if a tainted variable shows up
# as a bare word inside a call to one of these, flag it.
SINKS = {
    "php": {
        "query": "SQL Injection",
        "exec": "Command Injection",
        "system": "Command Injection",
        "shell_exec": "Command Injection",
        "passthru": "Command Injection",
        "popen": "Command Injection",
        "include": "Path Traversal / LFI",
        "include_once": "Path Traversal / LFI",
        "require": "Path Traversal / LFI",
        "require_once": "Path Traversal / LFI",
        "fopen": "Path Traversal / LFI",
        "unserialize": "Unsafe Deserialization",
        "eval": "Command Injection / RCE",
    },
    "python": {
        "execute": "SQL Injection",
        "executemany": "SQL Injection",
        "system": "Command Injection",
        "popen": "Command Injection",
        "open": "Path Traversal / LFI",
        "send_file": "Path Traversal / LFI",
        "loads": "Unsafe Deserialization",
        "render_template_string": "Server-Side Template Injection (SSTI)",
        "eval": "Command Injection / RCE",
        "redirect": "Open Redirect",
    },
    "js": {
        "query": "SQL Injection",
        "execute": "SQL Injection",
        "exec": "Command Injection",
        "execSync": "Command Injection",
        "readFile": "Path Traversal / LFI",
        "readFileSync": "Path Traversal / LFI",
        "sendFile": "Path Traversal / LFI",
        "renderString": "Server-Side Template Injection (SSTI)",
        "eval": "Command Injection / RCE",
        "redirect": "Open Redirect",
    },
}

# Sinks reached via a METHOD CALL ON the tainted variable itself (the tainted
# var is the receiver, e.g. `f.save(path)` where `f` came from
# request.files), as opposed to SINKS above where the tainted var shows up as
# an ARGUMENT to some other call. Structurally different shape, so it's its
# own small pass rather than being forced through the argument-based sink
# matcher — a receiver never shows up as an argument of its own method call.
METHOD_SINKS = {
    "python": {
        "save": "Unrestricted File Upload",
    },
}

# Format String Injection: a distinct shape from the argument/receiver sinks
# above — here the thing that's "tainted" is the TEMPLATE STRING ITSELF, not
# a value passed into a safe fixed template. The telltale sign (narrow but
# low-noise on purpose) is a variable iteratively built up via `var += ...`
# — i.e. NOT a one-shot literal template — that is later the receiver of its
# own `.format(...)` call. A plain `"Hello {}".format(name)` never matches
# this (the template is a single literal), but
# `template += get_logs()` ... `template.format(config=config)` does: if any
# upstream chunk concatenated into `template` is attacker-influenced (e.g. it
# came from a log file the attacker could write arbitrary `{...}` syntax
# into), `.format()` will resolve that syntax against whatever kwargs were
# passed, which can walk object attributes to leak secrets.
FORMAT_BUILD_RE = {
    "python": re.compile(r"""^\s*(\w+)\s*\+="""),
}
FORMAT_SINK_RE = {
    "python": re.compile(r"""\b(\w+)\.format\s*\("""),
}

SEVERITY_BY_VULN = {
    "SQL Injection": "high",
    "Command Injection": "high",
    "Command Injection / RCE": "high",
    "Path Traversal / LFI": "high",
    "Unsafe Deserialization": "high",
    "Server-Side Template Injection (SSTI)": "high",
    "Cross-Site Scripting (XSS)": "high",
    "Open Redirect": "medium",
    "Unrestricted File Upload": "medium",
    "Format String Injection": "high",
    "LDAP Injection": "high",
    "SSRF (Server-Side Request Forgery)": "high",
    "ReportLab Paragraph Injection (CVE-2023-33733)": "high",
}

WHY_BY_VULN = {
    "SQL Injection": "Variable assigned from user input earlier in the file is used inside a query call here.",
    "Command Injection": "Variable assigned from user input earlier in the file is passed to a shell execution call here.",
    "Command Injection / RCE": "Variable assigned from user input earlier in the file reaches an eval() call here.",
    "Path Traversal / LFI": "Variable assigned from user input earlier in the file is used to build a file path here.",
    "Unsafe Deserialization": "Variable assigned from user input earlier in the file is deserialized here.",
    "Server-Side Template Injection (SSTI)": "Variable assigned from user input earlier in the file is rendered as a template here.",
    "Cross-Site Scripting (XSS)": "Variable assigned from user input earlier in the file is echoed/printed without escaping here.",
    "Open Redirect": "Variable assigned from user input earlier in the file is used as a redirect target here.",
    "Unrestricted File Upload": "A file object taken from request.files earlier in the file is saved here — check "
                                 "whether its extension/content-type is validated anywhere before this call.",
    "Format String Injection": "This variable is built up piece by piece with `+=` rather than being a single "
                                "literal template, then passed as the control string to its own .format() call "
                                "here. If any concatenated piece can contain attacker-influenced text (e.g. it "
                                "came from a log file, a stored value, or a header), that text's own `{...}` "
                                "syntax gets interpreted by .format() against whatever kwargs/args are given, "
                                "which can walk object attributes to leak secrets.",
    "LDAP Injection": "Variable assigned from user input earlier in the file is concatenated into an LDAP search "
                       "filter here. An attacker-controlled filter can inject extra filter clauses (e.g. an "
                       "always-true `|` branch) to bypass an auth check or enumerate directory entries the query "
                       "wasn't meant to return.",
    "SSRF (Server-Side Request Forgery)": "Variable assigned from user input earlier in the file is used as the "
                                           "URL for an outbound request here — the server can be made to fetch "
                                           "internal/cloud-metadata URLs or scan the internal network on the "
                                           "attacker's behalf.",
    "ReportLab Paragraph Injection (CVE-2023-33733)": "Variable assigned from user input earlier in the file is "
        "passed straight into reportlab.platypus.Paragraph() here. Paragraph() parses its text argument as "
        "ReportLab's own mini-markup language (<b>, <font color=\"...\">, <a href=\"...\">, <img src=\"...\">, "
        "...) — it is never just inert text. On reportlab<=3.6.12 a crafted `color` attribute value escapes the "
        "library's rl_safe_eval() sandbox entirely for arbitrary Python/OS code execution (CVE-2023-33733). "
        "Even on a patched version, this is still markup injection into the generated PDF (formatting/layout "
        "control, an <img src=\"http://...\"> the server will fetch, server-side read of a local path that "
        "img tag can reference).",
}

PAYLOAD_BY_VULN = {
    "SQL Injection": "' OR 1=1 -- ",
    "Command Injection": "; cat flag.txt #",
    "Command Injection / RCE": "Depends on language — try to reach os/system access.",
    "Path Traversal / LFI": "../../../../etc/passwd",
    "Unsafe Deserialization": "Craft a malicious payload matching the deserialization format in use.",
    "Server-Side Template Injection (SSTI)": "{{7*7}} to confirm, then escalate to an RCE gadget for the engine in use.",
    "Cross-Site Scripting (XSS)": "<script>alert(document.domain)</script>",
    "Open Redirect": "https://evil.example.com",
    "Unrestricted File Upload": "Upload an .html/.svg/.js file and see if it's served back as that content-type "
                                "(not just stored) — enables stored XSS or a service-worker takeover.",
    "Format String Injection": "Get a `{self.__init__.__globals__[SOME_SECRET]}`-style payload into whatever "
                                "upstream text gets concatenated into the template (e.g. a logged header value), "
                                "then trigger the .format() call to resolve it and leak the attribute.",
    "LDAP Injection": "*)(uid=*))(|(uid=* — closes the intended filter clause early and ORs in an "
                      "always-true branch; adjust the attribute name to whatever the filter is built around "
                      "(uid, cn, mail, ...).",
    "SSRF (Server-Side Request Forgery)": "Try http://127.0.0.1:PORT/, http://169.254.169.254/latest/meta-data/ "
                                           "(cloud metadata), or an internal service hostname.",
    "ReportLab Paragraph Injection (CVE-2023-33733)": "First confirm the markup is live with something inert like "
        "<b>test</b> or <font color=\"red\">test</font> in the vulnerable field, then check the reportlab version "
        "(pip show reportlab / requirements.txt). If <=3.6.12, use the public rl_safe_eval sandbox-escape PoC for "
        "CVE-2023-33733 (github.com/c53elyas/CVE-2023-33733) in the same `color` attribute to get code execution "
        "and read /flag.txt directly.",
}


def _first_call_arg(line: str, call_start_idx: int) -> str:
    """Given the index of the '(' that opens a call, return the text of
    just its first top-level argument (stops at the first top-level comma
    or the matching close paren). Naive but good enough for single-line
    CTF-style calls; doesn't need to be perfect to cut false positives."""
    depth = 0
    buf = []
    i = call_start_idx
    n = len(line)
    while i < n:
        ch = line[i]
        if ch == "(":
            depth += 1
            if depth == 1:
                i += 1
                continue
        elif ch == ")":
            depth -= 1
            if depth == 0:
                break
        elif ch == "," and depth == 1:
            break
        if depth >= 1:
            buf.append(ch)
        i += 1
    return "".join(buf)


_PURE_LITERAL_RE = re.compile(r"""^(["'])(?:[^\\]|\\.)*?\1$""")

# A redirect target whose literal portion starts with a single `/` (not `//`,
# which is a protocol-relative, off-site URL) can only ever stay on the same
# origin, no matter what the interpolated/tainted part of the string is —
# e.g. redirect("/voter/{}".format(id)) or redirect(f"/user/{user_id}/edit").
# That's not an open redirect, so skip it rather than flag a same-origin path.
_SAME_ORIGIN_REDIRECT_RE = re.compile(r"""^\s*[\"'`]/(?!/)""")


def _is_same_origin_redirect_target(arg: str) -> bool:
    return bool(_SAME_ORIGIN_REDIRECT_RE.match(arg.strip()))


def _var_referenced(var: str, text: str) -> bool:
    """True if `var` appears as a genuine variable reference in `text`, as
    opposed to a coincidental match. The one real gotcha this guards
    against: a short variable name like `f` colliding with a Python string
    prefix letter (`f"..."`, `r"..."`, `b"..."`, `rb"..."`, etc.) — a plain
    word-boundary match on `f` would "find" it inside `f"{...}"` even though
    that `f` is a string-literal prefix, not a reference to a variable
    named `f`. A real variable reference is never directly touching a
    quote character with no operator between (`var"literal"` isn't valid
    syntax in any of the languages this module targets), so excluding that
    shape is safe for every variable name, not just the single-letter ones
    that happen to double as string prefixes."""
    return bool(re.search(r"\$?\b" + re.escape(var) + r"\b(?!['\"])", text))


def _is_plain_literal(arg: str, language: str) -> bool:
    """True if `arg` is just a single quoted string with no interpolation —
    e.g. "SELECT * FROM t WHERE x = %s". A plain literal can't execute a
    variable, so a variable *name* coincidentally appearing as a word inside
    it (e.g. a column called `name`) is not a real finding."""
    s = arg.strip()
    if not s:
        return False
    if language == "python" and re.match(r"""^[fF][rR]?["']""", s):
        return False  # f-string: IS interpolated, not a plain literal
    if language == "js" and s.startswith("`") and "${" in s:
        return False  # template literal with interpolation
    return bool(_PURE_LITERAL_RE.match(s))


@dataclass
class TaintFinding:
    file: str
    line_no: int
    line_text: str
    vuln_name: str
    severity: str
    why: str
    payload: str
    confidence: str
    tainted_var: str


def find_tainted_sinks(path: str, language: str, lines: List[str]) -> List[TaintFinding]:
    src_pattern = SOURCE_PATTERNS.get(language)
    sinks = SINKS.get(language)
    if not src_pattern or not sinks:
        return []

    tainted_vars = set()
    for line in lines:
        m = src_pattern.search(line)
        if m:
            tainted_vars.add(m.group(1))

    if not tainted_vars:
        return []

    # Propagate taint through simple re-assignment for a few passes, so
    # "$sql = '...' . $user . '...'" also marks $sql as tainted once $user is.
    assign_pattern = ASSIGNMENT_PATTERNS.get(language)
    if assign_pattern:
        for _ in range(4):  # fixpoint-ish; a handful of passes covers short chains
            added = False
            for line in lines:
                for m in assign_pattern.finditer(line):
                    groups = [g for g in m.groups() if g]
                    if len(groups) < 2:
                        continue
                    lhs, rhs = groups[0], groups[-1]
                    if lhs in tainted_vars:
                        continue
                    for var in tainted_vars:
                        if _var_referenced(var, rhs):
                            tainted_vars.add(lhs)
                            added = True
                            break
            if not added:
                break

    findings = []
    sink_call_re = re.compile(
        r"\b(" + "|".join(re.escape(s) for s in sinks) + r")\s*\("
    )

    # PHP's echo/print have no parentheses, so they can't go through the
    # generic paren-based sink matcher above. Handle them as a special case.
    echo_re = re.compile(r"""\b(?:echo|print)\s+\$?(\w+)\b""") if language == "php" else None

    # Method-call-on-tainted-receiver sinks (e.g. `f.save(path)` where `f`
    # itself is tainted, not an argument). See METHOD_SINKS above for why
    # this needs its own matcher shape.
    method_sinks = METHOD_SINKS.get(language)
    method_sink_re = (
        re.compile(r"\b(\w+)\.(" + "|".join(re.escape(m) for m in method_sinks) + r")\s*\(")
        if method_sinks else None
    )

    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue

        if echo_re and "htmlspecialchars" not in line:
            m = echo_re.search(line)
            if m and m.group(1) in tainted_vars:
                findings.append(TaintFinding(
                    file=path,
                    line_no=line_no,
                    line_text=stripped[:200],
                    vuln_name="Cross-Site Scripting (XSS)",
                    severity=SEVERITY_BY_VULN["Cross-Site Scripting (XSS)"],
                    why=WHY_BY_VULN["Cross-Site Scripting (XSS)"],
                    payload=PAYLOAD_BY_VULN["Cross-Site Scripting (XSS)"],
                    confidence="possible",
                    tainted_var=m.group(1),
                ))

        if method_sink_re:
            mm = method_sink_re.search(line)
            if mm and mm.group(1) in tainted_vars:
                receiver, method_name = mm.group(1), mm.group(2)
                vuln = method_sinks[method_name]
                findings.append(TaintFinding(
                    file=path,
                    line_no=line_no,
                    line_text=stripped[:200],
                    vuln_name=vuln,
                    severity=SEVERITY_BY_VULN.get(vuln, "medium"),
                    why=WHY_BY_VULN.get(vuln, "Tainted variable reaches a dangerous sink."),
                    payload=PAYLOAD_BY_VULN.get(vuln, "Investigate manually."),
                    confidence="possible",
                    tainted_var=receiver,
                ))

        call_match = sink_call_re.search(line)
        if not call_match:
            continue
        sink_name = call_match.group(1)
        vuln = sinks[sink_name]
        # Only look at the sink call's FIRST argument — the query string /
        # command / path itself. A tainted var passed as a later argument
        # (e.g. execute("...%s...", (name,)) ) is normal parameterized
        # binding, not a vulnerability, so we deliberately ignore it there.
        open_paren_idx = call_match.end() - 1
        first_arg = _first_call_arg(line, open_paren_idx)
        if _is_plain_literal(first_arg, language):
            continue  # a plain string literal can't execute a variable
        if vuln == "Open Redirect" and _is_same_origin_redirect_target(first_arg):
            continue  # a leading single "/" can only ever redirect on-site
        for var in tainted_vars:
            if _var_referenced(var, first_arg):
                findings.append(TaintFinding(
                    file=path,
                    line_no=line_no,
                    line_text=stripped[:200],
                    vuln_name=vuln,
                    severity=SEVERITY_BY_VULN.get(vuln, "medium"),
                    why=WHY_BY_VULN.get(vuln, "Tainted variable reaches a dangerous sink."),
                    payload=PAYLOAD_BY_VULN.get(vuln, "Investigate manually."),
                    confidence="possible",
                    tainted_var=var,
                ))
                break  # one flag per line is enough
    return findings


def find_format_string_sinks(path: str, language: str, lines: List[str]) -> List[TaintFinding]:
    """Separate, independent pass from find_tainted_sinks() above: this one
    doesn't need SOURCE_PATTERNS/SINKS at all, since what's "tainted" here is
    the template string itself (see FORMAT_BUILD_RE/FORMAT_SINK_RE docstring),
    not a value flowing from a request object into an argument."""
    build_re = FORMAT_BUILD_RE.get(language)
    sink_re = FORMAT_SINK_RE.get(language)
    if not build_re or not sink_re:
        return []

    built_up_vars = set()
    for line in lines:
        m = build_re.match(line)
        if m:
            built_up_vars.add(m.group(1))

    if not built_up_vars:
        return []

    findings = []
    vuln = "Format String Injection"
    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        m = sink_re.search(line)
        if m and m.group(1) in built_up_vars:
            findings.append(TaintFinding(
                file=path,
                line_no=line_no,
                line_text=stripped[:200],
                vuln_name=vuln,
                severity=SEVERITY_BY_VULN.get(vuln, "medium"),
                why=WHY_BY_VULN.get(vuln, "Tainted template string reaches its own .format() call."),
                payload=PAYLOAD_BY_VULN.get(vuln, "Investigate manually."),
                confidence="possible",
                tainted_var=m.group(1),
            ))
    return findings
