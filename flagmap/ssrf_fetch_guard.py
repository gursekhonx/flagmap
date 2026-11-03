"""
ssrf_fetch_guard.py — best-effort suppression of `patterns.py`'s
taint-blind JS SSRF regex (`fetch(var, ...)`/`axios.get(var)`/
`http.get(var)`, the "possible"-confidence entry — never the separate,
"likely"-confidence entry that requires a literal `req.query`/`req.params`/
`req.body` in the same match) when the whole file is unambiguously
client-side JS.

That "possible"-confidence rule exists as a coarse backstop for exactly
the case its own why-text names: "an outbound HTTP request made to a URL
held in a plain variable... if it traces back to a request parameter."
It's written with server-side Node/Express code in mind — a route
handler that reads a URL from somewhere and calls `fetch()`/`axios.get()`
with it — but it fires on ANY `.js`-mapped file calling `fetch(var)`,
with no check at all for whether this is server code handling a real
HTTP request or a browser script making its own ordinary network call.

Found via real-world testing against WebGoat: `lessons/webauthn/js/
webauthn.js`'s `webauthnRequest(url, options)` helper and `lessons/
securitymisconfiguration/js/security-misconfiguration-task2.js`'s click
handlers both call `fetch(url, ...)`/`fetch(url, {...})` with a variable
— but both run entirely in the BROWSER. There's no SSRF here even in
principle: Server-Side Request Forgery is specifically about tricking a
*server* into making a request from its own privileged network position
on an attacker's behalf. A client's own browser making its own fetch
call is just ordinary web traffic, already bound by the browser's same-
origin policy and the user's own network position — there's no
trust-boundary crossing for "SSRF" to even describe. Confirmed via the
real security-misconfiguration-task2.js case: its `url` is built from
`configButton.getAttribute('data-url')`, a value baked into the page's
own DOM by the server that rendered it, not attacker-supplied at all.

Deliberately scoped to ONLY the "possible"-confidence, taint-blind
regex entry, identified by a stable substring of its own why-text
(`"held in a plain variable — check where that variable"`) — the
separate "likely"-confidence entry (`fetch(...).*req\\.(?:query|params|
body)`) is never touched: it requires `req.query`/`req.params`/
`req.body` literally in the same match, which no browser script could
ever produce (there's no Express `req` object in client-side JS), so it
was never at risk of this false positive and narrowing it further would
only risk a false negative on a real server-side bug.

Reuses `js_clientside_guard.py`'s `is_clientside_js()` — the exact same
"is this file unambiguously client-side" predicate `jquery_dom_guard.py`
already uses for its own, unrelated IDOR fallback false positive — so a
file is suppressed here only when it shows no `req.`/`res.` reference,
no server-framework import, and no route-registration call anywhere (or
is already recognized as vendored by `vendor_guard.py`). Confirmed
true-negative against the project's own `tests/fixtures/js/vuln_sinks.js`
SSRF case (`app.get("/proxy", ...)` with `req.query.url`), which keeps
firing exactly as before since that file is wall-to-wall Express
signals.

Known blind spot, same honesty standard as `jquery_dom_guard.py`: a real
server-side SSRF bug reached only through this coarse fallback rule, in
a file that happens to use none of `is_clientside_js()`'s recognized
signals, would also be wrongly suppressed. Accepted for the same reason
— it hasn't been hit in any real corpus tested so far (DVWA, Mutillidae,
NodeGoat, RailsGoat, Juice Shop, WebGoat), and the alternative (leaving
the rule unconditional) was actively producing confirmed noise on
completely ordinary client-side `fetch()` calls, which are close to
universal in any modern web front-end.
"""

from typing import List

from .js_clientside_guard import is_clientside_js

_VULN_NAME = "SSRF (Server-Side Request Forgery)"
_SUPPRESSIBLE_WHY_SUBSTRING = "held in a plain variable — check where that variable"


def filter_clientside_js_false_ssrf(path: str, language: str, lines: List[str], findings: List) -> List:
    """Returns `findings` with any SSRF entry removed when it came from
    `patterns.py`'s taint-blind `fetch(var, ...)`-style regex (identified
    by its own distinctive why-text, never the stricter `req.query`-
    anchored entry) inside a JS file with no server-side signal
    anywhere. Every other finding — including every SSRF finding that
    actually names a `req.*` source, every non-SSRF finding, and
    anything in a non-JS file — passes through unchanged. See module
    docstring for exactly what this does and doesn't try to prove."""
    if language != "js":
        return findings
    suppressible = [
        f for f in findings
        if getattr(f, "vuln_name", None) == _VULN_NAME and _SUPPRESSIBLE_WHY_SUBSTRING in getattr(f, "why", "")
    ]
    if not suppressible:
        return findings

    full_text = "".join(lines)
    if not is_clientside_js(path, full_text):
        return findings  # some sign of server-route code exists somewhere in the file — never suppress

    to_remove = {f.line_no for f in suppressible}
    return [
        f for f in findings
        if not (f.vuln_name == _VULN_NAME and _SUPPRESSIBLE_WHY_SUBSTRING in f.why and f.line_no in to_remove)
    ]
