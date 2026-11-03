"""
js_clientside_guard.py — shared "is this JS file unambiguously client-side,
with no server-route signal anywhere" predicate, factored out of
`jquery_dom_guard.py` (v1.19.0) so a second guard (`ssrf_fetch_guard.py`,
v1.20.0) can reuse the exact same signal rather than growing a second,
slightly-diverging copy of it.

The predicate: no `req.`/`res.` reference, no
`require("express"/"koa"/"fastify"/"http"/"https")`, and no
`app.(get|post|put|delete|patch|use)(` / `router.(...)(` call anywhere in
the whole file — OR the file is already recognized as vendored by
`vendor_guard.py`'s own, independently-tested `is_vendor_file()` (which
bypasses the signal scan entirely; see below for why).

Deliberately does NOT include the long forms `request.` / `response.`
as a signal, even though an earlier version of this check (shipped inside
`jquery_dom_guard.py` in v1.19.0) did. Narrowed in v1.20.0 after it
turned out to collide with TWO unrelated, extremely common JS
conventions that have nothing to do with Express/Koa request handling:

  1. jQuery UI's own Autocomplete widget names its `source` callback
     `function(request, response)` as a plain variable-naming
     convention (this is what `jquery_dom_guard.py`'s own
     `is_vendor_file()` bypass exists for in the first place).
  2. The Fetch API's own standard promise-chain idiom —
     `fetch(url).then(function(response) { return response.json(); })`
     — names its resolved value `response` constantly, in essentially
     EVERY piece of client-side code that calls `fetch()` at all. This
     is what motivated extracting this module: `ssrf_fetch_guard.py`
     needs to recognize a file as client-side specifically BECAUSE it
     calls `fetch()`, so a signal that fires on `response.json()` —
     the single most common way to actually consume a fetch() result —
     would make the "no server signal" check next to useless for the
     exact files it most needs to clear.

`req.`/`res.` (the short forms) are kept: real Express/Koa/Fastify
handler code overwhelmingly uses the short spelling by convention, and
neither collides with any client-side idiom found so far. The known
blind spot this trades away — a real server file that spells its
handler parameters `request`/`response` in full, with no other
recognized signal anywhere in the file — is accepted for the same
reason `vendor_guard.py`'s own filename-only signals accept their
blind spots: it hasn't been hit in any real corpus tested so far (DVWA,
Mutillidae, NodeGoat, RailsGoat, Juice Shop, WebGoat), and the
alternative (keeping the long forms) was actively hiding a confirmed,
much more common false positive.
"""

import re

from .vendor_guard import is_vendor_file

_JS_SERVER_SIGNAL_RE = re.compile(
    r"""\breq\.|\bres\.|
        require\(\s*['"](?:express|koa|fastify|http|https)['"]\s*\)|
        \bapp\.(?:get|post|put|delete|patch|use)\s*\(|
        \brouter\.(?:get|post|put|delete|patch|use)\s*\(""",
    re.IGNORECASE | re.VERBOSE,
)


def is_clientside_js(path: str, full_text: str) -> bool:
    """True when this JS file is unambiguously client-side: either
    `vendor_guard.py` already recognizes it as a vendored/third-party
    library (which skips the signal scan below entirely — see module
    docstring for why), or nothing in its text looks like server-route
    handling code at all. False whenever there's real ambiguity — the
    caller should then leave whatever finding it was considering alone."""
    if is_vendor_file(path, full_text):
        return True
    return not _JS_SERVER_SIGNAL_RE.search(full_text)
